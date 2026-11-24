"""The HTTP clients of the three routes: one explicit enclave, the router that discovery chooses, and the gateway.

Each is an ``httpx`` client whose transport verifies before it sends and
binds every request to the keys of the current verification, so a caller's
own timeouts and request options keep the guarantees. Each constructor
checks its options before any network I/O, then does the route's first
network work before it returns, so a misconfigured client fails here rather
than on its first request. The asynchronous clients are built with
``await Cls.create(...)``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import TracebackType
from typing import Self, TypeAlias
from urllib.parse import urlsplit

import httpx

from tinfoil import _cachesecret
from tinfoil._chain import (
    AsyncReplay,
    Replay,
    with_cache_secret,
    with_cache_secret_async,
    with_enclave_url,
    with_enclave_url_async,
    with_origin_restriction,
    with_origin_restriction_async,
)
from tinfoil._enclave import Enclave, new_verifier
from tinfoil._errors import ConfigurationError
from tinfoil._fetchers import (
    AsyncAttestationFetcher,
    AsyncRouterListFetcher,
    AttestationFetcher,
    AttestationRelay,
    RouterListFetcher,
    RouterListRelay,
    async_document_fetch,
    async_router_list,
    sync_document_fetch,
    sync_router_list,
)
from tinfoil._gateway import (
    DEFAULT_GATEWAY_URL,
    AsyncGatewayTransport,
    Catalog,
    GatewayTransport,
    ModelPin,
    ReplicaVerification,
)
from tinfoil._router import discover, discover_async
from tinfoil._transport import (
    USE_CLIENT_DEFAULT,
    AsyncAttestedTransport,
    AttestedTransport,
    UseClientDefault,
    async_mode_for,
    mode_for,
    resolve_transport,
)
from tinfoil._trust import Trust, verifier_inputs
from tinfoil._types import (
    DEFAULT_HTTP_TIMEOUT,
    LastVerification,
    OnVerification,
    TimeoutTypes,
    Transport,
    VerificationCheck,
)
from tinfoil._url import (
    has_query_or_fragment,
    origin_of,
    refuse_enclave_origin_proxy,
    with_trailing_slash,
)
from tinfoil.verifier import Policy, VerificationReport

ASYNC_CONSTRUCTOR = "{name} is built with 'await {name}.create(...)'"


class _Attested:
    """What the enclave and router clients share: the verified enclave and the chain their requests go through.
    The chain, from the inside out: the proxy header, one replay after a key rejection, the cache secret, and
    origin pinning. The cache secret sits above the attested transport, so the field it adds is sealed with the
    rest of the body or sent over the pinned connection; an empty secret, as on the enclave clients, adds none.
    ``http_client`` is the caller's ``httpx`` client over
    the chain; ``secure`` is a second one over the same chain that OpenAI clients send through, which changes
    to the caller's client, such as its headers, authentication or event hooks, cannot reach."""

    def __init__(self, keyed: AttestedTransport, proxy_url: str, secret: str) -> None:
        host = keyed.enclave.host
        chain = with_enclave_url(keyed, host, proxy_url)
        chain = Replay(chain, buffer_bodies=keyed.mode.buffers_request_bodies)
        chain = with_cache_secret(chain, secret)
        guard = with_origin_restriction(chain, host, proxy_url)
        self.keyed = keyed
        self.http_client = httpx.Client(transport=guard, timeout=keyed.timeout)
        self.secure = httpx.Client(transport=guard, timeout=keyed.timeout)
        self.base_url = proxy_url or f"https://{host}/"

    def close(self) -> None:
        self.http_client.close()
        self.secure.close()


class _AsyncAttested:
    def __init__(self, keyed: AsyncAttestedTransport, proxy_url: str, secret: str) -> None:
        host = keyed.enclave.host
        chain = with_enclave_url_async(keyed, host, proxy_url)
        chain = AsyncReplay(chain, buffer_bodies=keyed.mode.buffers_request_bodies)
        chain = with_cache_secret_async(chain, secret)
        guard = with_origin_restriction_async(chain, host, proxy_url)
        self.keyed = keyed
        self.http_client = httpx.AsyncClient(transport=guard, timeout=keyed.timeout)
        self.secure = httpx.AsyncClient(transport=guard, timeout=keyed.timeout)
        self.base_url = proxy_url or f"https://{host}/"

    async def close(self) -> None:
        await self.http_client.aclose()
        await self.secure.aclose()


class _AttestedClient:
    """The methods and properties the enclave and router clients share."""

    _attested: _Attested

    @property
    def http_client(self) -> httpx.Client:
        """The ``httpx`` client that sends through the attested transport. It verifies the enclave again before
        new requests when the verification expires or its key changes, and refuses requests to any other origin,
        so sensitive headers cannot be disclosed elsewhere. A request's body and the response to it are protected
        end to end; headers, and a request without a body, are not private on the EHBP transport. Attested
        requests never follow redirects: a 3xx response is returned to the caller. A streaming request body,
        such as an iterator, is sent only on the ``TLS`` transport; the EHBP transport reads bodies into
        memory, since a sealed body may be sent again after a key rotation."""
        return self._attested.http_client

    @property
    def base_url(self) -> str:
        """The URL that requests are sent to: the ``EHBP`` proxy URL, with a trailing slash, or the enclave's own
        origin when the client connects directly. Build request URLs for ``http_client`` from it so that they
        follow the route."""
        return self._attested.base_url

    @property
    def enclave(self) -> str:
        """The host of the enclave that the client verifies. It stays the enclave's host when requests go through
        an ``EHBP`` proxy URL."""
        return self._attested.keyed.enclave.host

    def last_verification(self) -> LastVerification:
        """The most recent verification attempt, without I/O, as ``(report, error)``: the report and None if it
        passed, and None and the client error that it raised if it failed, with the verifier's
        ``VerificationError`` and its report as that error's ``__cause__`` when the verifier rejected the
        document. Every attempt counts: the first verification, its retry, a refresh after expiry or a key
        rotation, and ``reverify``. A report that it returns may have expired or been rejected since;
        ``ensure_verified`` returns one that is valid. For a router client it describes the router that the
        client chose."""
        return self._attested.keyed.last_verification()

    def ensure_verified(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> VerificationReport:
        """The report of a verification that is valid now, verifying first only if the cached one has expired or
        been rejected. It also prepares the TLS pin or HPKE key for it, so returning means requests can be sent.
        ``timeout`` bounds each network operation of a verification: ``httpx.USE_CLIENT_DEFAULT``, the default,
        selects the client's own, None disables the timeout, and the attestation fetch as a whole is bounded at 30
        seconds besides."""
        return self._attested.keyed.ensure_verified(timeout=timeout)

    def reverify(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> VerificationReport:
        """Verifies again even if the cached verification is still valid, and returns the new report. ``timeout``
        is as for ``ensure_verified``. A failure raises as usual; an AttestationError also discards the cached
        verification and retires the connections that were made under it, so that no later request is sent under
        it and the next request verifies again. A NetworkError, a ConfigurationError or an interruption keeps a
        cached verification that is still fresh."""
        return self._attested.keyed.reverify(timeout=timeout)

    def close(self) -> None:
        """Releases the client's connections and stops re-verification. After it, the client's own methods
        raise ConfigurationError, while a request sent through the closed ``http_client`` raises the
        ``RuntimeError`` that ``httpx`` raises for a closed client. An OpenAI client built over this one closes
        it with itself, and its copies share it, so closing a copy closes the original's too. A client is not
        shared across ``os.fork``: its connections and verification state belong to the process that made it."""
        self._attested.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()


class _AsyncAttestedClient:
    _attested: _AsyncAttested

    @property
    def http_client(self) -> httpx.AsyncClient:
        """The ``httpx.AsyncClient`` that sends through the attested transport; see the synchronous client for
        what it protects, redirects and streaming request bodies."""
        return self._attested.http_client

    @property
    def base_url(self) -> str:
        """The URL that requests are sent to: the ``EHBP`` proxy URL, or the enclave's own origin."""
        return self._attested.base_url

    @property
    def enclave(self) -> str:
        """The host of the enclave the client verifies."""
        return self._attested.keyed.enclave.host

    def last_verification(self) -> LastVerification:
        """The most recent verification attempt, without I/O, as for the synchronous client. It is not a
        coroutine."""
        return self._attested.keyed.last_verification()

    async def ensure_verified(self) -> VerificationReport:
        """The report of a verification that is valid now, verifying first only if the cached one has expired or
        been rejected. Cancelling the task ends its wait, not a verification other callers share."""
        return await self._attested.keyed.ensure_verified()

    async def reverify(self) -> VerificationReport:
        """Verifies again even if the cached verification is still valid, and returns the new report. As for the
        synchronous client, an AttestationError discards the cached verification, so that the next request
        verifies again, while a NetworkError, a ConfigurationError or a cancellation keeps one that is still
        fresh."""
        return await self._attested.keyed.reverify()

    async def close(self) -> None:
        """Releases the client's connections and stops re-verification; see the synchronous client for what a
        closed client refuses, how OpenAI copies share it, and forking."""
        await self._attested.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.close()


def _enclave_parts(
    host: str,
    trust: Trust,
    transport: Transport | None,
    policy: Policy | None,
    verification_check: VerificationCheck | None,
    on_verification: OnVerification | None,
    fetch_attestation: object,
    *,
    asynchronous: bool,
) -> tuple[Enclave, Transport, str, Trust]:
    """The checks an enclave client makes before any network I/O, in order: the host, the trust argument, the
    transport and its proxy URL, the attestation fetcher, the verifier that the trust and the policy describe,
    whether the trust can be satisfied at all, and a proxy URL on the enclave's own origin. Returns the enclave,
    the transport, the proxy URL and a copy of the trust argument."""
    if not host:
        raise ConfigurationError("enclave host is required")
    inputs = verifier_inputs(trust)
    resolved, proxy_url = resolve_transport(transport)
    fetch_document = None if asynchronous else sync_document_fetch(fetch_attestation)
    fetch_document_async = async_document_fetch(fetch_attestation) if asynchronous else None
    verifier = new_verifier(inputs.config, policy)
    enclave = Enclave(
        host,
        inputs.pin,
        verifier=verifier,
        verification_check=verification_check,
        on_verification=on_verification,
        fetch_document=fetch_document,
        fetch_document_async=fetch_document_async,
    )
    refuse_enclave_origin_proxy(proxy_url, host)
    return enclave, resolved, proxy_url, inputs.trust


class EnclaveHTTPClient(_AttestedClient):
    """An ``httpx`` client whose requests reach only one attested enclave.

    ``host`` is the enclave, with an optional port, and ``trust`` names who
    vouches for the config that it runs: a ``RepoPin``, ``ProjectPin``,
    ``SignedBy``, ``AuthorizedBy``, ``EmbeddedConfig`` or ``EitherPin``. Both
    are required. ``policy``, a ``tinfoil.verifier.Policy``, holds the checks
    that apply on top of the trust; None keeps every default. ``transport``
    is ``TLS()``, the default, or ``EHBP(proxy_url=...)``; a proxy URL is
    where requests are sent, and they carry ``X-Tinfoil-Enclave-Url`` so
    that the proxy can forward them. ``fetch_attestation`` is how the client
    obtains each attestation document: an ``AttestationFetcher`` callable or
    an ``AttestationRelay``; None fetches it directly from the enclave.
    ``verification_check``, when set, is called with the verified facts of
    each verification that passes the trust and the policy before the client
    uses the enclave's keys; raising rejects the enclave, and the rejection
    is not retried. ``on_verification``, when set, is called with the
    enclave's host and the outcome of every verification attempt, as
    ``OnVerification`` describes; ``last_verification`` returns the most
    recent one. ``timeout`` is
    the ``httpx`` timeout of ``http_client`` and of the client's own
    attestation fetches, which are bounded as a whole besides, at 30
    seconds each; it defaults to ``DEFAULT_HTTP_TIMEOUT``.

    The client sends request bodies as they are: it never adds or changes a
    ``user_cache_secret`` member, so a caller that points it at Tinfoil's
    router and wants a scoped prompt cache sets that member in each request
    body, for example with the ``openai`` package's ``extra_body``.

    The trust argument and the options are checked before any network I/O,
    including that the trust can be satisfied at all; a value of another
    type is a ConfigurationError. The enclave is then verified before the
    constructor returns. The client verifies again by itself when the
    verification expires or is rejected.
    """

    def __init__(
        self,
        host: str,
        trust: Trust,
        *,
        transport: Transport | None = None,
        policy: Policy | None = None,
        verification_check: VerificationCheck | None = None,
        on_verification: OnVerification | None = None,
        fetch_attestation: AttestationFetcher | AttestationRelay | None = None,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
    ) -> None:
        enclave, resolved, proxy_url, self._trust = _enclave_parts(
            host, trust, transport, policy, verification_check, on_verification, fetch_attestation, asynchronous=False
        )
        keyed = AttestedTransport(enclave, mode_for(resolved), timeout=timeout)
        self._attested = _Attested(keyed, proxy_url, "")
        try:
            keyed.ensure_verified()
        except BaseException:
            self.close()
            raise

    @property
    def trust(self) -> Trust:
        """The trust argument that the enclave is verified under. It is a copy that shares no mutable value with
        the caller's, so later changes by the caller have no effect on the client."""
        return self._trust


class AsyncEnclaveHTTPClient(_AsyncAttestedClient):
    """``EnclaveHTTPClient`` for asyncio, built with ``await AsyncEnclaveHTTPClient.create(...)``, which takes
    the same arguments, with an ``AsyncAttestationFetcher`` or an ``AttestationRelay`` for ``fetch_attestation``."""

    def __init__(self, *, _attested: _AsyncAttested | None = None, _trust: Trust | None = None) -> None:
        if _attested is None or _trust is None:
            raise ConfigurationError(ASYNC_CONSTRUCTOR.format(name=type(self).__name__))
        self._attested = _attested
        self._trust = _trust

    @classmethod
    async def create(
        cls,
        host: str,
        trust: Trust,
        *,
        transport: Transport | None = None,
        policy: Policy | None = None,
        verification_check: VerificationCheck | None = None,
        on_verification: OnVerification | None = None,
        fetch_attestation: AsyncAttestationFetcher | AttestationRelay | None = None,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
    ) -> Self:
        enclave, resolved, proxy_url, copied = _enclave_parts(
            host, trust, transport, policy, verification_check, on_verification, fetch_attestation, asynchronous=True
        )
        keyed = AsyncAttestedTransport(enclave, async_mode_for(resolved), timeout=timeout)
        client = cls(_attested=_AsyncAttested(keyed, proxy_url, ""), _trust=copied)
        try:
            await keyed.ensure_verified()
        except BaseException:
            await client.close()
            raise
        return client

    @property
    def trust(self) -> Trust:
        """The trust argument that the enclave is verified under, as on ``EnclaveHTTPClient``."""
        return self._trust


class RouterHTTPClient(_AttestedClient):
    """An ``httpx`` client whose requests reach only the attested router it discovered.

    The constructor checks its options before any network I/O, then tries
    the routers on Tinfoil's router list, in random order, for at most 30
    seconds and keeps the first that verifies, falling back to
    ``inference.tinfoil.sh``, which it verifies before returning. It
    discovers again each time it is called. ``fetch_router_list``, a
    ``RouterListFetcher`` callable or a ``RouterListRelay``, replaces the
    fetch of Tinfoil's list; ``fetch_attestation`` obtains the documents of
    every router that discovery tries and of the fallback.
    An ``EHBP`` proxy URL forwards requests to the router that discovery
    chooses. ``policy`` applies on top of the
    router's fixed trust, its own repository. ``user_cache_secret`` empty selects a random secret that is
    generated once per process and shared by every client in it; pass a
    value for a secret that is stable across processes. When that secret
    can't be generated because the operating system's random source fails,
    the constructor raises the exception that ``secrets`` raised, unchanged,
    before any network I/O. The other options are those of
    ``EnclaveHTTPClient``.
    """

    def __init__(
        self,
        *,
        transport: Transport | None = None,
        policy: Policy | None = None,
        verification_check: VerificationCheck | None = None,
        on_verification: OnVerification | None = None,
        user_cache_secret: str | None = None,
        fetch_attestation: AttestationFetcher | AttestationRelay | None = None,
        fetch_router_list: RouterListFetcher | RouterListRelay | None = None,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
    ) -> None:
        resolved, proxy_url = resolve_transport(transport)
        fetch_document = sync_document_fetch(fetch_attestation)
        list_routers = sync_router_list(fetch_router_list)
        verifier = new_verifier(None, policy)
        mode = mode_for(resolved)
        secret = _cachesecret.resolve(user_cache_secret)
        keyed = discover(
            verifier,
            verification_check,
            lambda enclave: AttestedTransport(enclave, mode, timeout=timeout),
            timeout=timeout,
            list_routers=list_routers,
            fetch_document=fetch_document,
            on_verification=on_verification,
        )
        self._attested = _Attested(keyed, proxy_url, secret)
        # Discovery leaves its fallback unverified.
        try:
            keyed.ensure_verified()
        except BaseException:
            self.close()
            raise


class AsyncRouterHTTPClient(_AsyncAttestedClient):
    """``RouterHTTPClient`` for asyncio, built with ``await AsyncRouterHTTPClient.create(...)``."""

    def __init__(self, *, _attested: _AsyncAttested | None = None) -> None:
        if _attested is None:
            raise ConfigurationError(ASYNC_CONSTRUCTOR.format(name=type(self).__name__))
        self._attested = _attested

    @classmethod
    async def create(
        cls,
        *,
        transport: Transport | None = None,
        policy: Policy | None = None,
        verification_check: VerificationCheck | None = None,
        on_verification: OnVerification | None = None,
        user_cache_secret: str | None = None,
        fetch_attestation: AsyncAttestationFetcher | AttestationRelay | None = None,
        fetch_router_list: AsyncRouterListFetcher | RouterListRelay | None = None,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
    ) -> Self:
        resolved, proxy_url = resolve_transport(transport)
        fetch_document = async_document_fetch(fetch_attestation)
        list_routers = async_router_list(fetch_router_list)
        verifier = new_verifier(None, policy)
        mode = async_mode_for(resolved)
        secret = _cachesecret.resolve(user_cache_secret)
        keyed = await discover_async(
            verifier,
            verification_check,
            lambda enclave: AsyncAttestedTransport(enclave, mode, timeout=timeout),
            timeout=timeout,
            list_routers=list_routers,
            fetch_document=fetch_document,
            on_verification=on_verification,
        )
        client = cls(_attested=_AsyncAttested(keyed, proxy_url, secret))
        try:
            await keyed.ensure_verified()
        except BaseException:
            await client.close()
            raise
        return client


GATEWAY_URL_INVALID = (
    "gateway base URL must be an absolute HTTPS URL with a host and without user information, a query or a fragment"
)
"""The message for a gateway URL that is refused. The URL itself is never echoed, since it may carry
credentials."""


def _gateway_url(url: str | None) -> tuple[str, str]:
    """The gateway base URL, with a trailing slash, and its host, which attestation is fetched through."""
    base_url = url or DEFAULT_GATEWAY_URL
    try:
        origin = origin_of(base_url)
    except ValueError:
        raise ConfigurationError(GATEWAY_URL_INVALID) from None
    if not origin.startswith("https://") or has_query_or_fragment(base_url):
        raise ConfigurationError(GATEWAY_URL_INVALID)
    return with_trailing_slash(base_url), urlsplit(base_url).netloc


class GatewayHTTPClient:
    """An ``httpx`` client for Tinfoil inference through the gateway. Each request is sealed to a verified
    replica of the model that it names, as with the ``EHBP`` transport: the gateway sees the method, URL and
    headers, and WebSocket upgrades are refused.

    ``model_pins`` pins models to repositories; with ``pinned_models_only``,
    only pinned models are served, which requires at least one pin.
    ``policy``, a ``tinfoil.verifier.Policy``, is the verification policy for
    unpinned models, and for pinned models whose pin sets none; a pin's own
    policy replaces it entirely for that model. ``verification_check`` is called with each
    replica's verified facts; a replica that it rejects is skipped for the
    next replica of the model. ``on_verification`` is called with the
    replica's host and the outcome of every attempt to verify a replica, and
    ``last_verification`` returns each replica's last attempt. ``user_cache_secret`` empty selects the random
    secret that is generated once per process, as on ``RouterHTTPClient``,
    whose constructor fails the same way when that secret can't be generated;
    the gateway sees a cache prefix keyed on it, never the secret. ``url``
    is the gateway's base URL, exposed as ``base_url`` with a trailing
    slash; None selects Tinfoil's gateway. ``catalog`` is read on every request and
    must return an immutable mapping; None fetches the gateway's catalog
    when the client is created and refreshes it every 10 seconds while the
    client is used, keeping the last catalog when a refresh fails.

    The options are copied and checked before any network I/O; the catalog
    is then fetched before the constructor returns. A model's replicas are
    verified on its first request, so pins may name models the catalog does
    not list. A verified replica's transport is kept while the catalog lists
    its host; when a changed catalog no longer does, the transport takes no
    new requests and closes once its responses in flight are done.

    Experimental: the gateway route is new, and this API may change or be
    removed in a later release.
    """

    def __init__(
        self,
        *,
        model_pins: Mapping[str, ModelPin] | None = None,
        pinned_models_only: bool = False,
        policy: Policy | None = None,
        verification_check: VerificationCheck | None = None,
        on_verification: OnVerification | None = None,
        user_cache_secret: str | None = None,
        url: str | None = None,
        catalog: Callable[[], Catalog] | None = None,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
    ) -> None:
        base_url, relay = _gateway_url(url)
        self._transport = GatewayTransport(
            base_url=base_url,
            relay=relay,
            catalog=catalog,
            model_pins=model_pins,
            pinned_models_only=pinned_models_only,
            policy=policy,
            verification_check=verification_check,
            on_verification=on_verification,
            user_cache_secret=user_cache_secret,
            timeout=timeout,
        )
        guard = with_origin_restriction(self._transport, "", base_url)
        self._http_client = httpx.Client(transport=guard, timeout=timeout)
        # What OpenAI clients send through, which changes to the caller's client cannot reach.
        self._secure = httpx.Client(transport=guard, timeout=timeout)
        self._base_url = base_url
        try:
            self._transport.models()
        except BaseException:
            self.close()
            raise

    @property
    def http_client(self) -> httpx.Client:
        """The ``httpx`` client that seals each request to a verified replica of its model. Requests never
        follow redirects: a 3xx response is returned to the caller. Request bodies are read into memory, since a
        sealed body may be sent again after a key rotation or a seal redirect; a multipart upload with an
        explicit ``X-Tinfoil-Model`` header is the exception and streams."""
        return self._http_client

    @property
    def base_url(self) -> str:
        """The gateway's base URL, which requests are sent to."""
        return self._base_url

    def models(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> list[str]:
        """The catalog's models that the client's policy serves, sorted, without verifying replicas. A failed
        catalog refresh does not fail it; only the first fetch can. ``timeout`` bounds each network operation of
        a catalog fetch that the call makes: ``httpx.USE_CLIENT_DEFAULT``, the default, selects the client's
        own, None disables the timeout, and the fetch as a whole is bounded at 10 seconds besides."""
        return self._transport.models(timeout=timeout)

    def ensure_verified(
        self, model: str, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT
    ) -> VerificationReport:
        """The report of a verification that is valid now of a replica serving ``model``, verifying replicas only
        if needed.
        ``timeout`` bounds each network operation of the catalog and attestation fetches that the call makes:
        ``httpx.USE_CLIENT_DEFAULT``, the default, selects the client's own, None disables the timeout, and each
        fetch as a whole is bounded besides, at 10 seconds for the catalog and 30 for an attestation."""
        return self._transport.ensure_verified(model, timeout=timeout)

    def last_verification(self) -> list[ReplicaVerification]:
        """One entry for each replica that the client has tried to verify and that the catalog still lists, failed
        replicas included, each holding that replica's last attempt, without I/O: its report if the attempt
        passed, and otherwise its error. A replica's earlier success is not kept once a later attempt for it
        fails. Reports may have expired or been rejected since."""
        return self._transport.last_verification()

    def close(self) -> None:
        """Releases every replica's connections and stops catalog refreshes; one in flight finishes on its own
        and its result is dropped. After it, the client's own methods raise ConfigurationError, while a request
        sent through the closed ``http_client`` raises the ``RuntimeError`` that ``httpx`` raises for a closed
        client. An OpenAI client built over this one closes it with itself, and its copies share it, so closing
        a copy closes the original's too. A client is not shared across ``os.fork``: its connections and
        verification state belong to the process that made it."""
        self._http_client.close()
        self._secure.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()


class AsyncGatewayHTTPClient:
    """``GatewayHTTPClient`` for asyncio, built with ``await AsyncGatewayHTTPClient.create(...)``, which takes the
    same arguments.

    Experimental: the gateway route is new, and this API may change or be
    removed in a later release.
    """

    def __init__(self, *, _transport: AsyncGatewayTransport | None = None, _base_url: str = "") -> None:
        if _transport is None:
            raise ConfigurationError(ASYNC_CONSTRUCTOR.format(name=type(self).__name__))
        self._transport = _transport
        self._base_url = _base_url
        guard = with_origin_restriction_async(_transport, "", _base_url)
        self._http_client = httpx.AsyncClient(transport=guard, timeout=_transport.timeout)
        self._secure = httpx.AsyncClient(transport=guard, timeout=_transport.timeout)

    @classmethod
    async def create(
        cls,
        *,
        model_pins: Mapping[str, ModelPin] | None = None,
        pinned_models_only: bool = False,
        policy: Policy | None = None,
        verification_check: VerificationCheck | None = None,
        on_verification: OnVerification | None = None,
        user_cache_secret: str | None = None,
        url: str | None = None,
        catalog: Callable[[], Catalog] | None = None,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
    ) -> Self:
        base_url, relay = _gateway_url(url)
        transport = AsyncGatewayTransport(
            base_url=base_url,
            relay=relay,
            catalog=catalog,
            model_pins=model_pins,
            pinned_models_only=pinned_models_only,
            policy=policy,
            verification_check=verification_check,
            on_verification=on_verification,
            user_cache_secret=user_cache_secret,
            timeout=timeout,
        )
        client = cls(_transport=transport, _base_url=base_url)
        try:
            await transport.models()
        except BaseException:
            await client.close()
            raise
        return client

    @property
    def http_client(self) -> httpx.AsyncClient:
        """The ``httpx.AsyncClient`` that seals each request to a verified replica of its model; see the
        synchronous client for redirects and request bodies."""
        return self._http_client

    @property
    def base_url(self) -> str:
        """The gateway's base URL, which requests are sent to: the ``url`` option with a trailing slash."""
        return self._base_url

    async def models(self) -> list[str]:
        """The catalog's models that the client's policy serves, sorted, without verifying replicas."""
        return await self._transport.models()

    async def ensure_verified(self, model: str) -> VerificationReport:
        """The report of a verification that is valid now of a replica serving ``model``."""
        return await self._transport.ensure_verified(model)

    def last_verification(self) -> list[ReplicaVerification]:
        """Each tried replica's last attempt, without I/O, as for the synchronous client. It is not a
        coroutine."""
        return self._transport.last_verification()

    async def close(self) -> None:
        """Releases every replica's connections and stops catalog refreshes; see the synchronous client for what
        a closed client refuses, how OpenAI copies share it, and forking."""
        await self._http_client.aclose()
        await self._secure.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.close()


AttestedHTTPClient: TypeAlias = EnclaveHTTPClient | RouterHTTPClient | GatewayHTTPClient
"""An HTTP client that an ``OpenAIClient`` sends through: one of this package's three, as its constructor
returned it."""

AsyncAttestedHTTPClient: TypeAlias = AsyncEnclaveHTTPClient | AsyncRouterHTTPClient | AsyncGatewayHTTPClient
"""An HTTP client that an ``AsyncOpenAIClient`` sends through, as its ``create`` returned it."""

__all__ = [
    "AsyncAttestedHTTPClient",
    "AsyncEnclaveHTTPClient",
    "AsyncGatewayHTTPClient",
    "AsyncRouterHTTPClient",
    "AttestedHTTPClient",
    "EnclaveHTTPClient",
    "GatewayHTTPClient",
    "RouterHTTPClient",
]
