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
from typing import Self
from urllib.parse import urlsplit

import httpx

from tinfoil._v3 import _cachesecret
from tinfoil._v3._chain import (
    AsyncReplay,
    Replay,
    with_cache_secret,
    with_cache_secret_async,
    with_enclave_url,
    with_enclave_url_async,
    with_origin_restriction,
    with_origin_restriction_async,
)
from tinfoil._v3._enclave import Enclave
from tinfoil._v3._errors import ConfigurationError
from tinfoil._v3._gateway import (
    DEFAULT_GATEWAY_URL,
    AsyncGatewayTransport,
    Catalog,
    GatewayTransport,
    ModelPin,
    ReplicaVerification,
)
from tinfoil._v3._router import discover, discover_async
from tinfoil._v3._transport import (
    USE_CLIENT_DEFAULT,
    AsyncAttestedTransport,
    AttestedTransport,
    UseClientDefault,
    async_mode_for,
    mode_for,
)
from tinfoil._v3._types import DEFAULT_TIMEOUT, DEFAULT_TRANSPORT_MODE, TimeoutTypes, TransportMode, VerificationCheck
from tinfoil._v3._url import origin_of, validate_base_url, validate_tls_base_url, with_trailing_slash
from tinfoil._v3.verifier import Verification, Verifier

ROUTER_PROXY_NEEDS_EHBP = 'a base URL is a proxy when discovering the router, which requires the "ehbp" transport mode'
ROUTER_NEEDS_REPO = "caller-authorized config requires an explicit enclave"
ASYNC_CONSTRUCTOR = "{name} is built with 'await {name}.create(...)'"


class _Attested:
    """What the enclave and router clients share: the verified enclave and the chain their requests go through.
    The chain, from the inside out: the proxy header, one replay after a key rejection, the cache secret, and
    origin pinning. The cache secret sits above the attested transport, so the field it adds is sealed with the
    rest of the body or sent over the pinned connection."""

    def __init__(self, keyed: AttestedTransport, transport_mode: TransportMode, base_url: str, secret: str) -> None:
        host = keyed.enclave.host
        if transport_mode == "tls":
            validate_tls_base_url(base_url, host)
        chain = with_enclave_url(keyed, host, base_url)
        chain = Replay(chain, buffer_bodies=keyed.mode.buffers_request_bodies)
        chain = with_cache_secret(chain, secret)
        guard = with_origin_restriction(chain, host, base_url)
        self.keyed = keyed
        self.http_client = httpx.Client(transport=guard, timeout=keyed.timeout)
        self.base_url = base_url or f"https://{host}/"
        self.openai_url = base_url or f"https://{host}/v1/"


class _AsyncAttested:
    def __init__(
        self, keyed: AsyncAttestedTransport, transport_mode: TransportMode, base_url: str, secret: str
    ) -> None:
        host = keyed.enclave.host
        if transport_mode == "tls":
            validate_tls_base_url(base_url, host)
        chain = with_enclave_url_async(keyed, host, base_url)
        chain = AsyncReplay(chain, buffer_bodies=keyed.mode.buffers_request_bodies)
        chain = with_cache_secret_async(chain, secret)
        guard = with_origin_restriction_async(chain, host, base_url)
        self.keyed = keyed
        self.http_client = httpx.AsyncClient(transport=guard, timeout=keyed.timeout)
        self.base_url = base_url or f"https://{host}/"
        self.openai_url = base_url or f"https://{host}/v1/"


class _AttestedClient:
    """The methods and properties the enclave and router clients share."""

    _attested: _Attested

    @property
    def http_client(self) -> httpx.Client:
        """The ``httpx`` client that sends through the attested transport. It verifies the enclave again before
        new requests when the verification expires or its key changes, and refuses requests to any other origin,
        so sensitive headers cannot be disclosed elsewhere. A request's body and the response to it are protected
        end to end; headers, and a request without a body, are not private on the EHBP transport."""
        return self._attested.http_client

    @property
    def base_url(self) -> str:
        """The URL requests are sent to: the ``base_url`` option, or the enclave's own origin. Build request URLs
        for ``http_client`` from it so they follow the route."""
        return self._attested.base_url

    @property
    def enclave(self) -> str:
        """The host of the enclave the client verifies. It stays the enclave's host when ``base_url`` is a
        proxy."""
        return self._attested.keyed.enclave.host

    @property
    def repo(self) -> str:
        """The repository the enclave is verified against, with any tag or digest pins. Empty when the
        verifier authorizes the config instead."""
        return self._attested.keyed.enclave.repo

    @property
    def current(self) -> Verification | None:
        """The last successful verification without checking it, or None. It may have expired or been rejected;
        ``ensure_verified`` returns one that is valid."""
        return self._attested.keyed.current

    def ensure_verified(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> Verification:
        """A verification that is valid now, verifying first only if the cached one has expired or been rejected.
        It also prepares the TLS pin or HPKE key for it, so returning means requests can be sent. ``timeout``
        bounds the network operations of a verification; the client's own applies by default."""
        return self._attested.keyed.ensure_verified(timeout=timeout)

    def reverify(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> Verification:
        """Verifies again even if the cached verification is still valid."""
        return self._attested.keyed.reverify(timeout=timeout)

    def close(self) -> None:
        """Releases the client's connections and stops re-verification. A closed client refuses requests and
        verifications with a ConfigurationError."""
        self._attested.http_client.close()

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
        """The ``httpx.AsyncClient`` that sends through the attested transport; see the synchronous client."""
        return self._attested.http_client

    @property
    def base_url(self) -> str:
        """The URL requests are sent to: the ``base_url`` option, or the enclave's own origin."""
        return self._attested.base_url

    @property
    def enclave(self) -> str:
        """The host of the enclave the client verifies."""
        return self._attested.keyed.enclave.host

    @property
    def repo(self) -> str:
        """The repository the enclave is verified against, with any tag or digest pins."""
        return self._attested.keyed.enclave.repo

    @property
    def current(self) -> Verification | None:
        """The last successful verification without checking it, or None."""
        return self._attested.keyed.current

    async def ensure_verified(self) -> Verification:
        """A verification that is valid now, verifying first only if the cached one has expired or been rejected.
        Cancelling the task ends its wait, not a verification other callers share."""
        return await self._attested.keyed.ensure_verified()

    async def reverify(self) -> Verification:
        """Verifies again even if the cached verification is still valid."""
        return await self._attested.keyed.reverify()

    async def close(self) -> None:
        """Releases the client's connections and stops re-verification. A closed client refuses requests and
        verifications with a ConfigurationError."""
        await self._attested.http_client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.close()


def _enclave_parts(
    host: str,
    repo: str | None,
    transport_mode: TransportMode,
    base_url: str | None,
    verifier: Verifier | None,
    verification_check: VerificationCheck | None,
) -> tuple[Enclave, str]:
    """The checks an enclave client makes before any network I/O, in order: the host, the transport mode, the
    base URL and the repository."""
    if not host:
        raise ConfigurationError("enclave host is required")
    mode_for(transport_mode)
    checked = validate_base_url(base_url) if base_url else ""
    enclave = Enclave(host, repo, verifier=verifier, verification_check=verification_check)
    return enclave, checked


class EnclaveHTTPClient(_AttestedClient):
    """An ``httpx`` client whose requests reach only one attested enclave.

    ``host`` is the enclave, with an optional port, and ``repo`` the
    repository it is verified against, ``owner/name[@tag][@sha256:digest]``;
    an empty or None ``repo`` accepts configs authorized by ``verifier``,
    which defaults to public registry trust. ``transport_mode`` defaults to
    ``"tls"``. ``base_url`` is a path on the enclave's own HTTPS origin, or
    a proxy on another origin, which requires ``"ehbp"``; requests to a
    proxy carry ``X-Tinfoil-Enclave-Url`` so it can forward them. A proxy
    must use HTTPS, since EHBP does not seal headers such as the API key;
    ``http://`` is accepted only for localhost or a loopback IP address.
    ``verification_check``, when set, is called with each verification that
    passes ``verifier`` before the client uses the enclave's keys; raising
    rejects the enclave, and the rejection is not retried.
    ``user_cache_secret``, when set, is the default prompt-cache scope for
    the client's requests; only Tinfoil's router reads it. ``timeout`` is
    the ``httpx`` timeout of ``http_client`` and of the client's own
    attestation fetches.

    The options are checked before any network I/O; the enclave is then
    verified before the constructor returns. The client verifies again by
    itself when the verification expires or is rejected.
    """

    def __init__(
        self,
        host: str,
        repo: str | None = None,
        *,
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> None:
        enclave, checked = _enclave_parts(host, repo, transport_mode, base_url, verifier, verification_check)
        keyed = AttestedTransport(enclave, mode_for(transport_mode), timeout=timeout)
        self._attested = _Attested(keyed, transport_mode, checked, user_cache_secret or "")
        try:
            keyed.ensure_verified()
        except BaseException:
            self.close()
            raise


class AsyncEnclaveHTTPClient(_AsyncAttestedClient):
    """``EnclaveHTTPClient`` for asyncio, built with ``await AsyncEnclaveHTTPClient.create(...)``, which takes
    the same arguments."""

    def __init__(self, *, _attested: _AsyncAttested | None = None) -> None:
        if _attested is None:
            raise ConfigurationError(ASYNC_CONSTRUCTOR.format(name=type(self).__name__))
        self._attested = _attested

    @classmethod
    async def create(
        cls,
        host: str,
        repo: str | None = None,
        *,
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Self:
        enclave, checked = _enclave_parts(host, repo, transport_mode, base_url, verifier, verification_check)
        keyed = AsyncAttestedTransport(enclave, async_mode_for(transport_mode), timeout=timeout)
        client = cls(_attested=_AsyncAttested(keyed, transport_mode, checked, user_cache_secret or ""))
        try:
            await keyed.ensure_verified()
        except BaseException:
            await client.close()
            raise
        return client


def _router_checks(transport_mode: TransportMode, base_url: str | None, verifier: Verifier | None) -> str:
    """The checks a router client makes before discovery, in order: the transport mode, the base URL, which is a
    proxy and so requires EHBP, and the verifier, which must verify against the router's repository."""
    mode_for(transport_mode)
    checked = ""
    if base_url:
        checked = validate_base_url(base_url)
        if transport_mode == "tls":
            raise ConfigurationError(ROUTER_PROXY_NEEDS_EHBP)
    if verifier is not None and verifier.caller_authorizes_config:
        raise ConfigurationError(ROUTER_NEEDS_REPO)
    return checked


class RouterHTTPClient(_AttestedClient):
    """An ``httpx`` client whose requests reach only the attested router it discovered.

    The constructor checks its options before any network I/O, then tries
    the routers on Tinfoil's router list for at most 30 seconds and keeps the
    first that verifies, falling back to ``inference.tinfoil.sh``, which it
    verifies before returning. It discovers again each time it is called.
    ``base_url`` is a proxy that forwards requests to the router discovery
    chooses, and requires ``"ehbp"``. A ``verifier`` that authorizes the
    config itself is refused, since the router is verified against its own
    repository. ``user_cache_secret`` empty resolves the secret from
    ``TINFOIL_USER_CACHE_SECRET`` or ``~/.tinfoil/user_cache_secret``. The
    other options are those of ``EnclaveHTTPClient``.
    """

    def __init__(
        self,
        *,
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> None:
        checked = _router_checks(transport_mode, base_url, verifier)
        mode = mode_for(transport_mode)
        keyed = discover(
            verifier,
            verification_check,
            lambda enclave: AttestedTransport(enclave, mode, timeout=timeout),
            timeout=timeout,
        )
        secret = _cachesecret.resolve(user_cache_secret)
        self._attested = _Attested(keyed, transport_mode, checked, secret)
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
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Self:
        checked = _router_checks(transport_mode, base_url, verifier)
        mode = async_mode_for(transport_mode)
        keyed = await discover_async(
            verifier,
            verification_check,
            lambda enclave: AsyncAttestedTransport(enclave, mode, timeout=timeout),
            timeout=timeout,
        )
        secret = _cachesecret.resolve(user_cache_secret)
        client = cls(_attested=_AsyncAttested(keyed, transport_mode, checked, secret))
        try:
            await keyed.ensure_verified()
        except BaseException:
            await client.close()
            raise
        return client


GATEWAY_URL_INVALID = "gateway base URL must be an absolute HTTPS URL with a host and without user information"
"""The message for a gateway URL that is refused. The URL itself is never echoed, since it may carry
credentials."""


def _gateway_url(url: str | None) -> tuple[str, str]:
    """The gateway base URL, with a trailing slash, and its host, which attestation is fetched through."""
    base_url = url or DEFAULT_GATEWAY_URL
    try:
        origin = origin_of(base_url)
    except ValueError:
        raise ConfigurationError(GATEWAY_URL_INVALID) from None
    if not origin.startswith("https://"):
        raise ConfigurationError(GATEWAY_URL_INVALID)
    return with_trailing_slash(base_url), urlsplit(base_url).netloc


class GatewayHTTPClient:
    """An ``httpx`` client for Tinfoil inference through the gateway. Each request is sealed to a verified
    replica of the model it names, as with the ``"ehbp"`` transport mode: the gateway sees the method, URL and
    headers, and WebSocket upgrades are refused.

    ``model_pins`` pins models to repositories; with ``pinned_models_only``,
    only pinned models are served, which requires at least one pin.
    ``verifier`` is the policy for unpinned models; a pin's own verifier
    replaces it for that model. ``verification_check`` is called with each
    replica's verification; a replica it rejects is skipped for the next
    replica of the model. ``user_cache_secret`` empty resolves the secret
    from the environment or the persisted file; the gateway sees a cache
    prefix keyed on it, never the secret. ``url`` is the gateway's base URL;
    None selects Tinfoil's gateway. ``catalog`` is read on every request and
    must return an immutable mapping; None fetches the gateway's catalog
    when the client is created and refreshes it every 10 seconds while the
    client is used, keeping the last catalog when a refresh fails.

    The options are copied and checked before any network I/O; the catalog
    is then fetched before the constructor returns. A model's replicas are
    verified on its first request, so pins may name models the catalog does
    not list.

    Experimental: the gateway route is new, and this API may change or be
    removed in a later release.
    """

    def __init__(
        self,
        *,
        model_pins: Mapping[str, ModelPin] | None = None,
        pinned_models_only: bool = False,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        url: str | None = None,
        catalog: Callable[[], Catalog] | None = None,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> None:
        base_url, relay = _gateway_url(url)
        self._transport = GatewayTransport(
            base_url=base_url,
            relay=relay,
            catalog=catalog,
            model_pins=model_pins,
            pinned_models_only=pinned_models_only,
            verifier=verifier,
            verification_check=verification_check,
            user_cache_secret=user_cache_secret,
            timeout=timeout,
        )
        guard = with_origin_restriction(self._transport, "", base_url)
        self._http_client = httpx.Client(transport=guard, timeout=timeout)
        self._base_url = base_url
        try:
            self._transport.models()
        except BaseException:
            self.close()
            raise

    @property
    def http_client(self) -> httpx.Client:
        """The ``httpx`` client that seals each request to a verified replica of its model."""
        return self._http_client

    @property
    def base_url(self) -> str:
        """The gateway's base URL, which requests are sent to."""
        return self._base_url

    def models(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> list[str]:
        """The catalog's models that the client's policy serves, sorted, without verifying replicas. A failed
        catalog refresh does not fail it; only the first fetch can."""
        return self._transport.models(timeout=timeout)

    def ensure_verified(
        self, model: str, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT
    ) -> Verification:
        """A verification that is valid now of a replica serving ``model``, verifying replicas only if needed."""
        return self._transport.ensure_verified(model, timeout=timeout)

    @property
    def current(self) -> list[ReplicaVerification]:
        """The last successful verification of each replica used so far, without checking them. They may have
        expired or been rejected."""
        return self._transport.verifications()

    def close(self) -> None:
        """Releases every replica's connections. A closed client refuses requests with a ConfigurationError."""
        self._http_client.close()

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

    @classmethod
    async def create(
        cls,
        *,
        model_pins: Mapping[str, ModelPin] | None = None,
        pinned_models_only: bool = False,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        url: str | None = None,
        catalog: Callable[[], Catalog] | None = None,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ) -> Self:
        base_url, relay = _gateway_url(url)
        transport = AsyncGatewayTransport(
            base_url=base_url,
            relay=relay,
            catalog=catalog,
            model_pins=model_pins,
            pinned_models_only=pinned_models_only,
            verifier=verifier,
            verification_check=verification_check,
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
        return self._http_client

    @property
    def base_url(self) -> str:
        return self._base_url

    async def models(self) -> list[str]:
        """The catalog's models that the client's policy serves, sorted, without verifying replicas."""
        return await self._transport.models()

    async def ensure_verified(self, model: str) -> Verification:
        """A verification that is valid now of a replica serving ``model``."""
        return await self._transport.ensure_verified(model)

    @property
    def current(self) -> list[ReplicaVerification]:
        return self._transport.verifications()

    async def close(self) -> None:
        await self._http_client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.close()


__all__ = [
    "AsyncEnclaveHTTPClient",
    "AsyncGatewayHTTPClient",
    "AsyncRouterHTTPClient",
    "EnclaveHTTPClient",
    "GatewayHTTPClient",
    "RouterHTTPClient",
]
