"""OpenAI clients over the attested HTTP clients. Each is an ``openai`` client whose requests go through one of
them, so every HTTP resource of the ``openai`` package works unchanged and no application data is sent before
the enclave is verified. The one exception is the realtime resource: it opens a websocket of its own, outside
``http_client``, so it is refused rather than left to bypass the attested transport."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from functools import cached_property
from typing import Any, NoReturn, Protocol, Self, TypedDict, TypeVar, Unpack

import httpx
import openai
from openai import DataResidency, Timeout
from openai.auth import WorkloadIdentity, X509WorkloadIdentity
from openai.resources.beta import AsyncBeta, Beta

from tinfoil._v3._clients import (
    AsyncEnclaveHTTPClient,
    AsyncGatewayHTTPClient,
    AsyncRouterHTTPClient,
    EnclaveHTTPClient,
    GatewayHTTPClient,
    RouterHTTPClient,
)
from tinfoil._v3._errors import ConfigurationError
from tinfoil._v3._gateway import Catalog, ModelPin
from tinfoil._v3._types import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_TRANSPORT_MODE,
    TimeoutTypes,
    TransportMode,
    VerificationCheck,
)
from tinfoil._v3.verifier import Verifier

_C = TypeVar("_C", bound=openai.AsyncOpenAI)

HTTP_CLIENT_FIXED = "http_client is the attested HTTP client's and cannot be replaced"
DROP_IN_OPTIONS = "{name} takes only the openai package's options; {keys} belong to {route}"
REALTIME_UNAVAILABLE = "realtime is not available over an attested client"
"""The message of the ConfigurationError that accessing a realtime resource raises: its websocket would open
outside the attested HTTP client, bypassing the origin guard, the TLS pin and EHBP."""

ROUTE_OPTIONS = frozenset(
    {"transport_mode", "base_url", "verifier", "verification_check", "user_cache_secret", "http_timeout"}
)
"""The options that configure a route, which the drop-in ``Client`` and ``AsyncClient`` refuse."""


class _SharedOptions(TypedDict, total=False):
    """The ``openai`` client options whose types are the same for the synchronous and asynchronous clients."""

    admin_api_key: str | None
    workload_identity: WorkloadIdentity | X509WorkloadIdentity | None
    organization: str | None
    project: str | None
    webhook_secret: str | None
    websocket_base_url: str | httpx.URL | None
    provider: object | None
    data_residency: DataResidency | None
    timeout: float | httpx.Timeout | Timeout | None
    max_retries: int
    default_headers: Mapping[str, str] | None
    default_query: Mapping[str, object] | None


class OpenAIOptions(_SharedOptions, total=False):
    """The ``openai.OpenAI`` constructor options that the synchronous OpenAI clients accept by keyword: every
    option of the installed ``openai`` package except ``http_client`` and ``base_url``, which the attested
    client fixes. ``timeout`` and ``max_retries`` are per request, as they are in the package; the attested
    client's own timeout is the ``http_timeout`` option. ``api_key`` may be a callable that returns the key."""

    api_key: str | Callable[[], str] | None


class AsyncOpenAIOptions(_SharedOptions, total=False):
    """``OpenAIOptions`` for the asynchronous clients, whose ``api_key`` callable returns an awaitable."""

    api_key: str | Callable[[], Awaitable[str]] | None


class _CopyOnlyOptions(TypedDict, total=False):
    """The options that ``copy`` and ``with_options`` take besides the constructor's: a replacement for the
    client's default headers or query, where ``default_headers`` and ``default_query`` merge into them."""

    set_default_headers: Mapping[str, str] | None
    set_default_query: Mapping[str, object] | None


class OpenAICopyOptions(OpenAIOptions, _CopyOnlyOptions, total=False):
    """The options of ``copy`` and ``with_options`` on the synchronous OpenAI clients."""


class AsyncOpenAICopyOptions(AsyncOpenAIOptions, _CopyOnlyOptions, total=False):
    """The options of ``copy`` and ``with_options`` on the asynchronous OpenAI clients."""


def _no_realtime() -> NoReturn:
    raise ConfigurationError(REALTIME_UNAVAILABLE)


class _Beta(Beta):
    """The ``beta`` resources without their realtime alias."""

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()


class _AsyncBeta(AsyncBeta):
    """``_Beta`` for the asynchronous clients."""

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()


class _Closable(Protocol):
    def close(self) -> None: ...


class _AsyncClosable(Protocol):
    async def close(self) -> None: ...


class _AttestedOpenAI(openai.OpenAI):
    """An ``openai.OpenAI`` client over an attested HTTP client, ``_tinfoil``, which it closes with itself and
    shares with its copies. Its realtime resource, and the ``beta`` alias, raise a ConfigurationError instead of
    opening a websocket outside the attested HTTP client."""

    _tinfoil: _Closable

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()

    @cached_property
    def beta(self) -> _Beta:
        return _Beta(self)

    def _shared(self) -> dict[str, object]:
        """What a copy's constructor receives besides the options: the attested client it shares."""
        return {"_http_client": self._tinfoil}

    # The method it overrides also takes base_url and http_client, which the attested client fixes, so this one
    # accepts fewer options than its supertype's.
    def copy(self, **kwargs: Unpack[OpenAICopyOptions]) -> Self:  # type: ignore[override]
        """A client with ``kwargs`` applied over this one's options, sharing its attested client."""
        return super().copy(**_copy_options(kwargs, self._shared()))

    with_options = copy  # type: ignore[assignment]

    def close(self) -> None:
        """Closes the attested client as well, which every copy shares, so a copy's ``close`` closes the
        original's too."""
        super().close()
        self._tinfoil.close()


class _AsyncAttestedOpenAI(openai.AsyncOpenAI):
    """``_AttestedOpenAI`` for ``openai.AsyncOpenAI``."""

    _tinfoil: _AsyncClosable

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()

    @cached_property
    def beta(self) -> _AsyncBeta:
        return _AsyncBeta(self)

    def _shared(self) -> dict[str, object]:
        return {"_http_client": self._tinfoil}

    def copy(self, **kwargs: Unpack[AsyncOpenAICopyOptions]) -> Self:  # type: ignore[override]
        """A client with ``kwargs`` applied over this one's options, sharing its attested client."""
        return super().copy(**_copy_options(kwargs, self._shared()))

    with_options = copy  # type: ignore[assignment]

    async def close(self) -> None:
        """Closes the attested client as well, which every copy shares, so a copy's ``close`` closes the
        original's too."""
        await super().close()
        await self._tinfoil.close()


def _openai_options(
    kwargs: Mapping[str, object], http_client: httpx.Client | httpx.AsyncClient, base_url: str
) -> dict[str, Any]:
    """``kwargs`` with the attested HTTP client and its base URL, which the caller's options cannot replace. The
    per-request ``timeout`` keeps the ``openai`` package's own default unless the caller sets it: the attested
    client's timeout, which ``http_timeout`` sets, is not adopted in its place."""
    options: dict[str, Any] = dict(kwargs)
    supplied = options.pop("http_client", None)
    if supplied is not None and supplied is not http_client:
        raise ConfigurationError(HTTP_CLIENT_FIXED)
    options.pop("base_url", None)
    options.setdefault("timeout", openai.DEFAULT_TIMEOUT)
    return {**options, "http_client": http_client, "base_url": base_url}


def _copy_options(kwargs: Mapping[str, object], shared: Mapping[str, object]) -> dict[str, Any]:
    """``kwargs`` for the ``openai`` package's ``copy``, with ``shared`` passed to the copy's constructor."""
    options: dict[str, Any] = dict(kwargs)
    options["_extra_kwargs"] = {**options.pop("_extra_kwargs", {}), **shared}
    return options


def _refuse_route_options(name: str, route: str, kwargs: Mapping[str, object]) -> None:
    """Raises ConfigurationError naming the route options in ``kwargs``, which ``name`` does not take."""
    refused = sorted(ROUTE_OPTIONS.intersection(kwargs))
    if refused:
        raise ConfigurationError(DROP_IN_OPTIONS.format(name=name, keys=", ".join(refused), route=route))


class EnclaveOpenAIClient(_AttestedOpenAI):
    """An ``openai.OpenAI`` client whose requests go through an ``EnclaveHTTPClient``, to ``base_url`` or, when
    that is unset, the enclave's ``/v1/`` API.

    ``host``, ``repo`` and the keyword options up to ``http_timeout`` are
    those of ``EnclaveHTTPClient``, which is created first and verifies the
    enclave; ``http_timeout`` is its ``timeout``. The remaining keyword
    arguments are ``OpenAIOptions``, the ``openai`` package's, applied after
    it; ``http_client`` and ``base_url`` are the attested client's and
    cannot be replaced. ``copy`` and ``with_options`` share the attested
    client, so closing a copy closes the original's too. The ``realtime``
    resource, whose websocket would bypass the attested client, raises a
    ConfigurationError.
    """

    _tinfoil: EnclaveHTTPClient

    def __init__(
        self,
        host: str,
        repo: str | None,
        *,
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        _http_client: EnclaveHTTPClient | None = None,
        **openai_kwargs: Unpack[OpenAIOptions],
    ) -> None:
        owned = _http_client is None
        if _http_client is None:
            _http_client = EnclaveHTTPClient(
                host,
                repo,
                transport_mode=transport_mode,
                base_url=base_url,
                verifier=verifier,
                verification_check=verification_check,
                user_cache_secret=user_cache_secret,
                timeout=http_timeout,
            )
        self._tinfoil = _http_client
        attested = _http_client._attested
        with _closing_on_failure(_http_client, owned):
            super().__init__(**_openai_options(openai_kwargs, attested.http_client, attested.openai_url))

    @property
    def http_client(self) -> EnclaveHTTPClient:
        """The enclave client the OpenAI client sends through."""
        return self._tinfoil

    def _shared(self) -> dict[str, object]:
        return {"host": self._tinfoil.enclave, "repo": self._tinfoil.repo, "_http_client": self._tinfoil}


class AsyncEnclaveOpenAIClient(_AsyncAttestedOpenAI):
    """``EnclaveOpenAIClient`` for asyncio, built with ``await AsyncEnclaveOpenAIClient.create(...)``, which
    takes the same arguments, with ``AsyncOpenAIOptions``. The ``realtime`` resource raises a
    ConfigurationError."""

    _tinfoil: AsyncEnclaveHTTPClient

    def __init__(
        self, *, _http_client: AsyncEnclaveHTTPClient | None = None, **openai_kwargs: Unpack[AsyncOpenAIOptions]
    ) -> None:
        if _http_client is None:
            raise ConfigurationError(f"{type(self).__name__} is built with 'await {type(self).__name__}.create(...)'")
        self._tinfoil = _http_client
        attested = _http_client._attested
        super().__init__(**_openai_options(openai_kwargs, attested.http_client, attested.openai_url))

    @classmethod
    async def create(
        cls,
        host: str,
        repo: str | None,
        *,
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        **openai_kwargs: Unpack[AsyncOpenAIOptions],
    ) -> Self:
        http_client = await AsyncEnclaveHTTPClient.create(
            host,
            repo,
            transport_mode=transport_mode,
            base_url=base_url,
            verifier=verifier,
            verification_check=verification_check,
            user_cache_secret=user_cache_secret,
            timeout=http_timeout,
        )
        return await _built(cls, http_client, openai_kwargs)

    @property
    def http_client(self) -> AsyncEnclaveHTTPClient:
        """The enclave client the OpenAI client sends through."""
        return self._tinfoil


class RouterOpenAIClient(_AttestedOpenAI):
    """An ``openai.OpenAI`` client whose requests go through a ``RouterHTTPClient``, to ``base_url`` or, when
    that is unset, the router's ``/v1/`` API. The keyword options up to ``http_timeout`` are those of
    ``RouterHTTPClient``, ``http_timeout`` being its ``timeout``; the remaining keyword arguments are
    ``OpenAIOptions``, the ``openai`` package's, except ``http_client`` and ``base_url``, which the attested
    client fixes. ``copy`` and ``with_options`` share the attested client, so closing a copy closes the
    original's too. The ``realtime`` resource, whose websocket would bypass the attested client, raises a
    ConfigurationError."""

    _tinfoil: RouterHTTPClient

    def __init__(
        self,
        *,
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        _http_client: RouterHTTPClient | None = None,
        **openai_kwargs: Unpack[OpenAIOptions],
    ) -> None:
        owned = _http_client is None
        if _http_client is None:
            _http_client = RouterHTTPClient(
                transport_mode=transport_mode,
                base_url=base_url,
                verifier=verifier,
                verification_check=verification_check,
                user_cache_secret=user_cache_secret,
                timeout=http_timeout,
            )
        self._tinfoil = _http_client
        attested = _http_client._attested
        with _closing_on_failure(_http_client, owned):
            super().__init__(**_openai_options(openai_kwargs, attested.http_client, attested.openai_url))

    @property
    def http_client(self) -> RouterHTTPClient:
        """The router client the OpenAI client sends through."""
        return self._tinfoil


class AsyncRouterOpenAIClient(_AsyncAttestedOpenAI):
    """``RouterOpenAIClient`` for asyncio, built with ``await AsyncRouterOpenAIClient.create(...)``, with
    ``AsyncOpenAIOptions``. The ``realtime`` resource raises a ConfigurationError."""

    _tinfoil: AsyncRouterHTTPClient

    def __init__(
        self, *, _http_client: AsyncRouterHTTPClient | None = None, **openai_kwargs: Unpack[AsyncOpenAIOptions]
    ) -> None:
        if _http_client is None:
            raise ConfigurationError(f"{type(self).__name__} is built with 'await {type(self).__name__}.create(...)'")
        self._tinfoil = _http_client
        attested = _http_client._attested
        super().__init__(**_openai_options(openai_kwargs, attested.http_client, attested.openai_url))

    @classmethod
    async def create(
        cls,
        *,
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        **openai_kwargs: Unpack[AsyncOpenAIOptions],
    ) -> Self:
        http_client = await AsyncRouterHTTPClient.create(
            transport_mode=transport_mode,
            base_url=base_url,
            verifier=verifier,
            verification_check=verification_check,
            user_cache_secret=user_cache_secret,
            timeout=http_timeout,
        )
        return await _built(cls, http_client, openai_kwargs)

    @property
    def http_client(self) -> AsyncRouterHTTPClient:
        return self._tinfoil


class GatewayOpenAIClient(_AttestedOpenAI):
    """An ``openai.OpenAI`` client whose requests go through a ``GatewayHTTPClient``, to the gateway's URL. The
    keyword options up to ``http_timeout`` are those of ``GatewayHTTPClient``, ``http_timeout`` being its
    ``timeout``; the remaining keyword arguments are ``OpenAIOptions``, the ``openai`` package's, except
    ``http_client`` and ``base_url``, which the gateway client fixes. ``copy`` and ``with_options`` share the
    gateway client, so closing a copy closes the original's too. The ``realtime`` resource, whose websocket
    would bypass the gateway client, raises a ConfigurationError.

    Experimental: the gateway route is new, and this API may change or be
    removed in a later release.
    """

    _tinfoil: GatewayHTTPClient

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
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        _http_client: GatewayHTTPClient | None = None,
        **openai_kwargs: Unpack[OpenAIOptions],
    ) -> None:
        owned = _http_client is None
        if _http_client is None:
            _http_client = GatewayHTTPClient(
                model_pins=model_pins,
                pinned_models_only=pinned_models_only,
                verifier=verifier,
                verification_check=verification_check,
                user_cache_secret=user_cache_secret,
                url=url,
                catalog=catalog,
                timeout=http_timeout,
            )
        self._tinfoil = _http_client
        with _closing_on_failure(_http_client, owned):
            super().__init__(**_openai_options(openai_kwargs, _http_client.http_client, _http_client.base_url))

    @property
    def http_client(self) -> GatewayHTTPClient:
        """The gateway client the OpenAI client sends through."""
        return self._tinfoil


class AsyncGatewayOpenAIClient(_AsyncAttestedOpenAI):
    """``GatewayOpenAIClient`` for asyncio, built with ``await AsyncGatewayOpenAIClient.create(...)``, with
    ``AsyncOpenAIOptions``. The ``realtime`` resource raises a ConfigurationError.

    Experimental: the gateway route is new, and this API may change or be
    removed in a later release.
    """

    _tinfoil: AsyncGatewayHTTPClient

    def __init__(
        self, *, _http_client: AsyncGatewayHTTPClient | None = None, **openai_kwargs: Unpack[AsyncOpenAIOptions]
    ) -> None:
        if _http_client is None:
            raise ConfigurationError(f"{type(self).__name__} is built with 'await {type(self).__name__}.create(...)'")
        self._tinfoil = _http_client
        super().__init__(**_openai_options(openai_kwargs, _http_client.http_client, _http_client.base_url))

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
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        **openai_kwargs: Unpack[AsyncOpenAIOptions],
    ) -> Self:
        http_client = await AsyncGatewayHTTPClient.create(
            model_pins=model_pins,
            pinned_models_only=pinned_models_only,
            verifier=verifier,
            verification_check=verification_check,
            user_cache_secret=user_cache_secret,
            url=url,
            catalog=catalog,
            timeout=http_timeout,
        )
        return await _built(cls, http_client, openai_kwargs)

    @property
    def http_client(self) -> AsyncGatewayHTTPClient:
        return self._tinfoil


class Client(RouterOpenAIClient):
    """An OpenAI client for Tinfoil's recommended route: the router, verified before the constructor returns. It
    takes only the ``openai`` package's options, ``OpenAIOptions``; a route option, such as a proxy
    ``base_url``, a transport mode, verifier, verification check, cache secret or ``http_timeout``, is a
    ConfigurationError here, from the constructor and from ``copy`` and ``with_options`` alike, and is configured
    on ``RouterOpenAIClient`` instead."""

    def __init__(self, *, _http_client: RouterHTTPClient | None = None, **openai_kwargs: Unpack[OpenAIOptions]) -> None:
        if _http_client is None:
            _refuse_route_options("Client", "RouterOpenAIClient", openai_kwargs)
        super().__init__(_http_client=_http_client, **openai_kwargs)

    # A copy's constructor receives the attested client's own base URL, so the caller's options are checked here.
    def copy(self, **kwargs: Unpack[OpenAICopyOptions]) -> Self:  # type: ignore[override]
        _refuse_route_options("Client", "RouterOpenAIClient", kwargs)
        return super().copy(**kwargs)

    with_options = copy  # type: ignore[assignment]


class AsyncClient(AsyncRouterOpenAIClient):
    """``Client`` for asyncio, built with ``await AsyncClient.create(...)`` or ``create_async_client``, with
    ``AsyncOpenAIOptions``."""

    def __init__(
        self, *, _http_client: AsyncRouterHTTPClient | None = None, **openai_kwargs: Unpack[AsyncOpenAIOptions]
    ) -> None:
        super().__init__(_http_client=_http_client, **openai_kwargs)

    # Narrower than the route client's create on purpose: the route options are refused here.
    @classmethod
    async def create(cls, **openai_kwargs: Unpack[AsyncOpenAIOptions]) -> Self:  # type: ignore[override]
        _refuse_route_options("AsyncClient", "AsyncRouterOpenAIClient", openai_kwargs)
        return await super().create(**openai_kwargs)

    def copy(self, **kwargs: Unpack[AsyncOpenAICopyOptions]) -> Self:  # type: ignore[override]
        _refuse_route_options("AsyncClient", "AsyncRouterOpenAIClient", kwargs)
        return super().copy(**kwargs)

    with_options = copy  # type: ignore[assignment]


def create_client(**openai_kwargs: Unpack[OpenAIOptions]) -> Client:
    """An OpenAI client for Tinfoil's recommended route, verified before it returns. ``openai_kwargs`` are the
    ``openai.OpenAI`` constructor's keyword arguments, such as ``api_key``, ``timeout`` and ``max_retries``."""
    return Client(**openai_kwargs)


async def create_async_client(**openai_kwargs: Unpack[AsyncOpenAIOptions]) -> AsyncClient:
    """``create_client`` for asyncio."""
    return await AsyncClient.create(**openai_kwargs)


@contextmanager
def _closing_on_failure(http_client: _Closable, owned: bool) -> Iterator[None]:
    """Closes ``http_client`` when the ``openai`` constructor inside refuses the options, but only when the
    constructor created it: a copy shares the original's, which stays in use."""
    try:
        yield
    except BaseException:
        if owned:
            http_client.close()
        raise


async def _built(cls: Callable[..., _C], http_client: _AsyncClosable, openai_kwargs: Mapping[str, object]) -> _C:
    """``cls`` over ``http_client``, which is closed when the ``openai`` constructor refuses the options."""
    try:
        return cls(_http_client=http_client, **openai_kwargs)
    except BaseException:
        await http_client.close()
        raise


__all__ = [
    "AsyncClient",
    "AsyncEnclaveOpenAIClient",
    "AsyncGatewayOpenAIClient",
    "AsyncOpenAICopyOptions",
    "AsyncOpenAIOptions",
    "AsyncRouterOpenAIClient",
    "Client",
    "EnclaveOpenAIClient",
    "GatewayOpenAIClient",
    "OpenAICopyOptions",
    "OpenAIOptions",
    "RouterOpenAIClient",
    "create_async_client",
    "create_client",
]
