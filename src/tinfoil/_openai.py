"""OpenAI clients over the attested HTTP clients. Each is an ``openai`` client whose requests go through one of
them, so every HTTP resource of the ``openai`` package works unchanged and no application data is sent before
the enclave is verified. The exceptions are the websocket entry points: the ``realtime`` resource and the
``connect`` methods of ``responses``, ``beta.responses``, ``live``, ``live.sideband`` and ``live.forks``. Each
opens a websocket of its own, which can't use the attested HTTP client, so each is refused with a
ConfigurationError rather than left to bypass the attested transport, and so is the ``websocket_base_url``
option that would point them elsewhere."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from functools import cached_property
from typing import Any, NoReturn, Protocol, Self, TypedDict, TypeVar, Unpack

import httpx
import openai
from openai import Timeout
from openai.resources.beta import AsyncBeta, Beta
from openai.resources.beta.responses import AsyncResponses as AsyncBetaResponses
from openai.resources.beta.responses import Responses as BetaResponses
from openai.resources.live import AsyncForks, AsyncLive, AsyncSideband, Forks, Live, Sideband
from openai.resources.responses import AsyncResponses, Responses

from tinfoil._clients import (
    AsyncEnclaveHTTPClient,
    AsyncGatewayHTTPClient,
    AsyncRouterHTTPClient,
    EnclaveHTTPClient,
    GatewayHTTPClient,
    RouterHTTPClient,
)
from tinfoil._errors import ConfigurationError
from tinfoil._gateway import Catalog, ModelPin
from tinfoil._types import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_TRANSPORT_MODE,
    TimeoutTypes,
    TransportMode,
    VerificationCheck,
)
from tinfoil.verifier import Verifier

_C = TypeVar("_C", bound=openai.AsyncOpenAI)

HTTP_CLIENT_FIXED = "http_client is the attested HTTP client's and cannot be replaced"
BASE_URL_FIXED = "base_url is the attested HTTP client's and cannot be replaced"
DROP_IN_OPTIONS = "{name} takes only the openai package's options; {keys} belong to {route}"
WEBSOCKET_UNAVAILABLE = "{name} is not available over an attested client"
"""The message of the ConfigurationError that a websocket entry point raises, naming it: a websocket can't use
the attested HTTP client, so it would open outside it, bypassing the origin guard, the TLS pin and EHBP."""
REALTIME_UNAVAILABLE = WEBSOCKET_UNAVAILABLE.format(name="realtime")
"""The message of the ConfigurationError that accessing a realtime resource raises."""

TRANSPORT_OPTION_UNSUPPORTED = (
    "the {key} option is not supported: the Tinfoil client owns the transport and base URL that requests go to"
)
_FORBIDDEN_TRANSPORT_OPTIONS = ("data_residency", "provider", "websocket_base_url", "workload_identity")
"""The ``openai`` client options that choose another base URL, including the one that websockets would connect
to, or that send requests, such as a token exchange, through an HTTP client of their own: each is a
ConfigurationError from every constructor, factory and copy, so that the guarantee that requests go through the
attested client does not depend on the ``openai`` package's own checks. An option that is ``None`` is unset."""

ROUTE_OPTIONS = frozenset(
    {"transport_mode", "base_url", "verifier", "verification_check", "user_cache_secret", "http_timeout"}
)
"""The options that configure a route, which the drop-in ``Client`` and ``AsyncClient`` refuse."""


class _SharedOptions(TypedDict, total=False):
    """The ``openai`` client options whose types are the same for the synchronous and asynchronous clients."""

    admin_api_key: str | None
    organization: str | None
    project: str | None
    webhook_secret: str | None
    timeout: float | httpx.Timeout | Timeout | None
    max_retries: int
    default_headers: Mapping[str, str] | None
    default_query: Mapping[str, object] | None


class OpenAIOptions(_SharedOptions, total=False):
    """The ``openai.OpenAI`` constructor options that the synchronous OpenAI clients accept by keyword: every
    option of the installed ``openai`` package except ``http_client`` and ``base_url``, which the attested
    client fixes, and ``data_residency``, ``provider``, ``websocket_base_url`` and ``workload_identity``, which
    would choose another base URL or send a token exchange through an HTTP client other than the attested one,
    and which are refused.
    ``timeout`` and ``max_retries`` are per request, as they are in the package; the attested client's own
    timeout is the ``http_timeout`` option. ``api_key`` may be a callable that returns the key."""

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


def _no_websocket(name: str) -> NoReturn:
    raise ConfigurationError(WEBSOCKET_UNAVAILABLE.format(name=name))


def _no_realtime() -> NoReturn:
    raise ConfigurationError(REALTIME_UNAVAILABLE)


# Each class below refuses a websocket entry point of its ``openai`` resource: the ``connect`` method, which
# raises before it builds a connection manager, so before ``websockets`` is imported or any I/O happens, while
# the resource's HTTP methods are left as they are. A ``connect`` that takes any arguments and never returns is
# compatible with the one it overrides.


class _Responses(Responses):
    """``responses`` without its websocket ``connect``."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("responses.connect")


class _AsyncResponses(AsyncResponses):
    """``_Responses`` for the asynchronous clients."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("responses.connect")


class _BetaResponses(BetaResponses):
    """``beta.responses`` without its websocket ``connect``."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("beta.responses.connect")


class _AsyncBetaResponses(AsyncBetaResponses):
    """``_BetaResponses`` for the asynchronous clients."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("beta.responses.connect")


class _Sideband(Sideband):
    """``live.sideband`` without its websocket ``connect``, which is all that it has."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("live.sideband.connect")


class _AsyncSideband(AsyncSideband):
    """``_Sideband`` for the asynchronous clients."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("live.sideband.connect")


class _Forks(Forks):
    """``live.forks`` without its websocket ``connect``, which is all that it has."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("live.forks.connect")


class _AsyncForks(AsyncForks):
    """``_Forks`` for the asynchronous clients."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("live.forks.connect")


class _Live(Live):
    """``live`` without its websocket ``connect`` and with the refusing ``sideband`` and ``forks``."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("live.connect")

    @cached_property
    def sideband(self) -> _Sideband:
        return _Sideband(self._client)

    @cached_property
    def forks(self) -> _Forks:
        return _Forks(self._client)


class _AsyncLive(AsyncLive):
    """``_Live`` for the asynchronous clients."""

    def connect(self, *args: object, **kwargs: object) -> NoReturn:
        _no_websocket("live.connect")

    @cached_property
    def sideband(self) -> _AsyncSideband:
        return _AsyncSideband(self._client)

    @cached_property
    def forks(self) -> _AsyncForks:
        return _AsyncForks(self._client)


class _Beta(Beta):
    """The ``beta`` resources without their realtime alias and with the refusing ``responses``."""

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()

    @cached_property
    def responses(self) -> _BetaResponses:
        return _BetaResponses(self._client)


class _AsyncBeta(AsyncBeta):
    """``_Beta`` for the asynchronous clients."""

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()

    @cached_property
    def responses(self) -> _AsyncBetaResponses:
        return _AsyncBetaResponses(self._client)


class _Closable(Protocol):
    def close(self) -> None: ...


class _AsyncClosable(Protocol):
    async def close(self) -> None: ...


class _AttestedOpenAI(openai.OpenAI):
    """An ``openai.OpenAI`` client over an attested HTTP client, ``_tinfoil``, which it closes with itself and
    shares with its copies. Its websocket entry points, the realtime resource, with its ``beta`` alias, and the
    ``connect`` methods of ``responses``, ``beta.responses``, ``live``, ``live.sideband`` and ``live.forks``,
    raise a ConfigurationError instead of opening a websocket outside the attested HTTP client."""

    _tinfoil: _Closable

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()

    @cached_property
    def beta(self) -> _Beta:
        return _Beta(self)

    @cached_property
    def responses(self) -> _Responses:
        return _Responses(self)

    @cached_property
    def live(self) -> _Live:
        return _Live(self)

    def _shared(self) -> dict[str, object]:
        """What a copy's constructor receives besides the options: the attested client it shares."""
        return {"_http_client": self._tinfoil}

    # The method it overrides also takes base_url and http_client, which the attested client fixes, and the
    # transport options, which are refused, so this one accepts fewer options than its supertype's.
    def copy(self, **kwargs: Unpack[OpenAICopyOptions]) -> Self:  # type: ignore[override]
        """A client with ``kwargs`` applied over this one's options, sharing its attested client."""
        return super().copy(**_copy_options(_without_transport_options(kwargs), self._shared()))

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

    @cached_property
    def responses(self) -> _AsyncResponses:
        return _AsyncResponses(self)

    @cached_property
    def live(self) -> _AsyncLive:
        return _AsyncLive(self)

    def _shared(self) -> dict[str, object]:
        return {"_http_client": self._tinfoil}

    def copy(self, **kwargs: Unpack[AsyncOpenAICopyOptions]) -> Self:  # type: ignore[override]
        """A client with ``kwargs`` applied over this one's options, sharing its attested client."""
        return super().copy(**_copy_options(_without_transport_options(kwargs), self._shared()))

    with_options = copy  # type: ignore[assignment]

    async def close(self) -> None:
        """Closes the attested client as well, which every copy shares, so a copy's ``close`` closes the
        original's too."""
        await super().close()
        await self._tinfoil.close()


def _openai_options(
    kwargs: Mapping[str, object], http_client: httpx.Client | httpx.AsyncClient, base_url: str
) -> dict[str, Any]:
    """``kwargs`` with the attested HTTP client and its base URL; an ``http_client`` or ``base_url`` in
    ``kwargs`` is a ConfigurationError unless it is the attested client's own, which a copy passes back. The
    per-request ``timeout`` keeps the ``openai`` package's own default unless the caller sets it: the attested
    client's timeout, which ``http_timeout`` sets, is not adopted in its place. A transport option that is set
    is a ConfigurationError, as it is from ``_without_transport_options``."""
    options = _without_transport_options(kwargs)
    supplied = options.pop("http_client", None)
    if supplied is not None and supplied is not http_client:
        raise ConfigurationError(HTTP_CLIENT_FIXED)
    supplied_url = options.pop("base_url", None)
    if supplied_url is not None and str(supplied_url) != base_url:
        raise ConfigurationError(BASE_URL_FIXED)
    options.setdefault("timeout", openai.DEFAULT_TIMEOUT)
    return {**options, "http_client": http_client, "base_url": base_url}


def _without_transport_options(kwargs: Mapping[str, object]) -> dict[str, Any]:
    """``kwargs`` without the unset transport options; one that is set is a ConfigurationError naming it. Each
    constructor, factory and copy calls this before any network I/O, and ``_openai_options`` calls it again for
    every ``openai`` client built, so that no path reaches the ``openai`` constructor with one set."""
    for key in _FORBIDDEN_TRANSPORT_OPTIONS:
        if kwargs.get(key) is not None:
            raise ConfigurationError(TRANSPORT_OPTION_UNSUPPORTED.format(key=key))
    return {key: value for key, value in kwargs.items() if key not in _FORBIDDEN_TRANSPORT_OPTIONS}


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
    client, so closing a copy closes the original's too. The websocket
    entry points, the ``realtime`` resource and the ``connect`` methods,
    whose websockets would bypass the attested client, raise a
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
        _without_transport_options(openai_kwargs)
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
    takes the same arguments, with ``AsyncOpenAIOptions``. The websocket entry points raise a
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
        _without_transport_options(openai_kwargs)
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
    original's too. The websocket entry points, the ``realtime`` resource and the ``connect`` methods, whose
    websockets would bypass the attested client, raise a ConfigurationError."""

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
        _without_transport_options(openai_kwargs)
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
    ``AsyncOpenAIOptions``. The websocket entry points raise a ConfigurationError."""

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
        _without_transport_options(openai_kwargs)
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
    ``http_client`` and ``base_url``, which the gateway client fixes: a ``base_url`` other than the gateway's
    is a ConfigurationError, since the gateway's base URL is its ``url`` option. ``copy`` and ``with_options``
    share the gateway client, so closing a copy closes the original's too. The websocket entry points, the
    ``realtime`` resource and the ``connect`` methods, whose websockets would bypass the gateway client, raise a
    ConfigurationError.

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
        _without_transport_options(openai_kwargs)
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
    ``AsyncOpenAIOptions``. The websocket entry points raise a ConfigurationError.

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
        _without_transport_options(openai_kwargs)
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
