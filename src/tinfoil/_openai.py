"""OpenAI clients over the attested HTTP clients. ``OpenAIClient`` and ``AsyncOpenAIClient`` are ``openai``
clients whose requests go through an HTTP client of this package, so every HTTP resource of the ``openai`` package
works unchanged and no application data is sent before the enclave is verified. The exceptions are the websocket
entry points: the ``realtime`` resource and the ``connect`` methods of ``responses``, ``beta.responses``,
``live``, ``live.sideband`` and ``live.forks``. Each opens a websocket of its own, which can't use the attested
HTTP client, so each is refused with a ConfigurationError rather than left to bypass the attested transport, and
so is the ``websocket_base_url`` option that would point them elsewhere."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from functools import cached_property
from typing import Any, NoReturn, Protocol, Self, TypedDict, Unpack
from urllib.parse import unquote

import httpx
import openai
from openai import Timeout
from openai.resources.beta import AsyncBeta, Beta
from openai.resources.beta.responses import AsyncResponses as AsyncBetaResponses
from openai.resources.beta.responses import Responses as BetaResponses
from openai.resources.live import AsyncForks, AsyncLive, AsyncSideband, Forks, Live, Sideband
from openai.resources.responses import AsyncResponses, Responses

from tinfoil._clients import (
    AsyncAttestedHTTPClient,
    AsyncEnclaveHTTPClient,
    AsyncGatewayHTTPClient,
    AsyncRouterHTTPClient,
    AttestedHTTPClient,
    EnclaveHTTPClient,
    GatewayHTTPClient,
    RouterHTTPClient,
)
from tinfoil._errors import ConfigurationError

HTTP_CLIENT_FIXED = "http_client is the attested HTTP client's and cannot be replaced"
DROP_IN_OPTIONS = "{name} takes only the openai package's options; for {keys}, pass a {route} to {openai}"
NOT_AN_ATTESTED_CLIENT = "the HTTP client must be {expected} that its constructor returned, not {actual}"
GATEWAY_API_PATH = (
    "invalid API path: a gateway client's URL already carries the API path; set the gateway client's url instead"
)
DEFAULT_API_PATH = "/v1/"
"""The API path of an OpenAI client without one."""
WEBSOCKET_UNAVAILABLE = "{name} is not available over an attested client"
"""The message of the ConfigurationError that a websocket entry point raises, naming it: a websocket can't use
the attested HTTP client, so it would open outside it, bypassing the origin guard, the TLS pin and EHBP."""
REALTIME_UNAVAILABLE = WEBSOCKET_UNAVAILABLE.format(name="realtime")
"""The message of the ConfigurationError that accessing a realtime resource raises."""

TRANSPORT_OPTION_UNSUPPORTED = (
    "the {key} option is not supported: the Tinfoil client owns the transport and base URL that requests go to"
)
_FORBIDDEN_TRANSPORT_OPTIONS = ("provider", "websocket_base_url", "workload_identity")
"""The ``openai`` client options that choose the base URL that websockets would connect to, or that send requests,
such as a token exchange, through an HTTP client of their own: each is a ConfigurationError from every
constructor, factory and copy, so that the guarantee that requests go through the attested client does not depend
on the ``openai`` package's own checks. An option that is ``None`` is unset."""

_IGNORED_OPTIONS = ("base_url", "data_residency")
"""The ``openai`` client options that choose the base URL, which the SDK sets itself after the caller's options,
so that they have no effect, as the ``OPENAI_BASE_URL`` environment variable has none."""

ROUTE_OPTIONS = frozenset(
    {"transport", "policy", "verification_check", "on_verification", "user_cache_secret", "http_timeout", "api_path"}
)
"""The options that configure a route or an API path, which the drop-in ``Client`` and ``AsyncClient`` refuse."""


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
    option of the installed ``openai`` package except ``http_client``, which the attested client fixes, the
    ``base_url`` and ``data_residency`` options, which the SDK overrides, and ``provider``,
    ``websocket_base_url`` and ``workload_identity``, which would choose another websocket URL or send a token
    exchange through an HTTP client other than the attested one, and which are refused.
    ``timeout`` and ``max_retries`` are per request, as they are in the package; the attested client's own
    timeout is the HTTP client's ``timeout`` option. ``api_key`` may be a callable that returns the key."""

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

    _api_path: str | None

    def _shared(self) -> dict[str, object]:
        """What a copy's constructor receives besides the options: the attested client that it shares, and the API
        path."""
        return {"client": self._tinfoil, "api_path": self._api_path}

    # The method it overrides also takes base_url and http_client, which the attested client fixes, and the
    # transport options, which are refused, so this one accepts fewer options than its supertype's.
    def copy(self, **kwargs: Unpack[OpenAICopyOptions]) -> Self:  # type: ignore[override]
        """A client with ``kwargs`` applied over this one's options, sharing its attested client and its API
        path."""
        return super().copy(**_copy_options(_caller_options(kwargs), self._shared()))

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

    _api_path: str | None

    def _shared(self) -> dict[str, object]:
        return {"client": self._tinfoil, "api_path": self._api_path}

    def copy(self, **kwargs: Unpack[AsyncOpenAICopyOptions]) -> Self:  # type: ignore[override]
        """A client with ``kwargs`` applied over this one's options, sharing its attested client and its API
        path."""
        return super().copy(**_copy_options(_caller_options(kwargs), self._shared()))

    with_options = copy  # type: ignore[assignment]

    async def close(self) -> None:
        """Closes the attested client as well, which every copy shares, so a copy's ``close`` closes the
        original's too."""
        await super().close()
        await self._tinfoil.close()


class OpenAIClient(_AttestedOpenAI):
    """An ``openai.OpenAI`` client whose requests go through ``client``: an ``EnclaveHTTPClient``,
    ``RouterHTTPClient`` or ``GatewayHTTPClient``. Anything else, an asynchronous client included, is a
    ConfigurationError. The constructor does no network I/O, since ``client`` was verified when it was created
    and verifies again by itself.

    Requests go to ``api_path`` under the client's ``base_url``: under the
    ``EHBP`` proxy URL when one is set, and under the enclave's own origin
    otherwise. ``api_path`` defaults to ``/v1/``; it must be an absolute
    path, without a query, a fragment, an encoded slash, or a ``.`` or
    ``..`` segment, percent-encoded or not. A gateway client's URL already
    carries the API path, so an ``api_path`` with a gateway client is a
    ConfigurationError.

    The remaining keyword arguments are ``OpenAIOptions``, the ``openai``
    package's. The SDK sets ``http_client`` and the base URL itself, after
    them: a ``base_url`` or ``data_residency`` option, or ``OPENAI_BASE_URL``
    in the environment, has no effect; set ``api_path`` to change the API
    path. An ``http_client`` other than the attested one is a
    ConfigurationError. ``copy`` and ``with_options`` share the attested
    client and the API path. ``close`` closes the attested client as well,
    as the ``openai`` package closes an ``http_client`` that it is given, so
    closing a copy closes the original's too. The websocket entry points,
    the ``realtime`` resource and the ``connect`` methods, whose websockets
    would bypass the attested client, raise a ConfigurationError.
    """

    _tinfoil: AttestedHTTPClient

    def __init__(
        self, client: AttestedHTTPClient, *, api_path: str | None = None, **openai_kwargs: Unpack[OpenAIOptions]
    ) -> None:
        options = _caller_options(openai_kwargs)
        secure, base_url = _sync_attachment(client, api_path)
        self._tinfoil = client
        self._api_path = api_path
        super().__init__(**_openai_options(options, secure, base_url))

    @property
    def http_client(self) -> AttestedHTTPClient:
        """The attested HTTP client that the OpenAI client sends through."""
        return self._tinfoil


class AsyncOpenAIClient(_AsyncAttestedOpenAI):
    """``OpenAIClient`` for asyncio: an ``openai.AsyncOpenAI`` client whose requests go through ``client``, an
    ``AsyncEnclaveHTTPClient``, ``AsyncRouterHTTPClient`` or ``AsyncGatewayHTTPClient``, with
    ``AsyncOpenAIOptions``. The constructor does no network I/O, so it is a plain constructor."""

    _tinfoil: AsyncAttestedHTTPClient

    def __init__(
        self,
        client: AsyncAttestedHTTPClient,
        *,
        api_path: str | None = None,
        **openai_kwargs: Unpack[AsyncOpenAIOptions],
    ) -> None:
        options = _caller_options(openai_kwargs)
        secure, base_url = _async_attachment(client, api_path)
        self._tinfoil = client
        self._api_path = api_path
        super().__init__(**_openai_options(options, secure, base_url))

    @property
    def http_client(self) -> AsyncAttestedHTTPClient:
        """The attested HTTP client that the OpenAI client sends through."""
        return self._tinfoil


class Client(OpenAIClient):
    """An OpenAI client for Tinfoil's recommended route: an ``OpenAIClient`` over a ``RouterHTTPClient`` that the
    constructor creates with the default options, verified before it returns. It takes only the ``openai``
    package's options, ``OpenAIOptions``; a route option or an API path is a ConfigurationError here, from the
    constructor and from ``copy`` and ``with_options`` alike: create a ``RouterHTTPClient`` with it and pass that
    to ``OpenAIClient`` instead."""

    def __init__(self, *, _router: RouterHTTPClient | None = None, **openai_kwargs: Unpack[OpenAIOptions]) -> None:
        owned = _router is None
        if _router is None:
            _refuse_route_options("Client", "RouterHTTPClient", "OpenAIClient", openai_kwargs)
            _caller_options(openai_kwargs)
            _router = RouterHTTPClient()
        try:
            super().__init__(_router, **openai_kwargs)
        except BaseException:
            if owned:
                _router.close()
            raise

    def _shared(self) -> dict[str, object]:
        return {"_router": self._tinfoil}

    @property
    def http_client(self) -> RouterHTTPClient:
        """The router client that the OpenAI client sends through."""
        return self._tinfoil  # type: ignore[return-value]

    # A copy's constructor receives the attested client, so the caller's options are checked here.
    def copy(self, **kwargs: Unpack[OpenAICopyOptions]) -> Self:  # type: ignore[override]
        _refuse_route_options("Client", "RouterHTTPClient", "OpenAIClient", kwargs)
        return super().copy(**kwargs)

    with_options = copy  # type: ignore[assignment]


class AsyncClient(AsyncOpenAIClient):
    """``Client`` for asyncio, built with ``await AsyncClient.create(...)`` or ``create_async_client``, with
    ``AsyncOpenAIOptions``."""

    def __init__(
        self, *, _router: AsyncRouterHTTPClient | None = None, **openai_kwargs: Unpack[AsyncOpenAIOptions]
    ) -> None:
        if _router is None:
            raise ConfigurationError(f"{type(self).__name__} is built with 'await {type(self).__name__}.create(...)'")
        super().__init__(_router, **openai_kwargs)

    @classmethod
    async def create(cls, **openai_kwargs: Unpack[AsyncOpenAIOptions]) -> Self:
        """The client over an ``AsyncRouterHTTPClient`` that it creates with the default options, verified before
        it returns."""
        _refuse_route_options("AsyncClient", "AsyncRouterHTTPClient", "AsyncOpenAIClient", openai_kwargs)
        _caller_options(openai_kwargs)
        router = await AsyncRouterHTTPClient.create()
        try:
            return cls(_router=router, **openai_kwargs)
        except BaseException:
            await router.close()
            raise

    def _shared(self) -> dict[str, object]:
        return {"_router": self._tinfoil}

    @property
    def http_client(self) -> AsyncRouterHTTPClient:
        """The router client that the OpenAI client sends through."""
        return self._tinfoil  # type: ignore[return-value]

    def copy(self, **kwargs: Unpack[AsyncOpenAICopyOptions]) -> Self:  # type: ignore[override]
        _refuse_route_options("AsyncClient", "AsyncRouterHTTPClient", "AsyncOpenAIClient", kwargs)
        return super().copy(**kwargs)

    with_options = copy  # type: ignore[assignment]


def create_client(**openai_kwargs: Unpack[OpenAIOptions]) -> Client:
    """An OpenAI client for Tinfoil's recommended route, verified before it returns. ``openai_kwargs`` are the
    ``openai.OpenAI`` constructor's keyword arguments, such as ``api_key``, ``timeout`` and ``max_retries``."""
    return Client(**openai_kwargs)


async def create_async_client(**openai_kwargs: Unpack[AsyncOpenAIOptions]) -> AsyncClient:
    """``create_client`` for asyncio."""
    return await AsyncClient.create(**openai_kwargs)


def _sync_attachment(client: object, api_path: str | None) -> tuple[httpx.Client, str]:
    """The protected ``httpx`` client of ``client`` and the base URL of the API under it; anything but one of the
    synchronous attested clients is a ConfigurationError."""
    if isinstance(client, EnclaveHTTPClient | RouterHTTPClient):
        attested = getattr(client, "_attested", None)
        if attested is not None:
            return attested.secure, join_api_path(attested.base_url, api_path)
    elif isinstance(client, GatewayHTTPClient) and getattr(client, "_secure", None) is not None:
        return client._secure, _gateway_base_url(client.base_url, api_path)
    raise ConfigurationError(
        NOT_AN_ATTESTED_CLIENT.format(
            expected="an EnclaveHTTPClient, RouterHTTPClient or GatewayHTTPClient", actual=type(client).__name__
        )
    )


def _async_attachment(client: object, api_path: str | None) -> tuple[httpx.AsyncClient, str]:
    """``_sync_attachment`` for the asynchronous attested clients."""
    if isinstance(client, AsyncEnclaveHTTPClient | AsyncRouterHTTPClient):
        attested = getattr(client, "_attested", None)
        if attested is not None:
            return attested.secure, join_api_path(attested.base_url, api_path)
    elif isinstance(client, AsyncGatewayHTTPClient) and getattr(client, "_secure", None) is not None:
        return client._secure, _gateway_base_url(client.base_url, api_path)
    raise ConfigurationError(
        NOT_AN_ATTESTED_CLIENT.format(
            expected="an AsyncEnclaveHTTPClient, AsyncRouterHTTPClient or AsyncGatewayHTTPClient",
            actual=type(client).__name__,
        )
    )


def _gateway_base_url(base_url: str, api_path: str | None) -> str:
    """A gateway client's base URL, which already carries the API path, so that an API path is refused."""
    if api_path is not None and api_path != "":
        raise ConfigurationError(GATEWAY_API_PATH)
    return base_url


_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def join_api_path(root: str, api_path: str | None) -> str:
    """``api_path``, or ``DEFAULT_API_PATH`` when it is None or empty, joined under ``root``, a proxy URL or an
    origin, whether or not ``root`` ends with a slash. The result ends with a slash, so that request paths join
    under it. An ``api_path`` that is not an absolute path that can only name a path under its root is a
    ConfigurationError."""
    if api_path is None or api_path == "":
        api_path = DEFAULT_API_PATH
    validate_api_path(api_path)
    joined = root.removesuffix("/") + api_path
    return joined if joined.endswith("/") else joined + "/"


def validate_api_path(api_path: object) -> None:
    """Requires an absolute path without a query, a fragment, an encoded slash, or a ``.`` or ``..`` segment,
    percent-encoded or not, so that it can only name a path under its root. Raises ConfigurationError."""
    if not isinstance(api_path, str):
        raise ConfigurationError(f"invalid API path: want a string, not {type(api_path).__name__}")
    if not api_path.startswith("/") or api_path.startswith("//"):
        raise ConfigurationError(f"invalid API path {api_path!r}: it must be an absolute path, such as /v1/")
    if "?" in api_path or "#" in api_path:
        raise ConfigurationError(f"invalid API path {api_path!r}: it must not carry a query or a fragment")
    if _PERCENT_ESCAPE.search(api_path) or _CONTROL.search(api_path):
        raise ConfigurationError(f"invalid API path {api_path!r}: it does not parse")
    for segment in api_path.split("/"):
        decoded = unquote(segment)
        if decoded in (".", "..") or "/" in decoded:
            raise ConfigurationError(
                f'invalid API path {api_path!r}: it must not contain a "." or ".." segment or an encoded slash'
            )


def _openai_options(
    options: Mapping[str, object], http_client: httpx.Client | httpx.AsyncClient, base_url: str
) -> dict[str, Any]:
    """``options``, which ``_caller_options`` checked, with the attested HTTP client and its base URL, which are
    set after them. An ``http_client`` in ``options`` is a ConfigurationError unless it is the attested client's
    own, which a copy passes back. The per-request ``timeout`` keeps the ``openai`` package's own default unless
    the caller sets it: the attested client's timeout is not adopted in its place."""
    options = dict(options)
    supplied = options.pop("http_client", None)
    if supplied is not None and supplied is not http_client:
        raise ConfigurationError(HTTP_CLIENT_FIXED)
    options.setdefault("timeout", openai.DEFAULT_TIMEOUT)
    return {**options, "http_client": http_client, "base_url": base_url}


def _caller_options(kwargs: Mapping[str, object]) -> dict[str, Any]:
    """``kwargs`` without the options that the SDK overrides and the unset transport options; a transport option
    that is set is a ConfigurationError naming it. Each constructor, factory and copy calls this before the
    ``openai`` constructor runs, so that no path reaches it with one set."""
    for key in _FORBIDDEN_TRANSPORT_OPTIONS:
        if kwargs.get(key) is not None:
            raise ConfigurationError(TRANSPORT_OPTION_UNSUPPORTED.format(key=key))
    dropped = (*_FORBIDDEN_TRANSPORT_OPTIONS, *_IGNORED_OPTIONS)
    return {key: value for key, value in kwargs.items() if key not in dropped}


def _copy_options(kwargs: Mapping[str, object], shared: Mapping[str, object]) -> dict[str, Any]:
    """``kwargs`` for the ``openai`` package's ``copy``, with ``shared`` passed to the copy's constructor."""
    options: dict[str, Any] = dict(kwargs)
    options["_extra_kwargs"] = {**options.pop("_extra_kwargs", {}), **shared}
    return options


def _refuse_route_options(name: str, route: str, openai_class: str, kwargs: Mapping[str, object]) -> None:
    """Raises ConfigurationError naming the route options in ``kwargs``, which ``name`` does not take."""
    refused = sorted(ROUTE_OPTIONS.intersection(kwargs))
    if refused:
        raise ConfigurationError(
            DROP_IN_OPTIONS.format(name=name, keys=", ".join(refused), route=route, openai=openai_class)
        )


__all__ = [
    "DEFAULT_API_PATH",
    "AsyncClient",
    "AsyncOpenAIClient",
    "AsyncOpenAICopyOptions",
    "AsyncOpenAIOptions",
    "Client",
    "OpenAIClient",
    "OpenAICopyOptions",
    "OpenAIOptions",
    "create_async_client",
    "create_client",
    "join_api_path",
    "validate_api_path",
]
