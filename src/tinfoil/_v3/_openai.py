"""OpenAI clients over the attested HTTP clients. Each is an ``openai`` client whose requests go through one of
them, so every HTTP resource of the ``openai`` package works unchanged and no application data is sent before
the enclave is verified. The one exception is the realtime resource: it opens a websocket of its own, outside
``http_client``, so it is refused rather than left to bypass the attested transport."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from functools import cached_property
from typing import Any, NoReturn, Protocol, Self, TypeVar

import httpx
import openai
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
DROP_IN_OPTIONS = "{name} takes only the openai package's options; configure the route with {route}"
REALTIME_UNAVAILABLE = "realtime is not available over an attested client"
"""The message of the ConfigurationError that accessing a realtime resource raises: its websocket would open
outside the attested HTTP client, bypassing the origin guard, the TLS pin and EHBP."""


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


class _AttestedOpenAI(openai.OpenAI):
    """An ``openai.OpenAI`` client whose realtime resource, and its ``beta`` alias, raise a ConfigurationError
    instead of opening a websocket outside the attested HTTP client."""

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()

    @cached_property
    def beta(self) -> _Beta:
        return _Beta(self)


class _AsyncAttestedOpenAI(openai.AsyncOpenAI):
    """``_AttestedOpenAI`` for ``openai.AsyncOpenAI``."""

    @property
    def realtime(self) -> NoReturn:
        _no_realtime()

    @cached_property
    def beta(self) -> _AsyncBeta:
        return _AsyncBeta(self)


def _openai_options(
    kwargs: dict[str, Any], http_client: httpx.Client | httpx.AsyncClient, base_url: str
) -> dict[str, Any]:
    """``kwargs`` with the attested HTTP client and its base URL, which the caller's options cannot replace. The
    per-request ``timeout`` keeps the ``openai`` package's own default unless the caller sets it: the attested
    client's timeout, which ``http_timeout`` sets, is not adopted in its place."""
    supplied = kwargs.pop("http_client", None)
    if supplied is not None and supplied is not http_client:
        raise ConfigurationError(HTTP_CLIENT_FIXED)
    kwargs.pop("base_url", None)
    kwargs.setdefault("timeout", openai.DEFAULT_TIMEOUT)
    return {**kwargs, "http_client": http_client, "base_url": base_url}


class EnclaveOpenAIClient(_AttestedOpenAI):
    """An ``openai.OpenAI`` client whose requests go through an ``EnclaveHTTPClient``, to ``base_url`` or, when
    that is unset, the enclave's ``/v1/`` API.

    ``host``, ``repo`` and the keyword options up to ``timeout`` are those
    of ``EnclaveHTTPClient``, which is created first and verifies the
    enclave; the remaining keyword arguments are the ``openai`` package's,
    applied after it, except ``http_client`` and ``base_url``, which the
    attested client fixes. ``copy`` and ``with_options`` keep the attested
    client. The ``realtime`` resource, whose websocket would bypass the
    attested client, raises a ConfigurationError.
    """

    def __init__(
        self,
        host: str = "",
        repo: str | None = None,
        *,
        transport_mode: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: str | None = None,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        _http_client: EnclaveHTTPClient | None = None,
        **openai_kwargs: Any,
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

    def copy(self, *args: Any, **kwargs: Any) -> Self:
        extra: Mapping[str, Any] = kwargs.pop("_extra_kwargs", {})
        return super().copy(*args, **kwargs, _extra_kwargs={**extra, "_http_client": self._tinfoil})

    with_options = copy

    def close(self) -> None:
        super().close()
        self._tinfoil.close()


class AsyncEnclaveOpenAIClient(_AsyncAttestedOpenAI):
    """``EnclaveOpenAIClient`` for asyncio, built with ``await AsyncEnclaveOpenAIClient.create(...)``, which
    takes the same arguments. The ``realtime`` resource raises a ConfigurationError."""

    def __init__(self, *, _http_client: AsyncEnclaveHTTPClient | None = None, **openai_kwargs: Any) -> None:
        if _http_client is None:
            raise ConfigurationError(f"{type(self).__name__} is built with 'await {type(self).__name__}.create(...)'")
        self._tinfoil = _http_client
        attested = _http_client._attested
        super().__init__(**_openai_options(openai_kwargs, attested.http_client, attested.openai_url))

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
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        **openai_kwargs: Any,
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

    def copy(self, *args: Any, **kwargs: Any) -> Self:
        extra: Mapping[str, Any] = kwargs.pop("_extra_kwargs", {})
        return super().copy(*args, **kwargs, _extra_kwargs={**extra, "_http_client": self._tinfoil})

    with_options = copy

    async def close(self) -> None:
        await super().close()
        await self._tinfoil.close()


class RouterOpenAIClient(_AttestedOpenAI):
    """An ``openai.OpenAI`` client whose requests go through a ``RouterHTTPClient``, to ``base_url`` or, when
    that is unset, the router's ``/v1/`` API. The keyword options up to ``http_timeout`` are those of
    ``RouterHTTPClient``; the remaining keyword arguments are the ``openai`` package's, except ``http_client``
    and ``base_url``, which the attested client fixes. The ``realtime`` resource, whose websocket would bypass
    the attested client, raises a ConfigurationError."""

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
        **openai_kwargs: Any,
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

    def copy(self, *args: Any, **kwargs: Any) -> Self:
        extra: Mapping[str, Any] = kwargs.pop("_extra_kwargs", {})
        return super().copy(*args, **kwargs, _extra_kwargs={**extra, "_http_client": self._tinfoil})

    with_options = copy

    def close(self) -> None:
        super().close()
        self._tinfoil.close()


class AsyncRouterOpenAIClient(_AsyncAttestedOpenAI):
    """``RouterOpenAIClient`` for asyncio, built with ``await AsyncRouterOpenAIClient.create(...)``. The
    ``realtime`` resource raises a ConfigurationError."""

    def __init__(self, *, _http_client: AsyncRouterHTTPClient | None = None, **openai_kwargs: Any) -> None:
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
        **openai_kwargs: Any,
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

    def copy(self, *args: Any, **kwargs: Any) -> Self:
        extra: Mapping[str, Any] = kwargs.pop("_extra_kwargs", {})
        return super().copy(*args, **kwargs, _extra_kwargs={**extra, "_http_client": self._tinfoil})

    with_options = copy

    async def close(self) -> None:
        await super().close()
        await self._tinfoil.close()


class GatewayOpenAIClient(_AttestedOpenAI):
    """An ``openai.OpenAI`` client whose requests go through a ``GatewayHTTPClient``, to the gateway's URL. The
    keyword options up to ``http_timeout`` are those of ``GatewayHTTPClient``; the remaining keyword arguments are
    the ``openai`` package's, except ``http_client`` and ``base_url``, which the gateway client fixes. The
    ``realtime`` resource, whose websocket would bypass the gateway client, raises a ConfigurationError.

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
        http_timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        _http_client: GatewayHTTPClient | None = None,
        **openai_kwargs: Any,
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

    def copy(self, *args: Any, **kwargs: Any) -> Self:
        extra: Mapping[str, Any] = kwargs.pop("_extra_kwargs", {})
        return super().copy(*args, **kwargs, _extra_kwargs={**extra, "_http_client": self._tinfoil})

    with_options = copy

    def close(self) -> None:
        super().close()
        self._tinfoil.close()


class AsyncGatewayOpenAIClient(_AsyncAttestedOpenAI):
    """``GatewayOpenAIClient`` for asyncio, built with ``await AsyncGatewayOpenAIClient.create(...)``. The
    ``realtime`` resource raises a ConfigurationError.

    Experimental: the gateway route is new, and this API may change or be
    removed in a later release.
    """

    def __init__(self, *, _http_client: AsyncGatewayHTTPClient | None = None, **openai_kwargs: Any) -> None:
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
        **openai_kwargs: Any,
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

    def copy(self, *args: Any, **kwargs: Any) -> Self:
        extra: Mapping[str, Any] = kwargs.pop("_extra_kwargs", {})
        return super().copy(*args, **kwargs, _extra_kwargs={**extra, "_http_client": self._tinfoil})

    with_options = copy

    async def close(self) -> None:
        await super().close()
        await self._tinfoil.close()


class Client(RouterOpenAIClient):
    """An OpenAI client for Tinfoil's recommended route: the router, verified before the constructor returns. It
    takes only the ``openai`` package's options; a proxy, transport mode, verifier, verification check or cache
    secret is configured on ``RouterOpenAIClient`` instead."""

    def __init__(self, *, _http_client: RouterHTTPClient | None = None, **openai_kwargs: Any) -> None:
        if _http_client is None and "base_url" in openai_kwargs:
            raise ConfigurationError(DROP_IN_OPTIONS.format(name="Client", route="RouterOpenAIClient"))
        super().__init__(_http_client=_http_client, **openai_kwargs)


class AsyncClient(AsyncRouterOpenAIClient):
    """``Client`` for asyncio, built with ``await AsyncClient.create(...)`` or ``create_async_client``."""

    def __init__(self, *, _http_client: AsyncRouterHTTPClient | None = None, **openai_kwargs: Any) -> None:
        super().__init__(_http_client=_http_client, **openai_kwargs)

    @classmethod
    async def create(cls, **openai_kwargs: Any) -> Self:
        if "base_url" in openai_kwargs:
            raise ConfigurationError(DROP_IN_OPTIONS.format(name="AsyncClient", route="AsyncRouterOpenAIClient"))
        return await super().create(**openai_kwargs)


def create_client(**openai_kwargs: Any) -> Client:
    """An OpenAI client for Tinfoil's recommended route, verified before it returns. ``openai_kwargs`` are the
    ``openai.OpenAI`` constructor's keyword arguments, such as ``api_key``, ``timeout`` and ``max_retries``."""
    return Client(**openai_kwargs)


async def create_async_client(**openai_kwargs: Any) -> AsyncClient:
    """``create_client`` for asyncio."""
    return await AsyncClient.create(**openai_kwargs)


class _Closable(Protocol):
    def close(self) -> None: ...


class _AsyncClosable(Protocol):
    async def close(self) -> None: ...


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


async def _built(cls: Callable[..., _C], http_client: _AsyncClosable, openai_kwargs: dict[str, Any]) -> _C:
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
    "AsyncRouterOpenAIClient",
    "Client",
    "EnclaveOpenAIClient",
    "GatewayOpenAIClient",
    "RouterOpenAIClient",
    "create_async_client",
    "create_client",
]
