"""The transports a route stacks in front of an attested transport, one layer each: the proxy header, one replay
after a key rejection, the cache secret, and origin pinning. Each route chooses which to stack, in what order."""

from __future__ import annotations

import httpx

from tinfoil import _cachesecret
from tinfoil._errors import ConfigurationError
from tinfoil._keys import is_key_rejection
from tinfoil._url import USERINFO_REFUSED, allowed_origins, enclave_url_header_value, request_origin

ENCLAVE_URL_HEADER = "X-Tinfoil-Enclave-Url"
"""Tells a proxy which enclave to forward a sealed request to, so the request reaches the enclave the client
verified."""

NOT_REPLAYABLE = "cannot retry request after key rotation: body is not replayable"


def with_enclave_url(next_transport: httpx.BaseTransport, enclave: str, base_url: str) -> httpx.BaseTransport:
    """``next_transport`` behind the ``X-Tinfoil-Enclave-Url`` header when ``base_url`` is a proxy on another
    origin than ``enclave``, and otherwise ``next_transport`` itself."""
    value = enclave_url_header_value(base_url, enclave)
    return next_transport if value is None else EnclaveURLHeader(next_transport, value)


def with_enclave_url_async(
    next_transport: httpx.AsyncBaseTransport, enclave: str, base_url: str
) -> httpx.AsyncBaseTransport:
    """``with_enclave_url`` for asynchronous transports."""
    value = enclave_url_header_value(base_url, enclave)
    return next_transport if value is None else AsyncEnclaveURLHeader(next_transport, value)


def with_cache_secret(next_transport: httpx.BaseTransport, secret: str) -> httpx.BaseTransport:
    """``next_transport`` behind the cache-secret injector when ``secret`` is not empty."""
    return next_transport if not secret else CacheSecretInjector(next_transport, secret)


def with_cache_secret_async(next_transport: httpx.AsyncBaseTransport, secret: str) -> httpx.AsyncBaseTransport:
    """``with_cache_secret`` for asynchronous transports."""
    return next_transport if not secret else AsyncCacheSecretInjector(next_transport, secret)


def with_origin_restriction(next_transport: httpx.BaseTransport, enclave: str, base_url: str) -> OriginGuard:
    """``next_transport`` behind a guard that refuses requests to any origin other than the enclave and
    ``base_url``. Either may be empty; the gateway passes only its base URL."""
    try:
        origins = allowed_origins(enclave, base_url)
    except ValueError as err:
        raise ConfigurationError(f"failed to determine allowed request origins: {err}") from None
    return OriginGuard(next_transport, origins, enclave)


def with_origin_restriction_async(
    next_transport: httpx.AsyncBaseTransport, enclave: str, base_url: str
) -> AsyncOriginGuard:
    """``with_origin_restriction`` for asynchronous transports."""
    try:
        origins = allowed_origins(enclave, base_url)
    except ValueError as err:
        raise ConfigurationError(f"failed to determine allowed request origins: {err}") from None
    return AsyncOriginGuard(next_transport, origins, enclave)


class _Guard:
    """Rejects requests to any origin other than the verified enclave or the configured proxy, so an HTTP client
    handed to a caller cannot disclose sensitive request headers, such as the API key, to an arbitrary host."""

    def __init__(self, origins: frozenset[str], enclave: str) -> None:
        self.allowed_origins = origins
        self.enclave = enclave

    def check(self, request: httpx.Request) -> None:
        try:
            origin = request_origin(str(request.url))
        except ValueError as err:
            if str(err) == USERINFO_REFUSED:
                raise ConfigurationError(f"refusing to send request: {USERINFO_REFUSED}") from None
            raise ConfigurationError(f"refusing to send request: {err}") from None
        if origin not in self.allowed_origins:
            raise ConfigurationError(
                f'refusing to send request to "{origin}": client is bound to enclave "{self.enclave}"'
            )


class OriginGuard(httpx.BaseTransport, _Guard):
    def __init__(self, next_transport: httpx.BaseTransport, origins: frozenset[str], enclave: str) -> None:
        _Guard.__init__(self, origins, enclave)
        self._next = next_transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.check(request)
        return self._next.handle_request(request)

    def close(self) -> None:
        self._next.close()


class AsyncOriginGuard(httpx.AsyncBaseTransport, _Guard):
    def __init__(self, next_transport: httpx.AsyncBaseTransport, origins: frozenset[str], enclave: str) -> None:
        _Guard.__init__(self, origins, enclave)
        self._next = next_transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.check(request)
        return await self._next.handle_async_request(request)

    async def aclose(self) -> None:
        await self._next.aclose()


def _with_header(request: httpx.Request, name: str, value: str) -> httpx.Request:
    """A copy of ``request`` with ``name`` set, so the caller's request is not mutated."""
    headers = request.headers.copy()
    headers[name] = value
    return httpx.Request(
        request.method, request.url, headers=headers, stream=request.stream, extensions=request.extensions
    )


class EnclaveURLHeader(httpx.BaseTransport):
    """Adds ``X-Tinfoil-Enclave-Url`` before delegating. EHBP leaves request headers in plaintext, so the header
    reaches the proxy while the body stays sealed to the enclave's HPKE key. The value is the verified enclave's
    host, which never changes, so every request, including replays and requests after re-verification, points at
    the enclave that was verified."""

    def __init__(self, next_transport: httpx.BaseTransport, enclave_url: str) -> None:
        self._next = next_transport
        self.enclave_url = enclave_url

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._next.handle_request(_with_header(request, ENCLAVE_URL_HEADER, self.enclave_url))

    def close(self) -> None:
        self._next.close()


class AsyncEnclaveURLHeader(httpx.AsyncBaseTransport):
    def __init__(self, next_transport: httpx.AsyncBaseTransport, enclave_url: str) -> None:
        self._next = next_transport
        self.enclave_url = enclave_url

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._next.handle_async_request(_with_header(request, ENCLAVE_URL_HEADER, self.enclave_url))

    async def aclose(self) -> None:
        await self._next.aclose()


def replayable(request: httpx.Request) -> bool:
    """Whether ``request``'s body can be sent again: it is in memory, as a request without a body, with ``content``
    bytes, or one that has been read is."""
    return isinstance(request.stream, httpx.ByteStream)


class Replay(httpx.BaseTransport):
    """Re-sends a request once when the layer below reports a key rejection, if the request's body can be read
    again. The rejection has already invalidated the verification, so the replay goes out under a fresh one. With
    ``buffer_bodies``, every body is read into memory before the first attempt, which the sealing mode needs:
    a body consumed by a sealed first attempt could otherwise be replayed empty."""

    def __init__(self, next_transport: httpx.BaseTransport, *, buffer_bodies: bool) -> None:
        self._next = next_transport
        self._buffer = buffer_bodies

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self._buffer and not replayable(request):
            request.read()
        try:
            return self._next.handle_request(request)
        except Exception as err:
            if not is_key_rejection(err):
                raise
            if not replayable(request):
                err.add_note(NOT_REPLAYABLE)
                raise
            # A failure of the replay is raised with the rejection as its context.
            return self._next.handle_request(request)

    def close(self) -> None:
        self._next.close()


class AsyncReplay(httpx.AsyncBaseTransport):
    """``Replay`` for asynchronous transports."""

    def __init__(self, next_transport: httpx.AsyncBaseTransport, *, buffer_bodies: bool) -> None:
        self._next = next_transport
        self._buffer = buffer_bodies

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._buffer and not replayable(request):
            await request.aread()
        try:
            return await self._next.handle_async_request(request)
        except Exception as err:
            if not is_key_rejection(err):
                raise
            if not replayable(request):
                err.add_note(NOT_REPLAYABLE)
                raise
            return await self._next.handle_async_request(request)

    async def aclose(self) -> None:
        await self._next.aclose()


def _injected(request: httpx.Request, secret: str) -> httpx.Request:
    """``request`` with the client-level secret in its body, or ``request`` itself when the body is forwarded
    unchanged. The body must have been read."""
    body = _cachesecret.inject(request.content, secret)
    if body is None:
        return request
    headers = request.headers.copy()
    headers.pop("Transfer-Encoding", None)
    headers["Content-Length"] = str(len(body))
    return httpx.Request(request.method, request.url, headers=headers, content=body, extensions=request.extensions)


class CacheSecretInjector(httpx.BaseTransport):
    """Injects the client-level ``user_cache_secret`` into the bodies of the requests that carry it. It sits
    above the sealing transport, so the field is added before the body is sealed, and above the replay, so a
    replay re-sends the injected body. A non-empty or non-string field already present is never overwritten; an
    empty string is replaced with the client-level secret."""

    def __init__(self, next_transport: httpx.BaseTransport, secret: str) -> None:
        self._next = next_transport
        self.secret = secret

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if _cachesecret.path_eligible(request.method, request.url.path):
            request.read()
            request = _injected(request, self.secret)
        return self._next.handle_request(request)

    def close(self) -> None:
        self._next.close()


class AsyncCacheSecretInjector(httpx.AsyncBaseTransport):
    """``CacheSecretInjector`` for asynchronous transports."""

    def __init__(self, next_transport: httpx.AsyncBaseTransport, secret: str) -> None:
        self._next = next_transport
        self.secret = secret

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if _cachesecret.path_eligible(request.method, request.url.path):
            await request.aread()
            request = _injected(request, self.secret)
        return await self._next.handle_async_request(request)

    async def aclose(self) -> None:
        await self._next.aclose()


__all__ = [
    "ENCLAVE_URL_HEADER",
    "NOT_REPLAYABLE",
    "AsyncCacheSecretInjector",
    "AsyncEnclaveURLHeader",
    "AsyncOriginGuard",
    "AsyncReplay",
    "CacheSecretInjector",
    "EnclaveURLHeader",
    "OriginGuard",
    "Replay",
    "replayable",
    "with_cache_secret",
    "with_cache_secret_async",
    "with_enclave_url",
    "with_enclave_url_async",
    "with_origin_restriction",
    "with_origin_restriction_async",
]
