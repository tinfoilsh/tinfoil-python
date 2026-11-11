"""HTTP transports whose connections are pinned to an attested TLS key.

The pin is checked in a network backend right after the TLS handshake and
before any request byte is written: the leaf certificate's SPKI fingerprint
must equal the attested one. The ordinary chain and hostname checks of the
TLS context stay on; the pin only adds to them. One transport serves one
fingerprint, so its connection pool is tied to that key.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable, Iterable
from typing import Any

import httpcore
import httpx

from tinfoil._v3._errors import ConfigurationError, attestation_error, wrap_attestation
from tinfoil._v3._keys import PeerLacksKeyError
from tinfoil._v3.verifier import UsageError, VerificationError, pin_tls_key

CERT_MISMATCH = "enclave certificate does not match the attested key; re-verify the enclave"
NO_TLS = "TLS transport mode requires an HTTPS request"
NO_VALID_CERTIFICATE = "TLS transport mode requires a verified certificate fingerprint"
NO_PEER_CERTIFICATE = "TLS transport mode could not read the peer certificate of the connection"

_CERTIFICATE_VERIFY_MARKERS = ("certificate_verify_failed", "certificate verify failed")

_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20, keepalive_expiry=5.0)

PinCheck = Callable[[ssl.SSLSocket | ssl.SSLObject], None]


class PinMismatchError(Exception):
    """The connection's leaf certificate does not carry the attested key. Raised in the handshake, before any
    request byte is written."""


class PinnedTransport(httpx.HTTPTransport):
    """An ``httpx`` transport whose every connection must present the TLS key ``fingerprint``, over the default
    certificate checks. A connection that fails those checks or the pin is reported as a ``PeerLacksKeyError``,
    since no request reached the peer."""

    def __init__(self, fingerprint: str) -> None:
        check = _pin(fingerprint)
        ssl_context = httpx.create_ssl_context()
        super().__init__(verify=ssl_context, http2=False, limits=_LIMITS)
        # The pool the parent built uses the default backend; the one that
        # checks the pin replaces it.
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=_LIMITS.max_connections,
            max_keepalive_connections=_LIMITS.max_keepalive_connections,
            keepalive_expiry=_LIMITS.keepalive_expiry,
            http1=True,
            http2=False,
            network_backend=PinnedBackend(check, httpcore.SyncBackend()),
        )
        self.fingerprint = fingerprint

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme != "https":
            raise _no_tls()
        try:
            return super().handle_request(request)
        except Exception as err:
            if is_certificate_error(err):
                raise PeerLacksKeyError(wrap_attestation(err))  # noqa: B904 - the cause is set
            raise


class AsyncPinnedTransport(httpx.AsyncHTTPTransport):
    """``PinnedTransport`` for ``httpx.AsyncClient``."""

    def __init__(self, fingerprint: str) -> None:
        check = _pin(fingerprint)
        ssl_context = httpx.create_ssl_context()
        super().__init__(verify=ssl_context, http2=False, limits=_LIMITS)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=_LIMITS.max_connections,
            max_keepalive_connections=_LIMITS.max_keepalive_connections,
            keepalive_expiry=_LIMITS.keepalive_expiry,
            http1=True,
            http2=False,
            network_backend=AsyncPinnedBackend(check, httpcore.AnyIOBackend()),
        )
        self.fingerprint = fingerprint

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme != "https":
            raise _no_tls()
        try:
            return await super().handle_async_request(request)
        except Exception as err:
            if is_certificate_error(err):
                raise PeerLacksKeyError(wrap_attestation(err))  # noqa: B904 - the cause is set
            raise


class PinnedBackend(httpcore.NetworkBackend):
    """A network backend whose TLS connections are checked against ``check`` right after the handshake."""

    def __init__(self, check: PinCheck, inner: httpcore.NetworkBackend) -> None:
        self._check = check
        self._inner = inner

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        stream = self._inner.connect_tcp(host, port, timeout, local_address, socket_options)
        return PinnedStream(stream, self._check)

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        stream = self._inner.connect_unix_socket(path, timeout, socket_options)
        return PinnedStream(stream, self._check)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class PinnedStream(httpcore.NetworkStream):
    """A network stream whose ``start_tls`` checks the peer's certificate against the pin before returning."""

    def __init__(self, inner: httpcore.NetworkStream, check: PinCheck) -> None:
        self._inner = inner
        self._check = check

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, timeout)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, timeout)

    def close(self) -> None:
        self._inner.close()

    def start_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
    ) -> httpcore.NetworkStream:
        tls = self._inner.start_tls(ssl_context, server_hostname, timeout)
        try:
            self._check(_tls_object(tls))
        except BaseException:
            tls.close()
            raise
        return PinnedStream(tls, self._check)

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class AsyncPinnedBackend(httpcore.AsyncNetworkBackend):
    """``PinnedBackend`` for an asynchronous pool."""

    def __init__(self, check: PinCheck, inner: httpcore.AsyncNetworkBackend) -> None:
        self._check = check
        self._inner = inner

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_tcp(host, port, timeout, local_address, socket_options)
        return AsyncPinnedStream(stream, self._check)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_unix_socket(path, timeout, socket_options)
        return AsyncPinnedStream(stream, self._check)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class AsyncPinnedStream(httpcore.AsyncNetworkStream):
    """``PinnedStream`` for an asynchronous backend."""

    def __init__(self, inner: httpcore.AsyncNetworkStream, check: PinCheck) -> None:
        self._inner = inner
        self._check = check

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
    ) -> httpcore.AsyncNetworkStream:
        tls = await self._inner.start_tls(ssl_context, server_hostname, timeout)
        try:
            self._check(_tls_object(tls))
        except BaseException:
            await tls.aclose()
            raise
        return AsyncPinnedStream(tls, self._check)

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


def is_certificate_error(err: BaseException) -> bool:
    """Whether ``err`` came from a certificate check in the TLS handshake, the pin included. Those happen before
    any request byte is sent, so they are safe to recover from by verifying again; other TLS errors can happen
    during request or response I/O and are not."""
    current: BaseException | None = err
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, PinMismatchError | ssl.SSLCertVerificationError):
            return True
        if isinstance(current, ssl.SSLError):
            message = str(current).lower()
            if any(marker in message for marker in _CERTIFICATE_VERIFY_MARKERS):
                return True
        current = current.__cause__ or current.__context__
    return False


def _pin(fingerprint: str) -> PinCheck:
    """The pin check for ``fingerprint``, which must be a SHA-256 SPKI fingerprint as lowercase hex."""
    try:
        check = pin_tls_key(fingerprint)
    except UsageError as err:
        raise attestation_error(err) from err

    def checked(connection: ssl.SSLSocket | ssl.SSLObject) -> None:
        try:
            check(connection)
        except VerificationError as err:
            raise PinMismatchError(CERT_MISMATCH) from err
        except UsageError as err:
            raise PinMismatchError(NO_PEER_CERTIFICATE) from err

    return checked


def _tls_object(stream: httpcore.NetworkStream | httpcore.AsyncNetworkStream) -> ssl.SSLSocket | ssl.SSLObject:
    """The TLS object of a stream after ``start_tls``: the ``ssl.SSLObject`` of an asynchronous stream, or the
    ``ssl.SSLSocket`` of a synchronous one, whose own TLS object is the interpreter's internal type."""
    ssl_object = stream.get_extra_info("ssl_object")
    if isinstance(ssl_object, ssl.SSLObject):
        return ssl_object
    sock = stream.get_extra_info("socket")
    if isinstance(sock, ssl.SSLSocket):
        return sock
    raise PinMismatchError(NO_PEER_CERTIFICATE)


def _no_tls() -> ConfigurationError:
    return ConfigurationError(NO_TLS)


__all__ = [
    "CERT_MISMATCH",
    "NO_TLS",
    "AsyncPinnedTransport",
    "PinMismatchError",
    "PinnedTransport",
    "is_certificate_error",
]
