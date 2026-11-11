"""HTTP transports that seal request and response bodies to an attested HPKE key.

A sealed request's method, URL and headers are not sealed, and neither is a
request without a body or its response. The enclave answers a body sealed
to a key it no longer holds with a key configuration mismatch, which is
reported as a ``PeerLacksKeyError`` so that the attested transport verifies
again. Every other protocol failure means the channel is not bound to the
attested key and is an AttestationError, whether it is detected before the
response body is handed over or while the body is read: a response chunk
that does not open is reported from the read that reached it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
from ehbp import AsyncEHBPTransport, EHBPError, EHBPTransport, KeyConfigMismatchError, ServerIdentity

from tinfoil._v3._errors import AttestationError, ConfigurationError, attestation_error
from tinfoil._v3._keys import PeerLacksKeyError

EHBP_TUNNEL = (
    "EHBP seals only request and response bodies, so it can't protect a protocol upgrade, such as a WebSocket, "
    "or a CONNECT tunnel; use the TLS transport mode on a direct connection"
)
NO_HPKE_KEY = "document endorses no HPKE key; cannot use the EHBP transport mode (use the TLS transport mode)"

# The transports sealed requests go out over when set; tests point them at a mock. None selects httpx's own.
_INNER_TRANSPORT: httpx.BaseTransport | None = None
_ASYNC_INNER_TRANSPORT: httpx.AsyncBaseTransport | None = None


def check_ehbp(request: httpx.Request) -> None:
    """Raises ConfigurationError for a request whose traffic continues outside the bodies EHBP seals: a protocol
    upgrade, such as a WebSocket, or a CONNECT tunnel. Sending one would look protected while nothing after the
    handshake is. Other requests are allowed, with or without a body."""
    if request.method.upper() == "CONNECT" or request.headers.get("Upgrade", ""):
        raise ConfigurationError(EHBP_TUNNEL)


def server_identity(hpke_public_key: str) -> ServerIdentity:
    """The identity to seal to for the attested HPKE key, as lowercase hex. Raises AttestationError for a key that
    does not parse."""
    try:
        return ServerIdentity.from_public_key_hex(hpke_public_key)
    except Exception as err:
        raise AttestationError(f"failed to parse HPKE public key: {err}") from err


class SealingTransport(httpx.BaseTransport):
    """An ``httpx`` transport that seals bodies to one attested HPKE key and sends them over ``inner``."""

    def __init__(self, identity: ServerIdentity, inner: httpx.BaseTransport | None = None) -> None:
        if inner is None:
            inner = _INNER_TRANSPORT if _INNER_TRANSPORT is not None else httpx.HTTPTransport()
        self._inner = inner
        self._sealing = EHBPTransport(identity, inner=self._inner)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        try:
            response = self._sealing.handle_request(request)
        except KeyConfigMismatchError as err:
            raise PeerLacksKeyError(err) from err
        except EHBPError as err:
            raise attestation_error(err) from err
        response.stream = _OpeningStream(response.stream)
        return response

    def close(self) -> None:
        self._sealing.close()


class AsyncSealingTransport(httpx.AsyncBaseTransport):
    """``SealingTransport`` for ``httpx.AsyncClient``."""

    def __init__(self, identity: ServerIdentity, inner: httpx.AsyncBaseTransport | None = None) -> None:
        if inner is None:
            inner = _ASYNC_INNER_TRANSPORT if _ASYNC_INNER_TRANSPORT is not None else httpx.AsyncHTTPTransport()
        self._inner = inner
        self._sealing = AsyncEHBPTransport(identity, inner=self._inner)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        try:
            response = await self._sealing.handle_async_request(request)
        except KeyConfigMismatchError as err:
            raise PeerLacksKeyError(err) from err
        except EHBPError as err:
            raise attestation_error(err) from err
        response.stream = _AsyncOpeningStream(response.stream)
        return response

    async def aclose(self) -> None:
        await self._sealing.aclose()


class _OpeningStream(httpx.SyncByteStream):
    """A response stream whose chunks are opened as they are read: a chunk that fails to open, or a body that
    ends without its final frame, is an AttestationError raised from the read that reached it, with the
    protocol error as its cause."""

    def __init__(self, inner: httpx.SyncByteStream | httpx.AsyncByteStream) -> None:
        self._inner = inner

    def __iter__(self) -> Iterator[bytes]:
        assert isinstance(self._inner, httpx.SyncByteStream)
        try:
            yield from self._inner
        except EHBPError as err:
            raise attestation_error(err) from err

    def close(self) -> None:
        if isinstance(self._inner, httpx.SyncByteStream):
            self._inner.close()


class _AsyncOpeningStream(httpx.AsyncByteStream):
    """``_OpeningStream`` for asynchronous responses."""

    def __init__(self, inner: httpx.SyncByteStream | httpx.AsyncByteStream) -> None:
        self._inner = inner

    async def __aiter__(self) -> AsyncIterator[bytes]:
        assert isinstance(self._inner, httpx.AsyncByteStream)
        try:
            async for chunk in self._inner:
                yield chunk
        except EHBPError as err:
            raise attestation_error(err) from err

    async def aclose(self) -> None:
        if isinstance(self._inner, httpx.AsyncByteStream):
            await self._inner.aclose()


__all__ = [
    "EHBP_TUNNEL",
    "NO_HPKE_KEY",
    "AsyncSealingTransport",
    "SealingTransport",
    "check_ehbp",
    "server_identity",
]
