"""The transport that verifies an enclave and ties requests to the keys of its current verification.

An ``AttestedTransport`` verifies its enclave on first use, and again when
the verification expires or is rejected, and sends each request over a
transport tied to the keys of the current verification. Concurrent callers
share one verification. A key rejection invalidates the verification the
request was sent under and is reported through ``is_key_rejection``;
replaying the request is up to the layer above.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Callable, Coroutine, Iterator
from typing import Any, Generic, Protocol, TypeVar

import httpx
from httpx._client import UseClientDefault  # the sentinel's type; httpx exports only the value

from tinfoil._v3._ehbp import NO_HPKE_KEY, AsyncSealingTransport, SealingTransport, check_ehbp, server_identity
from tinfoil._v3._enclave import FRESHNESS_EXPIRED, Enclave, is_fresh
from tinfoil._v3._errors import AttestationError, ConfigurationError
from tinfoil._v3._keys import PeerLacksKeyError, key_rejection
from tinfoil._v3._tls import NO_TLS, AsyncPinnedTransport, PinnedTransport
from tinfoil._v3._types import DEFAULT_HTTP_TIMEOUT, TimeoutTypes, TransportMode
from tinfoil._v3.verifier import Verification

CLIENT_CLOSED = "client is closed"
"""The message of the ConfigurationError that a closed client raises."""

USE_CLIENT_DEFAULT = httpx.USE_CLIENT_DEFAULT
"""The per-call ``timeout`` value that keeps the client's own."""

_T = TypeVar("_T", "RetiringTransport", "AsyncRetiringTransport")

VerifyMethod = Callable[..., Verification]
AsyncVerifyMethod = Callable[..., Coroutine[Any, Any, Verification]]


class Mode(Protocol):
    """A mode protects requests with the keys of one verification: TLS pins connections to its TLS key, and EHBP
    seals bodies to its HPKE key."""

    @property
    def buffers_request_bodies(self) -> bool:
        """Whether request bodies must be in memory before they are sent, so that a replay can reproduce them."""

    def validate_request(self, request: httpx.Request) -> None:
        """Raises ConfigurationError for a request the mode cannot protect, before any network I/O."""

    def new_transport(self, verified: Verification) -> httpx.BaseTransport:
        """A transport tied to ``verified``'s keys. It reports an error meaning the peer does not hold those keys,
        detected before the application processes the request, as a ``PeerLacksKeyError``."""


class AsyncMode(Protocol):
    """``Mode`` for asynchronous transports."""

    @property
    def buffers_request_bodies(self) -> bool: ...

    def validate_request(self, request: httpx.Request) -> None: ...

    def new_transport(self, verified: Verification) -> httpx.AsyncBaseTransport: ...


class TLSMode:
    """Pins connections to the attested TLS key. It owns the connections and refuses plaintext requests, which no
    pinned connection carries."""

    buffers_request_bodies = False

    def validate_request(self, request: httpx.Request) -> None:
        _validate_tls(request)

    def new_transport(self, verified: Verification) -> httpx.BaseTransport:
        return PinnedTransport(_tls_key(verified))


class AsyncTLSMode:
    """``TLSMode`` for asynchronous transports."""

    buffers_request_bodies = False

    def validate_request(self, request: httpx.Request) -> None:
        _validate_tls(request)

    def new_transport(self, verified: Verification) -> httpx.AsyncBaseTransport:
        return AsyncPinnedTransport(_tls_key(verified))


class EHBPMode:
    """Seals bodies to the attested HPKE key and sends them over a plain transport."""

    buffers_request_bodies = True

    def validate_request(self, request: httpx.Request) -> None:
        check_ehbp(request)

    def new_transport(self, verified: Verification) -> httpx.BaseTransport:
        return SealingTransport(server_identity(_hpke_key(verified)))


class AsyncEHBPMode:
    """``EHBPMode`` for asynchronous transports."""

    buffers_request_bodies = True

    def validate_request(self, request: httpx.Request) -> None:
        check_ehbp(request)

    def new_transport(self, verified: Verification) -> httpx.AsyncBaseTransport:
        return AsyncSealingTransport(server_identity(_hpke_key(verified)))


def _validate_tls(request: httpx.Request) -> None:
    if request.url.scheme != "https":
        raise ConfigurationError(NO_TLS)


def mode_for(transport_mode: TransportMode) -> Mode:
    """The synchronous mode for ``transport_mode``; an unknown mode is a ConfigurationError."""
    if transport_mode == "tls":
        return TLSMode()
    if transport_mode == "ehbp":
        return EHBPMode()
    raise ConfigurationError(f"unknown transport mode {transport_mode!r}")


def async_mode_for(transport_mode: TransportMode) -> AsyncMode:
    """The asynchronous mode for ``transport_mode``; an unknown mode is a ConfigurationError."""
    if transport_mode == "tls":
        return AsyncTLSMode()
    if transport_mode == "ehbp":
        return AsyncEHBPMode()
    raise ConfigurationError(f"unknown transport mode {transport_mode!r}")


def _tls_key(verified: Verification) -> str:
    key = verified.tls_public_key_fp
    if key is None:
        raise AttestationError('document endorses no "tls" key')
    return key


def _hpke_key(verified: Verification) -> str:
    key = verified.hpke_public_key
    if key is None:
        raise AttestationError(NO_HPKE_KEY)
    return key


class _State(Generic[_T]):
    """One successful verification and the transport created for its keys. They are published together, so a
    request never sends under keys other than those of the verification it checked."""

    __slots__ = ("rejected", "transport", "verification")

    def __init__(self, verification: Verification, transport: _T) -> None:
        self.verification = verification
        self.transport: _T = transport
        self.rejected = False

    def valid(self) -> bool:
        return not self.rejected and is_fresh(self.verification)


class _Refresh:
    """One refresh that every caller needing it waits for."""

    __slots__ = ("done", "error")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.error: BaseException | None = None


class AttestedTransport(httpx.BaseTransport):
    """Sends requests over the transport of ``enclave``'s current verification, verifying first when needed.

    ``timeout`` bounds the network operations of a verification that a
    request triggers; ``ensure_verified`` and ``reverify`` take their own.
    """

    def __init__(self, enclave: Enclave, mode: Mode, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT) -> None:
        self.enclave = enclave
        self.mode = mode
        self.timeout = timeout
        self._lock = threading.Lock()
        self._current: _State[RetiringTransport] | None = None
        self._refresh: _Refresh | None = None
        self._closed = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Validate first, so a request the mode can't protect never triggers a verification.
        self.mode.validate_request(request)
        state = self._verified(False, Enclave.verify, self.timeout, None)
        try:
            return state.transport.handle_request(request)
        except PeerLacksKeyError as err:
            # Invalidate the state the request was sent under, not the current one,
            # so a late rejection can't retire a newer verification.
            self._invalidate(state)
            raise key_rejection(err)  # noqa: B904 - the cause is set

    def ensure_verified(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> Verification:
        """A verification that is valid now, verifying first only if the current one has expired or been
        invalidated. Returning means requests can be sent under it."""
        return self._verified(False, Enclave.verify, self._timeout(timeout), None).verification

    def reverify(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> Verification:
        """Verifies again even if the current verification is still valid."""
        return self._verified(True, Enclave.verify, self._timeout(timeout), None).verification

    def verify_once(
        self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT, deadline: float | None = None
    ) -> Verification:
        """``reverify`` without a retry of a failed attempt, so a caller trying several enclaves moves on
        quickly. ``deadline`` is a ``time.monotonic`` instant the attempt must finish by."""
        return self._verified(True, Enclave.verify_once, self._timeout(timeout), deadline).verification

    @property
    def current(self) -> Verification | None:
        """The last successful verification without checking it, or None before the first. It may have expired
        or been invalidated; ``ensure_verified`` returns one that is valid."""
        with self._lock:
            return None if self._current is None else self._current.verification

    def close(self) -> None:
        """Ends the transport: closes its connections and refuses later requests and verifications."""
        with self._lock:
            self._closed = True
            state, self._current = self._current, None
        if state is not None:
            state.transport.close()

    def _timeout(self, timeout: TimeoutTypes | UseClientDefault) -> TimeoutTypes:
        return self.timeout if isinstance(timeout, UseClientDefault) else timeout

    def _verified(
        self, force: bool, verify: VerifyMethod, timeout: TimeoutTypes, deadline: float | None
    ) -> _State[RetiringTransport]:
        """A valid state, refreshing it first when ``force`` is set or the current one is invalid. Concurrent
        callers share one refresh, including its failure."""
        while True:
            with self._lock:
                if self._closed:
                    raise ConfigurationError(CLIENT_CLOSED)
                state = self._current
                if state is not None and state.valid() and not force:
                    return state
                refresh = self._refresh
                owner = refresh is None
                if refresh is None:
                    refresh = self._refresh = _Refresh()
            if owner:
                try:
                    self._refresh_once(verify, timeout, deadline)
                except BaseException as err:
                    refresh.error = err
                    raise
                finally:
                    with self._lock:
                        self._refresh = None
                    refresh.done.set()
            else:
                refresh.done.wait()
                if refresh.error is not None:
                    raise refresh.error
            # A request can reject the new state before this caller wakes, so
            # check the current state again rather than trust the refresh.
            force = False

    def _refresh_once(self, verify: VerifyMethod, timeout: TimeoutTypes, deadline: float | None) -> None:
        verified = verify(self.enclave, timeout=timeout, deadline=deadline)
        transport = RetiringTransport(self.mode.new_transport(verified))
        with self._lock:
            if self._closed:
                transport.close()
                raise ConfigurationError(CLIENT_CLOSED)
            state = _State(verified, transport)
            # Creating the transport or waiting for the lock can outlast freshness.
            if not state.valid():
                transport.close()
                raise AttestationError(FRESHNESS_EXPIRED)
            replaced, self._current = self._current, state
        if replaced is not None:
            # Connections of the replaced state are tied to its keys.
            replaced.transport.retire()

    def _invalidate(self, state: _State[RetiringTransport]) -> None:
        with self._lock:
            state.rejected = True


class AsyncAttestedTransport(httpx.AsyncBaseTransport):
    """``AttestedTransport`` for ``httpx.AsyncClient``. A waiting caller's cancellation ends its own wait, not
    the shared verification."""

    def __init__(self, enclave: Enclave, mode: AsyncMode, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT) -> None:
        self.enclave = enclave
        self.mode = mode
        self.timeout = timeout
        self._current: _State[AsyncRetiringTransport] | None = None
        self._refresh: asyncio.Task[None] | None = None
        self._closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.mode.validate_request(request)
        state = await self._verified(False, Enclave.verify_async, self.timeout, None)
        try:
            return await state.transport.handle_async_request(request)
        except PeerLacksKeyError as err:
            state.rejected = True
            raise key_rejection(err)  # noqa: B904 - the cause is set

    async def ensure_verified(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> Verification:
        """A verification that is valid now, verifying first only if the current one has expired or been
        invalidated."""
        state = await self._verified(False, Enclave.verify_async, self._timeout(timeout), None)
        return state.verification

    async def reverify(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> Verification:
        """Verifies again even if the current verification is still valid."""
        state = await self._verified(True, Enclave.verify_async, self._timeout(timeout), None)
        return state.verification

    async def verify_once(
        self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT, deadline: float | None = None
    ) -> Verification:
        """``reverify`` without a retry of a failed attempt."""
        state = await self._verified(True, Enclave.verify_once_async, self._timeout(timeout), deadline)
        return state.verification

    @property
    def current(self) -> Verification | None:
        """The last successful verification without checking it, or None before the first."""
        return None if self._current is None else self._current.verification

    async def aclose(self) -> None:
        """Ends the transport: closes its connections, stops a verification in progress and refuses later
        requests and verifications."""
        self._closed = True
        state, self._current = self._current, None
        refresh, self._refresh = self._refresh, None
        if refresh is not None:
            refresh.cancel()
        if state is not None:
            await state.transport.aclose()

    def _timeout(self, timeout: TimeoutTypes | UseClientDefault) -> TimeoutTypes:
        return self.timeout if isinstance(timeout, UseClientDefault) else timeout

    async def _verified(
        self, force: bool, verify: AsyncVerifyMethod, timeout: TimeoutTypes, deadline: float | None
    ) -> _State[AsyncRetiringTransport]:
        while True:
            if self._closed:
                raise ConfigurationError(CLIENT_CLOSED)
            state = self._current
            if state is not None and state.valid() and not force:
                return state
            refresh = self._refresh
            if refresh is None:
                refresh = self._refresh = asyncio.create_task(self._refresh_once(verify, timeout, deadline))
                refresh.add_done_callback(self._refresh_done)
            # The refresh runs in its own task, so this caller's cancellation ends
            # only its wait; the task keeps serving the other callers.
            await asyncio.shield(refresh)
            force = False

    def _refresh_done(self, task: asyncio.Task[None]) -> None:
        if self._refresh is task:
            self._refresh = None
        if not task.cancelled():
            # Every waiter re-raises the failure through shield(); this marks it
            # retrieved for a refresh that no waiter is left to observe.
            task.exception()

    async def _refresh_once(self, verify: AsyncVerifyMethod, timeout: TimeoutTypes, deadline: float | None) -> None:
        verified = await verify(self.enclave, timeout=timeout, deadline=deadline)
        transport = AsyncRetiringTransport(self.mode.new_transport(verified))
        if self._closed:
            await transport.aclose()
            raise ConfigurationError(CLIENT_CLOSED)
        state = _State(verified, transport)
        if not state.valid():
            await transport.aclose()
            raise AttestationError(FRESHNESS_EXPIRED)
        replaced, self._current = self._current, state
        if replaced is not None:
            await replaced.transport.retire()


class RetiringTransport(httpx.BaseTransport):
    """A transport that can be retired: it stops taking requests and closes once the responses in flight are
    done, so a replaced binding's connections go away without cutting off a streaming response. ``close``
    ends everything at once."""

    def __init__(self, inner: httpx.BaseTransport) -> None:
        self._inner = inner
        self._lock = threading.Lock()
        self._inflight = 0
        self._retired = False
        self._closed = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            if self._retired or self._closed:
                raise ConfigurationError(CLIENT_CLOSED)
            self._inflight += 1
        try:
            response = self._inner.handle_request(request)
        except BaseException:
            self._release()
            raise
        response.stream = _ReleasingStream(response.stream, self._release)
        return response

    def retire(self) -> None:
        with self._lock:
            self._retired = True
            idle = self._inflight == 0
        if idle:
            self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._inner.close()

    def _release(self) -> None:
        with self._lock:
            self._inflight -= 1
            last = self._retired and self._inflight == 0
        if last:
            self.close()


class AsyncRetiringTransport(httpx.AsyncBaseTransport):
    """``RetiringTransport`` for asynchronous transports."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner
        self._inflight = 0
        self._retired = False
        self._closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._retired or self._closed:
            raise ConfigurationError(CLIENT_CLOSED)
        self._inflight += 1
        try:
            response = await self._inner.handle_async_request(request)
        except BaseException:
            await self._release()
            raise
        response.stream = _AsyncReleasingStream(response.stream, self._release)
        return response

    async def retire(self) -> None:
        self._retired = True
        if self._inflight == 0:
            await self.aclose()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._inner.aclose()

    async def _release(self) -> None:
        self._inflight -= 1
        if self._retired and self._inflight == 0:
            await self.aclose()


class _ReleasingStream(httpx.SyncByteStream):
    """A response stream that reports once when it is closed."""

    def __init__(self, inner: httpx.SyncByteStream | httpx.AsyncByteStream, release: Callable[[], None]) -> None:
        self._inner = inner
        self._release: Callable[[], None] | None = release

    def __iter__(self) -> Iterator[bytes]:
        assert isinstance(self._inner, httpx.SyncByteStream)
        yield from self._inner

    def close(self) -> None:
        release, self._release = self._release, None
        try:
            if isinstance(self._inner, httpx.SyncByteStream):
                self._inner.close()
        finally:
            if release is not None:
                release()


class _AsyncReleasingStream(httpx.AsyncByteStream):
    """``_ReleasingStream`` for asynchronous responses."""

    def __init__(
        self, inner: httpx.SyncByteStream | httpx.AsyncByteStream, release: Callable[[], Coroutine[Any, Any, None]]
    ) -> None:
        self._inner = inner
        self._release: Callable[[], Coroutine[Any, Any, None]] | None = release

    async def __aiter__(self) -> AsyncIterator[bytes]:
        assert isinstance(self._inner, httpx.AsyncByteStream)
        async for chunk in self._inner:
            yield chunk

    async def aclose(self) -> None:
        release, self._release = self._release, None
        try:
            if isinstance(self._inner, httpx.AsyncByteStream):
                await self._inner.aclose()
        finally:
            if release is not None:
                await release()


__all__ = [
    "CLIENT_CLOSED",
    "USE_CLIENT_DEFAULT",
    "AsyncAttestedTransport",
    "AsyncEHBPMode",
    "AsyncMode",
    "AsyncRetiringTransport",
    "AsyncTLSMode",
    "AttestedTransport",
    "EHBPMode",
    "Mode",
    "RetiringTransport",
    "TLSMode",
    "UseClientDefault",
    "async_mode_for",
    "mode_for",
]
