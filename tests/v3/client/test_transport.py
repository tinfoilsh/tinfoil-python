"""The attested transport: verify once, share one refresh, invalidate on a key rejection without replaying,
keep streams open past expiry, retire replaced bindings and refuse after close."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from tests.v3.client.helpers import HOST, fake_enclave, response, verification
from tinfoil._v3._enclave import FRESHNESS_EXPIRED
from tinfoil._v3._errors import AttestationError, ConfigurationError, NetworkError, network_error
from tinfoil._v3._keys import KeyRejectedError, PeerLacksKeyError, is_key_rejection
from tinfoil._v3._tls import CERT_MISMATCH, NO_TLS
from tinfoil._v3._transport import (
    CLIENT_CLOSED,
    AsyncAttestedTransport,
    AsyncEHBPMode,
    AsyncTLSMode,
    AttestedTransport,
    EHBPMode,
    RetiringTransport,
    TLSMode,
    async_mode_for,
    mode_for,
)
from tinfoil._v3.verifier import Verification

Fetch = Callable[[], Verification]
NewTransport = Callable[[Verification], httpx.BaseTransport]


class FakeMode:
    """A mode that builds the transport ``build`` makes for each verification and validates no requests."""

    buffers_request_bodies = False

    def __init__(self, build: NewTransport | None = None) -> None:
        self.build = build or (lambda _: httpx.MockTransport(lambda _: response(200, b"ok")))
        self.built: list[Verification] = []

    def validate_request(self, request: httpx.Request) -> None:
        pass

    def new_transport(self, verified: Verification) -> httpx.BaseTransport:
        self.built.append(verified)
        return self.build(verified)


class AsyncFakeMode(FakeMode):
    def new_transport(self, verified: Verification) -> httpx.AsyncBaseTransport:  # type: ignore[override]
        self.built.append(verified)
        return self.build(verified)  # type: ignore[return-value]


class Closing(httpx.BaseTransport):
    """A transport that counts its closes."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.closes = 0
        self.handler = handler or (lambda _: response(200, b"ok"))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self.handler(request)

    def close(self) -> None:
        self.closes += 1


def transport(fetch: Fetch, mode: FakeMode | TLSMode | EHBPMode | None = None) -> AttestedTransport:
    return AttestedTransport(fake_enclave(fetch), mode or FakeMode())


def get(keyed: httpx.BaseTransport, url: str = f"https://{HOST}/v1/models") -> httpx.Response:
    return keyed.handle_request(httpx.Request("GET", url))


def test_ensure_verified_reuses_a_valid_verification() -> None:
    calls = 0

    def fetch() -> Verification:
        nonlocal calls
        calls += 1
        return verification("key")

    keyed = transport(fetch)
    assert keyed.current is None
    for _ in range(2):
        keyed.ensure_verified()
    assert calls == 1, "a valid verification is reused"
    keyed.reverify()
    assert calls == 2, "reverify always verifies"
    assert keyed.current is not None


def test_expired_keys_never_authorize_a_request() -> None:
    calls = 0
    requests = 0

    deadline = datetime.now(UTC) + timedelta(seconds=0.1)

    def fetch() -> Verification:
        nonlocal calls
        calls += 1
        return verification("key", deadline=deadline)

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return response(200)

    keyed = transport(fetch, FakeMode(lambda _: httpx.MockTransport(handler)))
    assert get(keyed).status_code == 200
    time.sleep(0.15)
    with pytest.raises(AttestationError, match=FRESHNESS_EXPIRED):
        get(keyed)
    assert requests == 1
    assert calls == 3, "the expired verification is refreshed, once more after the retry delay"


@pytest.mark.parametrize("refresh_error", [None, network_error("verification failed")], ids=["success", "failure"])
def test_refresh_coalesces_requests_and_explicit_verify(refresh_error: NetworkError | None) -> None:
    release = threading.Event()
    lock = threading.Lock()
    attempts = 0
    requests = 0

    def fetch() -> Verification:
        nonlocal attempts
        with lock:
            attempts += 1
        release.wait(5)
        if refresh_error is not None:
            raise refresh_error
        return verification("new")

    def build(verified: Verification) -> httpx.BaseTransport:
        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal requests
            with lock:
                requests += 1
            assert verified.tls_public_key_fp == "new", "used old key"
            return response(200)

        return httpx.MockTransport(handler)

    keyed = transport(fetch, FakeMode(build))
    results: list[BaseException | None] = []

    def run(call: Callable[[], object]) -> None:
        try:
            call()
            results.append(None)
        except BaseException as err:
            results.append(err)

    threads = [threading.Thread(target=run, args=(lambda: get(keyed),)) for _ in range(16)]
    threads.append(threading.Thread(target=run, args=(keyed.reverify,)))
    for thread in threads:
        thread.start()
    time.sleep(0.1)
    assert attempts == 1
    release.set()
    for thread in threads:
        thread.join(5)
    assert len(results) == 17
    if refresh_error is not None:
        assert all(result is refresh_error for result in results)
        assert requests == 0
    else:
        assert all(result is None for result in results)
        assert requests == 16


def test_requests_use_the_explicit_verification() -> None:
    attempts = 0

    def fetch() -> Verification:
        nonlocal attempts
        attempts += 1
        return verification("old" if attempts == 1 else "new")

    def build(verified: Verification) -> httpx.BaseTransport:
        return httpx.MockTransport(lambda _: response(200, headers={"Key": verified.hpke_public_key or ""}))

    keyed = transport(fetch, FakeMode(build))
    keyed.ensure_verified()
    verified = keyed.reverify()
    assert verified.code_tag == "new"
    assert get(keyed).headers["Key"] == "01" * 32
    assert keyed.current is not None
    assert keyed.current.code_tag == "new"
    assert attempts == 2


@pytest.mark.parametrize(
    ("name", "err", "lacks_key"),
    [
        ("TLS", PeerLacksKeyError(AttestationError(CERT_MISMATCH)), True),
        ("EHBP", PeerLacksKeyError(RuntimeError("KEY_CONFIG_MISMATCH: rotated")), True),
        ("network", httpx.ConnectError("connection refused"), False),
    ],
)
def test_key_rejection_invalidates_without_replay(name: str, err: BaseException, lacks_key: bool) -> None:
    sends = 0
    refreshes = 0
    failing: NetworkError | None = None

    def fetch() -> Verification:
        nonlocal refreshes
        if failing is not None:
            raise failing
        refreshes += 1
        return verification("new")

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal sends
        sends += 1
        raise err

    keyed = AttestedTransport(fake_enclave(fetch), FakeMode(lambda _: httpx.MockTransport(handler)))
    keyed._refresh_once(lambda enclave, **_: verification("old"), None, None)  # the initial state, as a test seam
    with pytest.raises(type(err) if not lacks_key else AttestationError) as raised:
        get(keyed)
    assert is_key_rejection(raised.value) == lacks_key, name
    if lacks_key:
        assert isinstance(raised.value.__cause__, KeyRejectedError)
        assert raised.value.__cause__.__cause__ is err.__cause__
    state = keyed._current
    assert state is not None
    assert state.rejected == lacks_key
    assert keyed.current is not None
    assert keyed.current.code_tag == "old"
    assert sends == 1
    assert refreshes == 0
    if not lacks_key:
        return
    failing = network_error("refresh failed")
    with pytest.raises(NetworkError, match="refresh failed"):
        get(keyed)
    assert keyed.current.code_tag == "old"
    assert sends == 1, "a failed refresh must not authorize the rejected state"
    failing = None
    with pytest.raises(AttestationError):
        get(keyed)
    assert refreshes == 1, "a later request establishes fresh state"
    assert sends == 2


def test_expiration_does_not_interrupt_a_stream() -> None:
    deadline = datetime.now(UTC) + timedelta(seconds=0.1)

    def chunks() -> list[bytes]:
        return [b"still ", b"streaming"]

    keyed = transport(
        lambda: verification("key", deadline=deadline),
        FakeMode(
            lambda _: httpx.MockTransport(lambda _: httpx.Response(200, stream=httpx.ByteStream(b"".join(chunks()))))
        ),
    )
    streaming = get(keyed)
    time.sleep(0.15)
    with pytest.raises(AttestationError, match=FRESHNESS_EXPIRED):
        get(keyed)
    assert streaming.read() == b"still streaming"


def test_plaintext_request_does_not_refresh() -> None:
    def fetch() -> Verification:
        pytest.fail("re-verification cannot make a plaintext URL acceptable")

    keyed = transport(fetch, TLSMode())
    with pytest.raises(ConfigurationError, match=NO_TLS):
        get(keyed, f"http://{HOST}/v1/models")
    with pytest.raises(ConfigurationError, match="EHBP seals only"):
        transport(fetch, EHBPMode()).handle_request(
            httpx.Request("GET", f"https://{HOST}/v1/realtime", headers={"Upgrade": "websocket"})
        )


def test_transport_failure_fails_verification() -> None:
    calls = 0

    def fetch() -> Verification:
        nonlocal calls
        calls += 1
        return verification("key")

    def build(_: Verification) -> httpx.BaseTransport:
        raise AttestationError("the verification endorses no key for this transport")

    keyed = transport(fetch, FakeMode(build))
    with pytest.raises(AttestationError, match="endorses no key"):
        keyed.ensure_verified()
    with pytest.raises(AttestationError, match="endorses no key"):
        get(keyed)
    assert keyed.current is None, "a verification the mode can't use is never kept"
    assert calls == 2, "each attempt verifies once, without a retry"


def test_modes_require_their_keys() -> None:
    with pytest.raises(AttestationError, match='no "tls" key'):
        TLSMode().new_transport(verification("", tls="", hpke="01" * 32))
    with pytest.raises(AttestationError, match="no HPKE key"):
        EHBPMode().new_transport(verification("key", hpke=None))
    with pytest.raises(AttestationError, match="no HPKE key"):
        AsyncEHBPMode().new_transport(verification("key", hpke=None))
    with pytest.raises(AttestationError, match='no "tls" key'):
        AsyncTLSMode().new_transport(verification("", tls="", hpke="01" * 32))
    assert isinstance(mode_for("tls"), TLSMode)
    assert isinstance(mode_for("ehbp"), EHBPMode)
    assert isinstance(async_mode_for("ehbp"), AsyncEHBPMode)
    with pytest.raises(ConfigurationError, match="unknown transport mode"):
        mode_for("quic")  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="unknown transport mode"):
        async_mode_for("quic")  # type: ignore[arg-type]


def test_refresh_rejects_an_expired_verification() -> None:
    attempts = 0

    def fetch() -> Verification:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return verification("old")
        return verification("expired", deadline=datetime.now(UTC) - timedelta(seconds=1))

    keyed = transport(fetch)
    keyed.ensure_verified()
    with pytest.raises(AttestationError, match=FRESHNESS_EXPIRED):
        keyed.reverify()
    state = keyed._current
    assert state is not None
    assert state.valid(), "a failed refresh leaves a valid verification in place"
    assert keyed.current is not None
    assert keyed.current.code_tag == "old"


def test_refresh_rejects_a_verification_that_expires_during_creation() -> None:
    sent = 0

    def build(_: Verification) -> httpx.BaseTransport:
        time.sleep(0.15)  # the verification expires while its transport is created

        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal sent
            sent += 1
            return response(200)

        return httpx.MockTransport(handler)

    keyed = transport(lambda: verification("key", deadline=datetime.now(UTC) + timedelta(seconds=0.1)), FakeMode(build))
    with pytest.raises(AttestationError, match=FRESHNESS_EXPIRED):
        get(keyed)
    assert sent == 0, "a verification that expired before publication never authorizes a request"
    assert keyed.current is None


def test_late_rejection_does_not_invalidate_the_replacement() -> None:
    release = threading.Event()
    verifications = 0

    def fetch() -> Verification:
        nonlocal verifications
        verifications += 1
        return verification("new")

    def build(verified: Verification) -> httpx.BaseTransport:
        def handler(_: httpx.Request) -> httpx.Response:
            if verified.code_tag == "old":
                release.wait(5)
                raise PeerLacksKeyError(AttestationError(CERT_MISMATCH))
            return response(200)

        return httpx.MockTransport(handler)

    keyed = transport(fetch, FakeMode(build))
    keyed._refresh_once(lambda enclave, **_: verification("old"), None, None)
    finished: list[BaseException] = []

    def send() -> None:
        try:
            get(keyed)
        except BaseException as err:
            finished.append(err)

    thread = threading.Thread(target=send)
    thread.start()
    time.sleep(0.05)
    keyed.reverify()
    release.set()
    thread.join(5)
    assert finished
    assert isinstance(finished[0], AttestationError)
    state = keyed._current
    assert state is not None
    assert state.valid(), "the replacement stays valid"
    assert keyed.current is not None
    assert keyed.current.code_tag == "new"
    assert verifications == 1


def test_refresh_retires_replaced_connections() -> None:
    created: list[Closing] = []

    def build(_: Verification) -> httpx.BaseTransport:
        if len(created) == 1:
            created.append(Closing())
            raise AttestationError("the new verification endorses no key for this transport")
        closing = Closing()
        created.append(closing)
        return closing

    keyed = transport(lambda: verification("key"), FakeMode(build))
    keyed.ensure_verified()
    first = created[0]
    with pytest.raises(AttestationError, match="endorses no key"):
        keyed.reverify()
    assert first.closes == 0, "a failed refresh keeps the current transport"
    keyed.reverify()
    assert first.closes == 1, "connections tied to the replaced keys are closed"


def test_retiring_waits_for_responses_in_flight() -> None:
    inner = Closing(lambda _: httpx.Response(200, stream=httpx.ByteStream(b"body")))
    retiring = RetiringTransport(inner)
    streaming = retiring.handle_request(httpx.Request("GET", f"https://{HOST}/"))
    retiring.retire()
    assert inner.closes == 0, "a response in flight keeps the binding open"
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        retiring.handle_request(httpx.Request("GET", f"https://{HOST}/"))
    assert streaming.read() == b"body"
    assert inner.closes == 1, "the last response closes the retired binding"
    retiring.close()
    assert inner.closes == 1


def test_closed_transport_refuses_everything() -> None:
    created: list[Closing] = []

    def build(_: Verification) -> httpx.BaseTransport:
        created.append(Closing())
        return created[-1]

    keyed = transport(lambda: verification("key"), FakeMode(build))
    keyed.ensure_verified()
    keyed.close()
    assert created[0].closes == 1
    assert keyed.current is None
    for call in (keyed.ensure_verified, keyed.reverify, lambda: get(keyed)):
        with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
            call()


@pytest.mark.asyncio
async def test_async_refresh_coalesces_and_survives_cancellation() -> None:
    release = asyncio.Event()
    attempts = 0

    def fetch() -> Verification:
        nonlocal attempts
        attempts += 1
        return verification("new")

    async def fetch_async() -> Verification:
        await release.wait()
        return fetch()

    enclave = fake_enclave(fetch)
    enclave._fetch_async = fetch_async
    keyed = AsyncAttestedTransport(enclave, AsyncFakeMode())
    waiters = [asyncio.create_task(keyed.ensure_verified()) for _ in range(8)]
    canceled = asyncio.create_task(keyed.reverify())
    await asyncio.sleep(0.05)
    canceled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await canceled
    assert attempts == 0, "the shared verification survives a waiter's cancellation"
    release.set()
    for waiter in waiters:
        assert (await waiter).code_tag == "new"
    assert attempts == 1
    assert keyed.current is not None


@pytest.mark.asyncio
async def test_async_key_rejection_and_close() -> None:
    sends = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal sends
        sends += 1
        raise PeerLacksKeyError(AttestationError(CERT_MISMATCH))

    keyed = AsyncAttestedTransport(
        fake_enclave(lambda: verification("key")), AsyncFakeMode(lambda _: httpx.MockTransport(handler))
    )
    with pytest.raises(AttestationError) as err:
        await keyed.handle_async_request(httpx.Request("GET", f"https://{HOST}/"))
    assert is_key_rejection(err.value)
    state = keyed._current
    assert state is not None
    assert state.rejected
    with pytest.raises(AttestationError):
        await keyed.handle_async_request(httpx.Request("GET", f"https://{HOST}/"))
    assert sends == 2, "the next request verifies again and sends under the fresh state"
    await keyed.aclose()
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        await keyed.ensure_verified()
