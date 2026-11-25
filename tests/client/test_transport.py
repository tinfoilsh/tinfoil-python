"""The attested transport: verify once, share one refresh, invalidate on a key rejection without replaying,
keep streams open past expiry, retire replaced bindings and refuse after close."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from tests.client.helpers import (
    HOST,
    current_facts,
    facts_of,
    fake_enclave,
    last_error,
    last_facts,
    report_of,
    reporting,
    reporting_async,
    response,
    verification,
)
from tinfoil import _transport
from tinfoil._enclave import DEADLINE_EXCEEDED, FRESHNESS_EXPIRED
from tinfoil._errors import AttestationError, ConfigurationError, NetworkError, TinfoilError, network_error
from tinfoil._keys import KeyRejectedError, PeerLacksKeyError, is_key_rejection
from tinfoil._tls import CERT_MISMATCH, NO_TLS
from tinfoil._transport import (
    CLIENT_CLOSED,
    TRANSPORT_RETIRED,
    AsyncAttestedTransport,
    AsyncEHBPMode,
    AsyncRetiringTransport,
    AsyncTLSMode,
    AttestedTransport,
    EHBPMode,
    RetiringTransport,
    TLSMode,
    async_mode_for,
    mode_for,
    resolve_transport,
)
from tinfoil._types import EHBP, TLS
from tinfoil.verifier import VerificationReport, VerifiedFacts

Fetch = Callable[[], VerifiedFacts]
NewTransport = Callable[[VerifiedFacts], httpx.BaseTransport]


class FakeMode:
    """A mode that builds the transport ``build`` makes for each verification and validates no requests."""

    buffers_request_bodies = False

    def __init__(self, build: NewTransport | None = None) -> None:
        self.build = build or (lambda _: httpx.MockTransport(lambda _: response(200, b"ok")))
        self.built: list[VerifiedFacts] = []

    def validate_request(self, request: httpx.Request) -> None:
        pass

    def new_transport(self, verified: VerifiedFacts) -> httpx.BaseTransport:
        self.built.append(verified)
        return self.build(verified)


class AsyncFakeMode(FakeMode):
    def new_transport(self, verified: VerifiedFacts) -> httpx.AsyncBaseTransport:  # type: ignore[override]
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


class AsyncClosing(Closing, httpx.AsyncBaseTransport):
    """``Closing`` for asynchronous transports."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self.handler(request)

    async def aclose(self) -> None:
        self.closes += 1


def transport(fetch: Fetch, mode: FakeMode | TLSMode | EHBPMode | None = None) -> AttestedTransport:
    return AttestedTransport(fake_enclave(fetch), mode or FakeMode())


def get(keyed: httpx.BaseTransport, url: str = f"https://{HOST}/v1/models") -> httpx.Response:
    return keyed.handle_request(httpx.Request("GET", url))


def test_ensure_verified_reuses_a_valid_verification() -> None:
    calls = 0

    def fetch() -> VerifiedFacts:
        nonlocal calls
        calls += 1
        return verification("key")

    keyed = transport(fetch)
    assert current_facts(keyed) is None
    for _ in range(2):
        keyed.ensure_verified()
    assert calls == 1, "a valid verification is reused"
    keyed.reverify()
    assert calls == 2, "reverify always verifies"
    assert current_facts(keyed) is not None


def test_expired_keys_never_authorize_a_request() -> None:
    calls = 0
    requests = 0

    deadline = datetime.now(UTC) + timedelta(seconds=0.1)

    def fetch() -> VerifiedFacts:
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
def test_refresh_coalesces_requests_and_explicit_verify(
    refresh_error: NetworkError | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    callers = 17
    arrived = threading.Barrier(callers, timeout=5)  # every caller starts at once, so they contend for one refresh
    all_waiting = threading.Event()  # set once every caller but the owner waits at the refresh
    fetching = threading.Event()  # set once the owner's refresh reaches the fetch
    release = threading.Event()
    lock = threading.Lock()
    attempts = 0
    refreshes = 0
    waiting = 0
    requests = 0

    class CountingEvent(threading.Event):
        def wait(self, timeout: float | None = None) -> bool:
            nonlocal waiting
            with lock:
                waiting += 1
                if waiting == callers - 1:
                    all_waiting.set()
            return super().wait(timeout)

    class ObservedRefresh(_transport._Refresh):
        def __init__(self) -> None:
            nonlocal refreshes
            super().__init__()
            refreshes += 1
            self.done = CountingEvent()

    monkeypatch.setattr(_transport, "_Refresh", ObservedRefresh)

    def fetch() -> VerifiedFacts:
        nonlocal attempts
        with lock:
            attempts += 1
        fetching.set()
        release.wait(5)
        if refresh_error is not None:
            raise refresh_error
        return verification("new")

    def build(verified: VerifiedFacts) -> httpx.BaseTransport:
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
        arrived.wait()
        try:
            call()
            results.append(None)
        except BaseException as err:
            results.append(err)

    threads = [threading.Thread(target=run, args=(lambda: get(keyed),)) for _ in range(callers - 1)]
    threads.append(threading.Thread(target=run, args=(keyed.reverify,)))
    for thread in threads:
        thread.start()
    assert all_waiting.wait(5), "every caller but the owner waits at the refresh"
    # The owner can reach the fetch after the others are waiting, so wait for it rather than race it.
    assert fetching.wait(5), "the owner's refresh fetches"
    assert attempts == 1
    release.set()
    for thread in threads:
        thread.join(5)
    assert refreshes == 1, "the callers that found the refresh in progress waited for it instead of starting one"
    assert attempts == (1 if refresh_error is None else 2), "a failed attempt is retried once, within the refresh"
    assert len(results) == callers
    if refresh_error is not None:
        assert all(result is refresh_error for result in results)
        assert requests == 0
    else:
        assert all(result is None for result in results)
        assert requests == 16


def test_verify_once_stops_waiting_for_a_shared_refresh_at_its_deadline() -> None:
    """A caller that joins a refresh another caller owns waits no longer than its own deadline: it leaves with
    the deadline error while the refresh goes on and completes for its owner."""
    started = threading.Event()
    release = threading.Event()
    attempts = 0

    def fetch() -> VerifiedFacts:
        nonlocal attempts
        attempts += 1
        started.set()
        release.wait(5)
        return verification("slow")

    keyed = transport(fetch)
    owner_result: list[VerificationReport | BaseException] = []

    def own() -> None:
        try:
            owner_result.append(keyed.reverify())
        except BaseException as err:
            owner_result.append(err)

    owner = threading.Thread(target=own)
    owner.start()
    assert started.wait(5)
    begun = time.monotonic()
    with pytest.raises(NetworkError, match=DEADLINE_EXCEEDED):
        keyed.verify_once(deadline=begun + 0.1)
    assert time.monotonic() - begun < 2.0, "the wait ended at the deadline, not at the refresh's end"
    assert not release.is_set(), "the owner's refresh is still running"
    release.set()
    owner.join(5)
    assert isinstance(owner_result[0], VerificationReport)
    assert facts_of(owner_result[0]).code_tag == "slow"
    assert attempts == 1, "the joining caller started no refresh of its own"
    assert current_facts(keyed) is not None
    assert facts_of(keyed.ensure_verified()).code_tag == "slow", "the refresh that outlasted the deadline still counts"


@pytest.mark.asyncio
async def test_async_verify_once_stops_waiting_for_a_shared_refresh_at_its_deadline() -> None:
    release = asyncio.Event()
    attempts = 0

    async def fetch_async() -> VerifiedFacts:
        nonlocal attempts
        attempts += 1
        await release.wait()
        return verification("slow")

    enclave = fake_enclave(lambda: verification("slow"))
    enclave._fetch_async = reporting_async(fetch_async)
    keyed = AsyncAttestedTransport(enclave, AsyncFakeMode())
    owner = asyncio.create_task(keyed.reverify())
    await asyncio.sleep(0.01)
    assert attempts == 1
    begun = time.monotonic()
    with pytest.raises(NetworkError, match=DEADLINE_EXCEEDED):
        await keyed.verify_once(deadline=begun + 0.1)
    assert time.monotonic() - begun < 2.0
    assert not owner.done(), "the owner's refresh survives the joining caller's deadline"
    release.set()
    assert facts_of(await owner).code_tag == "slow"
    assert attempts == 1
    assert facts_of(await keyed.ensure_verified()).code_tag == "slow"


def test_requests_use_the_explicit_verification() -> None:
    attempts = 0

    def fetch() -> VerifiedFacts:
        nonlocal attempts
        attempts += 1
        return verification("old" if attempts == 1 else "new")

    def build(verified: VerifiedFacts) -> httpx.BaseTransport:
        return httpx.MockTransport(lambda _: response(200, headers={"Key": verified.hpke_public_key or ""}))

    keyed = transport(fetch, FakeMode(build))
    keyed.ensure_verified()
    verified = keyed.reverify()
    assert facts_of(verified).code_tag == "new"
    assert get(keyed).headers["Key"] == "01" * 32
    assert current_facts(keyed) is not None
    assert tag(current_facts(keyed)) == "new"
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

    def fetch() -> VerifiedFacts:
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
    # The initial state, as a test seam.
    keyed._refresh_once(lambda enclave, **_: report_of(verification("old")), None, None, [])
    with pytest.raises(type(err) if not lacks_key else AttestationError) as raised:
        get(keyed)
    assert is_key_rejection(raised.value) == lacks_key, name
    if lacks_key:
        assert isinstance(raised.value.__cause__, KeyRejectedError)
        assert raised.value.__cause__.__cause__ is err.__cause__
        assert str(raised.value) == (CERT_MISMATCH if name == "TLS" else str(err.__cause__)), (
            "the underlying message is carried once, without a prefix"
        )
    state = keyed._current
    assert state is not None
    assert state.rejected == lacks_key
    assert current_facts(keyed) is not None
    assert tag(current_facts(keyed)) == "old"
    assert sends == 1
    assert refreshes == 0
    if not lacks_key:
        return
    failing = network_error("refresh failed")
    with pytest.raises(NetworkError, match="refresh failed"):
        get(keyed)
    assert tag(current_facts(keyed)) == "old"
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
    def fetch() -> VerifiedFacts:
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

    def fetch() -> VerifiedFacts:
        nonlocal calls
        calls += 1
        return verification("key")

    def build(_: VerifiedFacts) -> httpx.BaseTransport:
        raise AttestationError("the verification endorses no key for this transport")

    keyed = transport(fetch, FakeMode(build))
    with pytest.raises(AttestationError, match="endorses no key"):
        keyed.ensure_verified()
    with pytest.raises(AttestationError, match="endorses no key"):
        get(keyed)
    assert current_facts(keyed) is None, "a verification the mode can't use is never kept"
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
    assert isinstance(mode_for(TLS()), TLSMode)
    assert isinstance(mode_for(EHBP()), EHBPMode)
    assert isinstance(async_mode_for(TLS()), AsyncTLSMode)
    assert isinstance(async_mode_for(EHBP("https://proxy.example/")), AsyncEHBPMode)
    for unchecked in ("ehbp", None):
        with pytest.raises(ConfigurationError, match="transport must be a TLS or EHBP value"):
            mode_for(unchecked)  # type: ignore[arg-type]
        with pytest.raises(ConfigurationError, match="transport must be a TLS or EHBP value"):
            async_mode_for(unchecked)  # type: ignore[arg-type]


def test_resolve_transport() -> None:
    assert resolve_transport(None) == (TLS(), "")
    assert resolve_transport(TLS()) == (TLS(), "")
    assert resolve_transport(EHBP()) == (EHBP(), "")
    assert resolve_transport(EHBP("")) == (EHBP(""), "")
    assert resolve_transport(EHBP("https://proxy.example/relay")) == (
        EHBP("https://proxy.example/relay"),
        "https://proxy.example/relay/",
    )
    assert resolve_transport(EHBP("http://[::1]:8080/relay"))[1] == "http://[::1]:8080/relay/"
    for not_a_transport in ("tls", "ehbp", TLS, EHBP, {"proxy_url": "https://proxy.example/"}):
        with pytest.raises(ConfigurationError, match="transport must be a TLS or EHBP value"):
            resolve_transport(not_a_transport)
    with pytest.raises(ConfigurationError, match="invalid proxy URL: want a string"):
        resolve_transport(EHBP(b"https://proxy.example/"))  # type: ignore[arg-type]


def test_refresh_rejects_an_expired_verification() -> None:
    attempts = 0

    def fetch() -> VerifiedFacts:
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
    assert state.discarded, "an expired replacement is an attestation failure, which discards the old one"
    assert current_facts(keyed) is not None
    assert tag(current_facts(keyed)) == "old", "current keeps the last successful verification"


def test_refresh_rejects_a_verification_that_expires_during_creation() -> None:
    sent = 0

    def build(_: VerifiedFacts) -> httpx.BaseTransport:
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
    assert current_facts(keyed) is None


def test_late_rejection_does_not_invalidate_the_replacement() -> None:
    sent_under_old = threading.Event()
    release = threading.Event()
    verifications = 0

    def fetch() -> VerifiedFacts:
        nonlocal verifications
        verifications += 1
        return verification("new")

    def build(verified: VerifiedFacts) -> httpx.BaseTransport:
        def handler(_: httpx.Request) -> httpx.Response:
            if verified.code_tag == "old":
                sent_under_old.set()
                release.wait(5)
                raise PeerLacksKeyError(AttestationError(CERT_MISMATCH))
            return response(200)

        return httpx.MockTransport(handler)

    keyed = transport(fetch, FakeMode(build))
    keyed._refresh_once(lambda enclave, **_: report_of(verification("old")), None, None, [])
    finished: list[BaseException] = []

    def send() -> None:
        try:
            get(keyed)
        except BaseException as err:
            finished.append(err)

    thread = threading.Thread(target=send)
    thread.start()
    assert sent_under_old.wait(5), "the request went out under the old verification"
    keyed.reverify()
    release.set()
    thread.join(5)
    assert finished
    assert isinstance(finished[0], AttestationError)
    state = keyed._current
    assert state is not None
    assert state.valid(), "the replacement stays valid"
    assert current_facts(keyed) is not None
    assert tag(current_facts(keyed)) == "new"
    assert verifications == 1


def test_refresh_retires_replaced_connections() -> None:
    created: list[Closing] = []

    def build(_: VerifiedFacts) -> httpx.BaseTransport:
        closing = Closing()
        created.append(closing)
        if len(created) == 3:
            raise AttestationError("the new verification endorses no key for this transport")
        return closing

    keyed = transport(lambda: verification("key"), FakeMode(build))
    keyed.ensure_verified()
    first = created[0]
    keyed.reverify()
    assert first.closes == 1, "connections tied to the replaced keys are closed"
    second = created[1]
    with pytest.raises(AttestationError, match="endorses no key"):
        keyed.reverify()
    assert second.closes == 1, "a refresh that fails with an attestation failure discards the current transport"
    assert current_facts(keyed) is not None


def test_retiring_waits_for_responses_in_flight() -> None:
    inner = Closing(lambda _: httpx.Response(200, stream=httpx.ByteStream(b"body")))
    retiring = RetiringTransport(inner)
    streaming = retiring.handle_request(httpx.Request("GET", f"https://{HOST}/"))
    retiring.retire()
    assert inner.closes == 0, "a response in flight keeps the binding open"
    with pytest.raises(ConfigurationError, match=TRANSPORT_RETIRED):
        retiring.handle_request(httpx.Request("GET", f"https://{HOST}/"))
    assert streaming.read() == b"body"
    assert inner.closes == 1, "the last response closes the retired binding"
    retiring.close()
    assert inner.closes == 1
    with pytest.raises(ConfigurationError, match=TRANSPORT_RETIRED):
        retiring.handle_request(httpx.Request("GET", f"https://{HOST}/"))
    closed = RetiringTransport(Closing())
    closed.close()
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        closed.handle_request(httpx.Request("GET", f"https://{HOST}/"))


@pytest.mark.asyncio
async def test_async_retiring_names_the_reason() -> None:
    retired = AsyncRetiringTransport(httpx.MockTransport(lambda _: response(200)))
    await retired.retire()
    with pytest.raises(ConfigurationError, match=TRANSPORT_RETIRED):
        await retired.handle_async_request(httpx.Request("GET", f"https://{HOST}/"))
    closed = AsyncRetiringTransport(httpx.MockTransport(lambda _: response(200)))
    await closed.aclose()
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        await closed.handle_async_request(httpx.Request("GET", f"https://{HOST}/"))


def test_closed_transport_refuses_everything() -> None:
    created: list[Closing] = []

    def build(_: VerifiedFacts) -> httpx.BaseTransport:
        created.append(Closing())
        return created[-1]

    keyed = transport(lambda: verification("key"), FakeMode(build))
    keyed.ensure_verified()
    keyed.close()
    assert created[0].closes == 1
    assert current_facts(keyed) is None
    for call in (keyed.ensure_verified, keyed.reverify, lambda: get(keyed)):
        with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
            call()


@pytest.mark.asyncio
async def test_async_refresh_coalesces_and_survives_cancellation() -> None:
    release = asyncio.Event()
    attempts = 0

    def fetch() -> VerifiedFacts:
        nonlocal attempts
        attempts += 1
        return verification("new")

    async def fetch_async() -> VerifiedFacts:
        await release.wait()
        return fetch()

    enclave = fake_enclave(fetch)
    enclave._fetch_async = reporting_async(fetch_async)
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
        assert facts_of(await waiter).code_tag == "new"
    assert attempts == 1
    assert current_facts(keyed) is not None


@pytest.mark.asyncio
async def test_async_close_during_a_refresh_refuses_its_waiters() -> None:
    """Close cancels the shared verification, and the callers waiting on it see the closed transport rather than
    the cancellation; a caller's own cancellation still ends only its wait, and the verification goes on."""
    started = asyncio.Event()
    release = asyncio.Event()
    attempts = 0

    def fetch() -> VerifiedFacts:
        nonlocal attempts
        attempts += 1
        return verification("new")

    async def fetch_async() -> VerifiedFacts:
        started.set()
        await release.wait()
        return fetch()

    enclave = fake_enclave(fetch)
    enclave._fetch_async = reporting_async(fetch_async)
    keyed = AsyncAttestedTransport(enclave, AsyncFakeMode())
    waiters = [asyncio.create_task(keyed.ensure_verified()) for _ in range(2)]
    await started.wait()
    own = asyncio.create_task(keyed.ensure_verified())
    await asyncio.sleep(0)
    own.cancel()
    with pytest.raises(asyncio.CancelledError):
        await own
    assert not waiters[0].done(), "one caller's cancellation leaves the verification and the other callers alone"
    await keyed.aclose()
    for waiter in waiters:
        with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
            await waiter
    assert attempts == 0, "the cancelled verification never completed"
    assert current_facts(keyed) is None
    release.set()
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        await keyed.ensure_verified()


@pytest.mark.asyncio
async def test_async_key_rejection_and_close() -> None:
    sent_under: list[str] = []
    fetches = 0

    def fetch() -> VerifiedFacts:
        nonlocal fetches
        fetches += 1
        return verification("key", tag=f"verification {fetches}")

    def build(verified: VerifiedFacts) -> httpx.BaseTransport:
        def handler(_: httpx.Request) -> httpx.Response:
            sent_under.append(verified.code_tag)
            raise PeerLacksKeyError(AttestationError(CERT_MISMATCH))

        return httpx.MockTransport(handler)

    mode = AsyncFakeMode(build)
    keyed = AsyncAttestedTransport(fake_enclave(fetch), mode)
    with pytest.raises(AttestationError) as err:
        await keyed.handle_async_request(httpx.Request("GET", f"https://{HOST}/"))
    assert is_key_rejection(err.value)
    rejected = keyed._current
    assert rejected is not None
    assert rejected.rejected
    assert fetches == 1
    with pytest.raises(AttestationError) as again:
        await keyed.handle_async_request(httpx.Request("GET", f"https://{HOST}/"))
    assert is_key_rejection(again.value)
    assert fetches == 2, "the rejection invalidated the state, so the next request verified again"
    assert sent_under == ["verification 1", "verification 2"], "the second request went out under the fresh one"
    assert [built.code_tag for built in mode.built] == sent_under, "each verification got a transport of its own"
    fresh = keyed._current
    assert fresh is not None
    assert fresh is not rejected
    assert fresh.rejected, "the fresh state was rejected in its turn"
    await keyed.aclose()
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        await keyed.ensure_verified()


class ScriptedEnclave:
    """A scripted enclave: each verification returns the next tag, or raises ``failure`` while it is set, and
    each request records the tag of the verification that it was sent under."""

    def __init__(self) -> None:
        self.verifications = 0
        self.failure: BaseException | None = None
        self.sent_under: list[str] = []
        self.transports: dict[str, AsyncClosing] = {}

    def fetch(self) -> VerifiedFacts:
        if self.failure is not None:
            raise self.failure
        self.verifications += 1
        return verification("key", tag=f"v{self.verifications}")

    def build(self, verified: VerifiedFacts) -> AsyncClosing:
        def handler(_: httpx.Request) -> httpx.Response:
            self.sent_under.append(verified.code_tag)
            # A streamed body, which a response built with content is not, stays in flight until it is closed.
            return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

        closing = self.transports[verified.code_tag] = AsyncClosing(handler)
        return closing


def sent(reply: httpx.Response) -> None:
    """Checks that a request went through and closes its response, so that it is no longer in flight."""
    assert reply.status_code == 200
    reply.close()


async def async_sent(keyed: AsyncAttestedTransport) -> None:
    """``sent`` for a request through an asynchronous transport."""
    reply = await keyed.handle_async_request(httpx.Request("GET", f"https://{HOST}/v1/models"))
    assert reply.status_code == 200
    await reply.aclose()


def scripted() -> tuple[ScriptedEnclave, AttestedTransport]:
    enclave = ScriptedEnclave()
    return enclave, transport(enclave.fetch, FakeMode(enclave.build))


def scripted_async() -> tuple[ScriptedEnclave, AsyncAttestedTransport]:
    enclave = ScriptedEnclave()
    return enclave, AsyncAttestedTransport(fake_enclave(enclave.fetch), AsyncFakeMode(enclave.build))


def async_get(keyed: AsyncAttestedTransport) -> Coroutine[Any, Any, httpx.Response]:
    return keyed.handle_async_request(httpx.Request("GET", f"https://{HOST}/v1/models"))


def tag(current: VerifiedFacts | None) -> str | None:
    """The code tag of ``current``, a transport's last successful verification, or None for none."""
    return None if current is None else current.code_tag


@pytest.mark.parametrize("recovers", [True, False], ids=["recovers", "still-fails"])
def test_failed_reverify_discards_a_fresh_verification(recovers: bool) -> None:
    enclave, keyed = scripted()
    sent(get(keyed))
    enclave.failure = AttestationError("nonce mismatch")
    with pytest.raises(AttestationError, match="nonce mismatch"):
        keyed.reverify()
    assert tag(current_facts(keyed)) == "v1", "the discarded state stays current, but no request is sent under it"
    assert last_facts(keyed) is None, "the last verification is the failure, not the earlier success"
    assert isinstance(last_error(keyed), AttestationError)
    assert enclave.transports["v1"].closes == 1, "the connections made under the discarded one were closed"
    if recovers:
        enclave.failure = None
        sent(get(keyed))
        assert enclave.sent_under == ["v1", "v2"], "the next request went out under a new verification"
        assert tag(current_facts(keyed)) == "v2"
    else:
        with pytest.raises(AttestationError, match="nonce mismatch"):
            get(keyed)
        assert enclave.sent_under == ["v1"], "nothing was sent"
        assert tag(current_facts(keyed)) == "v1", "a failed attempt doesn't replace the discarded state"
        assert last_facts(keyed) is None


@pytest.mark.parametrize(
    "failure",
    [network_error("attestation source unreachable"), ConfigurationError("misconfigured fetcher")],
    ids=["network", "configuration"],
)
def test_failed_reverify_keeps_a_fresh_verification_on_other_failures(failure: Exception) -> None:
    enclave, keyed = scripted()
    sent(get(keyed))
    enclave.failure = failure
    with pytest.raises(type(failure)):
        keyed.reverify()
    sent(get(keyed))
    assert enclave.sent_under == ["v1", "v1"], "the next request went out under the cached verification"
    assert enclave.verifications == 1
    assert enclave.transports["v1"].closes == 0


def test_failed_reverify_keeps_a_fresh_verification_on_interruption() -> None:
    enclave, keyed = scripted()
    sent(get(keyed))
    enclave.failure = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        keyed.reverify()
    sent(get(keyed))
    assert enclave.sent_under == ["v1", "v1"]


def test_failed_refresh_after_a_key_rejection_discards_the_verification() -> None:
    enclave, keyed = scripted()
    rejecting = True

    def build(verified: VerifiedFacts) -> httpx.BaseTransport:
        closing = enclave.build(verified)
        handler = closing.handler

        def maybe_reject(request: httpx.Request) -> httpx.Response:
            if rejecting:
                raise PeerLacksKeyError(AttestationError(CERT_MISMATCH))
            return handler(request)

        closing.handler = maybe_reject
        return closing

    keyed.mode = FakeMode(build)
    with pytest.raises(AttestationError) as rejected:
        get(keyed)
    assert is_key_rejection(rejected.value)
    enclave.failure = AttestationError("the rotated key isn't attested")
    with pytest.raises(AttestationError, match="isn't attested"):
        get(keyed)
    assert tag(current_facts(keyed)) == "v1", "the failure discarded the rejected state, which stays current"
    assert isinstance(last_error(keyed), AttestationError), "the failed refresh is the last verification"
    assert enclave.transports["v1"].closes == 1
    enclave.failure = None
    rejecting = False
    sent(get(keyed))
    assert enclave.sent_under == ["v2"]


def test_failed_refresh_at_expiry_discards_the_verification() -> None:
    enclave, keyed = scripted()
    keyed._refresh_once(
        lambda enclave, **_: report_of(verification("old", deadline=datetime.now(UTC) + timedelta(seconds=0.1))),
        None,
        None,
        [],
    )
    old = keyed._current
    assert old is not None
    time.sleep(0.15)
    enclave.failure = AttestationError("bad document")
    with pytest.raises(AttestationError, match="bad document"):
        get(keyed)
    assert current_facts(keyed) is old.facts
    assert old.discarded
    assert old.transport._closed, "the expired verification's connections were closed"
    assert enclave.sent_under == []


def test_failed_reverify_keeps_a_newer_verification() -> None:
    enclave, keyed = scripted()
    keyed.ensure_verified()

    def publish_then_fail() -> VerifiedFacts:
        # Another publisher's verification lands while this re-verification is in flight.
        keyed._refresh_once(lambda enclave, **_: report_of(verification("newer")), None, None, [])
        raise AttestationError("nonce mismatch")

    keyed.enclave._fetch = reporting(publish_then_fail)
    with pytest.raises(AttestationError, match="nonce mismatch"):
        keyed.reverify()
    assert current_facts(keyed) is not None
    assert tag(current_facts(keyed)) == "newer", "the failure discards only the verification that it was replacing"
    sent(get(keyed))
    assert enclave.sent_under == ["newer"]


@pytest.mark.asyncio
@pytest.mark.parametrize("recovers", [True, False], ids=["recovers", "still-fails"])
async def test_async_failed_reverify_discards_a_fresh_verification(recovers: bool) -> None:
    enclave, keyed = scripted_async()
    await async_sent(keyed)
    enclave.failure = AttestationError("nonce mismatch")
    with pytest.raises(AttestationError, match="nonce mismatch"):
        await keyed.reverify()
    assert tag(current_facts(keyed)) == "v1"
    assert enclave.transports["v1"].closes == 1
    if recovers:
        enclave.failure = None
        await async_sent(keyed)
        assert enclave.sent_under == ["v1", "v2"]
        assert tag(current_facts(keyed)) == "v2"
    else:
        with pytest.raises(AttestationError, match="nonce mismatch"):
            await async_get(keyed)
        assert enclave.sent_under == ["v1"]
        assert tag(current_facts(keyed)) == "v1"
    await keyed.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [network_error("attestation source unreachable"), ConfigurationError("misconfigured fetcher")],
    ids=["network", "configuration"],
)
async def test_async_failed_reverify_keeps_a_fresh_verification_on_other_failures(failure: Exception) -> None:
    enclave, keyed = scripted_async()
    await async_sent(keyed)
    enclave.failure = failure
    with pytest.raises(type(failure)):
        await keyed.reverify()
    await async_sent(keyed)
    assert enclave.sent_under == ["v1", "v1"]
    assert enclave.verifications == 1
    await keyed.aclose()


@pytest.mark.asyncio
async def test_async_cancelled_reverify_keeps_a_fresh_verification() -> None:
    enclave, keyed = scripted_async()
    await async_sent(keyed)
    started = asyncio.Event()

    async def blocked() -> VerifiedFacts:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    keyed.enclave._fetch_async = reporting_async(blocked)
    reverify = asyncio.create_task(keyed.reverify())
    await started.wait()
    reverify.cancel()
    with pytest.raises(asyncio.CancelledError):
        await reverify
    await async_sent(keyed)
    assert enclave.sent_under == ["v1", "v1"], "the caller's cancellation keeps the cached verification"
    await keyed.aclose()


@pytest.mark.asyncio
async def test_async_failed_reverify_keeps_a_newer_verification() -> None:
    _, keyed = scripted_async()
    await keyed.ensure_verified()

    async def publish_then_fail() -> VerifiedFacts:
        async def newer(_: object, **__: object) -> VerificationReport:
            return report_of(verification("newer"))

        await keyed._refresh_once(newer, None, None)
        raise AttestationError("nonce mismatch")

    keyed.enclave._fetch_async = reporting_async(publish_then_fail)
    with pytest.raises(AttestationError, match="nonce mismatch"):
        await keyed.reverify()
    assert current_facts(keyed) is not None
    assert tag(current_facts(keyed)) == "newer"
    await keyed.aclose()


def waiting_on_refresh(monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    """An event that is set once a caller waits on a refresh that another caller runs."""
    waiting = threading.Event()

    class ObservedDone(threading.Event):
        def wait(self, timeout: float | None = None) -> bool:
            waiting.set()
            return super().wait(timeout)

    class ObservedRefresh(_transport._Refresh):
        def __init__(self) -> None:
            super().__init__()
            self.done = ObservedDone()

    monkeypatch.setattr(_transport, "_Refresh", ObservedRefresh)
    return waiting


class Raising:
    """An ``on_verification_attempt`` callback that records each call and then raises."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, VerificationReport | None, TinfoilError | None]] = []

    def __call__(self, host: str, report: VerificationReport | None, error: TinfoilError | None) -> None:
        self.calls.append((host, report, error))
        raise RuntimeError("the callback failed")


def test_a_raising_callback_leaves_the_outcome_to_every_waiting_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    """The callback raising changes neither the outcome nor what a second caller waiting on the same verification
    gets, and later attempts are still reported."""
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def fetch() -> VerifiedFacts:
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            release.wait(5)
        return verification(f"v{calls}")

    callback = Raising()
    keyed = AttestedTransport(fake_enclave(fetch, on_verification_attempt=callback), FakeMode())
    results: list[VerificationReport | BaseException] = []

    def call() -> None:
        try:
            results.append(keyed.ensure_verified())
        except BaseException as err:
            results.append(err)

    waiting = waiting_on_refresh(monkeypatch)
    owner = threading.Thread(target=call)
    owner.start()
    assert started.wait(5)
    waiter = threading.Thread(target=call)
    waiter.start()
    assert waiting.wait(5), "the second caller waits on the owner's verification"
    release.set()
    owner.join(5)
    waiter.join(5)
    assert len(results) == 2
    assert all(isinstance(result, VerificationReport) for result in results), results
    assert results[0] is results[1], "the waiting caller got the same outcome"
    assert calls == 1
    assert keyed.last_verification_attempt() == (results[0], None)
    assert len(callback.calls) == 1
    later = keyed.reverify()
    assert facts_of(later).code_tag == "v2"
    assert callback.calls[-1] == (HOST, later, None), "a later attempt is still reported"


@pytest.mark.asyncio
async def test_async_a_raising_callback_leaves_the_outcome_to_every_waiting_caller() -> None:
    release = asyncio.Event()
    calls = 0

    async def fetch_async() -> VerifiedFacts:
        nonlocal calls
        calls += 1
        if calls == 1:
            await release.wait()
        return verification(f"v{calls}")

    callback = Raising()
    enclave = fake_enclave(lambda: verification("unused"), on_verification_attempt=callback)
    enclave._fetch_async = reporting_async(fetch_async)
    keyed = AsyncAttestedTransport(enclave, AsyncFakeMode())
    owner = asyncio.create_task(keyed.ensure_verified())
    await asyncio.sleep(0.01)
    waiter = asyncio.create_task(keyed.ensure_verified())
    await asyncio.sleep(0.01)
    release.set()
    first, second = await asyncio.gather(owner, waiter)
    assert first is second, "the waiting caller got the same outcome"
    assert calls == 1
    assert keyed.last_verification_attempt() == (first, None)
    assert len(callback.calls) == 1
    later = await keyed.reverify()
    assert facts_of(later).code_tag == "v2"
    assert callback.calls[-1] == (HOST, later, None), "a later attempt is still reported"
    await keyed.aclose()


def test_a_raising_callback_leaves_a_failure_to_every_waiting_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    started = threading.Event()
    release = threading.Event()
    fetches = 0

    def fetch() -> VerifiedFacts:
        nonlocal fetches
        fetches += 1
        started.set()
        release.wait(5)
        raise AttestationError("rejected")

    callback = Raising()
    keyed = AttestedTransport(fake_enclave(fetch, on_verification_attempt=callback), FakeMode())
    results: list[BaseException | VerificationReport] = []

    def call() -> None:
        try:
            results.append(keyed.ensure_verified())
        except BaseException as err:
            results.append(err)

    waiting = waiting_on_refresh(monkeypatch)
    owner = threading.Thread(target=call)
    owner.start()
    assert started.wait(5)
    waiter = threading.Thread(target=call)
    waiter.start()
    assert waiting.wait(5), "the second caller waits on the owner's verification"
    release.set()
    owner.join(5)
    waiter.join(5)
    assert len(results) == 2
    assert all(isinstance(result, AttestationError) for result in results), results
    assert results[0] is results[1], "the waiting caller got the same failure, not the callback's exception"
    assert fetches == 2, "one verification, with its retry, that both callers shared"
    assert keyed.last_verification_attempt() == (None, results[0])
    assert callback.calls[-1] == (HOST, None, results[0])


def current_tag(keyed: AttestedTransport | AsyncAttestedTransport) -> str | None:
    """The code tag of the transport's current verification, or None when it has none."""
    current = keyed.current_verification()
    return None if current is None else facts_of(current).code_tag


class TestCurrentVerification:
    """The ``current_verification`` conformance cases: the report of the verification that requests are bound to
    now, never one that has expired or that a failure discarded."""

    def test_none_before_the_first_success(self) -> None:
        enclave, keyed = scripted()
        assert keyed.current_verification() is None
        enclave.failure = network_error("unreachable")
        with pytest.raises(NetworkError):
            keyed.ensure_verified()
        assert keyed.current_verification() is None
        assert enclave.verifications == 0

    def test_is_the_fresh_verification(self) -> None:
        enclave, keyed = scripted()
        ensured = keyed.ensure_verified()
        assert keyed.current_verification() is ensured, "the report that ensure_verified returned"
        assert keyed.last_verification_attempt() == (ensured, None)
        assert enclave.verifications == 1, "reading it performs no verification"

    @pytest.mark.parametrize(
        "failure",
        [network_error("attestation source unreachable"), ConfigurationError("misconfigured fetcher")],
        ids=["network", "configuration"],
    )
    def test_kept_after_a_failure_that_keeps_the_verification(self, failure: TinfoilError) -> None:
        enclave, keyed = scripted()
        ensured = keyed.ensure_verified()
        enclave.failure = failure
        with pytest.raises(type(failure)) as raised:
            keyed.reverify()
        assert keyed.current_verification() is ensured, "the cached verification is still the current one"
        assert keyed.last_verification_attempt() == (None, raised.value), "the last attempt is the failure"
        sent(get(keyed))
        assert enclave.sent_under == ["v1"], "requests still go through under it"

    def test_none_after_an_attestation_failure(self) -> None:
        enclave, keyed = scripted()
        keyed.ensure_verified()
        enclave.failure = AttestationError("nonce mismatch")
        with pytest.raises(AttestationError):
            keyed.reverify()
        assert keyed.current_verification() is None, "the failure discarded the verification"
        enclave.failure = None
        reverified = keyed.ensure_verified()
        assert keyed.current_verification() is reverified
        assert current_tag(keyed) == "v2"

    def test_none_after_a_key_rejection(self) -> None:
        def build(_: VerifiedFacts) -> httpx.BaseTransport:
            def reject(_: httpx.Request) -> httpx.Response:
                raise PeerLacksKeyError(AttestationError(CERT_MISMATCH))

            return httpx.MockTransport(reject)

        keyed = transport(lambda: verification("key"), FakeMode(build))
        keyed.ensure_verified()
        with pytest.raises(AttestationError):
            get(keyed)
        assert keyed.current_verification() is None, "the rejection marked the verification stale"

    def test_none_after_expiry(self) -> None:
        verifications = 0

        def fetch() -> VerifiedFacts:
            nonlocal verifications
            verifications += 1
            return verification("key", tag=f"v{verifications}", deadline=datetime.now(UTC) + timedelta(seconds=0.1))

        keyed = transport(fetch)
        first = keyed.ensure_verified()
        assert keyed.current_verification() is first
        time.sleep(0.15)
        assert keyed.current_verification() is None, "the verification has expired"
        assert verifications == 1, "reading it starts no verification"
        assert keyed.last_verification_attempt() == (first, None), "the last attempt is still the success"
        second = keyed.ensure_verified()
        assert keyed.current_verification() is second
        assert current_tag(keyed) == "v2"


@pytest.mark.asyncio
async def test_async_current_verification() -> None:
    enclave, keyed = scripted_async()
    assert keyed.current_verification() is None
    ensured = await keyed.ensure_verified()
    assert keyed.current_verification() is ensured
    enclave.failure = network_error("attestation source unreachable")
    with pytest.raises(NetworkError) as raised:
        await keyed.reverify()
    assert keyed.current_verification() is ensured, "a network failure keeps the fresh verification current"
    assert keyed.last_verification_attempt() == (None, raised.value)
    await async_sent(keyed)
    enclave.failure = AttestationError("nonce mismatch")
    with pytest.raises(AttestationError):
        await keyed.reverify()
    assert keyed.current_verification() is None, "an attestation failure discards it"
    enclave.failure = None
    assert keyed.current_verification() is None
    reverified = await keyed.ensure_verified()
    assert keyed.current_verification() is reverified
    assert current_tag(keyed) == "v2"
    await keyed.aclose()
