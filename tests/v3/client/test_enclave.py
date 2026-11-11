"""The enclave core: configuration checks, the one retry, freshness, the verification check, the deadline that
bounds an attempt as a whole, and the transport keys a document must endorse."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta

import pytest

from tests.v3.client.helpers import HOST, Recorder, fake_enclave, response, verification
from tinfoil._v3 import _enclave, _fetch
from tinfoil._v3._enclave import (
    DEADLINE_EXCEEDED,
    FRESHNESS_EXPIRED,
    Enclave,
    VerificationRejected,
    retryable,
    validate_transport_keys,
)
from tinfoil._v3._errors import (
    AttestationError,
    ConfigurationError,
    NetworkError,
    TinfoilError,
    attestation_error,
    network_error,
)
from tinfoil._v3.verifier import (
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    CryptoMaterialItem,
    Verification,
    VerificationError,
    Verifier,
)


def authorizer() -> Verifier:
    return Verifier(config_authorizer=lambda _: None)


def test_construction_checks_config() -> None:
    with pytest.raises(ConfigurationError):
        Enclave("enclave.example", "not a reference")
    Enclave("enclave.example")
    with pytest.raises(ConfigurationError, match="config authorizer"):
        Enclave("enclave.example", "org/repo", verifier=authorizer())
    with pytest.raises(ConfigurationError, match="host is required"):
        Enclave("", "org/repo")
    with pytest.raises(ConfigurationError, match="invalid host"):
        Enclave("https://enclave.example", "org/repo")
    with pytest.raises(ConfigurationError, match="invalid host"):
        Enclave("enclave.example", "org/repo", relay="relay.example/path")
    shared = Verifier(freshness_max_age=timedelta(hours=1))
    enclave = Enclave("enclave.example", "org/repo", relay="relay.example", verifier=shared)
    assert enclave.verifier is shared, "enclaves share the caller's verifier"
    assert enclave.relay == "relay.example"
    assert Enclave("enclave.example", None).repo == ""


@pytest.mark.parametrize(
    ("name", "first", "last", "attempts"),
    [
        ("fetch then success", network_error("first attempt"), None, 2),
        ("attestation then success", attestation_error("first attempt"), None, 2),
        ("both attempts fail", network_error("first attempt"), attestation_error("last attempt"), 2),
        ("configuration", ConfigurationError("first attempt"), None, 1),
    ],
)
def test_initialization_recovery(
    name: str, first: TinfoilError, last: TinfoilError | None, attempts: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    slept: list[float] = []
    monkeypatch.setattr(_enclave, "VERIFICATION_RETRY_DELAY", 1.0)
    monkeypatch.setattr(time, "sleep", slept.append)
    calls = 0

    def fetch() -> Verification:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise first
        if last is not None:
            raise last
        return verification("fresh")

    enclave = fake_enclave(fetch)
    if attempts == 2 and last is None:
        assert enclave.verify().code_tag == "fresh"
    else:
        with pytest.raises(TinfoilError) as err:
            enclave.verify()
        if last is None:
            assert err.value is first
        else:
            assert err.value is last
            assert err.value.__context__ is first, "the first failure stays reachable"
    assert calls == attempts, name
    assert slept == [1.0] * (attempts - 1)


def test_verify_once_does_not_retry() -> None:
    calls = 0

    def fetch() -> Verification:
        nonlocal calls
        calls += 1
        raise network_error("unavailable")

    with pytest.raises(NetworkError):
        fake_enclave(fetch).verify_once()
    assert calls == 1


@pytest.mark.asyncio
async def test_initialization_recovery_async(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(_enclave, "VERIFICATION_RETRY_DELAY", 1.0)
    monkeypatch.setattr(asyncio, "sleep", sleep)
    calls = 0

    def fetch() -> Verification:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise network_error("first attempt")
        return verification("fresh")

    assert (await fake_enclave(fetch).verify_async()).code_tag == "fresh"
    assert calls == 2
    assert slept == [1.0]


def test_verification_check_sees_every_verification() -> None:
    checked: list[str] = []

    def check(v: Verification) -> None:
        checked.append(v.code_tag)

    enclave = fake_enclave(lambda: verification("key"), check=check)
    assert enclave.verify().code_tag == "key"
    enclave.verify()
    assert checked == ["key", "key"]


def test_verification_check_rejects_without_retry() -> None:
    rejection = RuntimeError("unapproved release")
    calls = 0

    def fetch() -> Verification:
        nonlocal calls
        calls += 1
        return verification("key")

    def check(_: Verification) -> None:
        raise rejection

    with pytest.raises(AttestationError) as err:
        fake_enclave(fetch, check=check).verify()
    assert isinstance(err.value.__cause__, VerificationRejected)
    assert err.value.__cause__.__cause__ is rejection
    assert f"verification check rejected {HOST}" in str(err.value)
    assert calls == 1, "a rejection is a decision about the evidence, so it isn't retried"


@pytest.mark.parametrize("slow_calls", [1, 2], ids=["fresh evidence outlives the check", "every check outlasts it"])
def test_slow_verification_check_fetches_fresh_evidence(slow_calls: int) -> None:
    """Evidence that expires during the check is refetched. The evidence fetched for a check that is slow has a
    short deadline, which the check outlasts; the evidence fetched after the last slow check has a wide one, so
    the success case does not depend on timing."""
    checks = 0
    fetches = 0

    def check(_: Verification) -> None:
        nonlocal checks
        checks += 1
        if checks <= slow_calls:
            time.sleep(0.25)  # outlasts the short deadline

    def fetch() -> Verification:
        nonlocal fetches
        fetches += 1
        validity = timedelta(seconds=0.1) if fetches <= slow_calls else timedelta(hours=1)
        return verification("key", deadline=datetime.now(UTC) + validity)

    enclave = fake_enclave(fetch, check=check)
    if slow_calls == 2:
        with pytest.raises(AttestationError, match=FRESHNESS_EXPIRED):
            enclave.verify()
    else:
        verified = enclave.verify()
        assert verified.freshness_expires_at is not None
        assert verified.freshness_expires_at - datetime.now(UTC) > timedelta(minutes=59)
    assert fetches == 2, "an expiry after the check is retried with fresh evidence"
    assert checks == 2


class TestDeadline:
    """``deadline`` bounds each attempt as a whole: the fetch, the verification and the check."""

    def test_slow_verification_is_refused_after_the_deadline(self) -> None:
        def fetch() -> Verification:
            time.sleep(0.1)  # a slow verifier
            return verification("key")

        with pytest.raises(NetworkError, match=DEADLINE_EXCEEDED):
            fake_enclave(fetch).verify_once(deadline=time.monotonic() + 0.02)
        assert fake_enclave(fetch).verify_once(deadline=time.monotonic() + 5).code_tag == "key"

    def test_slow_check_is_refused_after_the_deadline(self) -> None:
        checked = 0

        def check(_: Verification) -> None:
            nonlocal checked
            checked += 1
            time.sleep(0.1)

        with pytest.raises(NetworkError, match=DEADLINE_EXCEEDED):
            fake_enclave(lambda: verification("key"), check=check).verify(deadline=time.monotonic() + 0.02)
        assert checked == 1, "the deadline leaves no budget for a retry"

    def test_passed_deadline_sends_nothing(self) -> None:
        def fetch() -> Verification:
            pytest.fail("a passed deadline must not start an attempt")

        with pytest.raises(NetworkError, match=DEADLINE_EXCEEDED):
            fake_enclave(fetch).verify(deadline=time.monotonic() - 1)

    def test_retry_only_when_it_fits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_enclave, "VERIFICATION_RETRY_DELAY", 0.5)
        monkeypatch.setattr(time, "sleep", lambda _: None)
        calls = 0

        def fetch() -> Verification:
            nonlocal calls
            calls += 1
            raise network_error("unavailable")

        with pytest.raises(NetworkError, match="unavailable"):
            fake_enclave(fetch).verify(deadline=time.monotonic() + 0.1)
        assert calls == 1, "a retry that cannot start before the deadline is not attempted"
        with pytest.raises(NetworkError, match="unavailable"):
            fake_enclave(fetch).verify(deadline=time.monotonic() + 5)
        assert calls == 3

    @pytest.mark.asyncio
    async def test_async_slow_verification_is_refused_after_the_deadline(self) -> None:
        async def fetch() -> Verification:
            await asyncio.sleep(0.1)
            return verification("key")

        enclave = Enclave(HOST, "org/repo", _fetch_async=fetch)
        with pytest.raises(NetworkError, match=DEADLINE_EXCEEDED):
            await enclave.verify_once_async(deadline=time.monotonic() + 0.02)
        assert (await enclave.verify_once_async(deadline=time.monotonic() + 5)).code_tag == "key"


def test_verification_without_a_deadline_is_rejected() -> None:
    with pytest.raises(AttestationError, match=FRESHNESS_EXPIRED):
        fake_enclave(lambda: verification("key", deadline=None)).verify()


@pytest.mark.parametrize(
    ("items", "want_hpke", "want_error"),
    [
        ([("tls", KEY_SPKI_FP_SHA256_V1_FORMAT, "fp")], None, None),
        ([("tls", KEY_SPKI_FP_SHA256_V1_FORMAT, "fp"), ("hpke", KEY_X25519_HPKE_V1_FORMAT, "hk")], "hk", None),
        ([("hpke", KEY_X25519_HPKE_V1_FORMAT, "hk")], None, 'endorses no "tls" key'),
        ([("tls", "unexpected", "fp")], None, '"tls" has format "unexpected"'),
        (
            [("tls", KEY_SPKI_FP_SHA256_V1_FORMAT, "fp"), ("hpke", "unexpected", "hk")],
            None,
            '"hpke" has format "unexpected"',
        ),
    ],
)
def test_transport_keys(items: list[tuple[str, str, str]], want_hpke: str | None, want_error: str | None) -> None:
    base = verification("fp", tls="", hpke=None)
    verified = Verification(
        code_digest=base.code_digest,
        code_tag=base.code_tag,
        config_repo=base.config_repo,
        code_measurement=base.code_measurement,
        enclave_measurement=base.enclave_measurement,
        crypto_material=tuple(CryptoMaterialItem(*item) for item in items),
        freshness_expires_at=base.freshness_expires_at,
        metadata=base.metadata,
    )
    if want_error is not None:
        with pytest.raises(AttestationError, match=want_error):
            validate_transport_keys(verified)
        return
    validate_transport_keys(verified)
    assert verified.tls_public_key_fp == "fp"
    assert verified.hpke_public_key == want_hpke


def test_retryable() -> None:
    assert retryable(network_error("x"))
    assert retryable(attestation_error("x"))
    assert not retryable(ConfigurationError("x"))
    assert not retryable(attestation_error(VerificationRejected(HOST, RuntimeError("no"))))


def test_rejected_document_is_an_attestation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = Recorder(lambda _: response(200, b"{}"))
    monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
    with pytest.raises(AttestationError) as err:
        Enclave("enclave.example", "org/repo").verify()
    assert isinstance(err.value.__cause__, VerificationError), "the verifier's error remains the cause"
    assert str(err.value) == str(err.value.__cause__), "the message is the verifier's own, without a prefix"
    assert len(recorder.requests) == 2, "a rejected document is fetched once more"


def test_unreachable_enclave_is_a_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = Recorder(lambda _: response(503))
    monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
    with pytest.raises(NetworkError) as err:
        Enclave("enclave.example", "org/repo").verify()
    assert str(err.value) == err.value.message
    assert "503" in err.value.message
    assert len(recorder.requests) == 2
