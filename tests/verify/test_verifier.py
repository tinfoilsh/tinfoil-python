from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from tinfoil import _sdkinfo
from tinfoil.verify import (
    Layer,
    UsageError,
    VerificationError,
    Verifier,
    _quote,
    _verifier,
    document,
)
from tinfoil.verify._provenance import AuthenticatedArtifact
from tinfoil.verify._references import ReferenceResolver, ResolvedReferences
from tinfoil.verify.document import KEY_SPKI_FP_SHA256_V1_FORMAT, CryptoMaterialItem
from tinfoil.verify.measurement import Measurement, PredicateType

NONCE = bytes(range(32))
AT = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
CODE = Measurement(PredicateType.SNP_TDX_MULTIPLATFORM_V1, ["aa" * 48, "bb" * 48, "cc" * 48])
ENCLAVE = Measurement(PredicateType.SEV_GUEST_V2, ["aa" * 48])
TLS = CryptoMaterialItem("tls", KEY_SPKI_FP_SHA256_V1_FORMAT, "dd" * 32)
CODE_ARTIFACT = AuthenticatedArtifact(
    repo="org/repo", tag="v1.2.3", commit="ff" * 20, subject_name="tinfoil-enclave.json", digest="ee" * 32
)


class Stages:
    """Every verification stage replaced by a fake that succeeds and records its arguments."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: dict[str, tuple[Any, ...]] = {}
        self.errors: dict[str, BaseException] = {}
        self.document = SimpleNamespace(
            cpu_evidence="cpu evidence", cpu_endorsements="cpu endorsements", crypto_material=(TLS,)
        )
        self.references = ResolvedReferences(
            quote="reference values", artifact=CODE_ARTIFACT, freshness_expires_at=AT + timedelta(days=6)
        )
        self.authenticated = _quote.AuthenticatedQuote(platform="sev-snp", identity="01" * 64, measurement=ENCLAVE)
        self.assembled = SimpleNamespace(code_measurement=CODE, validate=lambda: self._stage("validate", None))

        monkeypatch.setattr(document, "parse", lambda *args: self._stage("parse", self.document, *args))
        monkeypatch.setattr(
            ReferenceResolver, "resolve", lambda _, *args: self._stage("resolve", self.references, *args)
        )
        monkeypatch.setattr(
            _quote, "authenticate", lambda *args: self._stage("authenticate", self.authenticated, *args)
        )
        monkeypatch.setattr(_quote, "assemble", lambda *args: self._stage("assemble", self.assembled, *args))

    def _stage(self, name: str, result: Any, *args: Any) -> Any:
        self.calls[name] = args
        if name in self.errors:
            raise self.errors[name]
        return result


@pytest.fixture
def stages(monkeypatch: pytest.MonkeyPatch) -> Stages:
    return Stages(monkeypatch)


def test_defaults():
    verifier = Verifier()
    assert verifier.freshness_max_age == timedelta(days=7)
    assert verifier.pinned_registers is None


@pytest.mark.parametrize("max_age", [None, timedelta(0)])
def test_unset_freshness_max_age_keeps_the_default(max_age):
    # Zero keeps the default, so a caller passing an unset policy field does
    # not silently disable the bound.
    assert Verifier(freshness_max_age=max_age).freshness_max_age == timedelta(days=7)


def test_freshness_max_age():
    assert Verifier(freshness_max_age=timedelta(hours=24)).freshness_max_age == timedelta(hours=24)


@pytest.mark.parametrize("max_age", [timedelta(microseconds=-1), timedelta(hours=-1)])
def test_negative_freshness_max_age_is_a_usage_error(max_age):
    with pytest.raises(UsageError, match="freshness maximum age must not be negative"):
        Verifier(freshness_max_age=max_age)


def test_pinned_registers_must_be_a_measurement():
    with pytest.raises(UsageError, match="pinned registers must be a Measurement"):
        Verifier(pinned_registers=["aa" * 48])  # type: ignore[arg-type]


def test_verify_returns_the_proven_facts(stages):
    verified = Verifier().verify_at(b"document", NONCE, "org/repo", AT)

    assert verified.config_repo == "org/repo"
    assert verified.code_digest == CODE_ARTIFACT.digest
    assert verified.code_tag == "v1.2.3"
    assert verified.code_measurement == CODE
    assert verified.enclave_measurement == ENCLAVE
    assert verified.crypto_material == (TLS,)
    assert verified.tls_public_key_fp == TLS.data
    assert verified.freshness_expires_at == AT + timedelta(days=6)
    assert verified.metadata.verifier.name == _sdkinfo.SDK_NAME
    assert verified.metadata.verifier.version == _sdkinfo.sdk_version()
    assert verified.metadata.verified_at == AT


def test_verify_appraises_every_stage_at_one_instant(stages):
    verifier = Verifier()
    verifier.verify_at(b"document", NONCE, "org/repo", AT)

    assert stages.calls["parse"] == (b"document", NONCE)
    assert stages.calls["resolve"] == (stages.document, "org/repo", AT)
    assert stages.calls["authenticate"] == ("cpu evidence", "cpu endorsements", AT, _quote.VendorRoots())
    assert stages.calls["assemble"] == (stages.document, "reference values", None, stages.authenticated)
    assert "validate" in stages.calls


def test_verify_reads_the_clock_once(monkeypatch, stages):
    class Clock(datetime):
        reads = 0

        @classmethod
        def now(cls, tz=None):
            cls.reads += 1
            return super().now(tz)

    monkeypatch.setattr(_verifier, "datetime", Clock)
    before = datetime.now(timezone.utc)
    verified = Verifier().verify(b"document", NONCE, "org/repo")
    after = datetime.now(timezone.utc)

    assert Clock.reads == 1
    assert before <= verified.metadata.verified_at <= after
    assert verified.metadata.verified_at.tzinfo is timezone.utc
    assert stages.calls["resolve"][2] is verified.metadata.verified_at
    assert stages.calls["authenticate"][2] is verified.metadata.verified_at


def test_verify_reports_the_instant_in_utc(stages):
    local = AT.astimezone(timezone(timedelta(hours=2)))
    verified = Verifier().verify_at(b"document", NONCE, "org/repo", local)
    assert verified.metadata.verified_at == AT
    assert verified.metadata.verified_at.tzinfo is timezone.utc


@pytest.mark.parametrize("instant", [AT.replace(tzinfo=None), AT.date(), AT.timestamp(), "2026-10-01T12:00:00Z", None])
def test_verify_at_requires_an_aware_datetime(stages, instant):
    with pytest.raises(UsageError, match="verification time must be a timezone-aware datetime"):
        Verifier().verify_at(b"document", NONCE, "org/repo", instant)
    assert stages.calls == {}


def test_verifiers_are_immutable():
    verifier = Verifier()
    with pytest.raises(AttributeError, match="immutable"):
        verifier._pinned_registers = ENCLAVE  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        del verifier._references
    assert verifier.pinned_registers is None


@pytest.mark.parametrize(
    ("stage", "layer"),
    [
        ("parse", Layer.ENVELOPE),
        ("resolve", Layer.PROVENANCE),
        ("authenticate", Layer.QUOTE),
        ("assemble", Layer.POLICY),
        ("validate", Layer.POLICY),
    ],
)
def test_a_failing_stage_is_rejected_at_its_layer(stages, stage, layer):
    cause = ValueError("boom")
    stages.errors[stage] = cause

    with pytest.raises(VerificationError) as caught:
        Verifier().verify_at(b"document", NONCE, "org/repo", AT)

    assert caught.value.layer is layer
    assert caught.value.__cause__ is cause
    assert str(caught.value) == f"verification error: {layer}: boom"


def test_later_stages_do_not_run_after_a_rejection(stages):
    stages.errors["resolve"] = ValueError("boom")
    with pytest.raises(VerificationError):
        Verifier().verify_at(b"document", NONCE, "org/repo", AT)
    assert "authenticate" not in stages.calls


def test_invalid_input_to_parse_is_a_usage_error(stages):
    cause = document.InvalidInputError("expected nonce must be 32 bytes, got 31")
    stages.errors["parse"] = cause

    with pytest.raises(UsageError) as caught:
        Verifier().verify_at(b"document", NONCE[:31], "org/repo", AT)

    assert caught.value.__cause__ is cause


@pytest.mark.parametrize(
    "err", [UsageError("invalid release reference"), VerificationError(Layer.QUOTE, "already classified")]
)
def test_classified_errors_pass_through(stages, err):
    stages.errors["resolve"] = err
    with pytest.raises(type(err)) as caught:
        Verifier().verify_at(b"document", NONCE, "org/repo", AT)
    assert caught.value is err


def test_unimplemented_steps_are_never_a_verdict(stages):
    stages.errors["authenticate"] = NotImplementedError()
    with pytest.raises(NotImplementedError):
        Verifier().verify_at(b"document", NONCE, "org/repo", AT)
