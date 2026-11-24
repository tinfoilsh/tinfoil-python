"""The verification report: the steps that the verifier records, the partial facts of a rejection, and the
report's immutability and JSON form. The conformance vectors check the report of every full verification in
``test_verify_vectors``."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import pickle
from datetime import UTC, datetime

import pytest

from tests import document_builder
from tests import verifier_fixtures as vf
from tinfoil.verifier import (
    LAYER_ENVELOPE,
    LAYER_POLICY,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    REPORT_SCHEMA_VERSION,
    SOURCE_EMBEDDED,
    SOURCE_ENDORSEMENT,
    SOURCE_POLICY,
    STEP_FAILED,
    STEP_NOT_RUN,
    STEP_PASSED,
    STEP_SKIPPED,
    ArtifactVerification,
    ConfigVerification,
    CPUEvidence,
    ExpectedFacts,
    ExpectedSEVSNP,
    MeasuredFacts,
    PartialFacts,
    Pin,
    SoftwareIdentity,
    VerificationError,
    VerificationMetadata,
    VerificationReport,
    Verifier,
)
from tinfoil.verifier._config import EndorsementResult
from tinfoil.verifier._document.collateral.collateral import FORMAT_V3
from tinfoil.verifier._measurement import SEVSNP
from tinfoil.verifier._report import PROVENANCE_EMBEDDED, ReportBuilder, measured_keys
from tinfoil.verifier._verifier import _embedded

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
NONCE = document_builder.test_nonce()


def rejection(verifier: Verifier, doc: bytes, nonce: bytes, pin: Pin) -> VerificationError:
    with pytest.raises(VerificationError) as rejected:
        verifier.verify_v3_at(doc, nonce, pin, NOW)
    assert rejected.value.report is not None
    return rejected.value


def statuses(report: VerificationReport) -> list[tuple[str, str]]:
    return [(step.layer, step.status) for step in report.steps]


def test_an_envelope_rejection_reports_no_facts() -> None:
    err = rejection(Verifier(), b"{}", NONCE, Pin(repo="org/repo"))
    report = err.report
    assert report is not None
    assert statuses(report) == [
        (LAYER_ENVELOPE, STEP_FAILED),
        (LAYER_PROVENANCE, STEP_NOT_RUN),
        (LAYER_QUOTE, STEP_NOT_RUN),
        (LAYER_POLICY, STEP_NOT_RUN),
    ]
    failed = report.failed_step
    assert failed is not None
    assert failed.message == err.message
    assert report.verified_facts is None
    assert report.partial_facts is not None
    assert report.partial_facts.expected is None
    assert report.partial_facts.measured is None
    assert report.metadata.verified_at == NOW


def test_a_provenance_rejection_reports_the_unverified_key_fingerprints() -> None:
    _, raw = document_builder.build(NONCE, collateral_entries=[])
    report = rejection(Verifier(), raw, NONCE, Pin(repo="org/repo")).report
    assert report is not None
    assert statuses(report) == [
        (LAYER_ENVELOPE, STEP_PASSED),
        (LAYER_PROVENANCE, STEP_FAILED),
        (LAYER_QUOTE, STEP_NOT_RUN),
        (LAYER_POLICY, STEP_NOT_RUN),
    ]
    partial = report.partial_facts
    assert partial is not None
    assert partial.expected is None
    measured = partial.measured
    assert measured is not None
    assert measured.cpu is None
    assert measured.tls_public_key_fp == document_builder.TLS_KEY.hex()
    assert measured.hpke_public_key_fp == hashlib.sha256(document_builder.HPKE_KEY).hexdigest()
    assert document_builder.HPKE_KEY.hex() not in report.to_json(), "the report never holds the HPKE key itself"


def test_a_document_without_keys_reports_no_fingerprints() -> None:
    _, raw = document_builder.build(NONCE, collateral_entries=[], crypto_items=[])
    report = rejection(Verifier(), raw, NONCE, Pin(repo="org/repo")).report
    assert report is not None
    assert report.partial_facts is not None
    measured = report.partial_facts.measured
    assert measured is not None
    assert measured.tls_public_key_fp is None
    assert measured.hpke_public_key_fp is None
    assert measured_keys(()) == measured


def test_embedded_references_skip_provenance_and_report_what_they_fix() -> None:
    """With every reference value embedded, provenance authenticates nothing and is skipped; the expected facts are
    the embedded values, with the code measurement in the layout of the platform that the document's evidence
    names. The dummy quote then fails to authenticate, so no CPU measurement is reported."""
    v = vf.embedded_verifier(vf.embedded_inputs())
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    report = rejection(v, raw, nonce, Pin()).report
    assert report is not None
    assert statuses(report) == [
        (LAYER_ENVELOPE, STEP_PASSED),
        (LAYER_PROVENANCE, STEP_SKIPPED),
        (LAYER_QUOTE, STEP_FAILED),
        (LAYER_POLICY, STEP_NOT_RUN),
    ]
    assert report.steps[1].message == PROVENANCE_EMBEDDED
    partial = report.partial_facts
    assert partial is not None
    expected, measured = partial.expected, partial.measured
    assert expected is not None
    assert measured is not None
    assert measured.cpu is None, "a quote that failed to authenticate is never parsed for the report"
    assert expected.artifact.source == SOURCE_EMBEDDED
    assert expected.config is not None
    assert expected.config.source == SOURCE_EMBEDDED
    assert expected.config.name == vf.EMBEDDED_CONFIG_NAME
    assert expected.platform is not None
    assert expected.platform.source == SOURCE_EMBEDDED
    assert expected.config_repo == expected.artifact.repo
    assert expected.code_measurement == ExpectedSEVSNP(launch=bytes.fromhex(vf.SNP_LAUNCH))
    assert expected.measurement is None, "only the policy step resolves the full expectation"


def test_provenance_is_skipped_only_when_every_reference_is_embedded() -> None:
    embedded = ArtifactVerification(source=SOURCE_EMBEDDED)
    endorsed = ArtifactVerification(source=SOURCE_ENDORSEMENT, repo="org/repo")
    config = ConfigVerification(source=SOURCE_EMBEDDED)
    refs = EndorsementResult(quote=object(), artifact=embedded, platform=embedded, config=config)  # type: ignore[arg-type]
    assert _embedded(refs)
    assert not _embedded(dataclasses.replace(refs, config=ConfigVerification(source=SOURCE_POLICY)))
    assert not _embedded(dataclasses.replace(refs, config=None))
    assert not _embedded(dataclasses.replace(refs, artifact=endorsed))
    assert not _embedded(dataclasses.replace(refs, platform=endorsed))
    assert not _embedded(dataclasses.replace(refs, platform=None))


def sample_report() -> VerificationReport:
    steps = ReportBuilder(VerificationMetadata(verifier=SoftwareIdentity("tinfoil-python", "1"), verified_at=NOW))
    steps.passed(LAYER_ENVELOPE)
    steps.measured = measured_keys(())
    return steps.failed(LAYER_PROVENANCE, "provenance: bad bundle")


def test_a_report_is_immutable() -> None:
    report = sample_report()
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.steps = ()  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.steps[0].status = STEP_FAILED  # type: ignore[misc]
    assert report.partial_facts is not None
    assert report.partial_facts.measured is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.partial_facts.measured.cpu = None  # type: ignore[misc]
    assert isinstance(report.steps, tuple)


def test_report_to_dict() -> None:
    report = sample_report()
    got = report.to_dict()
    assert got == {
        "schema_version": REPORT_SCHEMA_VERSION,
        "steps": [
            {"layer": "envelope", "status": "passed"},
            {"layer": "provenance", "status": "failed", "message": "provenance: bad bundle"},
            {"layer": "quote", "status": "not_run"},
            {"layer": "policy", "status": "not_run"},
        ],
        "partial_facts": {"measured": {}},
        "metadata": {"verified_at": "2026-08-06T12:00:00Z", "verifier": {"name": "tinfoil-python", "version": "1"}},
    }
    assert REPORT_SCHEMA_VERSION == 1
    assert json.loads(report.to_json()) == got
    assert json.loads(report.to_json(indent=2)) == got
    launch = bytes([1]) * 48
    assert report.partial_facts is not None
    full = dataclasses.replace(
        report, partial_facts=dataclasses.replace(report.partial_facts, expected=_expected(launch))
    ).to_dict()
    assert full["partial_facts"]["expected"] == {
        "config_repo": "org/repo",
        "artifact": {"source": "endorsement", "repo": "org/repo", "digest": "ab" * 32},
        "code_measurement": {"platform": "sev-snp", "launch": launch.hex()},
        "measurement": {"platform": "sev-snp", "launch": launch.hex()},
    }
    cpu = dataclasses.replace(
        report.partial_facts,
        measured=MeasuredFacts(cpu=CPUEvidence(measurement=SEVSNP(launch=launch)), tls_public_key_fp="cd" * 32),
    )
    assert dataclasses.replace(report, partial_facts=cpu).to_dict()["partial_facts"] == {
        "measured": {"cpu_measurement": {"platform": "sev-snp", "launch": launch.hex()}, "tls_public_key_fp": "cd" * 32}
    }
    # A release that fixes no register on the platform has no code measurement in the form.
    unfixed = dataclasses.replace(_expected(launch), code_measurement=ExpectedSEVSNP())
    without = dataclasses.replace(report, partial_facts=PartialFacts(expected=unfixed)).to_dict()
    assert "code_measurement" not in without["partial_facts"]["expected"]


def test_report_metadata_names_the_verifier_only_when_its_version_is_known() -> None:
    """An SDK that runs from a source tree without an installed package can't name its version, so its report leaves
    the verifier out rather than writing a placeholder."""
    for verifier in (SoftwareIdentity("tinfoil-python", "unknown"), SoftwareIdentity("tinfoil-python", "")):
        metadata = VerificationMetadata(verifier=verifier, verified_at=NOW)
        report = dataclasses.replace(sample_report(), metadata=metadata)
        assert report.to_dict()["metadata"] == {"verified_at": "2026-08-06T12:00:00Z"}


def _expected(launch: bytes) -> ExpectedFacts:
    return ExpectedFacts(
        config_repo="org/repo",
        artifact=ArtifactVerification(source=SOURCE_ENDORSEMENT, repo="org/repo", digest="ab" * 32),
        code_measurement=ExpectedSEVSNP(launch=launch),
        measurement=SEVSNP(launch=launch),
    )


def test_a_verification_error_keeps_its_report_through_pickling_and_copying() -> None:
    err = rejection(Verifier(), b"{}", NONCE, Pin(repo="org/repo"))
    for clone in (pickle.loads(pickle.dumps(err)), copy.copy(err), copy.deepcopy(err)):
        assert isinstance(clone, VerificationError)
        assert clone.report == err.report
        assert (clone.layer, clone.message) == (err.layer, err.message)
