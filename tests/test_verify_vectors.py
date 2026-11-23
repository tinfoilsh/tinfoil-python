"""Every full-verify conformance vector through the verifier: the verdict, the layer, the facts and the report."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.vectors import vector, vector_group
from tinfoil.verifier._document.document import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    parse,
)
from tinfoil.verifier._errors import (
    LAYER_ENVELOPE,
    LAYER_POLICY,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    UsageError,
    VerificationError,
)
from tinfoil.verifier._measurement import SEVSNP, Expected, ExpectedSEVSNP, Measurement
from tinfoil.verifier._options import Policy
from tinfoil.verifier._report import (
    LAYERS,
    STEP_FAILED,
    STEP_NOT_RUN,
    STEP_PASSED,
    STEP_SKIPPED,
    VerificationReport,
    hpke_public_key_fp,
)
from tinfoil.verifier._verification import crypto_material_data
from tinfoil.verifier._verifier import Overrides, Pin, _build

STAGE = "verify-attestation-v3"
GROUPS = ("golden", "golden-tdx", "freshness", "real-frozen")
SEV_SNP_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
TDX_TYPE = "https://tinfoil.sh/predicate/tdx-guest/v2"
CODES = {
    LAYER_ENVELOPE: "ENVELOPE_REJECTED",
    LAYER_PROVENANCE: "PROVENANCE_REJECTED",
    LAYER_QUOTE: "QUOTE_REJECTED",
    LAYER_POLICY: "POLICY_REJECTED",
}


def full_verify_params() -> list[Any]:
    fixtures = [fixture for group in GROUPS for fixture in vector_group(group) if fixture["stage"] == STAGE]
    if not fixtures:
        return [pytest.param(None, id="vectors-absent", marks=pytest.mark.skip(reason="conformance vectors not found"))]
    return [pytest.param(fixture, id=fixture["id"]) for fixture in fixtures]


def measurement_of(measurement: Measurement) -> dict[str, Any]:
    if isinstance(measurement, SEVSNP):
        return {"type": SEV_SNP_TYPE, "registers": [measurement.launch.hex()]}
    registers = (measurement.mrtd, measurement.rtmr0, measurement.rtmr1, measurement.rtmr2, measurement.rtmr3)
    return {"type": TDX_TYPE, "registers": [register.hex() for register in registers]}


def expected_of(expected: Expected) -> dict[str, Any]:
    def hex_of(register: bytes | None) -> str:
        return "" if register is None else register.hex()

    if isinstance(expected, ExpectedSEVSNP):
        return {"type": SEV_SNP_TYPE, "registers": [hex_of(expected.launch)]}
    registers = (expected.mrtd, expected.rtmr0, expected.rtmr1, expected.rtmr2, expected.rtmr3)
    return {"type": TDX_TYPE, "registers": [hex_of(register) for register in registers]}


def check_report(report: VerificationReport, rejected: VerificationError | None) -> None:
    """``report`` keeps the report's rules for its verdict: the four layers in order; on an accept, every step
    passed or was skipped, with verified facts and no partial facts; on a rejection, the failed step is the error's
    layer, with its message, no step after it ran, and each partial fact is present only once the step that
    establishes it passed. A step before the failed one may be not_run, since checks don't always run in layer
    order."""
    assert tuple(step.layer for step in report.steps) == LAYERS
    if rejected is None:
        assert all(step.status in (STEP_PASSED, STEP_SKIPPED) for step in report.steps), report.steps
        assert report.verified_facts is not None
        assert report.partial_facts is None
        assert report.failed_step is None
        return
    assert rejected.report is report
    failed = report.failed_step
    assert failed is not None
    assert failed.layer == rejected.layer
    assert failed.message == rejected.message
    after = report.steps[LAYERS.index(failed.layer) + 1 :]
    assert all(step.status == STEP_NOT_RUN for step in after), report.steps
    assert [step.status for step in report.steps].count(STEP_FAILED) == 1
    assert report.verified_facts is None
    partial = report.partial_facts
    assert partial is not None

    def ran(layer: str) -> bool:
        return any(step.layer == layer and step.status in (STEP_PASSED, STEP_SKIPPED) for step in report.steps)

    assert (partial.measured is not None) == ran(LAYER_ENVELOPE)
    assert (partial.expected is not None) == ran(LAYER_PROVENANCE)
    if partial.measured is not None:
        assert (partial.measured.cpu is not None) == ran(LAYER_QUOTE), "no quote is parsed for the report"
    if partial.expected is not None and partial.expected.measurement is not None:
        assert failed.layer == LAYER_POLICY, "the full expectation is resolved only by the policy step"


@pytest.mark.parametrize("fixture", full_verify_params())
def test_full_verify_vectors(fixture: dict[str, Any]) -> None:
    data, expected = fixture["input"], fixture["expected"]
    ask, ark = data.get("ask_pem", ""), data.get("amd_root_ca_pem", "")
    sigstore = data.get("sigstore_trusted_root_json_b64", "")
    verifier = _build(
        overrides=Overrides(
            sigstore_root=base64.b64decode(sigstore) if sigstore else None,
            amd_root_pem=f"{ask.strip()}\n{ark.strip()}\n".encode() if ask else None,
            intel_root_pem=data["intel_sgx_root_pem"].encode() if data.get("intel_sgx_root_pem") else None,
        )
    )
    doc = base64.b64decode(data["document_b64"])
    nonce = bytes.fromhex(data["nonce_hex"])
    now = datetime.fromtimestamp(data["verification_time_unix"], UTC)
    if not expected["accepted"] and expected["code"] == "MALFORMED_INPUT":
        with pytest.raises(UsageError):
            verifier.verify_v3_at(doc, nonce, Pin(repo=data["repo"]), now)
        return
    if not expected["accepted"] and expected["code"] != "ENVELOPE_REJECTED":
        with pytest.raises(VerificationError) as rejected:
            verifier.verify_v3_at(doc, nonce, Pin(repo=data["repo"]), now)
        assert CODES[rejected.value.layer] == expected["code"]
        assert rejected.value.__cause__ is not None
        assert rejected.value.report is not None
        check_report(rejected.value.report, rejected.value)
        assert rejected.value.report.metadata.verified_at == now
        return
    report = None
    rejection: VerificationError | None = None
    try:
        report = verifier.verify_v3_at(doc, nonce, Pin(repo=data["repo"]), now)
    except VerificationError as err:
        rejection = err
    if report is None:
        assert rejection is not None
        assert rejection.layer == LAYER_ENVELOPE
        assert rejection.report is not None
        check_report(rejection.report, rejection)
        assert not expected["accepted"]
        return
    check_report(report, None)
    verified = report.verified_facts
    assert verified is not None
    if not expected["accepted"]:
        # The verifier proves the document; the channel keys that every client needs are the adapter's
        # requirement, reported as an envelope rejection.
        assert expected["code"] == "ENVELOPE_REJECTED"
        assert verified.tls_public_key_fp is None or verified.hpke_public_key is None
        return
    facts = {
        "code_digest": verified.code_digest,
        "code_measurement": expected_of(verified.code_measurement),
        "enclave_measurement": measurement_of(verified.enclave_measurement),
        "tls_public_key_fp": verified.tls_public_key_fp,
        "hpke_public_key": verified.hpke_public_key,
    }
    expectations = {key: want for key, want in expected.items() if key not in ("accepted", "code")}
    missing = set(expectations) - set(facts)
    assert not missing, f"the fixture expects facts that this test does not compute: {sorted(missing)}"
    for key, want in expectations.items():
        assert facts[key] == want, key
    assert report.metadata.verified_at == now
    assert all(step.status == STEP_PASSED for step in report.steps), "v2 collateral is endorsed, never embedded"
    assert verified.freshness_expires_at is not None, "every vector's references are endorsed, so a deadline applies"
    assert verified.freshness_expires_at >= now
    assert (verified.config, verified.runtime, verified.platform) == (None, None, None), "v2 collateral"
    assert verified.code_tag != ""
    assert verified.config_repo == data["repo"].split("@")[0]


@pytest.mark.parametrize(
    ("group", "name", "deadline"),
    [
        ("golden", "golden-happy", datetime(2034, 12, 30, tzinfo=UTC)),
        ("golden-tdx", "tdx-golden-happy", datetime(2030, 1, 1, tzinfo=UTC)),
    ],
)
def test_hardware_bounds_cached_verification(group: str, name: str, deadline: datetime) -> None:
    data = vector(group, name)["input"]
    verifier = _build(
        policy=Policy(freshness_max_age=timedelta(days=20 * 365)),
        overrides=Overrides(
            sigstore_root=base64.b64decode(data["sigstore_trusted_root_json_b64"]),
            amd_root_pem=f"{data['ask_pem'].strip()}\n{data['amd_root_ca_pem'].strip()}\n".encode()
            if data.get("ask_pem")
            else None,
            intel_root_pem=data["intel_sgx_root_pem"].encode() if data.get("intel_sgx_root_pem") else None,
        ),
    )
    doc, nonce = base64.b64decode(data["document_b64"]), bytes.fromhex(data["nonce_hex"])
    now = datetime.fromtimestamp(data["verification_time_unix"], UTC)
    verified = verifier.verify_v3_at(doc, nonce, Pin(repo=data["repo"]), now).verified_facts
    assert verified is not None
    assert verified.freshness_expires_at == deadline
    with pytest.raises(VerificationError) as rejected:
        verifier.verify_v3_at(doc, nonce, Pin(repo=data["repo"]), deadline + timedelta(seconds=1))
    assert rejected.value.layer == LAYER_QUOTE


def _vector_verifier(data: dict[str, Any]) -> Any:
    return _build(
        overrides=Overrides(
            sigstore_root=base64.b64decode(data["sigstore_trusted_root_json_b64"]),
            amd_root_pem=f"{data['ask_pem'].strip()}\n{data['amd_root_ca_pem'].strip()}\n".encode()
            if data.get("ask_pem")
            else None,
            intel_root_pem=data["intel_sgx_root_pem"].encode() if data.get("intel_sgx_root_pem") else None,
        )
    )


def _rejection(group: str, name: str) -> VerificationError:
    fixture = vector(group, name)
    data = fixture["input"]
    doc, nonce = base64.b64decode(data["document_b64"]), bytes.fromhex(data["nonce_hex"])
    now = datetime.fromtimestamp(data["verification_time_unix"], UTC)
    with pytest.raises(VerificationError) as rejected:
        _vector_verifier(data).verify_v3_at(doc, nonce, Pin(repo=data["repo"]), now)
    return rejected.value


@pytest.mark.parametrize(("group", "name"), [("golden", "s14-measurement"), ("golden-tdx", "t18-rtmr1")])
def test_a_measurement_mismatch_reports_both_sides(group: str, name: str) -> None:
    """A check after the policy step resolved every register reports the full expectation next to the authenticated
    measurement, register by register; the key fingerprints come from the document, unverified."""
    err = _rejection(group, name)
    assert err.layer == LAYER_POLICY
    report = err.report
    assert report is not None
    assert report.partial_facts is not None
    expected, measured = report.partial_facts.expected, report.partial_facts.measured
    assert expected is not None
    assert measured is not None
    assert measured.cpu is not None
    assert expected.measurement is not None
    assert type(expected.measurement) is type(measured.cpu.measurement)
    assert expected.measurement != measured.cpu.measurement
    assert expected.code_measurement is not None
    assert type(expected.measurement).__name__ == type(expected.code_measurement).__name__.removeprefix("Expected")
    assert expected.artifact.digest != ""
    assert expected.config_repo != ""
    assert [step.status for step in report.steps] == [STEP_PASSED, STEP_PASSED, STEP_PASSED, STEP_FAILED]
    data = vector(group, name)["input"]
    items = parse(base64.b64decode(data["document_b64"]), bytes.fromhex(data["nonce_hex"])).crypto_material_items()
    tls = crypto_material_data(items, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT)
    hpke = crypto_material_data(items, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT)
    assert tls is not None
    assert hpke is not None
    assert measured.tls_public_key_fp == tls
    assert measured.hpke_public_key_fp == hashlib.sha256(bytes.fromhex(hpke)).hexdigest()


def test_an_unendorsed_machine_reports_no_full_expectation() -> None:
    """A policy rejection before every register was resolved leaves the full expectation out, while the code
    measurement and the authenticated measurement are reported."""
    err = _rejection("golden", "i5-not-endorsed")
    assert err.layer == LAYER_POLICY
    assert err.report is not None
    assert err.report.partial_facts is not None
    expected, measured = err.report.partial_facts.expected, err.report.partial_facts.measured
    assert expected is not None
    assert expected.measurement is None
    assert expected.code_measurement is not None
    assert measured is not None
    assert measured.cpu is not None


def test_hpke_fingerprint_is_the_sha256_of_the_key_bytes() -> None:
    key = "01" * 32
    assert hpke_public_key_fp(key) == "72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793"
    assert hpke_public_key_fp("") is None
    assert hpke_public_key_fp("not hex") is None
