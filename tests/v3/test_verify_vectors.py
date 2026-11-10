"""Every full-verify conformance vector through the verifier: the verdict, the layer and the facts."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import pytest

from tests.v3.vectors import vector_group
from tinfoil._v3.verifier._errors import (
    LAYER_ENVELOPE,
    LAYER_POLICY,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    VerificationError,
)
from tinfoil._v3.verifier._measurement import SEVSNP, Expected, ExpectedSEVSNP, Measurement
from tinfoil._v3.verifier._verifier import Overrides, _build

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
    if not expected["accepted"] and expected["code"] != "ENVELOPE_REJECTED":
        with pytest.raises(VerificationError) as rejected:
            verifier.verify_v3_at(doc, nonce, data["repo"], now)
        assert CODES[rejected.value.layer] == expected["code"]
        assert rejected.value.__cause__ is not None
        return
    verified = None
    rejected_layer = None
    try:
        verified = verifier.verify_v3_at(doc, nonce, data["repo"], now)
    except VerificationError as err:
        rejected_layer = err.layer
    if verified is None:
        assert rejected_layer == LAYER_ENVELOPE
        assert not expected["accepted"]
        return
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
    for key, want in expected.items():
        if key in facts:
            assert facts[key] == want, key
    assert verified.metadata.verified_at == now
    assert verified.freshness_expires_at is not None, "every vector's references are endorsed, so a deadline applies"
    assert verified.freshness_expires_at >= now
    assert (verified.config, verified.runtime, verified.platform) == (None, None, None), "v2 collateral"
    assert verified.code_tag != ""
    assert verified.config_repo == data["repo"].split("@")[0]
