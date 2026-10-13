"""Envelope checks for collateral that verification may never select."""

import pytest

from tinfoil.v3 import envelope as env
from tinfoil.v3.errors import ENVELOPE_REJECTED, VerificationError

from docbuilder import NONCE, build_doc


UNKNOWN_FORMAT = "https://example.com/collateral/v1"
REFERENCE_FORMATS = (
    env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT,
    env.COLLATERAL_SIGSTORE_PLATFORM_V1_FORMAT,
    env.COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT,
)


def entry(format_=UNKNOWN_FORMAT, *, role=env.ROLE_ENDORSEMENT, data=None):
    return {"id": "unused", "role": role, "format": format_, "subjects": ["gpu"], "data": data}


def rejects(collateral, match):
    with pytest.raises(VerificationError, match=match) as error:
        env.check(build_doc(collateral=collateral), NONCE)
    assert error.value.layer == ENVELOPE_REJECTED


@pytest.mark.parametrize("data", [None, [], "opaque", 1, True])
def test_unknown_collateral_requires_object(data):
    rejects([entry(data=data)], "data is not a JSON object")


def test_missing_collateral_data_rejects():
    value = entry()
    del value["data"]
    rejects([value], "data is not a JSON object")


@pytest.mark.parametrize("format_,role", [
    (UNKNOWN_FORMAT, env.ROLE_ENDORSEMENT),
    (env.COLLATERAL_AMD_CRL_V1_FORMAT, env.ROLE_REFERENCE_VALUES),
    (env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT, env.ROLE_ENDORSEMENT),
])
def test_unrecognized_role_format_pair_preserves_opaque_object(format_, role):
    doc, _ = env.check(build_doc(collateral=[entry(format_, role=role, data={"future": [1]})]), NONCE)
    assert doc.collateral[0].data == b'{"future":[1]}'


@pytest.mark.parametrize("encoded", ["AA==\n", "AA==\r\n", "AB=="])
def test_cpu_report_requires_canonical_base64(encoded):
    with pytest.raises(VerificationError) as error:
        env.check(build_doc(mutate=lambda doc: doc["cpu_evidence"].update(report_base64=encoded)), NONCE)
    assert error.value.layer == ENVELOPE_REJECTED


@pytest.mark.parametrize("format_,data", [
    (env.COLLATERAL_AMD_VCEK_V1_FORMAT, {"vcek_der_base64": "AB=="}),
    (env.COLLATERAL_AMD_CRL_V1_FORMAT, {"crl_der_base64": "AA==\n"}),
    (env.COLLATERAL_INTEL_PCS_V1_FORMAT, {"responses": [{"body_base64": "AB=="}]}),
])
def test_unused_hardware_collateral_requires_canonical_base64(format_, data):
    rejects([entry(format_, data=data)], "base64")


@pytest.mark.parametrize("format_", [
    env.COLLATERAL_AMD_VCEK_V1_FORMAT,
    env.COLLATERAL_AMD_CRL_V1_FORMAT,
    env.COLLATERAL_INTEL_PCS_V1_FORMAT,
])
def test_unused_known_hardware_collateral_is_strictly_decoded(format_):
    rejects([entry(format_, data={"unknown": True})], "unknown object member")


@pytest.mark.parametrize("format_", REFERENCE_FORMATS)
@pytest.mark.parametrize("bundle", ["missing", None])
def test_unused_reference_requires_bundle(format_, bundle):
    data = {"sigstore_bundle": bundle}
    if bundle == "missing":
        del data["sigstore_bundle"]
    if format_ != env.COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT:
        data["digest"] = "aa" * 32
    rejects([entry(format_, role=env.ROLE_REFERENCE_VALUES, data=data)], "missing sigstore_bundle")


@pytest.mark.parametrize("format_", REFERENCE_FORMATS[:2])
def test_unused_code_and_platform_require_digest(format_):
    rejects([entry(format_, role=env.ROLE_REFERENCE_VALUES, data={"sigstore_bundle": {}})], "missing digest")


def test_invalid_witness_bundle_is_left_for_provenance():
    value = entry(env.COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT,
                  role=env.ROLE_REFERENCE_VALUES, data={"sigstore_bundle": {}})
    doc, _ = env.check(build_doc(collateral=[value]), NONCE)
    assert env.freshness_collateral(doc, value["id"]) == b"{}"


def test_explicit_legacy_collateral_format_accepts():
    doc, _ = env.check(build_doc(mutate=lambda doc: doc.update(collateral_format=env.LEGACY_COLLATERAL_FORMAT)), NONCE)
    assert doc.challenge.nonce == NONCE.hex()


@pytest.mark.parametrize("format_", ["https://tinfoil.sh/predicate/attestation-collaterals/v3", UNKNOWN_FORMAT])
def test_unsupported_collateral_format_rejects(format_):
    with pytest.raises(VerificationError, match="unsupported collateral format"):
        env.check(build_doc(mutate=lambda doc: doc.update(collateral_format=format_)), NONCE)
