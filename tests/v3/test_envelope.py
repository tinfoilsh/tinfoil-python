"""Envelope strict-parse and challenge-binding tests (Go: envelope_test)."""

import json

import pytest

from tinfoil.v3 import envelope
from tinfoil.v3.errors import (
    ENVELOPE_REJECTED,
    PROVENANCE_REJECTED,
    CollateralNotFoundError,
    VerificationError,
)

from docbuilder import CRYPTO_SECTION, DEVICE_SECTION, NONCE, b64, build_doc


def assert_envelope_rejects(doc_bytes, nonce=NONCE, match=None):
    with pytest.raises(VerificationError, match=match) as ei:
        envelope.check(doc_bytes, nonce)
    assert ei.value.layer == ENVELOPE_REJECTED


def test_happy_check_returns_report_data():
    doc_bytes = build_doc()
    doc, report_data = envelope.check(doc_bytes, NONCE)
    assert len(report_data) == 64
    assert report_data[32:] == b"\x00" * 32
    assert report_data.hex() == doc.challenge.report_data
    items = envelope.crypto_material_items(doc)
    assert [i.id for i in items] == ["tls", "hpke"]
    assert envelope.crypto_material_item(doc, "tls").data == "11" * 32
    assert envelope.crypto_material_item(doc, "nope") is None
    assert envelope.device_evidence_items(doc) == []


def test_wrong_nonce_rejects():
    assert_envelope_rejects(build_doc(), bytes(32), match="nonce does not match")


def test_bad_nonce_size_rejects():
    assert_envelope_rejects(build_doc(), b"\x00" * 31, match="must be 32 bytes")


def test_unknown_document_format_rejects():
    def mutate(d):
        d["format"] = "https://tinfoil.sh/predicate/attestation/v2"

    assert_envelope_rejects(build_doc(mutate=mutate), match="unsupported document format")


def test_unknown_report_data_algorithm_rejects():
    def mutate(d):
        d["challenge"]["report_data_algorithm"] += "-x"

    assert_envelope_rejects(build_doc(mutate=mutate), match="report_data_algorithm")


def test_unknown_member_rejects():
    def mutate(d):
        d["extra"] = 1

    assert_envelope_rejects(build_doc(mutate=mutate), match="unknown object member")


def test_duplicate_member_rejects():
    doc = build_doc()
    dup = doc[:-1] + b',"format":"x"}'
    assert_envelope_rejects(dup, match="duplicate object member")


def test_uppercase_nonce_hex_rejects():
    def mutate(d):
        d["challenge"]["nonce"] = d["challenge"]["nonce"].upper()

    assert_envelope_rejects(build_doc(mutate=mutate), match="not lowercase hex")


def test_tampered_report_data_rejects():
    def mutate(d):
        d["challenge"]["report_data"] = "cc" * 64

    assert_envelope_rejects(build_doc(mutate=mutate), match="report_data does not match")


def test_tampered_section_hash_rejects():
    def mutate(d):
        d["cpu_evidence"]["endorsed"]["crypto_material_hash"] = "ab" * 32

    assert_envelope_rejects(build_doc(mutate=mutate), match="crypto_material hash")


def test_non_canonical_base64_section_rejects():
    def mutate(d):
        # "AB==" decodes (its padding bits are non-zero) but does not survive
        # the round-trip; the canonical check must reject it before hashing.
        d["crypto_material"] = "AB=="

    assert_envelope_rejects(build_doc(mutate=mutate), match="not canonical base64")


def test_incomplete_cpu_evidence_rejects():
    def mutate(d):
        d["cpu_evidence"]["report_base64"] = ""

    assert_envelope_rejects(build_doc(mutate=mutate), match="cpu_evidence is incomplete")


def test_missing_sections_reject():
    for key in ("crypto_material", "device_evidence"):

        def mutate(d, key=key):
            d[key] = ""

        assert_envelope_rejects(build_doc(mutate=mutate), match=f"{key} section is missing")


def test_duplicate_crypto_item_id_rejects():
    section = {
        "format": envelope.CRYPTO_MATERIAL_V1_FORMAT,
        "items": [
            {"id": "tls", "format": envelope.KEY_SPKI_FP_SHA256_V1_FORMAT, "data": "11" * 32},
            {"id": "tls", "format": envelope.KEY_X25519_HPKE_V1_FORMAT, "data": "22" * 32},
        ],
    }
    assert_envelope_rejects(build_doc(crypto_section=section), match="duplicate crypto_material item id")


def test_known_key_format_wrong_length_rejects():
    section = {
        "format": envelope.CRYPTO_MATERIAL_V1_FORMAT,
        "items": [{"id": "tls", "format": envelope.KEY_SPKI_FP_SHA256_V1_FORMAT, "data": "11" * 31}],
    }
    assert_envelope_rejects(build_doc(crypto_section=section), match="must be 32 bytes")


def test_unknown_key_format_data_still_validated():
    for data, msg in (("", "data is empty"), ("abc", "not lowercase hex"), ("AB", "not lowercase hex")):
        section = {
            "format": envelope.CRYPTO_MATERIAL_V1_FORMAT,
            "items": [{"id": "x", "format": "https://example/fmt", "data": data}],
        }
        assert_envelope_rejects(build_doc(crypto_section=section), match=msg)
    # Valid unknown-format data of any even length is accepted.
    section = {
        "format": envelope.CRYPTO_MATERIAL_V1_FORMAT,
        "items": [{"id": "x", "format": "https://example/fmt", "data": "abcd"}],
    }
    envelope.check(build_doc(crypto_section=section), NONCE)


def test_missing_items_reject():
    assert_envelope_rejects(
        build_doc(crypto_section={"format": envelope.CRYPTO_MATERIAL_V1_FORMAT}),
        match=r"crypto_material.items is missing",
    )
    assert_envelope_rejects(
        build_doc(device_section={"format": envelope.DEVICE_EVIDENCE_V1_FORMAT, "items": None}),
        match=r"device_evidence.items is missing",
    )


def test_wrong_section_format_rejects():
    assert_envelope_rejects(
        build_doc(crypto_section={"format": "x", "items": []}),
        match="unsupported crypto_material section format",
    )
    assert_envelope_rejects(
        build_doc(device_section={"format": "x", "items": []}),
        match="unsupported device_evidence section format",
    )


def test_duplicate_member_inside_section_rejects():
    crypto_bytes = (
        b'{"format":"' + envelope.CRYPTO_MATERIAL_V1_FORMAT.encode() + b'","format":"x","items":[]}'
    )

    def mutate(d):
        pass

    # Build manually so the endorsed hash matches the malformed section: the
    # strict parse must reject before/independently of hashing.
    import hashlib

    device_bytes = json.dumps(DEVICE_SECTION, separators=(",", ":")).encode()
    ch = hashlib.sha256(crypto_bytes).digest()
    dh = hashlib.sha256(device_bytes).digest()
    rd = envelope.compute_report_data(NONCE, ch, dh)
    doc = {
        "format": envelope.ATTESTATION_V3_FORMAT,
        "challenge": {
            "nonce": NONCE.hex(),
            "report_data": rd.hex(),
            "report_data_algorithm": envelope.REPORT_DATA_V1_ALGORITHM,
        },
        "cpu_evidence": {
            "format": envelope.SEV_SNP_REPORT_V1_FORMAT,
            "report_base64": b64(b"\x00"),
            "endorsed": {"crypto_material_hash": ch.hex(), "device_evidence_hash": dh.hex()},
        },
        "crypto_material": b64(crypto_bytes),
        "device_evidence": b64(device_bytes),
        "collateral": [],
    }
    assert_envelope_rejects(
        json.dumps(doc).encode(), match="duplicate object member"
    )


def _sigstore_entry(id_, fmt, payload=None):
    if payload is None:
        payload = {"repo": "o/r", "tag": "v1", "digest": "ab" * 32, "sigstore_bundle": {"x": 1}}
    return {"id": id_, "role": envelope.ROLE_REFERENCE_VALUES, "format": fmt, "data": payload}


def test_collateral_validation():
    entry = _sigstore_entry("c1", envelope.COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    bad_role = dict(entry, role="whatever")
    assert_envelope_rejects(build_doc(collateral=[bad_role]), match="unknown role")
    assert_envelope_rejects(
        build_doc(collateral=[entry, dict(entry)]), match="duplicate collateral entry id"
    )
    no_id = dict(entry, id="")
    assert_envelope_rejects(build_doc(collateral=[no_id]), match="is incomplete")


def test_reference_values_collateral_lookup():
    e1 = _sigstore_entry("c1", envelope.COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    e2 = _sigstore_entry(
        "c2",
        envelope.COLLATERAL_SIGSTORE_CODE_V1_FORMAT,
        payload={"repo": "other/r", "tag": "", "digest": "", "sigstore_bundle": {}},
    )
    doc, _ = envelope.check(build_doc(collateral=[e1, e2]), NONCE)
    sc = envelope.reference_values_collateral(doc, envelope.COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    assert sc.repo == "o/r" and sc.tag == "v1" and sc.digest == "ab" * 32  # first wins
    assert json.loads(sc.sigstore_bundle) == {"x": 1}

    with pytest.raises(CollateralNotFoundError) as ei:
        envelope.reference_values_collateral(doc, envelope.COLLATERAL_SIGSTORE_PLATFORM_V1_FORMAT)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_reference_values_collateral_bad_payload():
    entry = _sigstore_entry("c1", envelope.COLLATERAL_SIGSTORE_CODE_V1_FORMAT, payload={"nope": 1})
    doc, _ = envelope.check(build_doc(collateral=[entry]), NONCE)
    with pytest.raises(VerificationError) as ei:
        envelope.reference_values_collateral(doc, envelope.COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_freshness_collateral_lookup():
    fresh = {
        "id": envelope.FRESHNESS_COLLATERAL_ID_CODE,
        "role": envelope.ROLE_REFERENCE_VALUES,
        "format": envelope.COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT,
        "data": {"sigstore_bundle": {"y": 2}},
    }
    doc, _ = envelope.check(build_doc(collateral=[fresh]), NONCE)
    bundle = envelope.freshness_collateral(doc, envelope.FRESHNESS_COLLATERAL_ID_CODE)
    assert json.loads(bundle) == {"y": 2}
    with pytest.raises(CollateralNotFoundError):
        envelope.freshness_collateral(doc, envelope.FRESHNESS_COLLATERAL_ID_PLATFORM)


def test_freshness_collateral_duplicate_id_rejects_at_parse():
    fresh = {
        "id": envelope.FRESHNESS_COLLATERAL_ID_CODE,
        "role": envelope.ROLE_REFERENCE_VALUES,
        "format": envelope.COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT,
        "data": {"sigstore_bundle": {}},
    }
    assert_envelope_rejects(
        build_doc(collateral=[fresh, dict(fresh)]), match="duplicate collateral entry id"
    )


def test_endorsement_collateral_lookup():
    entry = {
        "id": "vcek",
        "role": envelope.ROLE_ENDORSEMENT,
        "format": envelope.COLLATERAL_AMD_VCEK_V1_FORMAT,
        "subjects": ["cpu"],
        "data": {"vcek_der_base64": b64(b"\x01"), "cert_chain_pem": "PEM"},
    }
    doc, _ = envelope.check(build_doc(collateral=[entry]), NONCE)
    found = envelope.endorsement_collateral(doc, envelope.COLLATERAL_AMD_VCEK_V1_FORMAT, "cpu")
    assert found is not None and found.id == "vcek"
    assert envelope.endorsement_collateral(doc, envelope.COLLATERAL_AMD_VCEK_V1_FORMAT, "gpu") is None
    vcek = envelope.parse_amd_vcek_collateral(found.data)
    assert vcek.cert_chain_pem == "PEM"


def test_compute_report_data_input_lengths():
    with pytest.raises(ValueError):
        envelope.compute_report_data(b"\x00" * 31, b"\x00" * 32, b"\x00" * 32)


def test_random_nonce():
    n = envelope.random_nonce()
    assert len(n) == envelope.NONCE_SIZE and n != envelope.random_nonce()
