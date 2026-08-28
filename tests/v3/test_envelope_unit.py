"""Envelope parse/check unit tests mirroring Go verifier/envelope semantics
not already covered by test_envelope.py: strict parse order, canonical
base64, the report_data ladder, and the collateral accessors. Documents come
from docbuilder.build_doc."""

import hashlib
import json

import pytest

from tinfoil.v3 import envelope as env
from tinfoil.v3.errors import (
    ENVELOPE_REJECTED,
    PROVENANCE_REJECTED,
    QUOTE_REJECTED,
    CollateralNotFoundError,
    VerificationError,
)

from docbuilder import NONCE, b64, build_doc


def crypto_section(items: list) -> dict:
    return {"format": env.CRYPTO_MATERIAL_V1_FORMAT, "items": items}


def device_section(items: list) -> dict:
    return {"format": env.DEVICE_EVIDENCE_V1_FORMAT, "items": items}


def swap_crypto_section(raw: bytes):
    """A build_doc mutate() that installs raw crypto_material bytes and
    re-binds the endorsed hash and REPORT_DATA, so only the targeted
    property differs."""

    def mutate(d):
        cmh = hashlib.sha256(raw).digest()
        deh = bytes.fromhex(d["cpu_evidence"]["endorsed"]["device_evidence_hash"])
        d["crypto_material"] = b64(raw)
        d["cpu_evidence"]["endorsed"]["crypto_material_hash"] = cmh.hex()
        d["challenge"]["report_data"] = env.compute_report_data(NONCE, cmh, deh).hex()

    return mutate


def expect_envelope_reject(doc_bytes: bytes, nonce: bytes = NONCE):
    with pytest.raises(VerificationError) as ei:
        env.check(doc_bytes, nonce)
    assert ei.value.layer == ENVELOPE_REJECTED
    return ei.value


# --- happy paths ---------------------------------------------------------------


def test_check_happy_path():
    doc, rd = env.check(build_doc(), NONCE)
    assert len(rd) == 64
    assert rd[32:] == bytes(32)
    assert rd.hex() == doc.challenge.report_data
    # report_data ladder: sha256(label || nonce || cmh || deh)
    expected = hashlib.sha256(
        env.REPORT_DATA_V1_ALGORITHM.encode()
        + NONCE
        + hashlib.sha256(doc.crypto_material_bytes).digest()
        + hashlib.sha256(doc.device_evidence_bytes).digest()
    ).digest()
    assert rd[:32] == expected


def test_parse_retains_exact_section_bytes():
    # Sections hash over the exact decoded bytes: whitespace inside the
    # encoded section must survive (never re-serialize).
    cm = b'{"format":"' + env.CRYPTO_MATERIAL_V1_FORMAT.encode() + b'", "items": []}'
    doc, _ = env.check(build_doc(mutate=swap_crypto_section(cm)), NONCE)
    assert doc.crypto_material_bytes == cm


def test_device_items_and_accessors():
    doc_bytes = build_doc(
        device_section=device_section(
            [
                {
                    "id": "gpu0",
                    "kind": "gpu",
                    "vendor": "nvidia",
                    "format": env.NVIDIA_GPU_EVIDENCE_V1_FORMAT,
                    "evidence": {"n": 1},
                }
            ]
        )
    )
    doc, _ = env.check(doc_bytes, NONCE)
    items = env.device_evidence_items(doc)
    assert len(items) == 1 and items[0].id == "gpu0"
    assert items[0].evidence == b'{"n":1}'  # exact raw source (compact doc)
    assert env.crypto_material_item(doc, "tls").data == "11" * 32
    assert env.crypto_material_item(doc, "nope") is None
    assert [i.id for i in env.crypto_material_items(doc)] == ["tls", "hpke"]


# --- strict document parse -------------------------------------------------------


def test_unknown_document_member_rejects():
    expect_envelope_reject(build_doc(mutate=lambda d: d.update(extra=1)))


def test_duplicate_document_member_rejects():
    good = build_doc()
    dup = good.replace(b'{"format":', b'{"format":"x","format":', 1)
    expect_envelope_reject(dup)


def test_trailing_data_rejects():
    expect_envelope_reject(build_doc() + b" {}")


def test_document_invalid_utf8_rejects():
    expect_envelope_reject(b'{"format":"\xff"}')


def test_unsupported_format_rejects():
    expect_envelope_reject(
        build_doc(mutate=lambda d: d.update(format="https://example.com/v9"))
    )


def test_unsupported_report_data_algorithm_rejects():
    def mut(d):
        d["challenge"]["report_data_algorithm"] = "https://tinfoil.sh/report-data/v2"

    expect_envelope_reject(build_doc(mutate=mut))


def test_wrong_length_report_data_rejects():
    def mut(d):
        d["challenge"]["report_data"] = "ab" * 63

    expect_envelope_reject(build_doc(mutate=mut))


# --- canonical base64 --------------------------------------------------------------


def test_non_canonical_base64_rejects():
    # "AB==" decodes to b"\x00" under a lenient decoder (non-zero padding
    # bits) but the canonical encoding of b"\x00" is "AA==": exactly one
    # accepted encoding per byte string.
    e = expect_envelope_reject(
        build_doc(mutate=lambda d: d.update(crypto_material="AB=="))
    )
    assert "canonical" in str(e)


def test_unpadded_base64_rejects():
    expect_envelope_reject(build_doc(mutate=lambda d: d.update(crypto_material="AA")))


def test_base64_with_newline_rejects():
    def mut(d):
        d["device_evidence"] = d["device_evidence"][:4] + "\n" + d["device_evidence"][4:]

    expect_envelope_reject(build_doc(mutate=mut))


# --- endorsed sections ---------------------------------------------------------------


def test_unknown_key_format_odd_or_empty_hex_rejects():
    fmt = "https://example.com/key/v1"
    for data in ("", "abc", "AA"):
        section = crypto_section([{"id": "k", "format": fmt, "data": data}])
        expect_envelope_reject(build_doc(crypto_section=section))
    # even-length lowercase hex of any size is fine for unknown formats
    doc, _ = env.check(
        build_doc(crypto_section=crypto_section([{"id": "k", "format": fmt, "data": "abcd"}])),
        NONCE,
    )
    assert env.crypto_material_item(doc, "k").data == "abcd"


def test_incomplete_crypto_item_rejects():
    section = crypto_section([{"id": "", "format": "f", "data": "aa"}])
    expect_envelope_reject(build_doc(crypto_section=section))


def test_duplicate_device_item_id_rejects():
    section = device_section(
        [
            {"id": "d", "kind": "", "vendor": "", "format": "f", "evidence": None},
            {"id": "d", "kind": "", "vendor": "", "format": "f", "evidence": None},
        ]
    )
    expect_envelope_reject(build_doc(device_section=section))


def test_missing_items_member_rejects():
    cm = json.dumps({"format": env.CRYPTO_MATERIAL_V1_FORMAT}).encode()
    expect_envelope_reject(build_doc(mutate=swap_crypto_section(cm)))


# --- challenge bindings ----------------------------------------------------------------


def test_bad_expected_nonce_size_rejects():
    with pytest.raises(VerificationError) as ei:
        env.check(build_doc(), b"\x00" * 31)
    assert ei.value.layer == ENVELOPE_REJECTED


def test_tampered_crypto_material_hash_rejects():
    def mut(d):
        d["cpu_evidence"]["endorsed"]["crypto_material_hash"] = "00" * 32

    e = expect_envelope_reject(build_doc(mutate=mut))
    assert "crypto_material hash" in str(e)


def test_tampered_device_evidence_hash_rejects():
    def mut(d):
        d["cpu_evidence"]["endorsed"]["device_evidence_hash"] = "00" * 32

    expect_envelope_reject(build_doc(mutate=mut))


def test_compute_report_data_input_sizes():
    with pytest.raises(ValueError):
        env.compute_report_data(b"\x00" * 31, b"\x00" * 32, b"\x00" * 32)


# --- collateral -----------------------------------------------------------------------


def sig_entry(id_, fmt, bundle=None):
    return {
        "id": id_,
        "role": env.ROLE_REFERENCE_VALUES,
        "format": fmt,
        "data": {
            "repo": "tinfoilsh/app",
            "tag": "v1.0.0",
            "digest": "ee" * 32,
            "sigstore_bundle": bundle if bundle is not None else {"v": 1},
        },
    }


def test_collateral_role_and_id_rules():
    bad_role = [{"id": "x", "role": "verifier", "format": "f", "data": None}]
    e = expect_envelope_reject(build_doc(collateral=bad_role))
    assert "unknown role" in str(e)

    dup_ids = [
        {"id": "x", "role": env.ROLE_ENDORSEMENT, "format": "f", "data": None},
        {"id": "x", "role": env.ROLE_ENDORSEMENT, "format": "g", "data": None},
    ]
    e = expect_envelope_reject(build_doc(collateral=dup_ids))
    assert "duplicate collateral entry id" in str(e)

    incomplete = [{"id": "", "role": env.ROLE_ENDORSEMENT, "format": "f"}]
    e = expect_envelope_reject(build_doc(collateral=incomplete))
    assert "incomplete" in str(e)


def test_reference_values_collateral_first_wins():
    doc_bytes = build_doc(
        collateral=[
            sig_entry("code-2", env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT, {"n": 1}),
            sig_entry("code-1", env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT, {"n": 2}),
        ]
    )
    doc, _ = env.check(doc_bytes, NONCE)
    sc = env.reference_values_collateral(doc, env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    assert sc.repo == "tinfoilsh/app" and sc.tag == "v1.0.0" and sc.digest == "ee" * 32
    assert sc.sigstore_bundle == b'{"n":1}'


def test_reference_values_collateral_not_found():
    doc, _ = env.check(build_doc(), NONCE)
    with pytest.raises(CollateralNotFoundError) as ei:
        env.reference_values_collateral(doc, env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_reference_values_collateral_strict_data_parse():
    entry = sig_entry("code", env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    entry["data"]["unknown"] = True
    doc, _ = env.check(build_doc(collateral=[entry]), NONCE)
    with pytest.raises(VerificationError) as ei:
        env.reference_values_collateral(doc, env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_freshness_collateral_lookup_and_duplicate_rejection():
    fresh = {
        "id": env.FRESHNESS_COLLATERAL_ID_CODE,
        "role": env.ROLE_REFERENCE_VALUES,
        "format": env.COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT,
        "data": {"sigstore_bundle": {"w": 1}},
    }
    doc, _ = env.check(build_doc(collateral=[fresh]), NONCE)
    assert env.freshness_collateral(doc, env.FRESHNESS_COLLATERAL_ID_CODE) == b'{"w":1}'

    with pytest.raises(CollateralNotFoundError):
        env.freshness_collateral(doc, env.FRESHNESS_COLLATERAL_ID_PLATFORM)

    # Two same-format freshness entries under different ids are legal at
    # parse; looking up an id present twice is impossible (ids are unique),
    # so duplicate rejection is exercised via a same-id pair, which already
    # rejects at parse — assert that.
    dup = [dict(fresh), dict(fresh)]
    expect_envelope_reject(build_doc(collateral=dup))


def test_endorsement_collateral_subject_match():
    entries = [
        {
            "id": "vcek",
            "role": env.ROLE_ENDORSEMENT,
            "format": env.COLLATERAL_AMD_VCEK_V1_FORMAT,
            "subjects": ["cpu"],
            "data": {"vcek_der_base64": "QQ==", "cert_chain_pem": "PEM"},
        },
        {
            "id": "crl",
            "role": env.ROLE_ENDORSEMENT,
            "format": env.COLLATERAL_AMD_CRL_V1_FORMAT,
            "subjects": ["cpu"],
            "data": {"crl_der_base64": "QUI="},
        },
    ]
    doc, _ = env.check(build_doc(collateral=entries), NONCE)
    entry = env.endorsement_collateral(
        doc, env.COLLATERAL_AMD_VCEK_V1_FORMAT, env.SUBJECT_CPU
    )
    assert entry is not None and entry.id == "vcek"
    assert (
        env.endorsement_collateral(doc, env.COLLATERAL_AMD_VCEK_V1_FORMAT, "gpu")
        is None
    )

    vcek = env.parse_amd_vcek_collateral(entry.data)
    assert vcek.vcek_der_base64 == "QQ==" and vcek.cert_chain_pem == "PEM"
    crl_entry = env.endorsement_collateral(
        doc, env.COLLATERAL_AMD_CRL_V1_FORMAT, env.SUBJECT_CPU
    )
    assert env.parse_amd_crl_collateral(crl_entry.data).crl_der_base64 == "QUI="


def test_typed_collateral_parsers_reject_with_quote_layer():
    with pytest.raises(VerificationError) as ei:
        env.parse_amd_vcek_collateral(b'{"vcek_der_base64":"QQ==","extra":1}')
    assert ei.value.layer == QUOTE_REJECTED
    with pytest.raises(VerificationError) as ei:
        env.parse_amd_crl_collateral(None)
    assert ei.value.layer == QUOTE_REJECTED


def test_parse_intel_pcs_collateral():
    data = json.dumps(
        {
            "responses": [
                {
                    "url": "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00806f050000",
                    "headers": {"TCB-Info-Issuer-Chain": ["a", "b"]},
                    "body_base64": "e30=",
                }
            ]
        }
    ).encode()
    pcs = env.parse_intel_pcs_collateral(data)
    assert len(pcs.responses) == 1
    assert pcs.responses[0].headers == {"TCB-Info-Issuer-Chain": ["a", "b"]}
    assert pcs.responses[0].body_base64 == "e30="
    assert env.parse_intel_pcs_collateral(b"{}").responses is None


def test_random_nonce_size():
    n1, n2 = env.random_nonce(), env.random_nonce()
    assert len(n1) == env.NONCE_SIZE and n1 != n2
