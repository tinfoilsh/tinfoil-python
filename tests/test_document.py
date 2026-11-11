"""Strict document parsing and the challenge bindings."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tests import document_builder as builder
from tinfoil.verifier._document import document as doc
from tinfoil.verifier._document.collateral import collateral, entry
from tinfoil.verifier._document.collateral.collateral import NotFoundError
from tinfoil.verifier._json import JsonObject


def test_build_and_verify() -> None:
    nonce = builder.test_nonce()
    raw, doc_bytes = builder.build(nonce)

    parsed = doc.parse(doc_bytes, nonce)
    report_data = parsed.expected_report_data()
    assert report_data is not None
    assert report_data.hex() == raw["challenge"]["report_data"]

    items = parsed.crypto_material_items()
    assert len(items) == 2
    assert items[0].id == doc.CRYPTO_MATERIAL_ID_TLS
    tls = parsed.crypto_material_item(doc.CRYPTO_MATERIAL_ID_TLS)
    assert tls is not None
    assert tls.format == doc.KEY_SPKI_FP_SHA256_V1_FORMAT
    assert tls == items[0]
    assert parsed.crypto_material_item("missing") is None
    assert parsed.device_evidence_items() == ()
    assert parsed.cpu_evidence() == doc.CpuEvidence(format=doc.SEVSNP_REPORT_V1_FORMAT, report=bytes([0x01]) * 1184)
    assert parsed.collateral_format() == collateral.FORMAT_V2


def test_expected_report_data_requires_parse() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    unbound = doc.decode_unbound(doc_bytes)
    assert unbound.expected_report_data() is None, "a document that was not bound has no expected REPORT_DATA"
    assert doc.parse(doc_bytes, nonce).expected_report_data() is not None


def test_nonce_mismatch() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    other = bytearray(nonce)
    other[0] ^= 0xFF
    with pytest.raises(doc.DocumentError, match="challenge nonce does not match the expected nonce"):
        doc.parse(doc_bytes, bytes(other))


def test_parse_rejects_wrong_nonce_length() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    for bad in (b"", nonce[:-1], nonce + b"\x00"):
        with pytest.raises(doc.InvalidInputError):
            doc.parse(doc_bytes, bad)


def test_tampered_device_evidence() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    tampered = builder.mutate_section(doc_bytes, "device_evidence", lambda s: s.replace(b'{"format"', b'{ "format"', 1))
    assert tampered != doc_bytes
    with pytest.raises(doc.DocumentError, match="device_evidence hash does not match"):
        doc.parse(tampered, nonce)


def test_report_data_mismatch() -> None:
    """Only challenge.report_data changes.

    Both section hashes still match, so the REPORT_DATA recomputation is what must reject.
    """
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    raw["challenge"]["report_data"] = (bytes([0x11]) * 64).hex()
    with pytest.raises(doc.DocumentError, match="challenge report_data does not match the recomputed value"):
        doc.parse(builder.encode(raw), nonce)


def test_transported_bytes_are_what_is_hashed() -> None:
    """Any change to the decoded section, even JSON-equivalent whitespace, breaks the hash binding."""
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    tampered = builder.mutate_crypto_section(doc_bytes, lambda s: s.replace(b'{"format"', b'{ "format"', 1))
    assert tampered != doc_bytes
    with pytest.raises(doc.DocumentError, match="crypto_material hash"):
        doc.parse(tampered, nonce)


def test_tampered_key() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    tampered = builder.mutate_crypto_section(
        doc_bytes, lambda s: s.replace(builder.TLS_KEY.hex().encode(), (bytes([0xAC]) * 32).hex().encode(), 1)
    )
    assert tampered != doc_bytes
    with pytest.raises(doc.DocumentError, match="crypto_material hash"):
        doc.parse(tampered, nonce)


def test_rejects_unknown_top_level_members() -> None:
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    raw["generated_at"] = "2026-01-01T00:00:00Z"
    with pytest.raises(doc.DocumentError, match="unknown object member name"):
        doc.parse(builder.encode(raw), nonce)


def test_rejects_unknown_algorithm() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    tampered = doc_bytes.replace(doc.REPORT_DATA_V1_ALGORITHM.encode(), b"https://tinfoil.sh/report-data/v2", 1)
    with pytest.raises(doc.DocumentError, match="report_data_algorithm"):
        doc.parse(tampered, nonce)


def test_rejects_unknown_document_format() -> None:
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    raw["format"] = "https://tinfoil.sh/predicate/attestation/v2"
    with pytest.raises(doc.DocumentError, match="unsupported document format"):
        doc.parse(builder.encode(raw), nonce)


def test_rejects_duplicate_item_ids() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    filler = (bytes([0xCC]) * 32).hex()
    duplicated = builder.mutate_crypto_section(
        doc_bytes,
        lambda s: s.replace(
            b'"items":[{"id":"tls"',
            b'"items":[{"id":"tls","format":"'
            + doc.KEY_SPKI_FP_SHA256_V1_FORMAT.encode()
            + b'","data":"'
            + filler.encode()
            + b'"},{"id":"tls"',
            1,
        ),
    )
    assert duplicated != doc_bytes
    with pytest.raises(doc.DocumentError, match="duplicate crypto_material item id 'tls'"):
        doc.parse(duplicated, nonce)


def test_rejects_malformed_key_material() -> None:
    """Known key formats must carry exactly 32 bytes of lowercase hex.

    A truncated TLS fingerprint rejects at parse time.
    """
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)
    short = builder.mutate_crypto_section(
        doc_bytes, lambda s: s.replace(builder.TLS_KEY.hex().encode(), (bytes([0xAA]) * 8).hex().encode(), 1)
    )
    assert short != doc_bytes
    with pytest.raises(doc.DocumentError, match="must be 32 bytes"):
        doc.parse(short, nonce)


def test_rejects_uppercase_hex() -> None:
    nonce = builder.test_nonce()
    raw, doc_bytes = builder.build(nonce)
    upper = doc_bytes.replace(raw["challenge"]["nonce"].encode(), raw["challenge"]["nonce"].upper().encode(), 1)
    with pytest.raises(doc.DocumentError, match="lowercase hex"):
        doc.parse(upper, nonce)


def test_rejects_non_canonical_base64() -> None:
    """A newline inside the crypto_material base64 leaves the decoded bytes, and so the endorsed hash, unchanged.

    Accepting it would mean two distinct documents with identical endorsed content.
    """
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    encoded = raw["crypto_material"]
    raw["crypto_material"] = encoded[:8] + "\n" + encoded[8:]
    with pytest.raises(doc.DocumentError, match="crypto_material is not canonical base64"):
        doc.parse(builder.encode(raw), nonce)


@pytest.mark.parametrize(
    "variant",
    [
        lambda e: e[:8] + "\n" + e[8:],  # embedded newline
        lambda e: e + "\r\n",  # trailing CRLF
        lambda e: e.removesuffix("AQE=") + "AQF=",  # non-zero padding bits
    ],
    ids=["embedded newline", "trailing CRLF", "nonzero padding bits"],
)
def test_rejects_non_canonical_report_base64(variant: Any) -> None:
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    encoded = raw["cpu_evidence"]["report_base64"]
    assert encoded.endswith("AQE=")
    # Each variant decodes to the same report bytes as the original.
    raw["cpu_evidence"]["report_base64"] = variant(encoded)
    with pytest.raises(doc.DocumentError, match=r"cpu_evidence\.report_base64"):
        doc.parse(builder.encode(raw), nonce)


def test_rejects_odd_length_unknown_format_data() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce)

    def insert(item: bytes) -> bytes:
        return builder.mutate_crypto_section(
            doc_bytes, lambda s: s.replace(b'"items":[', b'"items":[' + item + b",", 1)
        )

    # "abc" matches the lowercase-hex character class but is not decodable.
    with pytest.raises(doc.DocumentError, match="crypto_material item 'x' data is not lowercase hex"):
        doc.parse(insert(b'{"id":"x","format":"https://example.com/key/v9","data":"abc"}'), nonce)
    with pytest.raises(doc.DocumentError, match="crypto_material item 'x' data is empty"):
        doc.parse(insert(b'{"id":"x","format":"https://example.com/key/v9","data":""}'), nonce)


def test_incomplete_crypto_item_and_missing_items() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(nonce, crypto_items=[{"id": "", "format": "f", "data": "ab"}])
    with pytest.raises(doc.DocumentError, match="crypto_material item is incomplete"):
        doc.parse(doc_bytes, nonce)
    _, doc_bytes = builder.build(nonce)
    missing = builder.mutate_crypto_section(
        doc_bytes, lambda s: json.dumps({"format": doc.CRYPTO_MATERIAL_V1_FORMAT}).encode()
    )
    with pytest.raises(doc.DocumentError, match=r"crypto_material\.items is missing"):
        doc.parse(missing, nonce)
    wrong_format = builder.mutate_crypto_section(
        doc_bytes,
        lambda s: s.replace(doc.CRYPTO_MATERIAL_V1_FORMAT.encode(), b"https://tinfoil.sh/crypto-material/v2", 1),
    )
    with pytest.raises(doc.DocumentError, match="unsupported crypto_material section format"):
        doc.parse(wrong_format, nonce)
    unknown_member = builder.mutate_crypto_section(
        doc_bytes, lambda s: s.replace(b'{"format"', b'{"extra":1,"format"', 1)
    )
    with pytest.raises(doc.DocumentError, match="parsing crypto_material"):
        doc.parse(unknown_member, nonce)


def test_device_evidence_items() -> None:
    nonce = builder.test_nonce()
    item = {
        "id": "gpu0",
        "kind": "gpu",
        "vendor": "nvidia",
        "format": doc.NVIDIA_GPU_EVIDENCE_V1_FORMAT,
        "evidence": {"nonce": "original"},
    }
    _, doc_bytes = builder.build(nonce, device_items=[item])
    parsed = doc.parse(doc_bytes, nonce)
    items = parsed.device_evidence_items()
    assert len(items) == 1
    assert items[0].id == "gpu0"
    assert items[0].kind == "gpu"
    assert items[0].vendor == "nvidia"
    assert isinstance(items[0].evidence, JsonObject)
    assert items[0].evidence["nonce"] == "original"

    _, doc_bytes = builder.build(nonce, device_items=[item, item])
    with pytest.raises(doc.DocumentError, match="duplicate device_evidence item id 'gpu0'"):
        doc.parse(doc_bytes, nonce)
    _, doc_bytes = builder.build(nonce, device_items=[{**item, "id": ""}])
    with pytest.raises(doc.DocumentError, match="device_evidence item has no id"):
        doc.parse(doc_bytes, nonce)
    _, doc_bytes = builder.build(nonce)
    missing = builder.mutate_section(
        doc_bytes, "device_evidence", lambda s: json.dumps({"format": doc.DEVICE_EVIDENCE_V1_FORMAT}).encode()
    )
    with pytest.raises(doc.DocumentError, match=r"device_evidence\.items is missing"):
        doc.parse(missing, nonce)


def test_missing_sections_and_incomplete_evidence() -> None:
    nonce = builder.test_nonce()
    for field in ("crypto_material", "device_evidence"):
        raw, _ = builder.build(nonce)
        del raw[field]
        with pytest.raises(doc.DocumentError, match=f"{field} section is missing"):
            doc.parse(builder.encode(raw), nonce)
    raw, _ = builder.build(nonce)
    raw["cpu_evidence"]["report_base64"] = ""
    with pytest.raises(doc.DocumentError, match="cpu_evidence is incomplete"):
        doc.parse(builder.encode(raw), nonce)
    raw, _ = builder.build(nonce)
    del raw["cpu_evidence"]
    with pytest.raises(doc.DocumentError, match="crypto_material_hash"):
        doc.parse(builder.encode(raw), nonce)


def test_rejects_wrong_member_types() -> None:
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    raw["challenge"]["nonce"] = 1
    with pytest.raises(doc.DocumentError, match="cannot unmarshal JSON number into string"):
        doc.parse(builder.encode(raw), nonce)
    raw, _ = builder.build(nonce)
    raw["collateral"] = {}
    with pytest.raises(doc.DocumentError, match="parsing attestation document"):
        doc.parse(builder.encode(raw), nonce)
    with pytest.raises(doc.DocumentError, match="parsing attestation document"):
        doc.parse(b"[]", nonce)
    with pytest.raises(doc.DocumentError, match="parsing attestation document"):
        doc.parse(b'{"format":1,"format":2}', nonce)
    with pytest.raises(doc.DocumentError, match="parsing attestation document"):
        doc.parse(b"", nonce)


def test_rejects_duplicate_collateral_ids() -> None:
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    raw["collateral"].append(
        {
            "id": raw["collateral"][0]["id"],
            "role": entry.ROLE_REFERENCE_VALUES,
            "format": collateral.SIGSTORE_CODE_V1_FORMAT,
            "data": {},
        }
    )
    with pytest.raises(doc.DocumentError, match="duplicate collateral entry id 'cpu-endorsement'"):
        doc.parse(builder.encode(raw), nonce)


def test_rejects_duplicate_freshness_artifact_id() -> None:
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    witness = {
        "id": collateral.FRESHNESS_ID_CODE,
        "role": entry.ROLE_REFERENCE_VALUES,
        "format": collateral.SIGSTORE_FRESHNESS_V1_FORMAT,
        "data": {"sigstore_bundle": {}},
    }
    raw["collateral"] += [witness, witness]
    with pytest.raises(doc.DocumentError, match=f"duplicate collateral entry id '{collateral.FRESHNESS_ID_CODE}'"):
        doc.parse(builder.encode(raw), nonce)


def ref_entry(format_: str, repo: str, entry_id: str | None = None) -> dict[str, Any]:
    return {
        "id": entry_id or format_,
        "role": entry.ROLE_REFERENCE_VALUES,
        "format": format_,
        "data": {"repo": repo, "tag": "v1", "digest": "ab" * 32, "sigstore_bundle": {"mediaType": repo}},
    }


def test_freshness_selects_artifact_id() -> None:
    nonce = builder.test_nonce()

    def witness(id_: str, media: str) -> dict[str, Any]:
        return {
            "id": id_,
            "role": entry.ROLE_REFERENCE_VALUES,
            "format": collateral.SIGSTORE_FRESHNESS_V1_FORMAT,
            "data": {"sigstore_bundle": {"mediaType": media}},
        }

    _, doc_bytes = builder.build(
        nonce,
        collateral_entries=[
            witness(collateral.FRESHNESS_ID_CODE, "code"),
            witness(collateral.FRESHNESS_ID_PLATFORM, "platform"),
        ],
    )
    parsed = doc.parse(doc_bytes, nonce)
    code = parsed.freshness(collateral.FRESHNESS_ID_CODE)
    assert isinstance(code.bundle, JsonObject)
    assert code.bundle["mediaType"] == "code"
    platform = parsed.freshness(collateral.FRESHNESS_ID_PLATFORM)
    assert isinstance(platform.bundle, JsonObject)
    assert platform.bundle["mediaType"] == "platform"
    for witness_id in ("", "missing-freshness"):
        with pytest.raises(NotFoundError):
            parsed.freshness(witness_id)


def test_sigstore_references() -> None:
    nonce = builder.test_nonce()
    _, doc_bytes = builder.build(
        nonce,
        collateral_entries=[
            ref_entry(collateral.SIGSTORE_CODE_V1_FORMAT, "org/code"),
            ref_entry(collateral.SIGSTORE_PLATFORM_V1_FORMAT, "org/platform"),
        ],
    )
    parsed = doc.parse(doc_bytes, nonce)
    code = parsed.sigstore_code()
    assert code.repo == "org/code"
    assert code.tag == "v1"
    assert code.digest == "ab" * 32
    assert isinstance(code.bundle, JsonObject)
    assert code.bundle["mediaType"] == "org/code"
    assert parsed.sigstore_platform().repo == "org/platform"

    _, empty_bytes = builder.build(nonce, collateral_entries=[])
    empty = doc.parse(empty_bytes, nonce)
    with pytest.raises(NotFoundError):
        empty.sigstore_code()
    with pytest.raises(NotFoundError):
        empty.sigstore_platform()
    with pytest.raises(NotFoundError):
        empty.config_endorsement()
    with pytest.raises(NotFoundError):
        empty.runtime()
    with pytest.raises(NotFoundError):
        empty.config_platform()

    malformed = ref_entry(collateral.SIGSTORE_CODE_V1_FORMAT, "org/code")
    malformed["data"] = {"repo": "org/code", "unknown": 1}
    _, malformed_bytes = builder.build(nonce, collateral_entries=[malformed])
    with pytest.raises(doc.DocumentError, match=f"parsing {collateral.SIGSTORE_CODE_V1_FORMAT} collateral entry"):
        doc.parse(malformed_bytes, nonce)


def test_cpu_endorsements_select_the_evidence_platform() -> None:
    nonce = builder.test_nonce()
    entries = [
        builder.cpu_entry(
            "vcek",
            collateral.AMD_VCEK_V1_FORMAT,
            json.dumps({"vcek_der_base64": builder.b64(b"vcek der"), "cert_chain_pem": "chain"}),
        ),
        builder.cpu_entry("crl", collateral.AMD_CRL_V1_FORMAT, json.dumps({"crl_der_base64": builder.b64(b"crl der")})),
        builder.cpu_entry(
            "pcs",
            collateral.INTEL_PCS_V1_FORMAT,
            json.dumps(
                {"responses": [{"url": "https://pcs.example", "headers": {}, "body_base64": builder.b64(b"body")}]}
            ),
        ),
    ]
    sev = doc.parse(*builder.build(nonce, collateral_entries=entries)[1:], nonce).cpu_endorsements()
    assert sev.amd_vcek is not None
    assert sev.amd_vcek.vcek_der == b"vcek der"
    assert sev.amd_vcek.cert_chain_pem == "chain"
    assert sev.amd_crl is not None
    assert sev.amd_crl.crl_der == b"crl der"
    assert sev.intel_pcs is None

    tdx = doc.parse(
        builder.build(nonce, collateral_entries=entries, evidence_format=doc.TDX_QUOTE_V1_FORMAT)[1], nonce
    ).cpu_endorsements()
    assert tdx.amd_vcek is None
    assert tdx.amd_crl is None
    assert tdx.intel_pcs is not None
    assert len(tdx.intel_pcs.responses) == 1
    assert tdx.intel_pcs.responses[0].url == "https://pcs.example"
    assert dict(tdx.intel_pcs.responses[0].headers) == {}
    assert tdx.intel_pcs.responses[0].body == b"body"

    unknown = doc.parse(
        builder.build(nonce, collateral_entries=entries, evidence_format="https://example.com/format/unknown")[1], nonce
    )
    assert unknown.cpu_endorsements() == collateral.CPUEndorsements()

    for evidence_format in (doc.SEVSNP_REPORT_V1_FORMAT, doc.TDX_QUOTE_V1_FORMAT):
        bare = doc.parse(builder.build(nonce, collateral_entries=[], evidence_format=evidence_format)[1], nonce)
        assert bare.cpu_endorsements() == collateral.CPUEndorsements(), "absence is for authentication to reject"


def test_collateral_format_round_trip() -> None:
    nonce = builder.test_nonce()
    for format_ in (None, collateral.FORMAT_V2, collateral.FORMAT_V3):
        _, doc_bytes = builder.build(nonce, collateral_format=format_)
        parsed = doc.parse(doc_bytes, nonce)
        assert parsed.collateral_format() == (format_ or collateral.FORMAT_V2)


def test_rejects_incompatible_collateral_format() -> None:
    nonce = builder.test_nonce()
    legacy = {
        "id": "code",
        "role": entry.ROLE_REFERENCE_VALUES,
        "format": collateral.SIGSTORE_CODE_V1_FORMAT,
        "data": {"digest": "digest", "sigstore_bundle": {}},
    }
    config = {
        "id": "tinfoil-config",
        "role": entry.ROLE_REFERENCE_VALUES,
        "format": "https://tinfoil.sh/collateral/config-endorsement/v1",
        "data": {"endorsement_ref": "sha256:" + "aa" * 32, "config_base64": "eA==", "sigstore_bundle": {}},
    }
    sigstore_witness = {
        "id": collateral.FRESHNESS_ID_CODE,
        "role": entry.ROLE_REFERENCE_VALUES,
        "format": collateral.SIGSTORE_FRESHNESS_V1_FORMAT,
        "data": {"sigstore_bundle": {}},
    }
    artifact_witness = {
        **sigstore_witness,
        "id": collateral.FRESHNESS_ID_PLATFORM,
        "format": collateral.ARTIFACT_FRESHNESS_V1_FORMAT,
    }
    cases: list[tuple[str | None, list[dict[str, Any]], str]] = [
        ("unknown", [], "unsupported collateral format"),
        (collateral.FORMAT_V3, [legacy], "legacy code collateral"),
        (None, [config], "config and runtime collateral require"),
        (collateral.FORMAT_V2, [config], "config and runtime collateral require"),
        (collateral.FORMAT_V3, [sigstore_witness], "freshness collateral is incompatible"),
        (None, [artifact_witness], "freshness collateral is incompatible"),
    ]
    for format_, entries, message in cases:
        _, doc_bytes = builder.build(nonce, collateral_format=format_, collateral_entries=entries)
        with pytest.raises(doc.DocumentError, match=message):
            doc.parse(doc_bytes, nonce)
    # The same entries parse under the format that they belong to.
    doc.parse(
        builder.build(nonce, collateral_format=collateral.FORMAT_V3, collateral_entries=[config, artifact_witness])[1],
        nonce,
    )
    doc.parse(builder.build(nonce, collateral_entries=[legacy, sigstore_witness])[1], nonce)


def test_compute_report_data() -> None:
    nonce = builder.test_nonce()
    cm_hash = hashlib.sha256(b"crypto").digest()
    de_hash = hashlib.sha256(b"device").digest()
    got = doc.compute_report_data(nonce, cm_hash, de_hash)
    digest = hashlib.sha256()
    digest.update(doc.REPORT_DATA_V1_ALGORITHM.encode())
    digest.update(nonce)
    digest.update(cm_hash)
    digest.update(de_hash)
    assert got == digest.digest() + bytes(32)
    with pytest.raises(ValueError, match="32 bytes each"):
        doc.compute_report_data(nonce[:16], cm_hash, de_hash)


def test_random_nonce() -> None:
    a, b = doc.random_nonce(), doc.random_nonce()
    assert len(a) == doc.NONCE_SIZE
    assert a != b


def test_round_trip_preserves_endorsed_bytes() -> None:
    """The document carries the exact endorsed bytes that were hashed at build time.

    They are recoverable with a plain base64 decode.
    """
    nonce = builder.test_nonce()
    raw, _ = builder.build(nonce)
    cm_hash = hashlib.sha256(base64.b64decode(raw["crypto_material"])).hexdigest()
    assert cm_hash == raw["cpu_evidence"]["endorsed"]["crypto_material_hash"]
    de_hash = hashlib.sha256(base64.b64decode(raw["device_evidence"])).hexdigest()
    assert de_hash == raw["cpu_evidence"]["endorsed"]["device_evidence_hash"]


def test_attested_key_envelope_vectors() -> None:
    """Public-only vectors shared across SDKs.

    Parsing must accept and preserve key formats that the SDK does not interpret.
    """
    vectors = json.loads((Path(__file__).parent / "testdata" / "attested-keys-vectors.json").read_text())
    assert len(vectors) == 3
    for vector in vectors:
        nonce = bytes.fromhex(vector["nonce"])
        raw, _ = builder.build(nonce)
        raw["crypto_material"] = vector["crypto_material"]
        raw["device_evidence"] = vector["device_evidence"]
        raw["cpu_evidence"]["endorsed"] = {
            "crypto_material_hash": vector["crypto_material_hash"],
            "device_evidence_hash": vector["device_evidence_hash"],
        }
        raw["challenge"]["report_data"] = vector["report_data"]
        parsed = doc.parse(builder.encode(raw), nonce)
        assert vector["item"]["format"] == doc.KEY_SPKI_V1_FORMAT
        assert parsed.crypto_material_items() == (doc.CryptoMaterialItem(**vector["item"]),), vector["algorithm"]
