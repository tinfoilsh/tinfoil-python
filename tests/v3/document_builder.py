"""A well-formed v3 document around a dummy quote, so document logic can be tested without hardware.

This is a test-local reimplementation of what production builders do:
serialize the endorsed sections once, hash those bytes, base64-wrap them,
and walk the REPORT_DATA ladder.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from typing import Any

from tinfoil._v3.verifier._document import document as doc
from tinfoil._v3.verifier._document.collateral import collateral, entry

TLS_KEY = bytes([0xAA]) * 32
HPKE_KEY = bytes([0xBB]) * 32


def test_nonce() -> bytes:
    return bytes(range(doc.NONCE_SIZE))


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


def cpu_entry(
    entry_id: str = "cpu-endorsement", format_: str = collateral.AMD_VCEK_V1_FORMAT, data: str | None = None
) -> dict[str, Any]:
    return {
        "id": entry_id,
        "role": entry.ROLE_ENDORSEMENT,
        "format": format_,
        "subjects": [entry.SUBJECT_CPU],
        "data": json.loads(data) if data is not None else {"vcek_der_base64": "", "cert_chain_pem": ""},
    }


def build_raw(
    nonce: bytes,
    *,
    crypto_items: list[dict[str, str]] | None = None,
    device_items: list[dict[str, Any]] | None = None,
    collateral_entries: list[dict[str, Any]] | None = None,
    collateral_format: str | None = None,
    evidence_format: str = doc.SEVSNP_REPORT_V1_FORMAT,
) -> dict[str, Any]:
    """The document as a JSON-ready dict, with every binding consistent."""
    if crypto_items is None:
        crypto_items = [
            {"id": doc.CRYPTO_MATERIAL_ID_TLS, "format": doc.KEY_SPKI_FP_SHA256_V1_FORMAT, "data": TLS_KEY.hex()},
            {"id": doc.CRYPTO_MATERIAL_ID_HPKE, "format": doc.KEY_X25519_HPKE_V1_FORMAT, "data": HPKE_KEY.hex()},
        ]
    crypto_bytes = json.dumps(
        {"format": doc.CRYPTO_MATERIAL_V1_FORMAT, "items": crypto_items}, separators=(",", ":")
    ).encode()
    device_bytes = json.dumps(
        {"format": doc.DEVICE_EVIDENCE_V1_FORMAT, "items": device_items or []}, separators=(",", ":")
    ).encode()
    crypto_hash = hashlib.sha256(crypto_bytes).digest()
    device_hash = hashlib.sha256(device_bytes).digest()
    report_data = doc.compute_report_data(nonce, crypto_hash, device_hash)
    raw: dict[str, Any] = {
        "format": doc.ATTESTATION_V3_FORMAT,
        "challenge": {
            "nonce": nonce.hex(),
            "report_data": report_data.hex(),
            "report_data_algorithm": doc.REPORT_DATA_V1_ALGORITHM,
        },
        "cpu_evidence": {
            "format": evidence_format,
            "report_base64": b64(bytes([0x01]) * 1184),
            "endorsed": {"crypto_material_hash": crypto_hash.hex(), "device_evidence_hash": device_hash.hex()},
        },
        "crypto_material": b64(crypto_bytes),
        "device_evidence": b64(device_bytes),
        "collateral": [cpu_entry()] if collateral_entries is None else collateral_entries,
    }
    if collateral_format is not None:
        raw["collateral_format"] = collateral_format
    return raw


def encode(raw: dict[str, Any]) -> bytes:
    return json.dumps(raw, separators=(",", ":")).encode()


def build(nonce: bytes, **kwargs: Any) -> tuple[dict[str, Any], bytes]:
    raw = build_raw(nonce, **kwargs)
    return raw, encode(raw)


def mutate_section(doc_bytes: bytes, field: str, mutate: Callable[[bytes], bytes]) -> bytes:
    """Decode an endorsed section, apply ``mutate`` to its bytes and re-encode it.

    The endorsed hashes are left as they were, so the result is a document whose section no longer matches its hash.
    """
    loose = json.loads(doc_bytes)
    section = base64.b64decode(loose[field])
    loose[field] = b64(mutate(section))
    return encode(loose)


def mutate_crypto_section(doc_bytes: bytes, mutate: Callable[[bytes], bytes]) -> bytes:
    return mutate_section(doc_bytes, "crypto_material", mutate)
