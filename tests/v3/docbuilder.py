"""Synthetic v3 document builder for envelope-layer tests: assembles a
structurally valid document around a given nonce, computing the endorsed
hashes and REPORT_DATA the way a real builder does."""

import base64
import hashlib
import json

from tinfoil.v3 import envelope

NONCE = bytes(range(32))

CRYPTO_SECTION = {
    "format": envelope.CRYPTO_MATERIAL_V1_FORMAT,
    "items": [
        {"id": "tls", "format": envelope.KEY_SPKI_FP_SHA256_V1_FORMAT, "data": "11" * 32},
        {"id": "hpke", "format": envelope.KEY_X25519_HPKE_V1_FORMAT, "data": "22" * 32},
    ],
}

DEVICE_SECTION = {"format": envelope.DEVICE_EVIDENCE_V1_FORMAT, "items": []}


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def build_doc(
    nonce: bytes = NONCE,
    crypto_section=CRYPTO_SECTION,
    device_section=DEVICE_SECTION,
    collateral=None,
    mutate=None,
) -> bytes:
    """Serialize a consistent v3 document; `mutate(doc_dict)` may then break
    it after the hashes were computed."""
    crypto_bytes = json.dumps(crypto_section, separators=(",", ":")).encode()
    device_bytes = json.dumps(device_section, separators=(",", ":")).encode()
    crypto_hash = hashlib.sha256(crypto_bytes).digest()
    device_hash = hashlib.sha256(device_bytes).digest()
    report_data = envelope.compute_report_data(nonce, crypto_hash, device_hash)
    doc = {
        "format": envelope.ATTESTATION_V3_FORMAT,
        "challenge": {
            "nonce": nonce.hex(),
            "report_data": report_data.hex(),
            "report_data_algorithm": envelope.REPORT_DATA_V1_ALGORITHM,
        },
        "cpu_evidence": {
            "format": envelope.SEV_SNP_REPORT_V1_FORMAT,
            "report_base64": b64(b"\x00" * 16),
            "endorsed": {
                "crypto_material_hash": crypto_hash.hex(),
                "device_evidence_hash": device_hash.hex(),
            },
        },
        "crypto_material": b64(crypto_bytes),
        "device_evidence": b64(device_bytes),
        "collateral": collateral if collateral is not None else [],
    }
    if mutate is not None:
        mutate(doc)
    return json.dumps(doc, separators=(",", ":")).encode()
