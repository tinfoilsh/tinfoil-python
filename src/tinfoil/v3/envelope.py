"""The v3 attestation document wire format and its strict parsing and
challenge verification (Go: verifier/envelope). Verifying the envelope
authenticates nothing by itself: the CPU quote must prove the hardware bound
the recomputed REPORT_DATA before any part of the document is trusted.

The document is flat: a challenge, CPU evidence, two endorsed sections
(crypto_material, device_evidence), and an array of collateral entries. The
endorsed sections are hash-bound into the CPU quote's REPORT_DATA:

    crypto_material_hash = SHA-256(base64-decoded crypto_material JSON bytes)
    device_evidence_hash = SHA-256(base64-decoded device_evidence JSON bytes)
    REPORT_DATA[0:32]    = SHA-256(REPORT_DATA_V1_ALGORITHM || nonce ||
                                   crypto_material_hash || device_evidence_hash)
    REPORT_DATA[32:64]   = zeros

Endorsed-section hashes are computed over the exact base64-decoded section
bytes; verifiers must never re-serialize them.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field as dc_field
from typing import Optional

from .bytesutil import (
    decode_canonical_base64,
    decode_lower_hex,
    is_lower_hex,
)
from .errors import (
    ENVELOPE_REJECTED,
    PROVENANCE_REJECTED,
    QUOTE_REJECTED,
    CollateralNotFoundError,
    VerificationError,
)
from . import strictjson
from .strictjson import RAW, STR, array_of, field, map_of, struct_of

# Format registry (v3).
ATTESTATION_V3_FORMAT = "https://tinfoil.sh/predicate/attestation/v3"
REPORT_DATA_V1_ALGORITHM = "https://tinfoil.sh/report-data/v1"

CRYPTO_MATERIAL_V1_FORMAT = "https://tinfoil.sh/crypto-material/v1"
DEVICE_EVIDENCE_V1_FORMAT = "https://tinfoil.sh/device-evidence/v1"

SEV_SNP_REPORT_V1_FORMAT = "https://tinfoil.sh/format/sev-snp-report/v1"
TDX_QUOTE_V1_FORMAT = "https://tinfoil.sh/format/tdx-quote/v1"
NVIDIA_GPU_EVIDENCE_V1_FORMAT = "https://tinfoil.sh/format/nvidia-gpu-evidence/v1"

# KEY_SPKI_FP_SHA256_V1_FORMAT is a 32-byte SHA-256 of the DER-encoded
# SubjectPublicKeyInfo (RFC 5280); KEY_X25519_HPKE_V1_FORMAT is a raw 32-byte
# X25519 public key (RFC 7748) used for HPKE (RFC 9180).
KEY_SPKI_FP_SHA256_V1_FORMAT = "https://tinfoil.sh/key/spki-fp-sha256/v1"
KEY_X25519_HPKE_V1_FORMAT = "https://tinfoil.sh/key/x25519-hpke/v1"

COLLATERAL_AMD_VCEK_V1_FORMAT = "https://tinfoil.sh/collateral/amd-vcek/v1"
COLLATERAL_AMD_CRL_V1_FORMAT = "https://tinfoil.sh/collateral/amd-crl/v1"
COLLATERAL_INTEL_PCS_V1_FORMAT = "https://tinfoil.sh/collateral/intel-pcs/v1"
COLLATERAL_NVIDIA_GPU_V1_FORMAT = "https://tinfoil.sh/collateral/nvidia-gpu/v1"
COLLATERAL_SIGSTORE_CODE_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-code/v1"
COLLATERAL_SIGSTORE_PLATFORM_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-platform/v1"
COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-freshness/v1"

# Collateral roles (RATS, RFC 9334).
ROLE_ENDORSEMENT = "endorsement"
ROLE_REFERENCE_VALUES = "reference-values"

# Conventional identifiers.
CRYPTO_MATERIAL_ID_TLS = "tls"
CRYPTO_MATERIAL_ID_HPKE = "hpke"
SUBJECT_CPU = "cpu"
FRESHNESS_COLLATERAL_ID_CODE = "code-freshness"
FRESHNESS_COLLATERAL_ID_PLATFORM = "platform-freshness"

# Required challenge nonce size in bytes.
NONCE_SIZE = 32

ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation"


@dataclass
class Challenge:
    nonce: str
    report_data: str
    report_data_algorithm: str


@dataclass
class EndorsedHashes:
    crypto_material_hash: str
    device_evidence_hash: str


@dataclass
class CPUEvidence:
    format: str
    report_base64: str
    endorsed: EndorsedHashes


@dataclass
class CryptoMaterialItem:
    """One endorsed key: the item format URI fully determines how data
    (lowercase hex) is interpreted."""

    id: str
    format: str
    data: str


@dataclass
class DeviceEvidenceItem:
    id: str
    kind: str
    vendor: str
    format: str
    evidence: Optional[bytes]  # raw JSON source bytes


@dataclass
class CollateralEntry:
    """One self-describing collateral record. Collateral is unendorsed
    transport: every entry is authenticated by its own signature chain during
    verification, so a tampered entry can only cause rejection."""

    id: str
    role: str
    format: str
    subjects: Optional[list[str]]
    data: Optional[bytes]  # raw JSON source bytes


@dataclass
class SigstoreCollateral:
    """Data of a sigstore-code or sigstore-platform reference-values entry.
    repo and tag are informational; trust comes from verifying sigstore_bundle
    against the expected signing identity and digest."""

    repo: str
    tag: str
    digest: str
    sigstore_bundle: bytes


@dataclass
class AMDVCEKCollateral:
    vcek_der_base64: str
    cert_chain_pem: str


@dataclass
class AMDCRLCollateral:
    crl_der_base64: str


@dataclass
class PCSResponse:
    url: str
    headers: dict[str, list[str]]
    body_base64: str


@dataclass
class IntelPCSCollateral:
    responses: Optional[list[PCSResponse]]


@dataclass
class _CryptoMaterialSection:
    format: str
    items: Optional[list[CryptoMaterialItem]]


@dataclass
class _DeviceEvidenceSection:
    format: str
    items: Optional[list[DeviceEvidenceItem]]


@dataclass
class Document:
    """Parsed v3 attestation document. The endorsed sections travel
    base64-encoded and are retained as exact bytes for hashing — no
    re-serialization (the same envelope discipline as DSSE and JWS)."""

    format: str
    challenge: Challenge
    cpu_evidence: CPUEvidence
    crypto_material: str
    device_evidence: str
    collateral: list[CollateralEntry]

    crypto_material_bytes: bytes = dc_field(repr=False, default=b"")
    device_evidence_bytes: bytes = dc_field(repr=False, default=b"")
    _crypto_material: Optional[_CryptoMaterialSection] = dc_field(repr=False, default=None)
    _device_evidence: Optional[_DeviceEvidenceSection] = dc_field(repr=False, default=None)


# --- strict schemas ----------------------------------------------------------

_CHALLENGE_SCHEMA = struct_of(
    {
        "nonce": field("nonce", STR),
        "report_data": field("report_data", STR),
        "report_data_algorithm": field("report_data_algorithm", STR),
    },
    cls=Challenge,
)

_CPU_EVIDENCE_SCHEMA = struct_of(
    {
        "format": field("format", STR),
        "report_base64": field("report_base64", STR),
        "endorsed": field(
            "endorsed",
            struct_of(
                {
                    "crypto_material_hash": field("crypto_material_hash", STR),
                    "device_evidence_hash": field("device_evidence_hash", STR),
                },
                cls=EndorsedHashes,
            ),
        ),
    },
    cls=CPUEvidence,
)

_COLLATERAL_ENTRY_SCHEMA = struct_of(
    {
        "id": field("id", STR),
        "role": field("role", STR),
        "format": field("format", STR),
        "subjects": field("subjects", array_of(STR)),
        "data": field("data", RAW),
    },
    cls=CollateralEntry,
)

_DOCUMENT_SCHEMA = struct_of(
    {
        "format": field("format", STR),
        "challenge": field("challenge", _CHALLENGE_SCHEMA),
        "cpu_evidence": field("cpu_evidence", _CPU_EVIDENCE_SCHEMA),
        "crypto_material": field("crypto_material", STR),
        "device_evidence": field("device_evidence", STR),
        "collateral": field("collateral", array_of(_COLLATERAL_ENTRY_SCHEMA)),
    },
)

_CRYPTO_MATERIAL_SECTION_SCHEMA = struct_of(
    {
        "format": field("format", STR),
        "items": field(
            "items",
            array_of(
                struct_of(
                    {
                        "id": field("id", STR),
                        "format": field("format", STR),
                        "data": field("data", STR),
                    },
                    cls=CryptoMaterialItem,
                )
            ),
        ),
    },
    cls=_CryptoMaterialSection,
)

_DEVICE_EVIDENCE_SECTION_SCHEMA = struct_of(
    {
        "format": field("format", STR),
        "items": field(
            "items",
            array_of(
                struct_of(
                    {
                        "id": field("id", STR),
                        "kind": field("kind", STR),
                        "vendor": field("vendor", STR),
                        "format": field("format", STR),
                        "evidence": field("evidence", RAW),
                    },
                    cls=DeviceEvidenceItem,
                )
            ),
        ),
    },
    cls=_DeviceEvidenceSection,
)

_SIGSTORE_COLLATERAL_SCHEMA = struct_of(
    {
        "repo": field("repo", STR),
        "tag": field("tag", STR),
        "digest": field("digest", STR),
        "sigstore_bundle": field("sigstore_bundle", RAW),
    },
)

_FRESHNESS_COLLATERAL_SCHEMA = struct_of(
    {"sigstore_bundle": field("sigstore_bundle", RAW)},
)

_AMD_VCEK_COLLATERAL_SCHEMA = struct_of(
    {
        "vcek_der_base64": field("vcek_der_base64", STR),
        "cert_chain_pem": field("cert_chain_pem", STR),
    },
    cls=AMDVCEKCollateral,
)

_AMD_CRL_COLLATERAL_SCHEMA = struct_of(
    {"crl_der_base64": field("crl_der_base64", STR)},
    cls=AMDCRLCollateral,
)

_INTEL_PCS_COLLATERAL_SCHEMA = struct_of(
    {
        "responses": field(
            "responses",
            array_of(
                struct_of(
                    {
                        "url": field("url", STR),
                        "headers": field("headers", map_of(array_of(STR))),
                        "body_base64": field("body_base64", STR),
                    },
                    cls=PCSResponse,
                )
            ),
        ),
    },
    cls=IntelPCSCollateral,
)


def _envelope_error(message: str) -> VerificationError:
    return VerificationError(ENVELOPE_REJECTED, message)


def compute_report_data(
    nonce: bytes, crypto_material_hash: bytes, device_evidence_hash: bytes
) -> bytes:
    """Derive the 64-byte REPORT_DATA per https://tinfoil.sh/report-data/v1:
    SHA-256 over the algorithm URI (domain-separation label) followed by the
    three fixed-length 32-byte inputs in order, then 32 zero bytes."""
    if len(nonce) != 32 or len(crypto_material_hash) != 32 or len(device_evidence_hash) != 32:
        raise ValueError(
            "report data inputs must be 32 bytes each "
            f"(got {len(nonce)}, {len(crypto_material_hash)}, {len(device_evidence_hash)})"
        )
    digest = hashlib.sha256(
        REPORT_DATA_V1_ALGORITHM.encode("utf-8")
        + nonce
        + crypto_material_hash
        + device_evidence_hash
    ).digest()
    return digest + b"\x00" * 32


def random_nonce() -> bytes:
    """Generate a cryptographically random 32-byte challenge nonce."""
    return secrets.token_bytes(NONCE_SIZE)


def _decode_lower_hex(name: str, value: str, want_len: int) -> bytes:
    try:
        return decode_lower_hex(name, value, want_len)
    except ValueError as e:
        raise _envelope_error(str(e)) from None


def _decode_canonical_base64(name: str, value: str) -> bytes:
    try:
        return decode_canonical_base64(name, value)
    except ValueError as e:
        raise _envelope_error(str(e)) from None


def parse_document(doc_bytes: bytes) -> Document:
    """Strictly parse a v3 document: unknown members reject (case-
    sensitively), duplicate member names reject everywhere, hex must be
    lowercase, base64 canonical, and item ids unique. The endorsed sections
    are retained as raw bytes for hashing. Raises VerificationError
    (ENVELOPE_REJECTED)."""
    try:
        d = strictjson.unmarshal(doc_bytes, _DOCUMENT_SCHEMA)
    except ValueError as e:
        raise _envelope_error(f"parsing attestation document: {e}") from None
    doc = Document(
        format=d["format"],
        challenge=d["challenge"],
        cpu_evidence=d["cpu_evidence"],
        crypto_material=d["crypto_material"],
        device_evidence=d["device_evidence"],
        collateral=d["collateral"] if d["collateral"] is not None else [],
    )

    if doc.format != ATTESTATION_V3_FORMAT:
        raise _envelope_error(f"unsupported document format {doc.format!r}")
    if doc.challenge.report_data_algorithm != REPORT_DATA_V1_ALGORITHM:
        raise _envelope_error(
            f"unsupported report_data_algorithm {doc.challenge.report_data_algorithm!r}"
        )
    _decode_lower_hex("challenge.nonce", doc.challenge.nonce, NONCE_SIZE)
    _decode_lower_hex("challenge.report_data", doc.challenge.report_data, 64)
    _decode_lower_hex(
        "cpu_evidence.endorsed.crypto_material_hash",
        doc.cpu_evidence.endorsed.crypto_material_hash,
        32,
    )
    _decode_lower_hex(
        "cpu_evidence.endorsed.device_evidence_hash",
        doc.cpu_evidence.endorsed.device_evidence_hash,
        32,
    )
    if doc.cpu_evidence.format == "" or doc.cpu_evidence.report_base64 == "":
        raise _envelope_error("cpu_evidence is incomplete")
    if doc.crypto_material == "":
        raise _envelope_error("crypto_material section is missing")
    if doc.device_evidence == "":
        raise _envelope_error("device_evidence section is missing")
    crypto_bytes = _decode_canonical_base64("crypto_material", doc.crypto_material)
    device_bytes = _decode_canonical_base64("device_evidence", doc.device_evidence)

    try:
        cm: _CryptoMaterialSection = strictjson.unmarshal(
            crypto_bytes, _CRYPTO_MATERIAL_SECTION_SCHEMA
        )
    except ValueError as e:
        raise _envelope_error(f"parsing crypto_material: {e}") from None
    if cm.format != CRYPTO_MATERIAL_V1_FORMAT:
        raise _envelope_error(f"unsupported crypto_material section format {cm.format!r}")
    if cm.items is None:
        raise _envelope_error("crypto_material.items is missing")
    seen: set[str] = set()
    for item in cm.items:
        if item.id == "" or item.format == "":
            raise _envelope_error("crypto_material item is incomplete")
        if item.id in seen:
            raise _envelope_error(f"duplicate crypto_material item id {item.id!r}")
        seen.add(item.id)
        if item.format in (KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT):
            # Known key formats are exactly 32 bytes; reject short, empty, or
            # odd-length material before callers trust it.
            _decode_lower_hex(f"crypto_material item {item.id!r} data", item.data, 32)
        else:
            # Unknown formats still must carry non-empty, decodable lowercase
            # hex: the character class alone would admit odd-length strings
            # that no hex decoder accepts.
            if item.data == "":
                raise _envelope_error(f"crypto_material item {item.id!r} data is empty")
            if not is_lower_hex(item.data) or len(item.data) % 2 != 0:
                raise _envelope_error(
                    f"crypto_material item {item.id!r} data is not lowercase hex"
                )

    try:
        de: _DeviceEvidenceSection = strictjson.unmarshal(
            device_bytes, _DEVICE_EVIDENCE_SECTION_SCHEMA
        )
    except ValueError as e:
        raise _envelope_error(f"parsing device_evidence: {e}") from None
    if de.format != DEVICE_EVIDENCE_V1_FORMAT:
        raise _envelope_error(f"unsupported device_evidence section format {de.format!r}")
    if de.items is None:
        raise _envelope_error("device_evidence.items is missing")
    seen = set()
    for de_item in de.items:
        if de_item.id == "":
            raise _envelope_error("device_evidence item has no id")
        if de_item.id in seen:
            raise _envelope_error(f"duplicate device_evidence item id {de_item.id!r}")
        seen.add(de_item.id)

    seen = set()
    for i, entry in enumerate(doc.collateral):
        if entry.id == "" or entry.format == "":
            raise _envelope_error(f"collateral entry {i} is incomplete")
        if entry.id in seen:
            raise _envelope_error(f"duplicate collateral entry id {entry.id!r}")
        seen.add(entry.id)
        if entry.role not in (ROLE_ENDORSEMENT, ROLE_REFERENCE_VALUES):
            raise _envelope_error(
                f"collateral entry {entry.id!r} has unknown role {entry.role!r}"
            )

    doc.crypto_material_bytes = crypto_bytes
    doc.device_evidence_bytes = device_bytes
    doc._crypto_material = cm
    doc._device_evidence = de
    return doc


def check(doc_bytes: bytes, expected_nonce: bytes) -> tuple[Document, bytes]:
    """Parse a v3 document and check the challenge bindings: nonce equality,
    endorsed-section hash recomputation, and REPORT_DATA recomputation.
    Returns the document and the expected 64-byte REPORT_DATA the CPU quote
    must bind. A check is not authentication: nothing in the document is
    trusted until the quote proves the hardware bound that REPORT_DATA."""
    if len(expected_nonce) != NONCE_SIZE:
        raise _envelope_error(
            f"expected nonce must be {NONCE_SIZE} bytes, got {len(expected_nonce)}"
        )
    doc = parse_document(doc_bytes)
    if doc.challenge.nonce != expected_nonce.hex():
        raise _envelope_error("challenge nonce does not match the expected nonce")

    crypto_hash = hashlib.sha256(doc.crypto_material_bytes).digest()
    device_hash = hashlib.sha256(doc.device_evidence_bytes).digest()
    if crypto_hash.hex() != doc.cpu_evidence.endorsed.crypto_material_hash:
        raise _envelope_error(
            "crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash"
        )
    if device_hash.hex() != doc.cpu_evidence.endorsed.device_evidence_hash:
        raise _envelope_error(
            "device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash"
        )

    report_data = compute_report_data(expected_nonce, crypto_hash, device_hash)
    if report_data.hex() != doc.challenge.report_data:
        raise _envelope_error("challenge report_data does not match the recomputed value")
    return doc, report_data


def crypto_material_items(doc: Document) -> list[CryptoMaterialItem]:
    """The parsed crypto_material items."""
    if doc._crypto_material is None or doc._crypto_material.items is None:
        return []
    return doc._crypto_material.items


def device_evidence_items(doc: Document) -> list[DeviceEvidenceItem]:
    """The parsed device_evidence items."""
    if doc._device_evidence is None or doc._device_evidence.items is None:
        return []
    return doc._device_evidence.items


def crypto_material_item(doc: Document, id_: str) -> Optional[CryptoMaterialItem]:
    """The crypto_material item with the given id, or None."""
    for item in crypto_material_items(doc):
        if item.id == id_:
            return item
    return None


def endorsement_collateral(
    doc: Document, fmt: str, subject: str
) -> Optional[CollateralEntry]:
    """The first endorsement-role collateral entry with the given format whose
    subjects include subject, or None."""
    for entry in doc.collateral:
        if entry.role != ROLE_ENDORSEMENT or entry.format != fmt:
            continue
        if subject in (entry.subjects or []):
            return entry
    return None


def reference_values_collateral(doc: Document, fmt: str) -> SigstoreCollateral:
    """The first reference-values collateral entry with the given format,
    parsed as a Sigstore collateral payload. First matching entry wins (ids
    are unique; two entries of the same format under different ids resolve in
    collateral order). Errors carry PROVENANCE_REJECTED: in the verification
    flow this lookup is the first step of reference-values authentication. A
    document without such an entry raises CollateralNotFoundError."""
    for entry in doc.collateral:
        if entry.role != ROLE_REFERENCE_VALUES or entry.format != fmt:
            continue
        try:
            sc = strictjson.unmarshal(entry.data or b"", _SIGSTORE_COLLATERAL_SCHEMA)
        except ValueError as e:
            raise VerificationError(
                PROVENANCE_REJECTED,
                f"parsing {fmt} collateral entry {entry.id!r}: {e}",
            ) from None
        return SigstoreCollateral(
            repo=sc["repo"],
            tag=sc["tag"],
            digest=sc["digest"],
            sigstore_bundle=sc["sigstore_bundle"] or b"",
        )
    raise CollateralNotFoundError(
        PROVENANCE_REJECTED,
        f"collateral entry not found: document carries no {fmt} reference-values entry",
    )


def freshness_collateral(doc: Document, id_: str) -> bytes:
    """The freshness witness sigstore_bundle bytes for the Sigstore
    reference-values entry selected by its collateral entry id, rejecting
    duplicate entries. Errors carry PROVENANCE_REJECTED."""
    found: Optional[bytes] = None
    for entry in doc.collateral:
        if (
            entry.id != id_
            or entry.role != ROLE_REFERENCE_VALUES
            or entry.format != COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT
        ):
            continue
        if found is not None:
            raise VerificationError(
                PROVENANCE_REJECTED,
                f"document carries duplicate freshness collateral entry {id_!r}",
            )
        try:
            fc = strictjson.unmarshal(entry.data or b"", _FRESHNESS_COLLATERAL_SCHEMA)
        except ValueError as e:
            raise VerificationError(
                PROVENANCE_REJECTED,
                f"parsing freshness collateral entry {entry.id!r}: {e}",
            ) from None
        found = fc["sigstore_bundle"] or b""
    if found is None:
        raise CollateralNotFoundError(
            PROVENANCE_REJECTED,
            "collateral entry not found: document carries no "
            f"{COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT} reference-values entry {id_!r}",
        )
    return found


# Typed strict parsers for endorsement collateral payloads, consumed by the
# quote layer (errors carry QUOTE_REJECTED, matching Go's step attribution).


def _parse_quote_collateral(data: Optional[bytes], schema, what: str):
    try:
        return strictjson.unmarshal(data or b"", schema)
    except ValueError as e:
        raise VerificationError(QUOTE_REJECTED, f"parsing {what}: {e}") from None


def parse_amd_vcek_collateral(data: Optional[bytes]) -> AMDVCEKCollateral:
    return _parse_quote_collateral(data, _AMD_VCEK_COLLATERAL_SCHEMA, "amd-vcek collateral")


def parse_amd_crl_collateral(data: Optional[bytes]) -> AMDCRLCollateral:
    return _parse_quote_collateral(data, _AMD_CRL_COLLATERAL_SCHEMA, "amd-crl collateral")


def parse_intel_pcs_collateral(data: Optional[bytes]) -> IntelPCSCollateral:
    return _parse_quote_collateral(data, _INTEL_PCS_COLLATERAL_SCHEMA, "intel-pcs collateral")
