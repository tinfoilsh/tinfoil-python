"""The v3 attestation document wire format and its strict parsing, which checks the challenge against the caller's
nonce.

Parsing authenticates nothing by itself: the CPU quote must prove that the
hardware bound the recomputed REPORT_DATA before any part of the document is
trusted.

Attestation document v3 (predicate https://tinfoil.sh/predicate/attestation/v3).

The document is flat: a challenge, CPU evidence, two endorsed sections
(crypto_material, device_evidence), and an array of collateral entries. The
endorsed sections are hash-bound into the CPU quote's REPORT_DATA::

    crypto_material_hash = SHA-256(base64-decoded crypto_material JSON bytes)
    device_evidence_hash = SHA-256(base64-decoded device_evidence JSON bytes)
    REPORT_DATA[0:32]    = SHA-256(REPORT_DATA_V1_ALGORITHM || nonce || crypto_material_hash || device_evidence_hash)
    REPORT_DATA[32:64]   = zeros

Endorsed-section hashes are computed over the exact base64-decoded section
bytes; verifiers must never re-serialize them.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._canonical import decode_base64, decode_lower_hex, is_lower_hex
from tinfoil._v3.verifier._document.collateral import entry as _entry
from tinfoil._v3.verifier._document.collateral.collateral import (
    ARTIFACT_FRESHNESS_V1_FORMAT,
    FORMAT_V2,
    FORMAT_V3,
    SIGSTORE_CODE_V1_FORMAT,
    SIGSTORE_FRESHNESS_V1_FORMAT,
    SIGSTORE_PLATFORM_V1_FORMAT,
    CPUEndorsements,
    NotFoundError,
    Set,
    decode,
)
from tinfoil._v3.verifier._document.collateral.config import CONFIG_ID, ConfigEndorsement
from tinfoil._v3.verifier._document.collateral.runtime import RUNTIME_ID, Runtime
from tinfoil._v3.verifier._document.collateral.sigstore import Freshness, SigstoreRef

# Format registry (v3).
ATTESTATION_V3_FORMAT = "https://tinfoil.sh/predicate/attestation/v3"
"""The v3 attestation document."""
REPORT_DATA_V1_ALGORITHM = "https://tinfoil.sh/report-data/v1"
"""The REPORT_DATA derivation described in the module docstring."""
CRYPTO_MATERIAL_V1_FORMAT = "https://tinfoil.sh/crypto-material/v1"
"""The crypto_material section envelope."""
DEVICE_EVIDENCE_V1_FORMAT = "https://tinfoil.sh/device-evidence/v1"
"""The device_evidence section envelope."""
SEVSNP_REPORT_V1_FORMAT = "https://tinfoil.sh/format/sev-snp-report/v1"
"""A raw 1184-byte SEV-SNP report, base64."""
TDX_QUOTE_V1_FORMAT = "https://tinfoil.sh/format/tdx-quote/v1"
"""A raw TDX Quote v4, base64."""
NVIDIA_GPU_EVIDENCE_V1_FORMAT = "https://tinfoil.sh/format/nvidia-gpu-evidence/v1"
"""An NVIDIA GPU evidence payload."""
KEY_SPKI_FP_SHA256_V1_FORMAT = "https://tinfoil.sh/key/spki-fp-sha256/v1"
"""A 32-byte SHA-256 of the DER-encoded SubjectPublicKeyInfo (RFC 5280), the standard pinning computation."""
KEY_SPKI_V1_FORMAT = "https://tinfoil.sh/key/spki/v1"
"""A complete DER-encoded SubjectPublicKeyInfo as lowercase hex. Consumers validate the key algorithm for their
protocol."""
KEY_X25519_HPKE_V1_FORMAT = "https://tinfoil.sh/key/x25519-hpke/v1"
"""A raw 32-byte X25519 public key (RFC 7748) used for HPKE (RFC 9180)."""

# Conventional identifiers.
CRYPTO_MATERIAL_ID_TLS = "tls"
"""The conventional id of the TLS key fingerprint."""
CRYPTO_MATERIAL_ID_HPKE = "hpke"
"""The conventional id of the HPKE public key."""

NONCE_SIZE = 32
"""The required challenge nonce size in bytes."""


class DocumentError(ValueError):
    """A document that fails to parse or is not bound to the caller's nonce."""


class InvalidInputError(ValueError):
    """A mistake in the caller's input to parse: a nonce of the wrong length."""


@dataclass(frozen=True, slots=True)
class CpuEvidence:
    """A document's decoded hardware evidence."""

    format: str
    """Selects the platform, e.g. SEVSNP_REPORT_V1_FORMAT."""
    report: bytes
    """The raw report (SEV-SNP) or quote (TDX)."""


@dataclass(frozen=True, slots=True)
class CryptoMaterialItem:
    """One endorsed key: the item format URI fully determines how ``data`` (lowercase hex) is interpreted."""

    id: str
    format: str
    data: str


@dataclass(frozen=True, slots=True)
class DeviceEvidenceItem:
    """One device's evidence; the item format URI versions the ``evidence`` payload."""

    id: str
    kind: str
    vendor: str
    format: str
    evidence: _json.JsonValue


@dataclass(frozen=True, slots=True)
class _Challenge:
    nonce: str
    report_data: str
    report_data_algorithm: str


@dataclass(frozen=True, slots=True)
class _EndorsedHashes:
    crypto_material_hash: str
    device_evidence_hash: str


class Document:
    """A parsed v3 attestation document.

    Obtain one from ``parse``, which decodes every field and checks the
    challenge against the caller's nonce. Every accessor returns immutable
    values.
    """

    __slots__ = (
        "_bound",
        "_challenge",
        "_collateral",
        "_collateral_format",
        "_crypto_material_bytes",
        "_crypto_material_items",
        "_device_evidence_bytes",
        "_device_evidence_items",
        "_endorsed",
        "_evidence",
        "_report_data",
    )

    def __init__(
        self,
        *,
        challenge: _Challenge,
        endorsed: _EndorsedHashes,
        evidence: CpuEvidence,
        collateral: Set,
        collateral_format: str,
        crypto_material_bytes: bytes,
        device_evidence_bytes: bytes,
        crypto_material_items: tuple[CryptoMaterialItem, ...],
        device_evidence_items: tuple[DeviceEvidenceItem, ...],
    ) -> None:
        self._challenge = challenge
        self._endorsed = endorsed
        self._evidence = evidence
        self._collateral = collateral
        self._collateral_format = collateral_format
        self._crypto_material_bytes = crypto_material_bytes
        self._device_evidence_bytes = device_evidence_bytes
        self._crypto_material_items = crypto_material_items
        self._device_evidence_items = device_evidence_items
        # Set by _bind once the challenge has been checked against the
        # caller's nonce; a decoded but unbound document has no REPORT_DATA
        # to compare against a quote.
        self._bound = False
        self._report_data: bytes | None = None

    def collateral_format(self) -> str:
        """The collateral format, which selects a verification policy, not a trust anchor."""
        return self._collateral_format or FORMAT_V2

    def cpu_evidence(self) -> CpuEvidence:
        return self._evidence

    def crypto_material_items(self) -> tuple[CryptoMaterialItem, ...]:
        return self._crypto_material_items

    def crypto_material_item(self, item_id: str) -> CryptoMaterialItem | None:
        for item in self._crypto_material_items:
            if item.id == item_id:
                return item
        return None

    def device_evidence_items(self) -> tuple[DeviceEvidenceItem, ...]:
        return self._device_evidence_items

    def cpu_endorsements(self) -> CPUEndorsements:
        """The endorsement collateral that the document's CPU evidence format uses, for the reserved CPU subject.

        Collateral that the document does not carry is None.
        """
        if self._evidence.format == SEVSNP_REPORT_V1_FORMAT:
            return CPUEndorsements(amd_vcek=self._collateral.cpu.amd_vcek, amd_crl=self._collateral.cpu.amd_crl)
        if self._evidence.format == TDX_QUOTE_V1_FORMAT:
            return CPUEndorsements(intel_pcs=self._collateral.cpu.intel_pcs)
        return CPUEndorsements()

    def sigstore_code(self) -> SigstoreRef:
        """The code-provenance reference-values entry. Raises NotFoundError without one."""
        return _sigstore_ref(self._collateral.sigstore_code, SIGSTORE_CODE_V1_FORMAT)

    def sigstore_platform(self) -> SigstoreRef:
        """The platform-endorsements reference-values entry. Raises NotFoundError without one."""
        return _sigstore_ref(self._collateral.sigstore_platform, SIGSTORE_PLATFORM_V1_FORMAT)

    def freshness(self, witness_id: str) -> Freshness:
        """The freshness witness with the given collateral id, such as FRESHNESS_ID_CODE.

        Raises NotFoundError without one.
        """
        witness = self._collateral.freshness.get(witness_id)
        if witness is None:
            raise NotFoundError(
                f"document carries no {SIGSTORE_FRESHNESS_V1_FORMAT} reference-values entry {witness_id!r}"
            )
        return witness

    def config_endorsement(self) -> ConfigEndorsement:
        """The decoded, unauthenticated config approval. Raises NotFoundError without one."""
        if self._collateral.config is None:
            raise NotFoundError(f"document carries no {CONFIG_ID!r} reference-values entry")
        return self._collateral.config

    def runtime(self) -> Runtime:
        """The decoded, unauthenticated runtime approval. Raises NotFoundError without one."""
        if self._collateral.runtime is None:
            raise NotFoundError(f"document carries no {RUNTIME_ID!r} reference-values entry")
        return self._collateral.runtime

    def config_platform(self) -> SigstoreRef:
        return self._collateral.config_platform()

    def expected_report_data(self) -> bytes | None:
        """The REPORT_DATA that the document's CPU quote must bind, recomputed by ``parse`` from the caller's nonce and
        the endorsed sections.

        None for a document that was never bound, whose zero REPORT_DATA must never be compared against a quote.
        """
        return self._report_data if self._bound else None

    def _bind(self, expected_nonce: bytes) -> None:
        """Check the challenge bindings against the caller's nonce and record the recomputed REPORT_DATA."""
        if self._challenge.nonce != expected_nonce.hex():
            raise DocumentError("challenge nonce does not match the expected nonce")
        crypto_hash = hashlib.sha256(self._crypto_material_bytes).digest()
        device_hash = hashlib.sha256(self._device_evidence_bytes).digest()
        if crypto_hash.hex() != self._endorsed.crypto_material_hash:
            raise DocumentError("crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash")
        if device_hash.hex() != self._endorsed.device_evidence_hash:
            raise DocumentError("device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash")
        report_data = compute_report_data(expected_nonce, crypto_hash, device_hash)
        if report_data.hex() != self._challenge.report_data:
            raise DocumentError("challenge report_data does not match the recomputed value")
        self._report_data = report_data
        self._bound = True


def _sigstore_ref(ref: SigstoreRef | None, format_: str) -> SigstoreRef:
    if ref is None:
        raise NotFoundError(f"document carries no {format_} reference-values entry")
    return ref


def compute_report_data(nonce: bytes, crypto_material_hash: bytes, device_evidence_hash: bytes) -> bytes:
    """The 64-byte REPORT_DATA per REPORT_DATA_V1_ALGORITHM.

    SHA-256 over the algorithm URI (a domain-separation label) followed by the three fixed-length 32-byte inputs in
    order, then 32 zero bytes.
    """
    if len(nonce) != 32 or len(crypto_material_hash) != 32 or len(device_evidence_hash) != 32:
        raise ValueError(
            "report data inputs must be 32 bytes each "
            f"(got {len(nonce)}, {len(crypto_material_hash)}, {len(device_evidence_hash)})"
        )
    digest = hashlib.sha256()
    digest.update(REPORT_DATA_V1_ALGORITHM.encode("ascii"))
    digest.update(nonce)
    digest.update(crypto_material_hash)
    digest.update(device_evidence_hash)
    return digest.digest() + bytes(32)


def random_nonce() -> bytes:
    """A cryptographically random challenge nonce."""
    return secrets.token_bytes(NONCE_SIZE)


def parse(doc: bytes, expected_nonce: bytes) -> Document:
    """Strictly parse a v3 document and check its challenge bindings against ``expected_nonce``, the nonce that the
    caller sent: nonce equality, endorsed-section hash recomputation, and REPORT_DATA recomputation.

    Parsing is strict: unknown members reject (case-sensitively), duplicate
    member names reject everywhere, hex must be lowercase, base64 canonical,
    and item ids unique. A parsed document is not authenticated: nothing in
    it is trusted until the quote proves that the hardware bound its
    REPORT_DATA, available from ``expected_report_data``.

    Raises InvalidInputError for a nonce of the wrong length and
    DocumentError for a document that fails to parse or bind.
    """
    if len(expected_nonce) != NONCE_SIZE:
        raise InvalidInputError(f"expected nonce must be {NONCE_SIZE} bytes, got {len(expected_nonce)}")
    document = decode_unbound(doc)
    document._bind(expected_nonce)
    return document


def decode_unbound(doc: bytes) -> Document:
    """Apply the structural rules alone and decode every field once, without checking the challenge.

    For the conformance adapter's block stages only; the verifier always
    binds. The document's ``expected_report_data`` is None.
    """
    try:
        return _decode(doc)
    except DocumentError:
        raise
    except ValueError as err:
        # Encoding, JSON, entry-shape and collateral errors are all ValueErrors.
        raise DocumentError(str(err)) from err


_DOCUMENT_MEMBERS = (
    "format",
    "challenge",
    "cpu_evidence",
    "crypto_material",
    "device_evidence",
    "collateral_format",
    "collateral",
)
_CHALLENGE_MEMBERS = ("nonce", "report_data", "report_data_algorithm")
_CPU_EVIDENCE_MEMBERS = ("format", "report_base64", "endorsed")
_ENDORSED_MEMBERS = ("crypto_material_hash", "device_evidence_hash")
_SECTION_MEMBERS = ("format", "items")
_CRYPTO_ITEM_MEMBERS = ("id", "format", "data")
_DEVICE_ITEM_MEMBERS = ("id", "kind", "vendor", "format", "evidence")


def _decode(doc: bytes) -> Document:
    try:
        root = _json.object_(_json.strict_parse(doc), "attestation document", _DOCUMENT_MEMBERS)
        format_ = _json.string(root, "format")
        raw_challenge = _json.struct(root, "challenge", _CHALLENGE_MEMBERS)
        challenge = _Challenge(
            nonce=_json.string(raw_challenge, "nonce"),
            report_data=_json.string(raw_challenge, "report_data"),
            report_data_algorithm=_json.string(raw_challenge, "report_data_algorithm"),
        )
        raw_evidence = _json.struct(root, "cpu_evidence", _CPU_EVIDENCE_MEMBERS)
        raw_endorsed = _json.struct(raw_evidence, "endorsed", _ENDORSED_MEMBERS)
        endorsed = _EndorsedHashes(
            crypto_material_hash=_json.string(raw_endorsed, "crypto_material_hash"),
            device_evidence_hash=_json.string(raw_endorsed, "device_evidence_hash"),
        )
        evidence_format = _json.string(raw_evidence, "format")
        report_base64 = _json.string(raw_evidence, "report_base64")
        crypto_material = _json.string(root, "crypto_material")
        device_evidence = _json.string(root, "device_evidence")
        collateral_format = _json.string(root, "collateral_format")
        entries = _entry.decode_entries(_json.raw(root, "collateral"))
    except _json.JsonError as err:
        raise DocumentError(f"parsing attestation document: {err}") from err

    if format_ != ATTESTATION_V3_FORMAT:
        raise DocumentError(f"unsupported document format {format_!r}")

    if challenge.report_data_algorithm != REPORT_DATA_V1_ALGORITHM:
        raise DocumentError(f"unsupported challenge.report_data_algorithm {challenge.report_data_algorithm!r}")
    decode_lower_hex("challenge.nonce", challenge.nonce, NONCE_SIZE)
    decode_lower_hex("challenge.report_data", challenge.report_data, 64)

    decode_lower_hex("cpu_evidence.endorsed.crypto_material_hash", endorsed.crypto_material_hash, 32)
    decode_lower_hex("cpu_evidence.endorsed.device_evidence_hash", endorsed.device_evidence_hash, 32)
    if evidence_format == "" or report_base64 == "":
        raise DocumentError("cpu_evidence is incomplete")
    report = decode_base64("cpu_evidence.report_base64", report_base64)

    crypto_items, crypto_bytes = _parse_crypto_material(crypto_material)
    device_items, device_bytes = _parse_device_evidence(device_evidence)
    collateral_set = _decode_collateral(collateral_format, entries)

    return Document(
        challenge=challenge,
        endorsed=endorsed,
        evidence=CpuEvidence(format=evidence_format, report=report),
        collateral=collateral_set,
        collateral_format=collateral_format,
        crypto_material_bytes=crypto_bytes,
        device_evidence_bytes=device_bytes,
        crypto_material_items=crypto_items,
        device_evidence_items=device_items,
    )


def _parse_crypto_material(encoded: str) -> tuple[tuple[CryptoMaterialItem, ...], bytes]:
    if encoded == "":
        raise DocumentError("crypto_material section is missing")
    crypto_bytes = decode_base64("crypto_material", encoded)
    try:
        section = _json.object_(_json.strict_parse(crypto_bytes), "crypto_material", _SECTION_MEMBERS)
        format_ = _json.string(section, "format")
        raw_items = _json.array(section, "items")
        items = []
        if raw_items is not None:
            for raw_item in raw_items:
                obj = _json.object_(raw_item, "crypto_material item", _CRYPTO_ITEM_MEMBERS)
                items.append(
                    CryptoMaterialItem(
                        id=_json.string(obj, "id"),
                        format=_json.string(obj, "format"),
                        data=_json.string(obj, "data"),
                    )
                )
    except _json.JsonError as err:
        raise DocumentError(f"parsing crypto_material: {err}") from err
    if format_ != CRYPTO_MATERIAL_V1_FORMAT:
        raise DocumentError(f"unsupported crypto_material section format {format_!r}")
    if raw_items is None:
        raise DocumentError("crypto_material.items is missing")
    seen: set[str] = set()
    for item in items:
        if item.id == "" or item.format == "":
            raise DocumentError("crypto_material item is incomplete")
        if item.id in seen:
            raise DocumentError(f"duplicate crypto_material item id {item.id!r}")
        seen.add(item.id)
        if item.format in (KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT):
            # Known key formats are exactly 32 bytes; reject short, empty or
            # odd-length material before callers trust it.
            decode_lower_hex(f"crypto_material item {item.id!r} data", item.data, 32)
        else:
            # Unknown formats still must carry non-empty, decodable lowercase
            # hex: the character class alone would admit odd-length strings
            # that no hex decoder accepts.
            if item.data == "":
                raise DocumentError(f"crypto_material item {item.id!r} data is empty")
            if not is_lower_hex(item.data) or len(item.data) % 2:
                raise DocumentError(f"crypto_material item {item.id!r} data is not lowercase hex")
    return tuple(items), crypto_bytes


def _parse_device_evidence(encoded: str) -> tuple[tuple[DeviceEvidenceItem, ...], bytes]:
    if encoded == "":
        raise DocumentError("device_evidence section is missing")
    device_bytes = decode_base64("device_evidence", encoded)
    try:
        section = _json.object_(_json.strict_parse(device_bytes), "device_evidence", _SECTION_MEMBERS)
        format_ = _json.string(section, "format")
        raw_items = _json.array(section, "items")
        items = []
        if raw_items is not None:
            for raw_item in raw_items:
                obj = _json.object_(raw_item, "device_evidence item", _DEVICE_ITEM_MEMBERS)
                items.append(
                    DeviceEvidenceItem(
                        id=_json.string(obj, "id"),
                        kind=_json.string(obj, "kind"),
                        vendor=_json.string(obj, "vendor"),
                        format=_json.string(obj, "format"),
                        evidence=_json.raw(obj, "evidence"),
                    )
                )
    except _json.JsonError as err:
        raise DocumentError(f"parsing device_evidence: {err}") from err
    if format_ != DEVICE_EVIDENCE_V1_FORMAT:
        raise DocumentError(f"unsupported device_evidence section format {format_!r}")
    if raw_items is None:
        raise DocumentError("device_evidence.items is missing")
    seen: set[str] = set()
    for item in items:
        if item.id == "":
            raise DocumentError("device_evidence item has no id")
        if item.id in seen:
            raise DocumentError(f"duplicate device_evidence item id {item.id!r}")
        seen.add(item.id)
    return tuple(items), device_bytes


def _decode_collateral(format_: str, entries: tuple[_entry.Entry, ...]) -> Set:
    if format_ not in ("", FORMAT_V2, FORMAT_V3):
        raise DocumentError(f"unsupported collateral format {format_!r}")
    collateral_set = decode(entries)
    if format_ == FORMAT_V3:
        if collateral_set.sigstore_code is not None:
            raise DocumentError(f"legacy code collateral is incompatible with {format_!r}")
    elif collateral_set.config is not None or collateral_set.runtime is not None:
        raise DocumentError(f"config and runtime collateral require {FORMAT_V3!r}")
    for witness in collateral_set.freshness.values():
        if (format_ == FORMAT_V3) != (witness.format == ARTIFACT_FRESHNESS_V1_FORMAT):
            raise DocumentError(f"freshness collateral is incompatible with {format_!r}")
    return collateral_set
