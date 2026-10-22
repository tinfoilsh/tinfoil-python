"""The v3 attestation document and its strict parsing.

A document carries a challenge, CPU evidence, two endorsed sections
(crypto_material and device_evidence) and collateral. The endorsed sections
are hash-bound into the CPU quote's REPORT_DATA::

    crypto_material_hash = SHA-256(base64-decoded crypto_material bytes)
    device_evidence_hash = SHA-256(base64-decoded device_evidence bytes)
    REPORT_DATA[0:32]    = SHA-256(REPORT_DATA_V1 || nonce || crypto_material_hash || device_evidence_hash)
    REPORT_DATA[32:64]   = zeros

Parsing checks the challenge against the caller's nonce but authenticates
nothing: no part of a document is trusted until its CPU quote proves the
hardware bound that REPORT_DATA.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import _formats
from .collateral import (
    ConfigEndorsement,
    CPUEndorsements,
    Freshness,
    Runtime,
    SigstoreRef,
    _Collateral,
)

__all__ = [
    "CPUEvidence",
    "CRYPTO_MATERIAL_ID_HPKE",
    "CRYPTO_MATERIAL_ID_TLS",
    "CryptoMaterialItem",
    "DeviceEvidenceItem",
    "Document",
    "InvalidInputError",
    "KEY_SPKI_FP_SHA256_V1_FORMAT",
    "KEY_SPKI_V1_FORMAT",
    "KEY_X25519_HPKE_V1_FORMAT",
    "NONCE_SIZE",
    "NVIDIA_GPU_EVIDENCE_V1_FORMAT",
    "SEV_SNP_REPORT_V1_FORMAT",
    "TDX_QUOTE_V1_FORMAT",
    "compute_report_data",
    "parse",
    "random_nonce",
]

NONCE_SIZE = 32
"""The challenge nonce size in bytes."""

SEV_SNP_REPORT_V1_FORMAT = _formats.SEV_SNP_REPORT_V1
"""CPU evidence: a raw 1184-byte AMD SEV-SNP attestation report."""
TDX_QUOTE_V1_FORMAT = _formats.TDX_QUOTE_V1
"""CPU evidence: a raw Intel TDX Quote v4."""
NVIDIA_GPU_EVIDENCE_V1_FORMAT = _formats.NVIDIA_GPU_EVIDENCE_V1
"""Device evidence: an NVIDIA GPU evidence payload."""

KEY_SPKI_FP_SHA256_V1_FORMAT = _formats.KEY_SPKI_FP_SHA256_V1
"""Crypto material: the SHA-256 of a DER SubjectPublicKeyInfo, 32 bytes."""
KEY_SPKI_V1_FORMAT = _formats.KEY_SPKI_V1
"""Crypto material: a complete DER SubjectPublicKeyInfo.

Consumers validate the key algorithm for their protocol.
"""
KEY_X25519_HPKE_V1_FORMAT = _formats.KEY_X25519_HPKE_V1
"""Crypto material: a raw 32-byte X25519 public key for HPKE (RFC 9180)."""

CRYPTO_MATERIAL_ID_TLS = _formats.CRYPTO_MATERIAL_ID_TLS
"""The conventional ID of the TLS key fingerprint."""
CRYPTO_MATERIAL_ID_HPKE = _formats.CRYPTO_MATERIAL_ID_HPKE
"""The conventional ID of the HPKE public key."""


class InvalidInputError(ValueError):
    """A mistake in the caller's input to parse, such as a nonce of the wrong length.

    A document that fails to parse is not marked with this type.
    """


@dataclass(frozen=True, slots=True)
class CPUEvidence:
    """A document's decoded hardware evidence."""

    format: str
    """Selects the platform, such as SEV_SNP_REPORT_V1_FORMAT."""
    report: bytes
    """The raw report (SEV-SNP) or quote (TDX)."""


@dataclass(frozen=True, slots=True)
class CryptoMaterialItem:
    """One endorsed key. ``format`` determines how ``data`` (lowercase hex) is read."""

    id: str
    format: str
    data: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DeviceEvidenceItem:
    """One device's evidence. ``format`` versions the ``evidence`` payload."""

    id: str
    kind: str
    vendor: str
    format: str
    evidence: bytes
    """The evidence payload, as JSON."""


class Document:
    """A parsed v3 attestation document.

    Obtain one from parse(), which decodes every field and checks the
    challenge against the caller's nonce. A document is immutable, and its
    accessors return decoded values. Lookups return None when the document
    carries no matching element.
    """

    __slots__ = (
        "_collateral",
        "_collateral_format",
        "_crypto_material",
        "_device_evidence",
        "_evidence",
        "_report_data",
    )

    _collateral: _Collateral
    _collateral_format: str | None
    _crypto_material: tuple[CryptoMaterialItem, ...]
    _device_evidence: tuple[DeviceEvidenceItem, ...]
    _evidence: CPUEvidence
    _report_data: bytes | None

    def __init__(self) -> None:
        raise TypeError("documents are created by tinfoil.verify.document.parse()")

    @classmethod
    def _create(
        cls,
        *,
        evidence: CPUEvidence,
        crypto_material: tuple[CryptoMaterialItem, ...],
        device_evidence: tuple[DeviceEvidenceItem, ...],
        collateral: _Collateral,
        collateral_format: str | None,
        report_data: bytes | None,
    ) -> Document:
        document = object.__new__(cls)
        document._evidence = evidence
        document._crypto_material = crypto_material
        document._device_evidence = device_evidence
        document._collateral = collateral
        document._collateral_format = collateral_format
        document._report_data = report_data
        return document

    @property
    def cpu_evidence(self) -> CPUEvidence:
        """The decoded CPU evidence."""
        return self._evidence

    @property
    def crypto_material(self) -> tuple[CryptoMaterialItem, ...]:
        """The endorsed crypto_material items."""
        return self._crypto_material

    @property
    def device_evidence(self) -> tuple[DeviceEvidenceItem, ...]:
        """The endorsed device_evidence items."""
        return self._device_evidence

    def crypto_material_item(self, item_id: str) -> CryptoMaterialItem | None:
        """The crypto_material item with ID ``item_id``."""
        return next((item for item in self._crypto_material if item.id == item_id), None)

    @property
    def collateral_format(self) -> str:
        """The collateral format, which selects a verification policy.

        A document without one carries legacy GitHub workload-release
        collateral.
        """
        return self._collateral_format or _formats.COLLATERAL_V2

    @property
    def cpu_endorsements(self) -> CPUEndorsements:
        """The endorsement collateral the CPU evidence's format uses."""
        cpu = self._collateral.cpu
        if self._evidence.format == _formats.SEV_SNP_REPORT_V1:
            return CPUEndorsements(amd_vcek=cpu.amd_vcek, amd_crl=cpu.amd_crl)
        if self._evidence.format == _formats.TDX_QUOTE_V1:
            return CPUEndorsements(intel_pcs=cpu.intel_pcs)
        return CPUEndorsements()

    @property
    def sigstore_code(self) -> SigstoreRef | None:
        """The code-provenance reference-values entry."""
        return self._collateral.sigstore_code

    @property
    def sigstore_platform(self) -> SigstoreRef | None:
        """The platform-endorsements reference-values entry."""
        return self._collateral.sigstore_platform

    def freshness(self, entry_id: str) -> Freshness | None:
        """The freshness witness or approval with collateral ID ``entry_id``."""
        return self._collateral.freshness.get(entry_id)

    @property
    def config_endorsement(self) -> ConfigEndorsement | None:
        """The decoded, unauthenticated config approval."""
        return self._collateral.config

    @property
    def runtime(self) -> Runtime | None:
        """The decoded, unauthenticated runtime approval."""
        return self._collateral.runtime

    def config_platform(self) -> SigstoreRef | None:
        """The platform reference config verification uses.

        Raises ValueError when the document carries conflicting platform
        entries.
        """
        return self._collateral.unambiguous_config_platform()

    @property
    def expected_report_data(self) -> bytes | None:
        """The 64-byte REPORT_DATA the CPU quote must bind.

        Recomputed by parse() from the caller's nonce and the endorsed
        sections. None for a document decoded without a nonce, whose quote
        must never be compared against anything.
        """
        return self._report_data


def parse(data: bytes, expected_nonce: bytes) -> Document:
    """Strictly parse a v3 document and check its challenge against ``expected_nonce``.

    ``expected_nonce`` is the nonce the caller sent, never one read from the
    document. Parsing checks nonce equality and recomputes the endorsed
    section hashes and REPORT_DATA. Unknown and duplicate members reject,
    hex must be lowercase, base64 canonical, and item IDs unique.

    Raises InvalidInputError for a nonce of the wrong length, and ValueError
    for a document that fails to parse or bind.
    """
    raise NotImplementedError


def _decode(data: bytes) -> Document:
    """Apply parse()'s structural rules without binding the challenge to a nonce."""
    raise NotImplementedError


def random_nonce() -> bytes:
    """A fresh, cryptographically random NONCE_SIZE-byte challenge nonce."""
    raise NotImplementedError


def compute_report_data(nonce: bytes, crypto_material_hash: bytes, device_evidence_hash: bytes) -> bytes:
    """Derive the 64-byte REPORT_DATA per https://tinfoil.sh/report-data/v1."""
    raise NotImplementedError
