"""The v3 attestation document and its strict parsing.

A document carries a challenge, CPU evidence, two endorsed sections
(crypto_material and device_evidence) and collateral. The endorsed sections
are hash-bound into the CPU quote's REPORT_DATA::

    crypto_material_hash = SHA-256(base64-decoded crypto_material)
    device_evidence_hash = SHA-256(base64-decoded device_evidence)
    REPORT_DATA[0:32]    = SHA-256("https://tinfoil.sh/report-data/v1" || nonce
                                   || crypto_material_hash || device_evidence_hash)
    REPORT_DATA[32:64]   = 32 zero bytes

Parsing checks the challenge against the caller's nonce but authenticates
nothing. No part of a document is trusted until its CPU quote proves that
the hardware bound this REPORT_DATA.
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
"""The size of a challenge nonce, in bytes."""

SEV_SNP_REPORT_V1_FORMAT = _formats.SEV_SNP_REPORT_V1
"""Format of CPU evidence that is a raw 1184-byte AMD SEV-SNP attestation report."""
TDX_QUOTE_V1_FORMAT = _formats.TDX_QUOTE_V1
"""Format of CPU evidence that is a raw Intel TDX Quote v4."""
NVIDIA_GPU_EVIDENCE_V1_FORMAT = _formats.NVIDIA_GPU_EVIDENCE_V1
"""Format of device evidence that is an NVIDIA GPU evidence payload."""

KEY_SPKI_FP_SHA256_V1_FORMAT = _formats.KEY_SPKI_FP_SHA256_V1
"""Format of a crypto material item whose data is the 32-byte SHA-256 of a DER SubjectPublicKeyInfo."""
KEY_SPKI_V1_FORMAT = _formats.KEY_SPKI_V1
"""Format of a crypto material item whose data is a complete DER SubjectPublicKeyInfo.

Consumers must check that the key algorithm suits their protocol.
"""
KEY_X25519_HPKE_V1_FORMAT = _formats.KEY_X25519_HPKE_V1
"""Format of a crypto material item whose data is a raw 32-byte X25519 public key for HPKE (RFC 9180)."""

CRYPTO_MATERIAL_ID_TLS = _formats.CRYPTO_MATERIAL_ID_TLS
"""The conventional ID of the crypto material item holding the TLS key fingerprint."""
CRYPTO_MATERIAL_ID_HPKE = _formats.CRYPTO_MATERIAL_ID_HPKE
"""The conventional ID of the crypto material item holding the HPKE public key."""


class InvalidInputError(ValueError):
    """The caller passed parse() invalid input, such as a nonce of the wrong length.

    parse() raises a plain ValueError, not this type, for a malformed document.
    """


@dataclass(frozen=True, slots=True)
class CPUEvidence:
    """The hardware evidence a document carries."""

    format: str
    """The evidence format, such as SEV_SNP_REPORT_V1_FORMAT, which selects the platform."""
    report: bytes
    """The raw SEV-SNP report or TDX quote."""


@dataclass(frozen=True, slots=True)
class CryptoMaterialItem:
    """A key the enclave endorses."""

    id: str
    """The item's ID, unique within the document, such as CRYPTO_MATERIAL_ID_TLS."""
    format: str
    """The item format, such as KEY_SPKI_FP_SHA256_V1_FORMAT, which defines what ``data`` holds."""
    data: str
    """The key material, as lowercase hex."""


@dataclass(frozen=True, slots=True, kw_only=True)
class DeviceEvidenceItem:
    """Evidence from one attached device, such as a GPU."""

    id: str
    """The item's ID, unique within the document."""
    kind: str
    """The kind of device, such as ``gpu``."""
    vendor: str
    format: str
    """The evidence format, such as NVIDIA_GPU_EVIDENCE_V1_FORMAT."""
    evidence: bytes
    """The evidence payload, as JSON."""


class Document:
    """A parsed v3 attestation document.

    Only parse() creates documents. A document is immutable. Its accessors
    return decoded values, and lookups return None when the document carries
    no matching element.
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
        object.__setattr__(document, "_evidence", evidence)
        object.__setattr__(document, "_crypto_material", crypto_material)
        object.__setattr__(document, "_device_evidence", device_evidence)
        object.__setattr__(document, "_collateral", collateral)
        object.__setattr__(document, "_collateral_format", collateral_format)
        object.__setattr__(document, "_report_data", report_data)
        return document

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"cannot assign to {name!r}: documents are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"cannot delete {name!r}: documents are immutable")

    @property
    def cpu_evidence(self) -> CPUEvidence:
        """The CPU evidence."""
        return self._evidence

    @property
    def crypto_material(self) -> tuple[CryptoMaterialItem, ...]:
        """The items of the endorsed crypto_material section."""
        return self._crypto_material

    @property
    def device_evidence(self) -> tuple[DeviceEvidenceItem, ...]:
        """The items of the endorsed device_evidence section."""
        return self._device_evidence

    def crypto_material_item(self, item_id: str) -> CryptoMaterialItem | None:
        """Return the crypto_material item with ID ``item_id``, or None."""
        return next((item for item in self._crypto_material if item.id == item_id), None)

    @property
    def collateral_format(self) -> str:
        """The collateral format, which selects how reference values are verified.

        A document that declares no collateral format carries the legacy
        format, attestation-collaterals/v2.
        """
        return self._collateral_format or _formats.COLLATERAL_V2

    @property
    def cpu_endorsements(self) -> CPUEndorsements:
        """The vendor collateral for the CPU evidence's platform.

        Only the members the evidence format uses are set; the rest are None.
        """
        cpu = self._collateral.cpu
        if self._evidence.format == _formats.SEV_SNP_REPORT_V1:
            return CPUEndorsements(amd_vcek=cpu.amd_vcek, amd_crl=cpu.amd_crl)
        if self._evidence.format == _formats.TDX_QUOTE_V1:
            return CPUEndorsements(intel_pcs=cpu.intel_pcs)
        return CPUEndorsements()

    @property
    def sigstore_code(self) -> SigstoreRef | None:
        """The code provenance entry (sigstore-code), or None."""
        return self._collateral.sigstore_code

    @property
    def sigstore_platform(self) -> SigstoreRef | None:
        """The platform-endorsements entry (sigstore-platform), or None."""
        return self._collateral.sigstore_platform

    def freshness(self, entry_id: str) -> Freshness | None:
        """Return the freshness witness or approval with collateral ID ``entry_id``, or None."""
        return self._collateral.freshness.get(entry_id)

    @property
    def config_endorsement(self) -> ConfigEndorsement | None:
        """The config collateral, or None.

        It holds exact config bytes and, when the config is signed, their
        approval bundle. Nothing in it is authenticated yet.
        """
        return self._collateral.config

    @property
    def runtime(self) -> Runtime | None:
        """The runtime collateral, or None.

        It holds a runtime manifest and its provenance bundle. Nothing in it
        is authenticated yet.
        """
        return self._collateral.runtime

    def config_platform(self) -> SigstoreRef | None:
        """Return the platform-endorsements entry config verification uses, or None.

        Raises:
            ValueError: More than one entry could serve as it.
        """
        return self._collateral.unambiguous_config_platform()

    @property
    def expected_report_data(self) -> bytes | None:
        """The 64-byte REPORT_DATA the CPU quote must bind, or None.

        parse() recomputes it from the caller's nonce and the endorsed
        sections. It is None only for a document decoded without a nonce,
        which the conformance adapter does to test single layers; such a
        document's quote must never be compared against anything.
        """
        return self._report_data


def parse(data: bytes, expected_nonce: bytes) -> Document:
    """Strictly parse a v3 document and check its challenge against ``expected_nonce``.

    Parsing checks that the challenge echoes the nonce, recomputes the
    endorsed section hashes and REPORT_DATA, and compares them with the
    document's. It rejects unknown and duplicate members, hex that isn't
    lowercase, non-canonical base64 and duplicate item IDs.

    Args:
        data: The document as received.
        expected_nonce: The NONCE_SIZE-byte nonce the caller sent. Never use
            a nonce read from the document.

    Raises:
        InvalidInputError: ``expected_nonce`` is invalid.
        ValueError: The document is malformed or isn't bound to the nonce.
    """
    raise NotImplementedError


def _decode(data: bytes) -> Document:
    """Apply parse()'s structural rules without binding the challenge to a nonce."""
    raise NotImplementedError


def random_nonce() -> bytes:
    """Return a fresh, cryptographically random NONCE_SIZE-byte challenge nonce."""
    raise NotImplementedError


def compute_report_data(nonce: bytes, crypto_material_hash: bytes, device_evidence_hash: bytes) -> bytes:
    """Return the 64-byte REPORT_DATA derived as https://tinfoil.sh/report-data/v1 specifies."""
    raise NotImplementedError
