"""CPU quote authentication (block B3): a genuine CPU produced these bytes.

Authentication verifies the quote's signature chain up to the pinned vendor
root from document-carried collateral only. It compares nothing against
expected values; that is assembly and validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..collateral import CPUEndorsements
from ..document import CPUEvidence
from ..measurement import Measurement


@dataclass(frozen=True, slots=True, kw_only=True)
class VendorRoots:
    """Vendor trust anchors. None selects the embedded production anchor."""

    # The AMD ASK then ARK certificates, PEM-encoded (the KDS cert_chain
    # layout).
    amd: bytes | None = None
    # The Intel SGX root CA certificate, PEM-encoded.
    intel: bytes | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthenticatedQuote:
    """A signature-verified quote, not yet compared against any expected value."""

    # PLATFORM_SEV_SNP or PLATFORM_TDX.
    platform: str
    # The authenticated machine identifier (SEV CHIP_ID or TDX PPID), lowercase
    # hex.
    identity: str
    # The launch measurement (SEV) or MRTD and RTMRs (TDX).
    measurement: Measurement


def authenticate(
    evidence: CPUEvidence, endorsements: CPUEndorsements, now: datetime, roots: VendorRoots
) -> AuthenticatedQuote:
    """Verify ``evidence`` up to the vendor root using only ``endorsements``.

    Certificate and CRL validity windows are judged at ``now``, the instant
    the rest of the document is appraised at; this never reads the clock.
    """
    raise NotImplementedError
