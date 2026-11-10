"""Authentication of a TDX quote: the PCK chain up to the embedded Intel SGX root, the quote and QE report
signatures, and the DCAP collateral appraisal, all from the document's captured PCS responses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tinfoil._v3.verifier._document.collateral.tdx import PCSResponse
from tinfoil._v3.verifier._measurement import TDX
from tinfoil._v3.verifier._quote.tdx.lib.abi import QuoteV4
from tinfoil._v3.verifier._quote.tdx.lib.chain import PCKCertificateChain
from tinfoil._v3.verifier._quote.tdx.lib.collateral import TcbLevel, TdxCollateral
from tinfoil._v3.verifier._quote.tdx.lib.pck import PckExtensions
from tinfoil._v3.verifier._x509.certificate import Certificate

QUOTE_VERSION = 4
RTMR_COUNT = 4


class TdxAuthenticationError(ValueError):
    """A quote whose chain, signatures or collateral appraisal does not check out."""


@dataclass(frozen=True, slots=True)
class Options:
    """Per-authentication overrides; the default selects the embedded Intel SGX root.

    This package is private and the public verifier builds these options
    itself, so the override is reachable only from the conformance adapter's
    internal factory, never from the public constructor.
    """

    test_only_root_pem: bytes | None = None
    """A replacement Intel SGX root certificate PEM for the conformance harness."""


@dataclass(frozen=True, slots=True)
class Evidence:
    """A TDX quote with the Intel PCS responses captured to authenticate it."""

    quote: bytes
    pcs: tuple[PCSResponse, ...]
    """Replayed instead of fetched."""


@dataclass(frozen=True, slots=True)
class Quote:
    """A signature-verified TDX quote, not yet compared against any expected value."""

    identity: str
    """The machines-map lookup key: PPID, lowercase hex."""
    measurement: TDX
    """The authenticated MRTD and four RTMRs."""
    tcb_evaluation_data_number: int
    """The lower of the TCB Info and QE Identity evaluation numbers in the verified collateral."""
    quote: QuoteV4
    pck_chain: PCKCertificateChain
    pck_extensions: PckExtensions
    collateral: TdxCollateral
    tcb_level: TcbLevel
    """The matched TCB level."""


def platform_measurements(quote: Quote) -> tuple[str, str]:
    """MRTD and RTMR0 as lowercase hex, read from the authenticated quote body."""
    raise NotImplementedError


def trusted_root(options: Options | None) -> Certificate:
    """The embedded Intel SGX root, or the replacement in ``options``; a PEM without a certificate is an error."""
    raise NotImplementedError


def check_reserved_bytes(quote: QuoteV4) -> None:
    """Reject non-zero reserved header bytes (8-11) and non-zero bytes after the signed data: trailing bytes may only
    be the zero padding of the fixed-size buffer the quote was read from."""
    raise NotImplementedError


def authenticate(evidence: Evidence, now: datetime, options: Options | None = None) -> Quote:
    """Verify the quote's signature chain up to the pinned Intel SGX root, replaying the captured PCS collateral.

    In order: ``now`` is timezone-aware; the root is selected; the quote
    parses as v4 with the Intel QE vendor id; reserved and trailing bytes
    are zero; the PCK chain is extracted and verified to the root at
    ``now``; the quote and QE report signatures and the QE report data
    binding verify; the PCK extensions are read; the collateral for the
    PCK's FMSPC and CA is replayed from the captured responses (TCB Info,
    QE Identity, PCK CRL, root CRL), each verified against its issuer
    chain to the root, each CRL within its window at ``now``, TCB Info and
    QE Identity not before their issue dates and not after their next
    updates; revocation, TCB status, TDX module identity and QE identity
    are appraised; the identity is the PPID; the registers are 48 bytes
    each.
    """
    raise NotImplementedError
