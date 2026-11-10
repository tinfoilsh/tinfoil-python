"""Authentication of a TDX quote: the PCK chain up to the embedded Intel SGX root, the quote and QE report
signatures, and the DCAP collateral appraisal, all from the document's captured PCS responses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tinfoil._v3.verifier._document.collateral.tdx import PCSResponse
from tinfoil._v3.verifier._measurement import TDX
from tinfoil._v3.verifier._quote.tdx.identity import IdentityError, identity
from tinfoil._v3.verifier._quote.tdx.lib.abi import QuoteV4, TdxQuoteParseError, parse_quote
from tinfoil._v3.verifier._quote.tdx.lib.chain import (
    PCKCertificateChain,
    TdxVerificationError,
    extract_ca_from_pck_cert,
    extract_pck_cert_chain,
    verify_pck_certificate_chain,
    verify_quote_signatures,
)
from tinfoil._v3.verifier._quote.tdx.lib.collateral import (
    CollateralError,
    TcbLevel,
    TdxCollateral,
    check_collateral_expiration,
    verify_qe_identity,
    verify_qe_report,
    verify_tcb_info,
    verify_td_quote_body,
)
from tinfoil._v3.verifier._quote.tdx.lib.pck import PckExtensionError, PckExtensions, extract_pck_extensions
from tinfoil._v3.verifier._quote.tdx.pcs import (
    PCSReplay,
    PCSReplayError,
    check_issue_dates,
    minimum_tcb_evaluation_data_number,
)
from tinfoil._v3.verifier._trust import INTEL_SGX_ROOT_CA_PEM
from tinfoil._v3.verifier._x509.certificate import Certificate, X509Error, parse_certificates_pem

QUOTE_VERSION = 4
RTMR_COUNT = 4

_LIBRARY_ERRORS = (
    TdxQuoteParseError,
    TdxVerificationError,
    PckExtensionError,
    CollateralError,
    PCSReplayError,
    IdentityError,
    X509Error,
)


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
    body = quote.quote.td_quote_body
    return body.mr_td.hex(), body.rtmrs[0].hex()


def trusted_root(options: Options | None) -> Certificate:
    """The embedded Intel SGX root, or the replacement in ``options``; a PEM without a certificate is an error.

    The first certificate of the PEM is the root; the embedded PEM is parsed
    on use, so a malformed one is a verification error rather than an
    import-time failure.
    """
    pem = INTEL_SGX_ROOT_CA_PEM if options is None or options.test_only_root_pem is None else options.test_only_root_pem
    try:
        return parse_certificates_pem(pem)[0]
    except X509Error as err:
        raise TdxAuthenticationError(f"parsing Intel SGX root certificate: {err}") from err


def check_reserved_bytes(quote: QuoteV4) -> None:
    """Reject non-zero reserved header bytes (8-11) and non-zero bytes after the signed data: trailing bytes may only
    be the zero padding of the fixed-size buffer the quote was read from."""
    if any(quote.header.reserved):
        raise TdxAuthenticationError("TDX quote header carries non-zero reserved bytes")
    if any(quote.extra_bytes):
        raise TdxAuthenticationError("TDX quote carries non-zero bytes after the signed data")


def authenticate(evidence: Evidence, now: datetime, options: Options | None = None) -> Quote:
    """Verify the quote's signature chain up to the pinned Intel SGX root, replaying the captured PCS collateral.

    In order: ``now`` is timezone-aware; the root is selected; the quote
    parses as v4; reserved and trailing bytes are zero; the captured
    responses are indexed; the PCK chain and the PCK extensions are read;
    the collateral for the PCK's FMSPC and CA is replayed from the captured
    responses (TCB Info, QE Identity, PCK CRL, root CRL, each CRL within
    its window at ``now``); the PCK chain is verified to the root at
    ``now`` with revocation; nothing in the collateral is expired at
    ``now``; TCB Info and QE Identity verify against their issuer chains to
    the root; the quote and QE report signatures and the QE report data
    binding verify; the TD quote body and QE report are appraised against
    the collateral; TCB Info and QE Identity are not before their issue
    dates; the identity is the PPID; the registers are 48 bytes each.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise TdxAuthenticationError("verification time is required")
    root = trusted_root(options)
    try:
        return _authenticate(evidence, now, root)
    except _LIBRARY_ERRORS as err:
        raise TdxAuthenticationError(f"verifying TDX quote: {err}") from err


def _authenticate(evidence: Evidence, now: datetime, root: Certificate) -> Quote:
    quote = parse_quote(evidence.quote)
    check_reserved_bytes(quote)
    replay = PCSReplay(evidence.pcs, now)

    chain = extract_pck_cert_chain(quote)
    extensions = extract_pck_extensions(chain.pck_cert)
    ca = extract_ca_from_pck_cert(chain.pck_cert)
    collateral = replay.collateral(extensions.fmspc, ca)

    roots = (root,)
    verify_pck_certificate_chain(chain, roots, collateral.root_crl.crl, collateral.pck_crl.crl, now)
    check_collateral_expiration(collateral, now)
    verify_tcb_info(collateral, roots, now)
    verify_qe_identity(collateral, roots, now)
    verify_quote_signatures(quote, evidence.quote, chain.pck_cert)
    tcb_level = verify_td_quote_body(quote.td_quote_body, collateral.tcb_info.tcb_info, extensions)
    verify_qe_report(
        quote.signed_data.certification_data.qe_report_data.qe_report_parsed, collateral.qe_identity.enclave_identity
    )

    check_issue_dates(collateral, now)
    machine = identity(quote)
    evaluation = minimum_tcb_evaluation_data_number(collateral)

    body = quote.td_quote_body
    if len(body.rtmrs) != RTMR_COUNT:
        raise TdxAuthenticationError(f"TDX quote carries {len(body.rtmrs)} RTMRs, want {RTMR_COUNT}")
    try:
        measurement = TDX(
            mrtd=body.mr_td, rtmr0=body.rtmrs[0], rtmr1=body.rtmrs[1], rtmr2=body.rtmrs[2], rtmr3=body.rtmrs[3]
        )
    except ValueError as err:
        raise TdxAuthenticationError(f"TDX quote measurement registers: {err}") from err
    return Quote(
        identity=machine,
        measurement=measurement,
        tcb_evaluation_data_number=evaluation,
        quote=quote,
        pck_chain=chain,
        pck_extensions=extensions,
        collateral=collateral,
        tcb_level=tcb_level,
    )
