"""
TDX Attestation Validation.

This module provides the top-level TDX attestation verification flow,
integrating quote parsing, cryptographic verification, and TCB validation.

Usage:
    from tinfoil.attestation.validate_tdx import verify_tdx_attestation

    verification = verify_tdx_attestation(attestation_doc)
    # verification.measurement contains the 5 TDX measurements
    # verification.public_key_fp contains the TLS key fingerprint
"""

import base64
import gzip
from dataclasses import dataclass
from typing import Optional

from .abi_tdx import parse_quote, QuoteV4, TdxQuoteParseError
from .verify_tdx import (
    verify_tdx_quote,
    TdxVerificationError,
    PCKCertificateChain,
)
from .pck_extensions import extract_pck_extensions, PckExtensions, PckExtensionError
from .collateral_tdx import (
    fetch_collateral,
    validate_tcb_status,
    validate_tdx_module_identity,
    validate_qe_identity,
    validate_certificate_revocation,
    check_collateral_freshness,
    CollateralError,
    TdxCollateral,
    TcbLevel,
)


class TdxValidationError(Exception):
    """Raised when TDX attestation validation fails."""
    pass


@dataclass
class TdxValidationResult:
    """
    Result of TDX attestation validation.

    Contains the validated quote, measurements, and TCB status.
    """
    quote: QuoteV4
    pck_chain: PCKCertificateChain
    pck_extensions: PckExtensions
    collateral: Optional[TdxCollateral]
    tcb_level: Optional[TcbLevel]
    measurements: list[str]  # [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
    tls_key_fp: str
    hpke_public_key: Optional[str]


def verify_tdx_attestation(
    attestation_doc: str,
    is_compressed: bool = True,
    skip_collateral: bool = False,
    min_tcb_evaluation_data_number: Optional[int] = None,
) -> TdxValidationResult:
    """
    Verify a TDX attestation document.

    This is the main entry point for TDX attestation verification.
    It performs the complete verification flow:

    1. Decode and decompress the attestation document
    2. Parse the TDX quote
    3. Verify cryptographic signatures (PCK chain, quote, QE report)
    4. Extract PCK certificate extensions (FMSPC, TCB)
    5. Fetch and validate collateral from Intel PCS
    6. Extract measurements and report data

    Args:
        attestation_doc: Base64-encoded attestation document
        is_compressed: Whether the document is gzip compressed
        skip_collateral: Skip collateral fetching (for testing/offline use)
        min_tcb_evaluation_data_number: Optional minimum tcbEvaluationDataNumber
            threshold for collateral freshness checks

    Returns:
        TdxValidationResult containing validated data

    Raises:
        TdxValidationError: If any validation step fails
    """
    # Step 1: Decode the attestation document
    try:
        raw_bytes = base64.b64decode(attestation_doc)
    except Exception as e:
        raise TdxValidationError(f"Failed to decode base64: {e}")

    if is_compressed:
        try:
            raw_bytes = gzip.decompress(raw_bytes)
        except Exception as e:
            raise TdxValidationError(f"Failed to decompress: {e}")

    # Step 2: Parse the TDX quote
    try:
        quote = parse_quote(raw_bytes)
    except TdxQuoteParseError as e:
        raise TdxValidationError(f"Failed to parse TDX quote: {e}")

    # Step 3: Verify cryptographic signatures
    try:
        pck_chain = verify_tdx_quote(quote, raw_bytes)
    except TdxVerificationError as e:
        raise TdxValidationError(f"TDX quote verification failed: {e}")

    # Step 4: Extract PCK certificate extensions
    try:
        pck_extensions = extract_pck_extensions(pck_chain.pck_cert)
    except PckExtensionError as e:
        raise TdxValidationError(f"Failed to extract PCK extensions: {e}")

    # Step 5: Fetch and validate collateral (optional)
    collateral = None
    tcb_level = None

    if not skip_collateral:
        try:
            collateral = fetch_collateral(pck_extensions, pck_chain.pck_cert)
            check_collateral_freshness(
                collateral,
                min_tcb_evaluation_data_number=min_tcb_evaluation_data_number,
            )

            # Validate certificate revocation (both PCK leaf and intermediate CA)
            validate_certificate_revocation(
                collateral, pck_chain.pck_cert, pck_chain.intermediate_cert
            )

            # Validate TCB status
            tcb_level = validate_tcb_status(
                collateral.tcb_info.tcb_info,
                quote.td_quote_body.tee_tcb_svn,
                pck_extensions,
            )

            # Validate TDX module identity (if module identities present in TCB Info)
            validate_tdx_module_identity(
                collateral.tcb_info.tcb_info,
                quote.td_quote_body.tee_tcb_svn,
                quote.td_quote_body.mr_signer_seam,
                quote.td_quote_body.seam_attributes,
            )

            # Validate QE identity
            qe_report = quote.signed_data.certification_data.qe_report_data
            if qe_report is not None:
                qe_parsed = qe_report.qe_report_parsed
                # Convert misc_select int to 4 bytes (little-endian)
                miscselect_bytes = qe_parsed.misc_select.to_bytes(4, byteorder='little')
                validate_qe_identity(
                    collateral.qe_identity.enclave_identity,
                    qe_parsed.isv_svn,
                    qe_parsed.mr_signer,
                    miscselect_bytes,
                    qe_parsed.attributes,
                    qe_parsed.isv_prod_id,
                )
        except CollateralError as e:
            raise TdxValidationError(f"Collateral validation failed: {e}")

    # Step 6: Extract measurements and report data
    measurements = quote.td_quote_body.get_measurements()
    measurements_hex = [m.hex() for m in measurements]

    # Extract TLS key fingerprint and HPKE key from report_data
    report_data = quote.td_quote_body.report_data
    tls_key_fp = report_data[0:32].hex()
    hpke_public_key = report_data[32:64].hex() if len(report_data) >= 64 else None

    return TdxValidationResult(
        quote=quote,
        pck_chain=pck_chain,
        pck_extensions=pck_extensions,
        collateral=collateral,
        tcb_level=tcb_level,
        measurements=measurements_hex,
        tls_key_fp=tls_key_fp,
        hpke_public_key=hpke_public_key,
    )


def verify_tdx_quote_only(raw_quote: bytes) -> TdxValidationResult:
    """
    Verify a raw TDX quote without collateral validation.

    This is useful for testing or when collateral is not available.
    It performs cryptographic verification but skips TCB status checks.

    Args:
        raw_quote: Raw TDX quote bytes

    Returns:
        TdxValidationResult (with collateral=None, tcb_level=None)

    Raises:
        TdxValidationError: If verification fails
    """
    # Parse the quote
    try:
        quote = parse_quote(raw_quote)
    except TdxQuoteParseError as e:
        raise TdxValidationError(f"Failed to parse TDX quote: {e}")

    # Verify cryptographic signatures
    try:
        pck_chain = verify_tdx_quote(quote, raw_quote)
    except TdxVerificationError as e:
        raise TdxValidationError(f"TDX quote verification failed: {e}")

    # Extract PCK certificate extensions
    try:
        pck_extensions = extract_pck_extensions(pck_chain.pck_cert)
    except PckExtensionError as e:
        raise TdxValidationError(f"Failed to extract PCK extensions: {e}")

    # Extract measurements
    measurements = quote.td_quote_body.get_measurements()
    measurements_hex = [m.hex() for m in measurements]

    # Extract report data
    report_data = quote.td_quote_body.report_data
    tls_key_fp = report_data[0:32].hex()
    hpke_public_key = report_data[32:64].hex() if len(report_data) >= 64 else None

    return TdxValidationResult(
        quote=quote,
        pck_chain=pck_chain,
        pck_extensions=pck_extensions,
        collateral=None,
        tcb_level=None,
        measurements=measurements_hex,
        tls_key_fp=tls_key_fp,
        hpke_public_key=hpke_public_key,
    )
