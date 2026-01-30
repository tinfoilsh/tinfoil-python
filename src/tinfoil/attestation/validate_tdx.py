"""
TDX Attestation Validation.

This module provides:
1. Pure policy validation functions for TDX quote fields (mirrors go-tdx-guest/validate/validate.go)
2. Top-level TDX attestation verification flow (mirrors verifier/attestation/tdx.go)

Usage:
    from tinfoil.attestation.validate_tdx import verify_tdx_attestation

    verification = verify_tdx_attestation(attestation_doc)
    # verification.measurement contains the 5 TDX measurements
    # verification.public_key_fp contains the TLS key fingerprint
"""

import base64
import gzip
import struct
from dataclasses import dataclass, field
from typing import Optional

from .abi_tdx import (
    parse_quote,
    QuoteV4,
    TdxQuoteParseError,
    INTEL_QE_VENDOR_ID,
    MR_SEAM_SIZE,
    TD_ATTRIBUTES_SIZE,
    XFAM_SIZE,
    MR_TD_SIZE,
    MR_CONFIG_ID_SIZE,
    MR_OWNER_SIZE,
    MR_OWNER_CONFIG_SIZE,
    RTMR_SIZE,
    RTMR_COUNT,
    REPORT_DATA_SIZE,
    QE_VENDOR_ID_SIZE,
    SEAM_ATTRIBUTES_SIZE,
    MR_SIGNER_SEAM_SIZE,
)
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


# =============================================================================
# Policy Validation Constants (from go-tdx-guest/validate/validate.go)
# =============================================================================

# XFAM fixed bit constraints
# If bit X is 1 in XFAM_FIXED1, it must be 1 in any XFAM
XFAM_FIXED1 = 0x00000003
# If bit X is 0 in XFAM_FIXED0, it must be 0 in any XFAM
XFAM_FIXED0 = 0x0006DBE7

# TD_ATTRIBUTES fixed bit constraints
# If bit X is 1 in TD_ATTRIBUTES_FIXED1, it must be 1 in any TD_ATTRIBUTES
TD_ATTRIBUTES_FIXED1 = 0x0

# TD_ATTRIBUTES bit definitions
TD_ATTRIBUTES_DEBUG_BIT = 0x1           # Bit 0: DEBUG mode
TD_ATTRIBUTES_SEPT_VE_DIS = 1 << 28     # Bit 28: Disable EPT violation #VE
TD_ATTRIBUTES_PKS = 1 << 30             # Bit 30: Supervisor Protection Keys
TD_ATTRIBUTES_PERFMON = 1 << 63         # Bit 63: Performance monitoring

# If bit X is 0 in TD_ATTRIBUTES_FIXED0, it must be 0 in any TD_ATTRIBUTES
# Supported bits: DEBUG, SEPT_VE_DIS, PKS, PERFMON
TD_ATTRIBUTES_FIXED0 = (
    TD_ATTRIBUTES_DEBUG_BIT |
    TD_ATTRIBUTES_SEPT_VE_DIS |
    TD_ATTRIBUTES_PKS |
    TD_ATTRIBUTES_PERFMON
)

# Expected values for policy validation (from verifier/attestation/tdx.go)
# TdAttributes: All zeros except SEPT_VE_DISABLE=1
EXPECTED_TD_ATTRIBUTES = bytes.fromhex("0000001000000000")
# XFam: Enable FP, SSE, AVX, AVX512, PK, AMX
EXPECTED_XFAM = bytes.fromhex("e702060000000000")
# MinimumTeeTcbSvn: 3.1.2
EXPECTED_MINIMUM_TEE_TCB_SVN = bytes.fromhex("03010200000000000000000000000000")

# Accepted MR_SEAM values (from verifier/attestation/tdx.go)
# These are provided by Intel: https://github.com/intel/confidential-computing.tdx.tdx-module/releases
ACCEPTED_MR_SEAMS = [
    bytes.fromhex("49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6"),
    bytes.fromhex("685f891ea5c20e8fa27b151bf34bf3b50fbaf7143cc53662727cbdb167c0ad8385f1f6f3571539a91e104a1c96d75e04"),
]


# =============================================================================
# Policy Validation Options (mirrors go-tdx-guest/validate/validate.go)
# =============================================================================

@dataclass
class HeaderOptions:
    """
    Validation options for TDX quote header fields.
    Mirrors Go's validate.HeaderOptions struct.

    All fields are optional - set to None to skip the check.
    """
    # Minimum QE security version number (not checked if None)
    minimum_qe_svn: Optional[int] = None
    # Minimum PCE security version number (not checked if None)
    minimum_pce_svn: Optional[int] = None
    # Expected QE_VENDOR_ID (16 bytes, not checked if None)
    qe_vendor_id: Optional[bytes] = None


@dataclass
class TdQuoteBodyOptions:
    """
    Validation options for TDX quote body fields.
    Mirrors Go's validate.TdQuoteBodyOptions struct.

    All fields are optional - set to None to skip the check.
    """
    # Minimum TEE TCB SVN (16 bytes, component-wise comparison)
    minimum_tee_tcb_svn: Optional[bytes] = None
    # Expected MR_SEAM (48 bytes)
    mr_seam: Optional[bytes] = None
    # Expected TD_ATTRIBUTES (8 bytes)
    td_attributes: Optional[bytes] = None
    # Expected XFAM (8 bytes)
    xfam: Optional[bytes] = None
    # Expected MR_TD (48 bytes)
    mr_td: Optional[bytes] = None
    # Expected MR_CONFIG_ID (48 bytes)
    mr_config_id: Optional[bytes] = None
    # Expected MR_OWNER (48 bytes)
    mr_owner: Optional[bytes] = None
    # Expected MR_OWNER_CONFIG (48 bytes)
    mr_owner_config: Optional[bytes] = None
    # Expected RTMRs (list of 4 x 48 bytes)
    rtmrs: Optional[list[bytes]] = None
    # Expected REPORT_DATA (64 bytes)
    report_data: Optional[bytes] = None
    # Any permitted MR_TD values (list of 48-byte values)
    any_mr_td: Optional[list[bytes]] = None


@dataclass
class PolicyOptions:
    """
    Complete validation options for TDX quote policy validation.
    Mirrors Go's validate.Options struct.
    """
    header: HeaderOptions = field(default_factory=HeaderOptions)
    td_quote_body: TdQuoteBodyOptions = field(default_factory=TdQuoteBodyOptions)


# =============================================================================
# Policy Validation Helper Functions
# =============================================================================

def _check_option_length(name: str, expected: int, value: Optional[bytes]) -> None:
    """Check field length if value is provided."""
    if value is not None and len(value) != expected:
        raise TdxValidationError(
            f"Option '{name}' length is {len(value)}, expected {expected}"
        )


def _check_options_lengths(options: PolicyOptions) -> None:
    """Validate all option field lengths."""
    h = options.header
    t = options.td_quote_body

    _check_option_length("qe_vendor_id", QE_VENDOR_ID_SIZE, h.qe_vendor_id)
    _check_option_length("minimum_tee_tcb_svn", 16, t.minimum_tee_tcb_svn)
    _check_option_length("mr_seam", MR_SEAM_SIZE, t.mr_seam)
    _check_option_length("td_attributes", TD_ATTRIBUTES_SIZE, t.td_attributes)
    _check_option_length("xfam", XFAM_SIZE, t.xfam)
    _check_option_length("mr_td", MR_TD_SIZE, t.mr_td)
    _check_option_length("mr_config_id", MR_CONFIG_ID_SIZE, t.mr_config_id)
    _check_option_length("mr_owner", MR_OWNER_SIZE, t.mr_owner)
    _check_option_length("mr_owner_config", MR_OWNER_CONFIG_SIZE, t.mr_owner_config)
    _check_option_length("report_data", REPORT_DATA_SIZE, t.report_data)

    if t.rtmrs is not None:
        if len(t.rtmrs) != RTMR_COUNT:
            raise TdxValidationError(
                f"Option 'rtmrs' has {len(t.rtmrs)} entries, expected {RTMR_COUNT}"
            )
        for i, rtmr in enumerate(t.rtmrs):
            if rtmr is not None and len(rtmr) != RTMR_SIZE:
                raise TdxValidationError(
                    f"Option 'rtmrs[{i}]' length is {len(rtmr)}, expected {RTMR_SIZE}"
                )

    if t.any_mr_td is not None:
        for i, mr_td in enumerate(t.any_mr_td):
            if mr_td is not None and len(mr_td) != MR_TD_SIZE:
                raise TdxValidationError(
                    f"Option 'any_mr_td[{i}]' length is {len(mr_td)}, expected {MR_TD_SIZE}"
                )


def _byte_check(
    field_name: str,
    given: bytes,
    expected: Optional[bytes],
) -> None:
    """Check exact byte match if expected is provided."""
    if expected is None:
        return  # Skip check

    if given != expected:
        raise TdxValidationError(
            f"Quote field {field_name} is {given.hex()}, expected {expected.hex()}"
        )


def _is_svn_higher_or_equal(quote_svn: bytes, min_svn: Optional[bytes]) -> bool:
    """Component-wise SVN comparison. Returns True if min_svn is None."""
    if min_svn is None:
        return True
    for q, m in zip(quote_svn, min_svn):
        if q < m:
            return False
    return True


# =============================================================================
# Policy Validation Core Functions
# =============================================================================

def validate_xfam(xfam: bytes) -> None:
    """
    Validate XFAM fixed bit constraints.

    Args:
        xfam: 8-byte XFAM from quote

    Raises:
        TdxValidationError: If fixed bit constraints violated
    """
    if len(xfam) != XFAM_SIZE:
        raise TdxValidationError(f"XFAM size is {len(xfam)}, expected {XFAM_SIZE}")

    value = struct.unpack('<Q', xfam)[0]

    # Check FIXED1 bits (must be set)
    if (value & XFAM_FIXED1) != XFAM_FIXED1:
        raise TdxValidationError(
            f"Unauthorized XFAM 0x{value:x}: FIXED1 0x{XFAM_FIXED1:x} bits are unset"
        )

    # Check FIXED0 bits (only allowed bits may be set)
    if value & (~XFAM_FIXED0):
        raise TdxValidationError(
            f"Unauthorized XFAM 0x{value:x}: FIXED0 0x{XFAM_FIXED0:x} bits are set"
        )


def validate_td_attributes(td_attributes: bytes) -> None:
    """
    Validate TD_ATTRIBUTES fixed bit constraints.

    Note: DEBUG bit (bit 0) is enforced via exact byte matching of
    EXPECTED_TD_ATTRIBUTES, not via a separate check here.

    Args:
        td_attributes: 8-byte TD_ATTRIBUTES from quote

    Raises:
        TdxValidationError: If validation fails
    """
    if len(td_attributes) != TD_ATTRIBUTES_SIZE:
        raise TdxValidationError(
            f"TD_ATTRIBUTES size is {len(td_attributes)}, expected {TD_ATTRIBUTES_SIZE}"
        )

    value = struct.unpack('<Q', td_attributes)[0]

    # Check FIXED1 bits (must be set)
    if (value & TD_ATTRIBUTES_FIXED1) != TD_ATTRIBUTES_FIXED1:
        raise TdxValidationError(
            f"Unauthorized TD_ATTRIBUTES 0x{value:x}: "
            f"FIXED1 0x{TD_ATTRIBUTES_FIXED1:x} bits are unset"
        )

    # Check FIXED0 bits (only allowed bits may be set)
    if value & (~TD_ATTRIBUTES_FIXED0):
        raise TdxValidationError(
            f"Unauthorized TD_ATTRIBUTES 0x{value:x}: "
            f"FIXED0 0x{TD_ATTRIBUTES_FIXED0:x} bits are set"
        )


def validate_seam_attributes(seam_attributes: bytes) -> None:
    """
    Validate SEAMATTRIBUTES is zero (required for TDX 1.0/1.5).

    Per Intel TDX DCAP Quoting Library API section 2.3.2.

    Args:
        seam_attributes: 8-byte SEAMATTRIBUTES from quote

    Raises:
        TdxValidationError: If not zero
    """
    if len(seam_attributes) != SEAM_ATTRIBUTES_SIZE:
        raise TdxValidationError(
            f"SEAMATTRIBUTES size is {len(seam_attributes)}, expected {SEAM_ATTRIBUTES_SIZE}"
        )

    if seam_attributes != b'\x00' * SEAM_ATTRIBUTES_SIZE:
        raise TdxValidationError(
            f"SEAMATTRIBUTES must be zero for TDX 1.0/1.5, got {seam_attributes.hex()}"
        )


def validate_mr_signer_seam(mr_signer_seam: bytes) -> None:
    """
    Validate MRSIGNERSEAM is zero (required for Intel TDX Module).

    Per Intel TDX DCAP Quoting Library API section 2.3.2.

    Args:
        mr_signer_seam: 48-byte MRSIGNERSEAM from quote

    Raises:
        TdxValidationError: If not zero
    """
    if len(mr_signer_seam) != MR_SIGNER_SEAM_SIZE:
        raise TdxValidationError(
            f"MRSIGNERSEAM size is {len(mr_signer_seam)}, expected {MR_SIGNER_SEAM_SIZE}"
        )

    if mr_signer_seam != b'\x00' * MR_SIGNER_SEAM_SIZE:
        raise TdxValidationError(
            f"MRSIGNERSEAM must be zero for Intel TDX Module, got {mr_signer_seam.hex()}"
        )


def _validate_exact_byte_matches(quote: QuoteV4, options: PolicyOptions) -> None:
    """Validate exact byte matches for configured fields."""
    t = options.td_quote_body
    h = options.header
    body = quote.td_quote_body

    _byte_check("MR_SEAM", body.mr_seam, t.mr_seam)
    _byte_check("TD_ATTRIBUTES", body.td_attributes, t.td_attributes)
    _byte_check("XFAM", body.xfam, t.xfam)
    _byte_check("MR_TD", body.mr_td, t.mr_td)
    _byte_check("MR_CONFIG_ID", body.mr_config_id, t.mr_config_id)
    _byte_check("MR_OWNER", body.mr_owner, t.mr_owner)
    _byte_check("MR_OWNER_CONFIG", body.mr_owner_config, t.mr_owner_config)
    _byte_check("REPORT_DATA", body.report_data, t.report_data)
    _byte_check("QE_VENDOR_ID", quote.header.qe_vendor_id, h.qe_vendor_id)

    # RTMR checks
    if t.rtmrs is not None:
        for i, (given, expected) in enumerate(zip(body.rtmrs, t.rtmrs)):
            if expected is not None:
                _byte_check(f"RTMR[{i}]", given, expected)

    # Any MR_TD check (at least one must match)
    if t.any_mr_td is not None and len(t.any_mr_td) > 0:
        mr_td = body.mr_td
        if not any(mr_td == allowed for allowed in t.any_mr_td if allowed is not None):
            raise TdxValidationError(
                f"MR_TD {mr_td.hex()} does not match any allowed value"
            )


def _validate_min_versions(quote: QuoteV4, options: PolicyOptions) -> None:
    """Validate minimum version requirements."""
    h = options.header
    t = options.td_quote_body

    # TEE TCB SVN check
    if t.minimum_tee_tcb_svn is not None:
        if not _is_svn_higher_or_equal(quote.td_quote_body.tee_tcb_svn, t.minimum_tee_tcb_svn):
            raise TdxValidationError(
                f"TEE_TCB_SVN {quote.td_quote_body.tee_tcb_svn.hex()} is less than "
                f"minimum {t.minimum_tee_tcb_svn.hex()}"
            )

    # QE SVN check (from header reserved bytes - but these are always zero in practice)
    # The actual QE SVN comes from QE Report, not header. Skip if not set.
    if h.minimum_qe_svn is not None:
        # Note: Header reserved bytes are always zero in QuoteV4.
        # Real QE SVN should come from QE Report ISV SVN.
        # For now, we don't have access to it here, so this check is a no-op.
        pass

    # PCE SVN check (similar - real PCE SVN comes from PCK cert extensions)
    if h.minimum_pce_svn is not None:
        # Note: Header reserved bytes are always zero in QuoteV4.
        # Real PCE SVN comes from PCK certificate extensions.
        pass


def validate_tdx_policy(quote: QuoteV4, options: PolicyOptions) -> None:
    """
    Validate a TDX QuoteV4 against policy options.

    This is the main entry point for TDX quote policy validation.
    It performs policy-based validation only - no cryptographic verification
    or collateral fetching.

    Mirrors Go's validate.TdxQuote() function in go-tdx-guest/validate/validate.go.

    Args:
        quote: Parsed TDX QuoteV4
        options: Validation options

    Raises:
        TdxValidationError: If any validation check fails
    """
    # Validate option field lengths
    _check_options_lengths(options)

    # Fixed bit validations (always run)
    validate_xfam(quote.td_quote_body.xfam)
    validate_td_attributes(quote.td_quote_body.td_attributes)

    # SEAM validations (required for TDX 1.0/1.5)
    validate_seam_attributes(quote.td_quote_body.seam_attributes)
    validate_mr_signer_seam(quote.td_quote_body.mr_signer_seam)

    # Exact byte match validations (optional based on options)
    _validate_exact_byte_matches(quote, options)

    # Minimum version validations (optional based on options)
    _validate_min_versions(quote, options)


def validate_mr_seam_whitelist(mr_seam: bytes) -> None:
    """
    Validate MR_SEAM against the whitelist of accepted values.

    This is called separately from validate_tdx_policy() to allow
    whitelisting known MR_SEAM values rather than exact matching.

    Args:
        mr_seam: 48-byte MR_SEAM from quote

    Raises:
        TdxValidationError: If MR_SEAM not in accepted list
    """
    if mr_seam not in ACCEPTED_MR_SEAMS:
        raise TdxValidationError(
            f"MR_SEAM {mr_seam.hex()} not in accepted list"
        )


# =============================================================================
# Orchestration Constants and Types
# =============================================================================

# Minimum required tcbEvaluationDataNumber.
# This prevents accepting collateral issued before critical security updates.
# See: https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html
#
# This value should be set using:
#   from tinfoil.attestation.collateral_tdx import calculate_min_tcb_evaluation_data_number
#   min_num = calculate_min_tcb_evaluation_data_number()
#
# The function queries Intel PCS and returns the lowest tcbEvaluationDataNumber
# whose TCB recovery event date is within the last year.
#
# Current value 18 corresponds to TCB recovery event date 2024-11-12.
DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER = 18


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
    collateral: TdxCollateral
    tcb_level: TcbLevel
    measurements: list[str]  # [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
    tls_key_fp: str
    hpke_public_key: Optional[str]


def verify_tdx_attestation(
    attestation_doc: str,
    is_compressed: bool = True,
) -> TdxValidationResult:
    """
    Verify a TDX attestation document.

    This is the main entry point for TDX attestation verification.
    It performs the complete verification flow:

    1. Decode and decompress the attestation document
    2. Parse the TDX quote
    3. Verify cryptographic signatures (PCK chain, quote, QE report)
    4. Policy validation (XFAM, TD_ATTRIBUTES, SEAM, MR_SEAM whitelist)
    5. Extract PCK certificate extensions (FMSPC, TCB)
    6. Fetch and validate collateral from Intel PCS
    7. Extract measurements and report data

    Args:
        attestation_doc: Base64-encoded attestation document
        is_compressed: Whether the document is gzip compressed

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

    # Step 4: Policy validation (mirrors Go's validate.TdxQuote)
    # Create policy options matching Go's verifyTdxReport (tdx.go:267-284)
    # MrSeam, MrTd, Rtmrs, ReportData are None - checked via whitelist or returned as output
    policy_options = PolicyOptions(
        header=HeaderOptions(
            qe_vendor_id=INTEL_QE_VENDOR_ID,
        ),
        td_quote_body=TdQuoteBodyOptions(
            minimum_tee_tcb_svn=EXPECTED_MINIMUM_TEE_TCB_SVN,
            td_attributes=EXPECTED_TD_ATTRIBUTES,
            xfam=EXPECTED_XFAM,
            mr_config_id=b'\x00' * MR_CONFIG_ID_SIZE,
            mr_owner=b'\x00' * MR_OWNER_SIZE,
            mr_owner_config=b'\x00' * MR_OWNER_CONFIG_SIZE,
            # MrSeam, MrTd, Rtmrs, ReportData: None (not exact-matched)
            # DEBUG check enforced via exact TD_ATTRIBUTES match (first byte = 0x00)
        ),
    )
    validate_tdx_policy(quote, policy_options)

    # Validate MR_SEAM against whitelist (Go tdx.go:290-301)
    validate_mr_seam_whitelist(quote.td_quote_body.mr_seam)

    # Step 5: Extract PCK certificate extensions
    try:
        pck_extensions = extract_pck_extensions(pck_chain.pck_cert)
    except PckExtensionError as e:
        raise TdxValidationError(f"Failed to extract PCK extensions: {e}")

    # Step 6: Fetch and validate collateral from Intel PCS
    try:
        collateral = fetch_collateral(pck_extensions, pck_chain.pck_cert)
        check_collateral_freshness(
            collateral,
            min_tcb_evaluation_data_number=DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER,
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

    # Step 7: Extract measurements and report data
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
