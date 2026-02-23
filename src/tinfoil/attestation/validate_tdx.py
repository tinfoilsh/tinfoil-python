"""
TDX Policy Validation.

This module provides pure policy validation functions for TDX quote fields.

This module contains:
- Policy validation functions (validate_xfam, validate_td_attributes, etc.)
- Policy option dataclasses (PolicyOptions, HeaderOptions, TdQuoteBodyOptions)
- Policy-related constants (XFAM_FIXED*, TD_ATTRIBUTES_FIXED*, etc.)
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

from .abi_tdx import (
    QuoteV4,
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
    TEE_TCB_SVN_SIZE,
)


# =============================================================================
# Policy Validation Error
# =============================================================================

class TdxValidationError(Exception):
    """Raised when TDX policy validation fails."""
    pass


# =============================================================================
# Policy Validation Constants
# =============================================================================

# XFAM fixed bit constraints
# If bit X is 1 in XFAM_FIXED1, it must be 1 in any XFAM
XFAM_FIXED1 = 0x00000003
# If bit X is 0 in XFAM_FIXED0, it must be 0 in any XFAM
XFAM_FIXED0 = 0x0006DBE7

# TD_ATTRIBUTES fixed bit constraints
# No FIXED1 bits for TD_ATTRIBUTES currently (no bits are mandatory-set).

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



# =============================================================================
# Policy Validation Options
# =============================================================================

@dataclass(frozen=True)
class HeaderOptions:
    """
    Validation options for TDX quote header fields.
    Mirrors Go's validate.HeaderOptions struct.

    All fields are optional - set to None to skip the check.
    """
    # Expected QE_VENDOR_ID (16 bytes, not checked if None)
    qe_vendor_id: Optional[bytes] = None


@dataclass(frozen=True)
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
    rtmrs: Optional[tuple[Optional[bytes], ...]] = None
    # Expected REPORT_DATA (64 bytes)
    report_data: Optional[bytes] = None
    # Any permitted MR_TD values (list of 48-byte values)
    any_mr_td: Optional[tuple[Optional[bytes], ...]] = None
    # Any permitted MR_SEAM values (list of 48-byte values)
    any_mr_seam: Optional[tuple[Optional[bytes], ...]] = None


@dataclass(frozen=True)
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
    _check_option_length("minimum_tee_tcb_svn", TEE_TCB_SVN_SIZE, t.minimum_tee_tcb_svn)
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
        if not any(v is not None for v in t.any_mr_td):
            raise TdxValidationError("Option 'any_mr_td' contains no non-None entries")
        for i, mr_td in enumerate(t.any_mr_td):
            if mr_td is not None and len(mr_td) != MR_TD_SIZE:
                raise TdxValidationError(
                    f"Option 'any_mr_td[{i}]' length is {len(mr_td)}, expected {MR_TD_SIZE}"
                )

    if t.any_mr_seam is not None:
        if not any(v is not None for v in t.any_mr_seam):
            raise TdxValidationError("Option 'any_mr_seam' contains no non-None entries")
        for i, mr_seam in enumerate(t.any_mr_seam):
            if mr_seam is not None and len(mr_seam) != MR_SEAM_SIZE:
                raise TdxValidationError(
                    f"Option 'any_mr_seam[{i}]' length is {len(mr_seam)}, expected {MR_SEAM_SIZE}"
                )

    # Mutual exclusion: exact-match and allowlist cannot both be set
    if t.mr_td is not None and t.any_mr_td is not None and len(t.any_mr_td) > 0:
        raise TdxValidationError(
            "Cannot set both 'mr_td' and 'any_mr_td' - use one or the other"
        )
    if t.mr_seam is not None and t.any_mr_seam is not None and len(t.any_mr_seam) > 0:
        raise TdxValidationError(
            "Cannot set both 'mr_seam' and 'any_mr_seam' - use one or the other"
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
    if len(quote_svn) != len(min_svn):
        return False
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

    Per Intel DCAP spec Section 2.3.2: "Verify that all TD Under Debug
    flags (i.e., the TDATTRIBUTES.TUD field in the TD Quote Body) are
    set to zero."

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

    # Mandatory: reject debug TDs unconditionally.
    # A debug TD has its memory visible to the host, defeating TDX
    # confidentiality guarantees.
    if value & TD_ATTRIBUTES_DEBUG_BIT:
        raise TdxValidationError(
            f"TD_ATTRIBUTES 0x{value:x}: DEBUG bit must not be set"
        )

    # Check FIXED0 bits (only allowed bits may be set)
    if value & (~TD_ATTRIBUTES_FIXED0):
        raise TdxValidationError(
            f"Unauthorized TD_ATTRIBUTES 0x{value:x}: "
            f"FIXED0 0x{TD_ATTRIBUTES_FIXED0:x} bits are set"
        )


def _validate_zero_field(name: str, value: bytes, expected_size: int, context: str) -> None:
    """Validate that a field is all zeros with the expected size."""
    if len(value) != expected_size:
        raise TdxValidationError(
            f"{name} size is {len(value)}, expected {expected_size}"
        )
    if value != b'\x00' * expected_size:
        raise TdxValidationError(
            f"{name} must be zero for {context}, got {value.hex()}"
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
    _validate_zero_field("SEAMATTRIBUTES", seam_attributes, SEAM_ATTRIBUTES_SIZE, "TDX 1.0/1.5")


def validate_mr_signer_seam(mr_signer_seam: bytes) -> None:
    """
    Validate MRSIGNERSEAM is zero (required for Intel TDX Module).

    Per Intel TDX DCAP Quoting Library API section 2.3.2.

    Args:
        mr_signer_seam: 48-byte MRSIGNERSEAM from quote

    Raises:
        TdxValidationError: If not zero
    """
    _validate_zero_field("MRSIGNERSEAM", mr_signer_seam, MR_SIGNER_SEAM_SIZE, "Intel TDX Module")


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
        if len(body.rtmrs) != len(t.rtmrs):
            raise TdxValidationError(
                f"RTMR count mismatch: quote has {len(body.rtmrs)}, "
                f"policy expects {len(t.rtmrs)}"
            )
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

    # Any MR_SEAM check (at least one must match)
    if t.any_mr_seam is not None and len(t.any_mr_seam) > 0:
        mr_seam = body.mr_seam
        if not any(mr_seam == allowed for allowed in t.any_mr_seam if allowed is not None):
            raise TdxValidationError(
                f"MR_SEAM {mr_seam.hex()} does not match any allowed value"
            )


def _validate_min_versions(quote: QuoteV4, options: PolicyOptions) -> None:
    """Validate minimum version requirements."""
    t = options.td_quote_body

    # TEE TCB SVN check
    if t.minimum_tee_tcb_svn is not None:
        if not _is_svn_higher_or_equal(quote.td_quote_body.tee_tcb_svn, t.minimum_tee_tcb_svn):
            raise TdxValidationError(
                f"TEE_TCB_SVN {quote.td_quote_body.tee_tcb_svn.hex()} is less than "
                f"minimum {t.minimum_tee_tcb_svn.hex()}"
            )



def validate_tdx_policy(quote: QuoteV4, options: PolicyOptions) -> None:
    """
    Validate a TDX QuoteV4 against policy options.

    This is the main entry point for TDX quote policy validation.
    It performs policy-based validation only - no cryptographic verification
    or collateral fetching.

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
