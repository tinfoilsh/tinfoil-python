"""Policy validation of a TDX quote: exact field matches, the minimum TEE TCB SVN, and the fixed bits of XFAM and
TD_ATTRIBUTES.

No cryptography and no collateral: a quote reaches this module after its
signatures and the Intel collateral were verified.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from tinfoil._v3.verifier._quote.tdx.lib.abi import (
    MR_CONFIG_ID_SIZE,
    MR_OWNER_CONFIG_SIZE,
    MR_OWNER_SIZE,
    MR_SEAM_SIZE,
    MR_TD_SIZE,
    QE_VENDOR_ID_SIZE,
    REPORT_DATA_SIZE,
    RTMR_COUNT,
    RTMR_SIZE,
    TD_ATTRIBUTES_SIZE,
    TEE_TCB_SVN_SIZE,
    XFAM_SIZE,
    QuoteV4,
)


class TdxValidationError(ValueError):
    """A quote that does not satisfy the validation options."""


# If bit X is 1 in XFAM_FIXED1, it must be 1 in any XFAM.
XFAM_FIXED1 = 0x00000003
# If bit X is 0 in XFAM_FIXED0, it must be 0 in any XFAM.
XFAM_FIXED0 = 0x0006DBE7

# If bit X is 1 in TD_ATTRIBUTES_FIXED1, it must be 1 in any TD_ATTRIBUTES.
TD_ATTRIBUTES_FIXED1 = 0x0
TD_ATTRIBUTES_DEBUG_BIT = 0x1
TD_ATTRIBUTES_SEPT_VE_DIS = 1 << 28
TD_ATTRIBUTES_PKS = 1 << 30
TD_ATTRIBUTES_PERFMON = 1 << 63
# Supported TD_ATTRIBUTES bits: DEBUG, SEPT_VE_DISABLE, PKS and PERFMON. If
# bit X is 0 in TD_ATTRIBUTES_FIXED0, it must be 0 in any TD_ATTRIBUTES.
TD_ATTRIBUTES_FIXED0 = TD_ATTRIBUTES_DEBUG_BIT | TD_ATTRIBUTES_SEPT_VE_DIS | TD_ATTRIBUTES_PKS | TD_ATTRIBUTES_PERFMON


@dataclass(frozen=True)
class HeaderOptions:
    """Validation options for the quote header. A None field is not checked."""

    qe_vendor_id: bytes | None = None
    """The expected QE_VENDOR_ID, 16 bytes."""


@dataclass(frozen=True)
class TdQuoteBodyOptions:
    """Validation options for the TD quote body. A None field is not checked."""

    minimum_tee_tcb_svn: bytes | None = None
    """The component-wise minimum TEE_TCB_SVN, 16 bytes."""
    mr_seam: bytes | None = None
    td_attributes: bytes | None = None
    xfam: bytes | None = None
    mr_td: bytes | None = None
    mr_config_id: bytes | None = None
    mr_owner: bytes | None = None
    mr_owner_config: bytes | None = None
    rtmrs: tuple[bytes | None, ...] | None = None
    """The four expected RTMRs; a None entry leaves that register unchecked."""
    report_data: bytes | None = None


@dataclass(frozen=True)
class PolicyOptions:
    """Complete validation options for a quote."""

    header: HeaderOptions = field(default_factory=HeaderOptions)
    td_quote_body: TdQuoteBodyOptions = field(default_factory=TdQuoteBodyOptions)


def _check_option_length(name: str, expected: int, value: bytes | None) -> None:
    if value is not None and len(value) != expected:
        raise TdxValidationError(f"option '{name}' length is {len(value)}, expected {expected}")


def _check_options_lengths(options: PolicyOptions) -> None:
    h = options.header
    t = options.td_quote_body
    _check_option_length("mr_seam", MR_SEAM_SIZE, t.mr_seam)
    _check_option_length("td_attributes", TD_ATTRIBUTES_SIZE, t.td_attributes)
    _check_option_length("xfam", XFAM_SIZE, t.xfam)
    _check_option_length("mr_td", MR_TD_SIZE, t.mr_td)
    _check_option_length("mr_config_id", MR_CONFIG_ID_SIZE, t.mr_config_id)
    _check_option_length("mr_owner", MR_OWNER_SIZE, t.mr_owner)
    _check_option_length("mr_owner_config", MR_OWNER_CONFIG_SIZE, t.mr_owner_config)
    _check_option_length("report_data", REPORT_DATA_SIZE, t.report_data)
    _check_option_length("qe_vendor_id", QE_VENDOR_ID_SIZE, h.qe_vendor_id)
    _check_option_length("minimum_tee_tcb_svn", TEE_TCB_SVN_SIZE, t.minimum_tee_tcb_svn)
    if t.rtmrs is not None:
        if len(t.rtmrs) != RTMR_COUNT:
            raise TdxValidationError(f"option 'rtmrs' has {len(t.rtmrs)} entries, expected {RTMR_COUNT}")
        for i, rtmr in enumerate(t.rtmrs):
            _check_option_length(f"rtmrs[{i}]", RTMR_SIZE, rtmr)


def _byte_check(field_name: str, given: bytes, expected: bytes | None) -> None:
    if expected is None:
        return
    if given != expected:
        raise TdxValidationError(f"quote field {field_name} is {given.hex()}. Expect {expected.hex()}")


def _exact_byte_match(quote: QuoteV4, options: PolicyOptions) -> None:
    t = options.td_quote_body
    body = quote.td_quote_body
    _byte_check("MR_SEAM", body.mr_seam, t.mr_seam)
    _byte_check("TD_ATTRIBUTES", body.td_attributes, t.td_attributes)
    _byte_check("XFAM", body.xfam, t.xfam)
    _byte_check("MR_TD", body.mr_td, t.mr_td)
    _byte_check("MR_CONFIG_ID", body.mr_config_id, t.mr_config_id)
    _byte_check("MR_OWNER", body.mr_owner, t.mr_owner)
    _byte_check("MR_OWNER_CONFIG", body.mr_owner_config, t.mr_owner_config)
    if t.rtmrs is not None:
        for i, (given, expected) in enumerate(zip(body.rtmrs, t.rtmrs, strict=True)):
            _byte_check(f"RTMR[{i}]", given, expected)
    _byte_check("REPORT_DATA", body.report_data, t.report_data)
    _byte_check("QE_VENDOR_ID", quote.header.qe_vendor_id, options.header.qe_vendor_id)


def _is_svn_higher_or_equal(quote_svn: bytes, minimum: bytes | None) -> bool:
    """Component-wise comparison; no minimum passes."""
    if minimum is None:
        return True
    if len(quote_svn) != len(minimum):
        return False
    return all(q >= m for q, m in zip(quote_svn, minimum, strict=True))


def _min_version_check(quote: QuoteV4, options: PolicyOptions) -> None:
    minimum = options.td_quote_body.minimum_tee_tcb_svn
    tee_tcb_svn = quote.td_quote_body.tee_tcb_svn
    if not _is_svn_higher_or_equal(tee_tcb_svn, minimum):
        assert minimum is not None
        raise TdxValidationError(
            f"TEE TCB security-version number {tee_tcb_svn.hex()} is less than the required minimum {minimum.hex()}"
        )


def validate_xfam(xfam: bytes) -> None:
    """The XFAM's FIXED1 bits are set and no bit outside FIXED0 is set."""
    if len(xfam) != XFAM_SIZE:
        raise TdxValidationError("xfam size is invalid")
    value = struct.unpack("<Q", xfam)[0]
    if (value & XFAM_FIXED1) != XFAM_FIXED1:
        raise TdxValidationError(f"unauthorized xfam 0x{value:x} as xfamFixed1 0x{XFAM_FIXED1:x} bits are unset")
    if value & ~XFAM_FIXED0:
        raise TdxValidationError(f"unauthorized xfam 0x{value:x} as xfamFixed0 0x{XFAM_FIXED0:x} bits are set")


def validate_td_attributes(td_attributes: bytes) -> None:
    """The TD_ATTRIBUTES' FIXED1 bits are set and no bit outside FIXED0 is set."""
    if len(td_attributes) != TD_ATTRIBUTES_SIZE:
        raise TdxValidationError("tdAttributes size is invalid")
    value = struct.unpack("<Q", td_attributes)[0]
    if (value & TD_ATTRIBUTES_FIXED1) != TD_ATTRIBUTES_FIXED1:
        raise TdxValidationError(
            f"unauthorized tdAttributes 0x{value:x} as tdAttributesFixed1 0x{TD_ATTRIBUTES_FIXED1:x} bits are unset"
        )
    if value & ~TD_ATTRIBUTES_FIXED0:
        raise TdxValidationError(
            f"unauthorized tdAttributes 0x{value:x} as tdAttributesFixed0 0x{TD_ATTRIBUTES_FIXED0:x} bits are set"
        )


def validate_tdx_policy(quote: QuoteV4, options: PolicyOptions) -> None:
    """Validate a parsed quote against the options: exact matches, the minimum TEE TCB SVN, then the fixed bits
    of XFAM and TD_ATTRIBUTES."""
    _check_options_lengths(options)
    _exact_byte_match(quote, options)
    _min_version_check(quote, options)
    validate_xfam(quote.td_quote_body.xfam)
    validate_td_attributes(quote.td_quote_body.td_attributes)
