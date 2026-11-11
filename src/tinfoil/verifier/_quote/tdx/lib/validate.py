"""Policy validation of a TDX quote: exact field matches, the minimum TEE TCB SVN, and the fixed bits of XFAM and
TD_ATTRIBUTES.

No cryptography and no collateral: a quote reaches this module after its
signatures and the Intel collateral were verified.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from tinfoil.verifier._quote.tdx.lib.abi import (
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


@dataclass(frozen=True, slots=True)
class _ByteField:
    """One quote field that an option pins verbatim: the option's name, the quote field's name, the field's size,
    the quote's value and the option's expected value (None when unchecked)."""

    option: str
    field: str
    size: int
    given: bytes
    expected: bytes | None


def _byte_fields(quote: QuoteV4, options: PolicyOptions) -> tuple[_ByteField, ...]:
    """The pinned fields in their check order; the four RTMRs appear once the option holds exactly four."""
    t = options.td_quote_body
    body = quote.td_quote_body
    rows = [
        _ByteField("mr_seam", "MR_SEAM", MR_SEAM_SIZE, body.mr_seam, t.mr_seam),
        _ByteField("td_attributes", "TD_ATTRIBUTES", TD_ATTRIBUTES_SIZE, body.td_attributes, t.td_attributes),
        _ByteField("xfam", "XFAM", XFAM_SIZE, body.xfam, t.xfam),
        _ByteField("mr_td", "MR_TD", MR_TD_SIZE, body.mr_td, t.mr_td),
        _ByteField("mr_config_id", "MR_CONFIG_ID", MR_CONFIG_ID_SIZE, body.mr_config_id, t.mr_config_id),
        _ByteField("mr_owner", "MR_OWNER", MR_OWNER_SIZE, body.mr_owner, t.mr_owner),
        _ByteField("mr_owner_config", "MR_OWNER_CONFIG", MR_OWNER_CONFIG_SIZE, body.mr_owner_config, t.mr_owner_config),
    ]
    if t.rtmrs is not None:
        if len(t.rtmrs) != RTMR_COUNT:
            raise TdxValidationError(f"option 'rtmrs' has {len(t.rtmrs)} entries, expected {RTMR_COUNT}")
        rows.extend(
            _ByteField(f"rtmrs[{i}]", f"RTMR[{i}]", RTMR_SIZE, given, expected)
            for i, (given, expected) in enumerate(zip(body.rtmrs, t.rtmrs, strict=True))
        )
    rows.append(_ByteField("report_data", "REPORT_DATA", REPORT_DATA_SIZE, body.report_data, t.report_data))
    rows.append(
        _ByteField(
            "qe_vendor_id", "QE_VENDOR_ID", QE_VENDOR_ID_SIZE, quote.header.qe_vendor_id, options.header.qe_vendor_id
        )
    )
    return tuple(rows)


def _check_options_lengths(rows: tuple[_ByteField, ...], options: PolicyOptions) -> None:
    """Every set option has its field's size; the minimum TEE TCB SVN, compared component-wise rather than
    verbatim, is checked here too."""
    minimum = options.td_quote_body.minimum_tee_tcb_svn
    sized = [(row.option, row.size, row.expected) for row in rows]
    sized.append(("minimum_tee_tcb_svn", TEE_TCB_SVN_SIZE, minimum))
    for name, size, expected in sized:
        if expected is not None and len(expected) != size:
            raise TdxValidationError(f"option '{name}' length is {len(expected)}, expected {size}")


def _exact_byte_match(rows: tuple[_ByteField, ...]) -> None:
    for row in rows:
        if row.expected is not None and row.given != row.expected:
            raise TdxValidationError(f"quote field {row.field} is {row.given.hex()}. Expect {row.expected.hex()}")


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
    rows = _byte_fields(quote, options)
    _check_options_lengths(rows, options)
    _exact_byte_match(rows)
    _min_version_check(quote, options)
    validate_xfam(quote.td_quote_body.xfam)
    validate_td_attributes(quote.td_quote_body.td_attributes)
