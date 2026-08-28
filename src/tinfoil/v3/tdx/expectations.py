"""TDX policy assembly and validation, a 1:1 port of Go
verifier/quote/tdx/expectations.go plus the go-tdx-guest/validate checks the
assembled options drive. Every rejection raises
VerificationError(POLICY_REJECTED)."""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field

from ..errors import POLICY_REJECTED, VerificationError
from ..policy import Artifact, Shape, TDXPolicy, decode_hex as decode_hex_policy
from ..policy import resolve_platform_measurement, validate_tdx_policy
from .authenticate import TdxQuote
from .quote import QuoteV4

# If bit X is 1 in xfamFixed1, it must be 1 in any xfam (validate.go).
_XFAM_FIXED1 = 0x00000003
# If bit X is 0 in xfamFixed0, it must be 0 in any xfam.
_XFAM_FIXED0 = 0x0006DBE7
# If bit X is 1 in tdAttributesFixed1, it must be 1 in any tdAttributes.
_TD_ATTRIBUTES_FIXED1 = 0x0
# Supported ATTRIBUTES bits: 0 (DEBUG), 28 (SEPT VE DISABLE), 30 (PKS),
# 63 (PERFMON). If bit X is 0 in tdAttributesFixed0, it must be 0.
_TD_ATTRIBUTES_FIXED0 = 0x1 | (1 << 28) | (1 << 30) | (1 << 63)

_UINT64_MASK = (1 << 64) - 1


@dataclass
class CodeRegisters:
    """The expected workload registers from code provenance; RTMR0 is a
    platform register and comes from the policy artifact instead."""

    rtmr1: bytes
    rtmr2: bytes
    rtmr3: bytes


@dataclass
class _ValidateOptions:
    qe_vendor_id: bytes
    minimum_tee_tcb_svn: bytes
    mr_seam: bytes
    td_attributes: bytes
    xfam: bytes
    mr_config_id: bytes
    mr_owner: bytes
    mr_owner_config: bytes
    mr_td: bytes = b""
    rtmrs: list[bytes] = dc_field(default_factory=list)
    report_data: bytes = b""


@dataclass
class TdxExpectations:
    """The fully translated TDX expected state, resolved at assembly so that
    validation performs no translation and no lookups. The collateral floor is
    separate because it is not a quote field."""

    opts: _ValidateOptions
    minimum_tcb_evaluation_data_number: int


def _policy_error(message: str) -> VerificationError:
    return VerificationError(POLICY_REJECTED, message)


def tdx_assemble(
    a: Artifact,
    p: TDXPolicy,
    required: Shape | None,
    q: TdxQuote,
    code: CodeRegisters,
    report_data: bytes,
) -> tuple[TdxExpectations, str]:
    """Translate a policy block into the complete expected state for a quote
    (Go: tdx.Assemble). The endorsed measurement set is resolved to a single
    MRTD/RTMR0 by the quote's authenticated registers under the required VM
    shape, so a quote outside the endorsed set fails assembly; every register
    comparison then happens inside tdx_validate. The returned name is the
    resolved measurements-map entry."""
    opts = _options(p)
    body = q.quote.td_quote_body
    if body is None or len(body.rtmrs) != 4:
        raise _policy_error("TDX quote body must carry exactly 4 RTMRs")
    if len(report_data) != 64:
        raise _policy_error(
            f"expected report data must be 64 bytes, got {len(report_data)}"
        )

    name, m = resolve_platform_measurement(
        a, p, required, body.mr_td.hex(), body.rtmrs[0].hex()
    )
    try:
        mrtd = decode_hex_policy("mrtd", m.mrtd, 48)
    except ValueError as e:
        raise _policy_error(f"platform measurement mrtd is not hex: {e}") from None
    try:
        rtmr0 = decode_hex_policy("rtmr0", m.rtmr0, 48)
    except ValueError as e:
        raise _policy_error(f"platform measurement rtmr0 is not hex: {e}") from None
    opts.mr_td = mrtd
    opts.rtmrs = [rtmr0, code.rtmr1, code.rtmr2, code.rtmr3]
    opts.report_data = report_data

    if p.minimum_tcb_evaluation_data_number is None:  # _options validated already
        raise _policy_error("policy minimum_tcb_evaluation_data_number is missing")
    return (
        TdxExpectations(
            opts=opts,
            minimum_tcb_evaluation_data_number=p.minimum_tcb_evaluation_data_number,
        ),
        name,
    )


def tdx_validate(e: TdxExpectations, q: TdxQuote) -> None:
    """Compare a quote against the assembled expected state: the library
    validation checks plus the collateral floor (Go: Expectations.Validate).
    It is the only TDX enforcement entry point, so no subset of the policy can
    be applied."""
    _validate_quote(q.quote, e.opts)
    if q.tcb_evaluation_data_number < e.minimum_tcb_evaluation_data_number:
        raise _policy_error(
            f"tcbEvaluationDataNumber {q.tcb_evaluation_data_number} is below "
            f"the policy minimum {e.minimum_tcb_evaluation_data_number}"
        )


def _options(p: TDXPolicy) -> _ValidateOptions:
    """Translate the policy block into library validation options (Go:
    expectations.go options)."""
    invalid = validate_tdx_policy(p)
    if invalid is not None:
        raise _policy_error(invalid)
    qe_vendor = _decode("qe_vendor_id", p.qe_vendor_id, 16)
    tee_tcb_svn = _decode("minimum_tee_tcb_svn", p.minimum_tee_tcb_svn, 16)
    mr_seam = _decode("mr_seam", p.mr_seam, 48)
    td_attributes = _decode("td_attributes", p.td_attributes, 8)
    xfam = _decode("xfam", p.xfam, 8)

    # MR_CONFIG_ID, MR_OWNER, and MR_OWNER_CONFIG are unconditionally pinned
    # to zero: Tinfoil launches never populate them. The QE and PCE security
    # versions are enforced by quote verification against Intel's signed QE
    # Identity and TCB Info collateral; the library's header minimums compare
    # reserved header bytes (pinned to zero at authentication) and are left
    # unset.
    return _ValidateOptions(
        qe_vendor_id=qe_vendor,
        minimum_tee_tcb_svn=tee_tcb_svn,
        mr_seam=mr_seam,
        td_attributes=td_attributes,
        xfam=xfam,
        mr_config_id=bytes(48),
        mr_owner=bytes(48),
        mr_owner_config=bytes(48),
    )


def _decode(name: str, value: str, want_len: int) -> bytes:
    try:
        return decode_hex_policy(name, value, want_len)
    except ValueError as e:
        raise _policy_error(str(e)) from None


def _validate_quote(quote: QuoteV4, opts: _ValidateOptions) -> None:
    """Mirror tdxvalidate.TdxQuote for quote v4: every check runs and all
    failures are reported (Go: multierr.Combine)."""
    errs: list[str] = []
    _exact_byte_match(quote, opts, errs)
    _min_version_check(quote, opts, errs)
    _validate_bits("xfam", quote.td_quote_body.xfam, _XFAM_FIXED1, _XFAM_FIXED0, errs)
    _validate_bits(
        "tdAttributes",
        quote.td_quote_body.td_attributes,
        _TD_ATTRIBUTES_FIXED1,
        _TD_ATTRIBUTES_FIXED0,
        errs,
    )
    if errs:
        raise _policy_error("; ".join(errs))


def _byte_check(
    option: str, field_name: str, size: int, given: bytes, required: bytes, errs: list[str]
) -> None:
    """Mirror go-tdx-guest validate.byteCheck: skip when unset, reject a
    wrong-sized expectation before comparing."""
    if len(required) == 0:
        return
    if len(required) != size:
        errs.append(f"option {option} must be nil or {size} bytes")
        return
    if required != given:
        errs.append(f"quote field {field_name} is {given.hex()}. Expect {required.hex()}")


def _exact_byte_match(quote: QuoteV4, opts: _ValidateOptions, errs: list[str]) -> None:
    body = quote.td_quote_body
    _byte_check("MrSeam", "MR_SEAM", 48, body.mr_seam, opts.mr_seam, errs)
    _byte_check("TdAttributes", "TD_ATTRIBUTES", 8, body.td_attributes, opts.td_attributes, errs)
    _byte_check("Xfam", "XFAM", 8, body.xfam, opts.xfam, errs)
    _byte_check("MrTd", "MR_TD", 48, body.mr_td, opts.mr_td, errs)
    _byte_check("MrConfigID", "MR_CONFIG_ID", 48, body.mr_config_id, opts.mr_config_id, errs)
    _byte_check("MrOwner", "MR_OWNER", 48, body.mr_owner, opts.mr_owner, errs)
    _byte_check(
        "MrOwnerConfig", "MR_OWNER_CONFIG", 48, body.mr_owner_config, opts.mr_owner_config, errs
    )
    if len(opts.rtmrs) != 0:
        if len(opts.rtmrs) != 4:
            errs.append(f"RTMR field size({len(opts.rtmrs)}) is not equal to expected size(4)")
        else:
            for i in range(4):
                if len(opts.rtmrs[i]) == 0:
                    continue
                if len(opts.rtmrs[i]) != 48:
                    errs.append(f"RTMR[{i}] should be 48 bytes, found {len(opts.rtmrs[i])}")
                    continue
                if opts.rtmrs[i] != body.rtmrs[i]:
                    errs.append(
                        f"quote field RTMR[{i}] is {body.rtmrs[i].hex()}. "
                        f"Expect {opts.rtmrs[i].hex()}"
                    )
    _byte_check("ReportData", "REPORT_DATA", 64, body.report_data, opts.report_data, errs)
    _byte_check(
        "QeVendorID", "QE_VENDOR_ID", 16, quote.header.qe_vendor_id, opts.qe_vendor_id, errs
    )


def _min_version_check(quote: QuoteV4, opts: _ValidateOptions, errs: list[str]) -> None:
    """Compare TEE_TCB_SVN component-wise; the QE/PCE header minimums are
    unset (zero) and the reserved header bytes are pinned to zero at
    authentication, so those comparisons are always satisfied."""
    svn = quote.td_quote_body.tee_tcb_svn
    if len(opts.minimum_tee_tcb_svn) != 0:
        for i in range(len(svn)):
            if svn[i] < opts.minimum_tee_tcb_svn[i]:
                errs.append(
                    f"TEE TCB security-version number {svn.hex()} is less than "
                    f"the required minimum {opts.minimum_tee_tcb_svn.hex()}"
                )
                break


def _validate_bits(name: str, value: bytes, fixed1: int, fixed0: int, errs: list[str]) -> None:
    if len(value) == 0:
        return
    if len(value) != 8:
        errs.append(f"{name} size is invalid")
        return
    v = int.from_bytes(value, "little")
    if v & fixed1 != fixed1:
        errs.append(
            f"unauthorized {name} 0x{v:x} as {name}Fixed1 0x{fixed1:x} bits are unset"
        )
    if v & (~fixed0 & _UINT64_MASK) != 0:
        errs.append(
            f"unauthorized {name} 0x{v:x} as {name}Fixed0 0x{fixed0:x} bits are set"
        )
