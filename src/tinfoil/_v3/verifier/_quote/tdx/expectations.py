"""Translation of an endorsed TDX policy into complete validation expectations, and their one application."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier._measurement import TDX
from tinfoil._v3.verifier._policy import PolicyError, TDXPolicy
from tinfoil._v3.verifier._quote.tdx.authenticate import Quote
from tinfoil._v3.verifier._quote.tdx.lib.validate import (
    HeaderOptions,
    PolicyOptions,
    TdQuoteBodyOptions,
    TdxValidationError,
    validate_tdx_policy,
)

MR_CONFIG_ID_SIZE = 48
MR_OWNER_SIZE = 48
MR_OWNER_CONFIG_SIZE = 48
REPORT_DATA_SIZE = 64


class TdxPolicyError(ValueError):
    """A policy that cannot be translated, or a quote that does not satisfy it."""


@dataclass(frozen=True, slots=True)
class Expectations:
    """The fully translated TDX expected state, resolved at assembly so that validation performs no translation and
    no lookups. The collateral floor is separate because it is not a quote field."""

    options: PolicyOptions
    minimum_tcb_evaluation_data_number: int


def assemble(policy: TDXPolicy, measurement: TDX, report_data: bytes, config_id: bytes) -> Expectations:
    """Translate complete reference values into validation options: the policy's fields, the five registers of
    ``measurement``, the 64-byte ``report_data`` and the 48-byte ``config_id``."""
    options = _options(policy)
    if len(report_data) != REPORT_DATA_SIZE:
        raise TdxPolicyError(f"report data must be {REPORT_DATA_SIZE} bytes, got {len(report_data)}")
    if len(config_id) != MR_CONFIG_ID_SIZE:
        raise TdxPolicyError(f"config id must be {MR_CONFIG_ID_SIZE} bytes, got {len(config_id)}")
    body = options.td_quote_body
    completed = PolicyOptions(
        header=options.header,
        td_quote_body=TdQuoteBodyOptions(
            minimum_tee_tcb_svn=body.minimum_tee_tcb_svn,
            mr_seam=body.mr_seam,
            td_attributes=body.td_attributes,
            xfam=body.xfam,
            mr_td=bytes(measurement.mrtd),
            mr_config_id=bytes(config_id),
            mr_owner=body.mr_owner,
            mr_owner_config=body.mr_owner_config,
            rtmrs=(
                bytes(measurement.rtmr0),
                bytes(measurement.rtmr1),
                bytes(measurement.rtmr2),
                bytes(measurement.rtmr3),
            ),
            report_data=bytes(report_data),
        ),
    )
    # ``validate`` rejected an absent minimum.
    assert policy.minimum_tcb_evaluation_data_number is not None
    return Expectations(options=completed, minimum_tcb_evaluation_data_number=policy.minimum_tcb_evaluation_data_number)


def validate(expectations: Expectations, quote: Quote) -> None:
    """Compare a quote against the assembled expected state: the library validation plus the collateral floor
    (the quote's evaluation number must reach the policy minimum). This is the only TDX enforcement entry point,
    so no subset of the policy can be applied."""
    try:
        validate_tdx_policy(quote.quote, expectations.options)
    except TdxValidationError as err:
        raise TdxPolicyError(str(err)) from err
    if quote.tcb_evaluation_data_number < expectations.minimum_tcb_evaluation_data_number:
        raise TdxPolicyError(
            f"tcbEvaluationDataNumber {quote.tcb_evaluation_data_number} is below the policy minimum "
            f"{expectations.minimum_tcb_evaluation_data_number}"
        )


def _options(policy: TDXPolicy) -> PolicyOptions:
    """Translate the policy block into validation options.

    The policy must validate; the QE vendor id, minimum TEE TCB SVN,
    MR_SEAM, TD attributes and XFAM decode from hex to their sizes.
    MR_OWNER and MR_OWNER_CONFIG are pinned to zero; MR_CONFIG_ID is set
    at assembly. The header's QE and PCE SVN minimums are left unset: those
    bytes are reserved in quote v4 and pinned to zero at authentication.
    """
    try:
        policy.validate()
    except PolicyError as err:
        raise TdxPolicyError(str(err)) from err
    # ``validate`` checked each field for lowercase hex of the exact size.
    return PolicyOptions(
        header=HeaderOptions(qe_vendor_id=bytes.fromhex(policy.qe_vendor_id)),
        td_quote_body=TdQuoteBodyOptions(
            minimum_tee_tcb_svn=bytes.fromhex(policy.minimum_tee_tcb_svn),
            mr_seam=bytes.fromhex(policy.mr_seam),
            td_attributes=bytes.fromhex(policy.td_attributes),
            xfam=bytes.fromhex(policy.xfam),
            mr_config_id=bytes(MR_CONFIG_ID_SIZE),
            mr_owner=bytes(MR_OWNER_SIZE),
            mr_owner_config=bytes(MR_OWNER_CONFIG_SIZE),
        ),
    )
