"""Assembly of TDX validation expectations from a policy, and their one application to an authenticated quote."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from tests.v3 import tdx_builders as tb
from tinfoil._v3.verifier._measurement import TDX
from tinfoil._v3.verifier._policy import PLATFORM_TDX, TDXPolicy, parse
from tinfoil._v3.verifier._quote.tdx.authenticate import Options, Quote, authenticate
from tinfoil._v3.verifier._quote.tdx.expectations import TdxPolicyError, _options, assemble, validate
from tinfoil._v3.verifier._quote.tdx.lib.abi import QuoteV4

FIXTURE = Path(__file__).parent / "testdata" / "platform-endorsements.json"
# A production identifier, public by design in the endorsement artifact.
INF7_PPID = "3b064a0f58d5dd3688780aeb40e0b5d2"


@pytest.fixture(scope="module")
def authenticated() -> Quote:
    scenario = tb.Scenario()
    return authenticate(scenario.evidence(), tb.NOW, Options(test_only_root_pem=scenario.root_pem()))


def matching_policy(quote: Quote, minimum: int = 5) -> TDXPolicy:
    body = quote.quote.td_quote_body
    return TDXPolicy(
        qe_vendor_id=quote.quote.header.qe_vendor_id.hex(),
        minimum_tee_tcb_svn=body.tee_tcb_svn.hex(),
        mr_seam=body.mr_seam.hex(),
        td_attributes=body.td_attributes.hex(),
        xfam=body.xfam.hex(),
        minimum_tcb_evaluation_data_number=minimum,
        platform_measurements=("sample",),
    )


def with_body(quote: Quote, **changes: Any) -> Quote:
    body = replace(quote.quote.td_quote_body, **changes)
    return replace(quote, quote=replace(quote.quote, td_quote_body=body))


def test_options_from_the_endorsement_artifact() -> None:
    artifact = parse(FIXTURE.read_bytes())
    _, policy = artifact.policy_for(INF7_PPID, PLATFORM_TDX)
    assert policy.tdx is not None
    options = _options(policy.tdx)
    assert options.header.qe_vendor_id == bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
    assert options.td_quote_body.mr_config_id == bytes(48)
    assert options.td_quote_body.mr_owner == bytes(48)
    assert options.td_quote_body.mr_owner_config == bytes(48)
    assert options.td_quote_body.td_attributes == bytes.fromhex("0000001000000000")
    assert options.td_quote_body.minimum_tee_tcb_svn == bytes.fromhex(policy.tdx.minimum_tee_tcb_svn)
    assert options.td_quote_body.xfam == bytes.fromhex(policy.tdx.xfam)
    assert policy.tdx.mr_seam
    assert options.td_quote_body.mr_seam == bytes.fromhex(policy.tdx.mr_seam)
    assert options.td_quote_body.mr_td is None
    assert options.td_quote_body.rtmrs is None
    assert options.td_quote_body.report_data is None


def test_options_require_a_valid_policy() -> None:
    with pytest.raises(TdxPolicyError, match="qe_vendor_id is required"):
        _options(TDXPolicy("", "", "", "", "", 0))
    with pytest.raises(TdxPolicyError, match="minimum_tcb_evaluation_data_number"):
        _options(replace(matching_policy_for_fixture(), minimum_tcb_evaluation_data_number=None))


def matching_policy_for_fixture() -> TDXPolicy:
    artifact = parse(FIXTURE.read_bytes())
    _, policy = artifact.policy_for(INF7_PPID, PLATFORM_TDX)
    assert policy.tdx is not None
    return policy.tdx


def test_validate(authenticated: Quote) -> None:
    """The single composed enforcement entry point, with a policy derived from the quote, then each dimension
    flipped."""
    quote = replace(authenticated, tcb_evaluation_data_number=5)
    body = quote.quote.td_quote_body
    code = TDX(mrtd=body.mr_td, rtmr0=body.rtmrs[0], rtmr1=body.rtmrs[1], rtmr2=body.rtmrs[2], rtmr3=body.rtmrs[3])
    report_data = body.report_data
    policy = matching_policy(quote)
    validate(assemble(policy, code, report_data, bytes(48)), quote)

    for field_name in ("mr_seam", "qe_vendor_id", "xfam", "td_attributes"):
        value = bytearray(bytes.fromhex(getattr(policy, field_name)))
        value[0] ^= 1
        bad = replace(policy, **cast(dict[str, Any], {field_name: bytes(value).hex()}))
        with pytest.raises(TdxPolicyError, match=field_name.upper()):
            validate(assemble(bad, code, report_data, bytes(48)), quote)

    stale = replace(quote, tcb_evaluation_data_number=4)
    with pytest.raises(TdxPolicyError, match="below the policy minimum"):
        validate(assemble(policy, code, report_data, bytes(48)), stale)

    bad_code = replace(code, mrtd=bytes([code.mrtd[0] ^ 1]) + code.mrtd[1:])
    with pytest.raises(TdxPolicyError, match="MR_TD"):
        validate(assemble(policy, bad_code, report_data, bytes(48)), quote)

    bad_code = replace(code, rtmr1=bytes([code.rtmr1[0] ^ 1]) + code.rtmr1[1:])
    with pytest.raises(TdxPolicyError, match="RTMR\\[1\\]"):
        validate(assemble(policy, bad_code, report_data, bytes(48)), quote)

    bad_report_data = bytes([report_data[0] ^ 1]) + report_data[1:]
    with pytest.raises(TdxPolicyError, match="REPORT_DATA"):
        validate(assemble(policy, code, bad_report_data, bytes(48)), quote)

    higher = bytearray(body.tee_tcb_svn)
    higher[2] += 1
    with pytest.raises(TdxPolicyError, match="TEE TCB security-version number"):
        validate(
            assemble(replace(policy, minimum_tee_tcb_svn=bytes(higher).hex()), code, report_data, bytes(48)), quote
        )


def test_config_bound_enforces_config_padding_and_every_runtime_register(authenticated: Quote) -> None:
    config_hash = hashlib.sha256(b"approved YAML bytes").digest()
    config_id = config_hash + bytes(48 - len(config_hash))
    quote = with_body(
        replace(authenticated, tcb_evaluation_data_number=5),
        mr_config_id=config_id,
        rtmrs=(bytes(48), bytes(48), bytes(48), bytes(48)),
    )
    body = quote.quote.td_quote_body
    expected = TDX(mrtd=body.mr_td, rtmr0=bytes(48), rtmr1=bytes(48), rtmr2=bytes(48), rtmr3=bytes(48))
    policy = replace(matching_policy(quote), platform_measurements=())
    expectations = assemble(policy, expected, body.report_data, config_id)
    validate(expectations, quote)

    def flip(value: bytes, index: int = 0) -> bytes:
        out = bytearray(value)
        out[index] ^= 1
        return bytes(out)

    mutations: dict[str, dict[str, Any]] = {
        "config hash": {"mr_config_id": flip(config_id)},
        "config padding": {"mr_config_id": config_hash + b"\x01" + bytes(15)},
        "MRTD": {"mr_td": flip(body.mr_td)},
        "RTMR0": {"rtmrs": (flip(bytes(48)), bytes(48), bytes(48), bytes(48))},
        "RTMR1": {"rtmrs": (bytes(48), flip(bytes(48)), bytes(48), bytes(48))},
        "RTMR2": {"rtmrs": (bytes(48), bytes(48), flip(bytes(48)), bytes(48))},
        "RTMR3": {"rtmrs": (bytes(48), bytes(48), bytes(48), flip(bytes(48)))},
        "MRSEAM": {"mr_seam": flip(body.mr_seam)},
        "attributes": {"td_attributes": flip(body.td_attributes)},
        "REPORT_DATA": {"report_data": flip(body.report_data)},
    }
    for name, changes in mutations.items():
        with pytest.raises(TdxPolicyError):
            validate(expectations, with_body(quote, **changes))
        assert name
    with pytest.raises(TdxPolicyError, match="below the policy minimum"):
        validate(expectations, replace(quote, tcb_evaluation_data_number=4))


def test_assembled_expectations_do_not_alias_their_inputs(authenticated: Quote) -> None:
    quote = replace(authenticated, tcb_evaluation_data_number=5)
    body = quote.quote.td_quote_body
    code = TDX(mrtd=body.mr_td, rtmr0=body.rtmrs[0], rtmr1=body.rtmrs[1], rtmr2=body.rtmrs[2], rtmr3=body.rtmrs[3])
    report_data = bytearray(body.report_data)
    config_id = bytearray(48)
    expectations = assemble(matching_policy(quote), code, bytes(report_data), bytes(config_id))
    report_data[0] ^= 1
    config_id[0] ^= 1
    validate(expectations, quote)


def test_assemble_checks_the_binding_sizes(authenticated: Quote) -> None:
    body = authenticated.quote.td_quote_body
    code = TDX(mrtd=body.mr_td, rtmr0=body.rtmrs[0], rtmr1=body.rtmrs[1], rtmr2=body.rtmrs[2], rtmr3=body.rtmrs[3])
    with pytest.raises(TdxPolicyError, match="report data must be 64 bytes"):
        assemble(matching_policy(authenticated), code, bytes(63), bytes(48))
    with pytest.raises(TdxPolicyError, match="config id must be 48 bytes"):
        assemble(matching_policy(authenticated), code, bytes(64), bytes(47))


def test_fixed_bits_are_enforced_even_when_the_policy_matches(authenticated: Quote) -> None:
    """A quote whose XFAM or TD_ATTRIBUTES set a bit outside the fixed-0 mask fails, policy agreement or not."""
    quote = replace(authenticated, tcb_evaluation_data_number=5)
    body = quote.quote.td_quote_body
    code = TDX(mrtd=body.mr_td, rtmr0=body.rtmrs[0], rtmr1=body.rtmrs[1], rtmr2=body.rtmrs[2], rtmr3=body.rtmrs[3])
    for field_name, value in (
        ("xfam", bytes.fromhex("e702060000000080")),
        ("td_attributes", bytes.fromhex("0200000000000000")),
    ):
        bad = with_body(quote, **{field_name: value})
        policy = replace(matching_policy(quote), **cast(dict[str, Any], {field_name: value.hex()}))
        with pytest.raises(TdxPolicyError, match="unauthorized"):
            validate(assemble(policy, code, body.report_data, bytes(48)), bad)
    assert isinstance(quote.quote, QuoteV4)
