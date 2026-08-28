"""TDX policy assembly/validation (tinfoil.v3.tdx.expectations), mirroring Go
expectations_test.go against a synthetic quote."""

import dataclasses

import pytest

from tdx_material import build_synth_chain, build_tdx_quote_v4
from tinfoil.v3.errors import POLICY_REJECTED, VerificationError
from tinfoil.v3.measurement import TDX_GUEST_V2, Measurement
from tinfoil.v3.policy import Artifact, PlatformMeasurement, Shape, TDXPolicy
from tinfoil.v3.tdx.authenticate import TdxQuote
from tinfoil.v3.tdx.expectations import CodeRegisters, tdx_assemble, tdx_validate
from tinfoil.v3.tdx.quote import quote_to_proto_v4

SHAPE = Shape(cpus=8, memory_mb=65536, gpus=None, disks=4)


@pytest.fixture(scope="module")
def quote() -> TdxQuote:
    chain = build_synth_chain()
    proto = quote_to_proto_v4(build_tdx_quote_v4(chain))
    body = proto.td_quote_body
    return TdxQuote(
        identity="55" * 16,
        measurement=Measurement(
            type=TDX_GUEST_V2,
            registers=[body.mr_td.hex()] + [r.hex() for r in body.rtmrs],
        ),
        tcb_evaluation_data_number=5,
        body=body,
        quote=proto,
    )


@pytest.fixture(scope="module")
def code(quote) -> CodeRegisters:
    body = quote.quote.td_quote_body
    return CodeRegisters(rtmr1=body.rtmrs[1], rtmr2=body.rtmrs[2], rtmr3=body.rtmrs[3])


@pytest.fixture(scope="module")
def report_data(quote) -> bytes:
    return quote.quote.td_quote_body.report_data


def matching_policy(quote) -> TDXPolicy:
    body = quote.quote.td_quote_body
    return TDXPolicy(
        qe_vendor_id=quote.quote.header.qe_vendor_id.hex(),
        minimum_tee_tcb_svn=body.tee_tcb_svn.hex(),
        mr_seam=body.mr_seam.hex(),
        td_attributes=body.td_attributes.hex(),
        xfam=body.xfam.hex(),
        minimum_tcb_evaluation_data_number=5,
        platform_measurements=["sample"],
    )


def artifact(quote) -> Artifact:
    body = quote.quote.td_quote_body
    return Artifact(
        format="",
        measurements={
            "sample": PlatformMeasurement(
                mrtd=body.mr_td.hex(),
                rtmr0=body.rtmrs[0].hex(),
                shape=SHAPE,
                stack=None,
            )
        },
        machines={},
        policies={},
    )


def assemble(a, p, quote, code, report_data):
    e, name = tdx_assemble(a, p, SHAPE, quote, code, report_data)
    assert name == "sample"
    return e


def test_options_translation(quote, code, report_data):
    e = assemble(artifact(quote), matching_policy(quote), quote, code, report_data)
    assert e.opts.qe_vendor_id.hex() == "939a7233f79c4ca9940a0db3957f0607"
    assert e.opts.mr_config_id == bytes(48)
    assert e.opts.mr_owner == bytes(48)
    assert e.opts.mr_owner_config == bytes(48)
    assert e.opts.mr_td == quote.quote.td_quote_body.mr_td
    assert e.opts.rtmrs[0] == quote.quote.td_quote_body.rtmrs[0]
    assert e.opts.report_data == report_data
    assert e.minimum_tcb_evaluation_data_number == 5


def test_validate_happy(quote, code, report_data):
    e = assemble(artifact(quote), matching_policy(quote), quote, code, report_data)
    tdx_validate(e, quote)  # does not raise


def test_bad_mr_seam_rejects(quote, code, report_data):
    p = dataclasses.replace(matching_policy(quote), mr_seam="00" * 48)
    e = assemble(artifact(quote), p, quote, code, report_data)
    with pytest.raises(VerificationError, match="MR_SEAM") as ei:
        tdx_validate(e, quote)
    assert ei.value.layer == POLICY_REJECTED


def test_collateral_floor_rejects(quote, code, report_data):
    # A collateral floor above the observed number must reject.
    e = assemble(artifact(quote), matching_policy(quote), quote, code, report_data)
    stale = dataclasses.replace(quote, tcb_evaluation_data_number=4)
    with pytest.raises(VerificationError, match="below the policy minimum"):
        tdx_validate(e, stale)


def test_unendorsed_measurement_fails_assembly(quote, code, report_data):
    # A quote whose MRTD/RTMR0 resolve no endorsed measurement fails at
    # assembly, before any validation runs.
    bad = Artifact(
        format="",
        measurements={
            "sample": PlatformMeasurement(mrtd="ff" * 48, rtmr0="ff" * 48, shape=SHAPE, stack=None)
        },
        machines={},
        policies={},
    )
    with pytest.raises(VerificationError, match="do not match any allowed configuration") as ei:
        tdx_assemble(bad, matching_policy(quote), SHAPE, quote, code, report_data)
    assert ei.value.layer == POLICY_REJECTED


def test_wrong_shape_fails_assembly(quote, code, report_data):
    with pytest.raises(VerificationError, match="required VM shape"):
        tdx_assemble(
            artifact(quote),
            matching_policy(quote),
            Shape(cpus=4, memory_mb=1024, gpus=None, disks=1),
            quote,
            code,
            report_data,
        )


def test_bad_td_attributes_rejects(quote, code, report_data):
    p = dataclasses.replace(matching_policy(quote), td_attributes="42" * 8)
    e = assemble(artifact(quote), p, quote, code, report_data)
    with pytest.raises(VerificationError, match="TD_ATTRIBUTES"):
        tdx_validate(e, quote)


def test_td_attributes_fixed0_bits_reported(quote, code, report_data):
    # 0x4242... sets bits outside tdAttributesFixed0; both the byte mismatch
    # and the fixed-bit violation are reported (multierr.Combine).
    p = dataclasses.replace(matching_policy(quote), td_attributes="42" * 8)
    e = assemble(artifact(quote), p, quote, code, report_data)
    with pytest.raises(VerificationError, match="quote field TD_ATTRIBUTES"):
        tdx_validate(e, quote)


def test_bad_code_register_rejects(quote, code, report_data):
    # A workload register differing from code provenance must reject.
    bad_code = dataclasses.replace(code, rtmr1=bytes(48))
    e = assemble(artifact(quote), matching_policy(quote), quote, bad_code, report_data)
    with pytest.raises(VerificationError, match=r"RTMR\[1\]"):
        tdx_validate(e, quote)


def test_bad_report_data_rejects(quote, code, report_data):
    # A REPORT_DATA differing from the envelope's expectation must reject.
    e = assemble(artifact(quote), matching_policy(quote), quote, code, bytes(64))
    with pytest.raises(VerificationError, match="REPORT_DATA"):
        tdx_validate(e, quote)


def test_minimum_tee_tcb_svn_rejects(quote, code, report_data):
    higher = bytearray(quote.quote.td_quote_body.tee_tcb_svn)
    higher[2] += 1
    p = dataclasses.replace(matching_policy(quote), minimum_tee_tcb_svn=bytes(higher).hex())
    e = assemble(artifact(quote), p, quote, code, report_data)
    with pytest.raises(VerificationError, match="TEE TCB security-version number"):
        tdx_validate(e, quote)


def test_invalid_policy_rejects_at_assembly(quote, code, report_data):
    p = dataclasses.replace(matching_policy(quote), minimum_tcb_evaluation_data_number=None)
    with pytest.raises(VerificationError, match="minimum_tcb_evaluation_data_number is required") as ei:
        tdx_assemble(artifact(quote), p, SHAPE, quote, code, report_data)
    assert ei.value.layer == POLICY_REJECTED

    p = dataclasses.replace(matching_policy(quote), qe_vendor_id="")
    with pytest.raises(VerificationError, match="qe_vendor_id is required"):
        tdx_assemble(artifact(quote), p, SHAPE, quote, code, report_data)
