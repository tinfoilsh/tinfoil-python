"""SEV-SNP expectations: policy translation per product line, the pinned fields, and validation of real Turin
reports against the endorsement fixture."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import replace

import pytest

from tests import sev_fixtures as fx
from tinfoil.verifier._measurement import SEVSNP
from tinfoil.verifier._policy import TCB, GuestPolicy, SEVSNPPolicy, SNPPlatform
from tinfoil.verifier._quote import sev
from tinfoil.verifier._quote.sev import expectations as exp
from tinfoil.verifier._quote.sev.authenticate import product_from_report, trusted_roots
from tinfoil.verifier._quote.sev.identity import identity
from tinfoil.verifier._quote.sev.lib import abi
from tinfoil.verifier._quote.sev.lib.abi import Report, parse_report
from tinfoil.verifier._quote.sev.lib.chain import CertificateChain
from tinfoil.verifier._x509.certificate import parse_certificate


def test_options_genoa() -> None:
    options = exp._options(fx.sev_policy(fx.BOX3_GENOA_ID), sev.PRODUCT_GENOA)
    assert options.minimum_build == 21
    assert options.minimum_version == (1 << 8) | 55
    assert options.minimum_tcb.bl_spl == 7
    assert options.minimum_tcb.snp_spl == 14
    assert options.minimum_tcb.ucode_spl == 72
    assert options.guest_policy.smt
    assert not options.guest_policy.debug
    assert options.platform_info is not None
    assert options.platform_info.tsme_enabled


def test_options_turin() -> None:
    options = exp._options(fx.sev_policy(fx.BOX2_TURIN_ID), sev.PRODUCT_TURIN)
    assert options.minimum_build == 0
    assert options.minimum_version == (1 << 8) | 58
    assert options.minimum_tcb.fmc_spl == 1
    assert options.minimum_tcb.bl_spl == 1
    assert options.minimum_tcb.tee_spl == 1
    assert options.minimum_tcb.snp_spl == 4
    assert options.minimum_tcb.ucode_spl == 82
    assert options.platform_info is not None
    assert options.platform_info.iommu_write_safe
    assert options.minimum_tcb.to_version_struct().tcb == 0x5200000004010101


def zero_tcb() -> TCB:
    return TCB(bl_spl=0, tee_spl=0, snp_spl=0, ucode_spl=0)


def pinned_policy() -> SEVSNPPolicy:
    return SEVSNPPolicy(
        minimum_build=21,
        minimum_api_version="1.55",
        minimum_abi_version="0.31",
        minimum_guest_svn=0,
        minimum_tcb=zero_tcb(),
        minimum_launch_tcb=zero_tcb(),
        guest_policy=GuestPolicy(smt=True, page_swap_disable=True),
        platform_info=SNPPlatform(),
        permit_provisional_firmware=False,
        vmpl=0,
        host_data="ab" * 32,
        image_id="cd" * 16,
        family_id="ef" * 16,
        require_author_key=False,
        require_id_block=False,
        minimum_launch_mitigation_vector=3,
        minimum_current_mitigation_vector=1,
    )


def test_options_pinned_fields() -> None:
    policy = pinned_policy()
    options = exp._options(policy, sev.PRODUCT_GENOA)
    assert options.host_data == bytes.fromhex("ab" * 32)
    assert options.image_id == bytes.fromhex("cd" * 16)
    assert options.family_id == bytes.fromhex("ef" * 16)
    assert options.guest_policy.page_swap_disable
    assert options.guest_policy.abi_major == 0
    assert options.guest_policy.abi_minor == 31
    assert options.minimum_launch_mitigation_vector == 3
    assert options.minimum_current_mitigation_vector == 1

    # The pinned fields are required: absent or malformed values reject.
    with pytest.raises(sev.SevPolicyError, match="host_data"):
        exp._options(replace(policy, host_data="abcd"), sev.PRODUCT_GENOA)
    with pytest.raises(sev.SevPolicyError, match="host_data"):
        exp._options(replace(policy, host_data=""), sev.PRODUCT_GENOA)

    # ID-block trust material is not modeled: requiring it must reject.
    with pytest.raises(sev.SevPolicyError, match="not supported"):
        exp._options(replace(policy, require_id_block=True), sev.PRODUCT_GENOA)


def test_options_reject_invalid_product_fields() -> None:
    turin = fx.sev_policy(fx.BOX2_TURIN_ID)
    with pytest.raises(sev.SevPolicyError, match="fmc_spl is required"):
        exp._options(replace(turin, minimum_tcb=replace(turin.minimum_tcb, fmc_spl=None)), sev.PRODUCT_TURIN)
    with pytest.raises(sev.SevPolicyError, match="iommu_write_safe is required"):
        exp._options(
            replace(turin, platform_info=replace(turin.platform_info, iommu_write_safe=False)), sev.PRODUCT_TURIN
        )

    genoa = fx.sev_policy(fx.BOX3_GENOA_ID)
    with pytest.raises(sev.SevPolicyError, match="fmc_spl is not valid"):
        exp._options(replace(genoa, minimum_tcb=replace(genoa.minimum_tcb, fmc_spl=1)), sev.PRODUCT_GENOA)
    with pytest.raises(sev.SevPolicyError, match="iommu_write_safe is not valid"):
        exp._options(
            replace(genoa, platform_info=replace(genoa.platform_info, iommu_write_safe=True)), sev.PRODUCT_GENOA
        )

    with pytest.raises(sev.SevPolicyError, match="unsupported SEV product line"):
        exp._options(turin, "Milan")


def test_version_parsing() -> None:
    assert exp.parse_version("minimum_api_version", "1.55") == (1 << 8) | 55
    assert exp.parse_version_parts("v", "255.0") == (255, 0)
    assert exp.parse_version_parts("v", "001.0") == (1, 0)
    for bad in ("1", "1.", ".1", "1.2.3", "256.0", "1.256", "a.b", "+1.0", "1.-1", "0001.0"):
        with pytest.raises(sev.SevPolicyError, match="v"):
            exp.parse_version_parts("v", bad)


def test_tcb_parts_translation() -> None:
    parts = exp.tcb_parts("minimum_tcb", sev.PRODUCT_GENOA, TCB(bl_spl=7, tee_spl=0, snp_spl=20, ucode_spl=72))
    assert parts.to_version_struct().tcb == fx.GENOA_TCB
    with pytest.raises(sev.SevPolicyError, match="minimum_tcb: SnpSpl TCB part is 200"):
        exp.tcb_parts("minimum_tcb", sev.PRODUCT_GENOA, TCB(bl_spl=0, tee_spl=0, snp_spl=200, ucode_spl=0))
    with pytest.raises(sev.SevPolicyError, match=r"minimum_tcb\.bl_spl is required"):
        exp.tcb_parts("minimum_tcb", sev.PRODUCT_GENOA, TCB(tee_spl=0, snp_spl=0, ucode_spl=0))


def test_parse_turin_platform_info() -> None:
    assert abi.parse_snp_platform_info(0x64) == abi.SnpPlatformInfo(
        ecc_enabled=True, alias_check_complete=True, iommu_write_safe=True
    )
    with pytest.raises(abi.AbiError, match="unrecognized platform info bit"):
        abi.parse_snp_platform_info(0x164)


def box2_quote() -> tuple[sev.Quote, Report]:
    report = parse_report(fx.box2_turin_report())
    vcek = parse_certificate(fx.box2_turin_vcek())
    pinned = trusted_roots(product_from_report(report), None)
    verified = sev.Quote(
        identity=identity(report.chip_id),
        measurement=SEVSNP(launch=report.measurement),
        product_line=pinned.product_line,
        report=report,
        chain=CertificateChain(ark=pinned.ark, ask=pinned.ask, vcek=vcek),
    )
    return verified, report


def with_report(verified: sev.Quote, report: Report) -> sev.Quote:
    return replace(verified, report=report)


def test_validate_box2_turin_attestation() -> None:
    verified, report = box2_quote()
    policy = fx.sev_policy(verified.identity)
    expected = sev.assemble(policy, verified, report.measurement, report.report_data)
    sev.validate(expected, verified)
    # The assembled expectations hold their own copies of the caller's bytes.
    report_data = bytearray(report.report_data)
    expected = sev.assemble(policy, verified, report.measurement, bytes(report_data))
    report_data[0] ^= 0xFF
    sev.validate(expected, verified)


def test_identity() -> None:
    assert identity(bytes.fromhex(fx.BOX2_TURIN_ID)) == fx.BOX2_TURIN_ID
    with pytest.raises(ValueError, match="must be 64 bytes"):
        identity(bytes([1, 2, 3]))


def test_check_signer_rejects_unsigned_chip_key_and_id_blocks() -> None:
    masked = abi.compose_signer_info(abi.SignerInfo(abi.ReportSigner.VCEK, mask_chip_key=True, author_key_en=False))
    with pytest.raises(sev.SevPolicyError, match="MASK_CHIP_KEY set"):
        exp.check_signer(fx.make_report(signer_info=masked))
    author = abi.compose_signer_info(abi.SignerInfo(abi.ReportSigner.VCEK, mask_chip_key=False, author_key_en=True))
    with pytest.raises(sev.SevPolicyError, match="carries an author key;"):
        exp.check_signer(fx.make_report(signer_info=author))
    with pytest.raises(sev.SevPolicyError, match="carries an ID block"):
        exp.check_signer(fx.make_report(id_key_digest=b"\x01" + bytes(47)))
    with pytest.raises(sev.SevPolicyError, match="carries an author key digest"):
        exp.check_signer(fx.make_report(author_key_digest=bytes(47) + b"\x01"))
    exp.check_signer(fx.make_report())


def test_check_signer_rejects_an_all_zero_chip_id() -> None:
    """The zero-CHIP_ID rule is applied at validation as well as at authentication, so a quote that reaches
    expectations with 64 zero bytes as its identity is rejected whichever path built it."""
    with pytest.raises(sev.SevPolicyError, match="CHIP_ID is all zero; masked platform identities"):
        exp.check_signer(fx.make_report(chip_id=bytes(64)))
    turin = parse_report(fx.box2_turin_report())
    exp.check_signer(turin)
    with pytest.raises(sev.SevPolicyError, match="CHIP_ID is all zero"):
        exp.check_signer(replace(turin, chip_id=bytes(64)))
    # A quote built around a zero identity, with expectations assembled for that identity, passes every other
    # check and is rejected by the signer check alone.
    verified, report = box2_quote()
    zeroed = replace(verified, identity=identity(bytes(64)), report=replace(report, chip_id=bytes(64)))
    expectations = exp.assemble(fx.sev_policy(verified.identity), zeroed, report.measurement, report.report_data)
    with pytest.raises(sev.SevPolicyError, match="CHIP_ID is all zero"):
        exp.validate(expectations, zeroed)


def test_assemble_checks_its_byte_arguments() -> None:
    verified, report = box2_quote()
    policy = fx.sev_policy(verified.identity)
    with pytest.raises(sev.SevPolicyError, match="launch measurement must be 48 bytes"):
        sev.assemble(policy, verified, bytes(47), report.report_data)
    with pytest.raises(sev.SevPolicyError, match="report data must be 64 bytes"):
        sev.assemble(policy, verified, report.measurement, bytes(63))
    with pytest.raises(sev.SevPolicyError, match="decoding platform identity"):
        sev.assemble(policy, replace(verified, identity="zz"), report.measurement, report.report_data)
    # The identity is the whole CHIP_ID; a bare Turin hwID is not enough.
    with pytest.raises(
        sev.SevPolicyError, match="decoding platform identity: platform identity must be 64 bytes, got 8"
    ):
        sev.assemble(policy, replace(verified, identity=fx.BOX2_TURIN_ID[:16]), report.measurement, report.report_data)


def test_config_bound_enforces_config_and_platform_constraints() -> None:
    """Authentication and appraisal are separate: these mutations exercise the complete appraisal of a quote after
    the authentication boundary."""
    guest_policy = 0x30133
    verified, captured = box2_quote()
    policy = fx.sev_policy(verified.identity)
    config_hash = hashlib.sha256(b"approved YAML bytes").digest()
    report = replace(captured, host_data=config_hash, policy=guest_policy)
    verified = with_report(verified, report)
    launch = report.measurement
    report_data = report.report_data
    policy = replace(policy, minimum_abi_version="1.51", host_data="")
    with pytest.raises(sev.SevPolicyError, match="host_data"):
        sev.assemble(policy, verified, launch, report_data)
    resolved = replace(policy, host_data=config_hash.hex())
    expected = sev.assemble(resolved, verified, launch, report_data)
    sev.validate(expected, verified)

    mutations: dict[str, Callable[[Report], Report]] = {
        "config hash": lambda r: replace(r, host_data=fx.flip(r.host_data, 0)),
        "launch measurement": lambda r: replace(r, measurement=fx.flip(r.measurement, 0)),
        "ABI below floor": lambda r: replace(r, policy=r.policy - 1),
        "guest debug": lambda r: replace(r, policy=r.policy | abi.snp_policy_to_int(abi.SnpPolicy(debug=True))),
        "platform state": lambda r: replace(r, platform_info=r.platform_info ^ 1),
        "family ID": lambda r: replace(r, family_id=fx.flip(r.family_id, 0)),
        "image ID": lambda r: replace(r, image_id=fx.flip(r.image_id, 0)),
        "ID block": lambda r: replace(r, id_key_digest=b"\x01" + r.id_key_digest[1:]),
        "versioned ID block": lambda r: replace(r, guest_svn=1, id_key_digest=b"\x01" + r.id_key_digest[1:]),
        "report data": lambda r: replace(r, report_data=fx.flip(r.report_data, 0)),
    }
    for name, mutate in mutations.items():
        with pytest.raises(sev.SevPolicyError):
            sev.validate(expected, with_report(verified, mutate(report)))
        assert name
    # The platform policy defines an ABI floor.
    sev.validate(expected, with_report(verified, replace(report, policy=report.policy + 1)))

    guest_svn_floor = 1
    legacy = sev.assemble(replace(resolved, minimum_guest_svn=guest_svn_floor), verified, launch, report_data)
    for svn in (guest_svn_floor, guest_svn_floor + 1):
        sev.validate(legacy, with_report(verified, replace(report, guest_svn=svn)))
    with pytest.raises(sev.SevPolicyError, match="GUEST_SVN"):
        sev.validate(legacy, with_report(verified, replace(report, guest_svn=guest_svn_floor - 1)))


def test_strict_equality_rejects_what_the_maximum_masks_allow() -> None:
    """A capability the policy permits but the report lacks passes the maximum-mask comparison and fails the exact
    one; a feature the policy forbids fails the mask first."""
    verified, report = box2_quote()
    expected = sev.assemble(fx.sev_policy(verified.identity), verified, report.measurement, report.report_data)
    smt_bit = abi.snp_policy_to_int(abi.SnpPolicy(smt=True)) & ~(1 << abi.POLICY_RESERVED_1_BIT)
    assert report.policy & smt_bit
    with pytest.raises(sev.SevPolicyError, match="guest policy does not match"):
        sev.validate(expected, with_report(verified, replace(report, policy=report.policy & ~smt_bit)))

    permitted_smt = replace(
        expected,
        options=replace(expected.options, platform_info=replace(expected.want_platform_info, smt_enabled=True)),
        want_platform_info=replace(expected.want_platform_info, smt_enabled=True),
    )
    assert not report.platform_info & 1
    with pytest.raises(sev.SevPolicyError, match="PLATFORM_INFO does not match"):
        sev.validate(permitted_smt, verified)
    with pytest.raises(sev.SevPolicyError, match="unauthorized feature SEV-TIO"):
        sev.validate(expected, with_report(verified, replace(report, platform_info=report.platform_info | 0x80)))
