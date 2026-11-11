"""Policy validation of a decoded SEV-SNP report: every rule in ``validate_report`` on hand-built reports."""

from __future__ import annotations

import pytest

from tests import sev_fixtures as fx
from tinfoil.verifier._quote.sev.lib.abi import (
    ReportSigner,
    SignerInfo,
    SnpPlatformInfo,
    SnpPolicy,
    compose_signer_info,
    snp_policy_to_int,
)
from tinfoil.verifier._quote.sev.lib.tcb import TCBParts, new_tcb_parts
from tinfoil.verifier._quote.sev.lib.validate import (
    ValidationError,
    ValidationOptions,
    compare_policy_versions,
    validate_platform_info,
    validate_policy,
    validate_report,
)

GENOA_MINIMUM = new_tcb_parts("Genoa", TCBParts(bl_spl=7, tee_spl=0, snp_spl=20, ucode_spl=72))
BASE_OPTIONS = ValidationOptions(guest_policy=SnpPolicy(smt=True))
"""Options that the default report of ``make_report`` satisfies: the policy allows SMT and nothing else."""


def policy(**flags: object) -> SnpPolicy:
    return SnpPolicy(**flags)  # type: ignore[arg-type]


class TestValidationOptions:
    def test_defaults_always_apply(self) -> None:
        options = ValidationOptions()
        assert options.guest_policy == SnpPolicy()
        assert options.minimum_guest_svn == 0
        assert options.minimum_build == 0
        assert options.minimum_version == 0
        assert options.minimum_tcb == TCBParts()
        assert options.minimum_launch_tcb == TCBParts()
        assert not options.permit_provisional_firmware
        for name in ("report_data", "host_data", "image_id", "family_id", "report_id", "report_id_ma"):
            assert getattr(options, name) is None
        assert options.measurement is None
        assert options.chip_id is None
        assert options.platform_info is None
        assert options.vmpl is None
        assert options.minimum_launch_mitigation_vector == 0
        assert options.minimum_current_mitigation_vector == 0

    def test_default_policy_forbids_every_capability(self) -> None:
        with pytest.raises(ValidationError, match="unauthorized symmetric multithreading"):
            validate_report(fx.make_report(), fx.genoa_extensions(), ValidationOptions())


class TestValidatePolicy:
    def test_exact_match_passes(self) -> None:
        required = policy(abi_major=2, abi_minor=1, smt=True, single_socket=True, mem_aes256_xts=True, rapl_dis=True)
        validate_policy(snp_policy_to_int(required), required)

    def test_abi_version_is_a_floor(self) -> None:
        report = snp_policy_to_int(policy(abi_major=2, abi_minor=1))
        validate_policy(report, policy(abi_major=2, abi_minor=0))
        validate_policy(report, policy(abi_major=1, abi_minor=255))
        with pytest.raises(ValidationError, match=r"required policy ABI version \(2.2\) is greater"):
            validate_policy(report, policy(abi_major=2, abi_minor=2))
        with pytest.raises(ValidationError, match="is greater"):
            validate_policy(report, policy(abi_major=3, abi_minor=0))

    @pytest.mark.parametrize(
        ("flag", "message"),
        [
            ("migrate_ma", "unauthorized migration agent capability"),
            ("debug", "unauthorized debug capability"),
            ("smt", "unauthorized symmetric multithreading"),
            ("cxl_allowed", "unauthorized CXL capability"),
        ],
    )
    def test_unauthorized_capabilities(self, flag: str, message: str) -> None:
        report = snp_policy_to_int(policy(**{flag: True}))
        with pytest.raises(ValidationError, match=message):
            validate_policy(report, policy())
        validate_policy(report, policy(**{flag: True}))

    @pytest.mark.parametrize(
        ("flag", "message"),
        [
            ("single_socket", "required single socket restriction not present"),
            ("mem_aes256_xts", "unauthorized memory encryption mode"),
            ("rapl_dis", "unauthorized RAPL capability"),
            ("ciphertext_hiding_dram", "ciphertext hiding in DRAM isn't enforced"),
            ("page_swap_disable", "unauthorized page swap capability"),
        ],
    )
    def test_missing_required_restrictions(self, flag: str, message: str) -> None:
        with pytest.raises(ValidationError, match=message):
            validate_policy(snp_policy_to_int(policy()), policy(**{flag: True}))
        validate_policy(snp_policy_to_int(policy(**{flag: True})), policy(**{flag: True}))

    def test_malformed_report_policy(self) -> None:
        with pytest.raises(ValidationError, match="could not parse SNP policy"):
            validate_policy(0, policy())


class TestComparePolicyVersions:
    def test_ordering(self) -> None:
        assert (
            compare_policy_versions(policy(abi_major=2, abi_minor=1), policy(abi_major=2, abi_minor=1, smt=True)) == 0
        )
        assert compare_policy_versions(policy(abi_major=1, abi_minor=1), policy(abi_major=2, abi_minor=1)) < 0
        assert compare_policy_versions(policy(abi_major=2, abi_minor=1), policy(abi_major=1, abi_minor=1)) > 0
        assert compare_policy_versions(policy(abi_major=1, abi_minor=0), policy(abi_major=1, abi_minor=1)) < 0
        assert compare_policy_versions(policy(abi_major=1, abi_minor=1), policy(abi_major=1, abi_minor=0)) > 0
        assert compare_policy_versions(policy(abi_major=1, abi_minor=255), policy(abi_major=2, abi_minor=0)) < 0


class TestValidatePlatformInfo:
    def test_none_leaves_the_field_unchecked(self) -> None:
        validate_platform_info(0xFF, None)

    def test_exact_match_passes(self) -> None:
        validate_platform_info(
            0b0010_1001, SnpPlatformInfo(smt_enabled=True, rapl_disabled=True, alias_check_complete=True)
        )

    @pytest.mark.parametrize(
        ("bit", "message"),
        [
            (0, "unauthorized platform feature SMT enabled"),
            (1, "unauthorized platform feature TSME enabled"),
            (7, "unauthorized feature SEV-TIO enabled"),
        ],
    )
    def test_unauthorized_features(self, bit: int, message: str) -> None:
        with pytest.raises(ValidationError, match=message):
            validate_platform_info(1 << bit, SnpPlatformInfo())

    @pytest.mark.parametrize(
        ("field", "message"),
        [
            ("ecc_enabled", "required platform feature ECC not enabled"),
            ("rapl_disabled", "unauthorized platform feature RAPL enabled"),
            ("ciphertext_hiding_dram_enabled", "required ciphertext hiding in DRAM not enforced"),
            ("alias_check_complete", "required memory alias check hasn't been completed"),
            ("iommu_write_safe", "required IOMMU write-safe hardware mitigation is not present"),
            ("tio_enabled", "required feature SEV-TIO not enabled"),
        ],
    )
    def test_missing_required_features(self, field: str, message: str) -> None:
        with pytest.raises(ValidationError, match=message):
            validate_platform_info(0, SnpPlatformInfo(**{field: True}))

    def test_reserved_bits_reject(self) -> None:
        with pytest.raises(ValidationError, match="could not parse SNP platform info"):
            validate_platform_info(1 << 8, SnpPlatformInfo())


class TestValidateReport:
    def test_base_report_passes(self) -> None:
        validate_report(fx.make_report(), fx.genoa_extensions(), BASE_OPTIONS)

    def test_minimum_guest_svn(self) -> None:
        report = fx.make_report(guest_svn=5)
        validate_report(
            report, fx.genoa_extensions(), ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_guest_svn=5)
        )
        validate_report(
            report, fx.genoa_extensions(), ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_guest_svn=3)
        )
        with pytest.raises(ValidationError, match="GUEST_SVN 5 is less than the required minimum 10"):
            validate_report(
                report, fx.genoa_extensions(), ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_guest_svn=10)
            )

    def test_minimum_build_and_version(self) -> None:
        exts = fx.genoa_extensions()
        validate_report(fx.make_report(), exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_build=21))
        with pytest.raises(ValidationError, match=r"firmware build number 21 is less than the required minimum 25"):
            validate_report(
                fx.make_report(), exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_build=25)
            )
        validate_report(
            fx.make_report(), exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_version=(1 << 8) | 55)
        )
        with pytest.raises(
            ValidationError, match=r"firmware API version \(1.55\) is less than the required minimum \(1.64\)"
        ):
            validate_report(
                fx.make_report(),
                exts,
                ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_version=(1 << 8) | 64),
            )

    def test_committed_must_equal_current_unless_provisional(self) -> None:
        exts = fx.genoa_extensions()
        provisional = ValidationOptions(guest_policy=SnpPolicy(smt=True), permit_provisional_firmware=True)
        with pytest.raises(
            ValidationError, match=r"committed build number 20 does not match the current build number 21"
        ):
            validate_report(fx.make_report(committed_build=20), exts, BASE_OPTIONS)
        validate_report(fx.make_report(committed_build=20), exts, provisional)
        with pytest.raises(ValidationError, match="committed build number 22 is greater"):
            validate_report(fx.make_report(committed_build=22), exts, provisional)
        with pytest.raises(ValidationError, match=r"committed API version \(1.54\) does not match"):
            validate_report(fx.make_report(committed_minor=54), exts, BASE_OPTIONS)
        validate_report(fx.make_report(committed_minor=54), exts, provisional)
        with pytest.raises(ValidationError, match=r"committed API version \(1.56\) is greater"):
            validate_report(fx.make_report(committed_minor=56), exts, provisional)

    def test_tcb_relationships(self) -> None:
        exts = fx.genoa_extensions()
        lower = fx.GENOA_TCB - 1
        higher = fx.GENOA_TCB + 1
        with pytest.raises(ValidationError, match=r"COMMITTED_TCB .* does not match the report's CURRENT_TCB"):
            validate_report(fx.make_report(committed_tcb=lower), exts, BASE_OPTIONS)
        provisional = ValidationOptions(guest_policy=SnpPolicy(smt=True), permit_provisional_firmware=True)
        validate_report(fx.make_report(committed_tcb=lower), exts, provisional)
        with pytest.raises(ValidationError, match=r"CURRENT_TCB .* is lower than the report's COMMITTED_TCB"):
            validate_report(fx.make_report(committed_tcb=higher), exts, provisional)
        with pytest.raises(ValidationError, match=r"REPORTED_TCB .* does not match the TCB of the VCEK certificate"):
            validate_report(fx.make_report(reported_tcb=lower), exts, BASE_OPTIONS)
        with pytest.raises(ValidationError, match=r"CURRENT_TCB .* is lower than the TCB of the VCEK certificate"):
            validate_report(fx.make_report(current_tcb=lower, committed_tcb=lower), exts, BASE_OPTIONS)
        validate_report(
            fx.make_report(), exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_tcb=GENOA_MINIMUM)
        )
        above = new_tcb_parts("Genoa", TCBParts(bl_spl=8, tee_spl=0, snp_spl=20, ucode_spl=72))
        with pytest.raises(ValidationError, match=r"REPORTED_TCB .* is lower than the policy minimum TCB"):
            validate_report(
                fx.make_report(), exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_tcb=above)
            )
        with pytest.raises(ValidationError, match=r"LAUNCH_TCB .* is lower than the policy minimum launch TCB"):
            validate_report(
                fx.make_report(), exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_launch_tcb=above)
            )
        validate_report(
            fx.make_report(launch_tcb=higher),
            exts,
            ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_launch_tcb=GENOA_MINIMUM),
        )

    def test_tcb_layouts_must_agree(self) -> None:
        turin_exts = fx.genoa_extensions()
        turin_exts = type(turin_exts)(
            struct_version=1, product_name="Turin-B0", hwid=bytes(8), tcb=turin_exts.tcb.__class__(version=1, tcb=0)
        )
        with pytest.raises(ValidationError, match="different TCB formats"):
            validate_report(fx.make_report(), turin_exts, BASE_OPTIONS)
        with pytest.raises(ValidationError, match="could not determine report TCB format"):
            validate_report(fx.make_report(cpuid1_eax_fms=0), fx.genoa_extensions(), BASE_OPTIONS)
        # A version 2 report is read in the legacy layout, which the version 0 certificate shares.
        validate_report(fx.make_report(version=2, cpuid1_eax_fms=0), fx.genoa_extensions(), BASE_OPTIONS)
        with pytest.raises(ValidationError, match="cannot be used with a non-legacy TCB format"):
            validate_report(fx.make_report(version=2, cpuid1_eax_fms=0), turin_exts, BASE_OPTIONS)
        # A minimum in another layout is never satisfied.
        turin_minimum = new_tcb_parts("Turin", TCBParts(fmc_spl=0, bl_spl=0, tee_spl=0, snp_spl=0, ucode_spl=0))
        with pytest.raises(ValidationError, match="lower than the policy minimum TCB"):
            validate_report(
                fx.make_report(),
                fx.genoa_extensions(),
                ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_tcb=turin_minimum),
            )

    def test_verbatim_fields(self) -> None:
        exts = fx.genoa_extensions()
        report = fx.make_report(report_data=b"A" * 64, host_data=b"B" * 32, measurement=b"C" * 48)
        options = ValidationOptions(
            guest_policy=SnpPolicy(smt=True), report_data=b"A" * 64, host_data=b"B" * 32, measurement=b"C" * 48
        )
        validate_report(report, exts, options)
        with pytest.raises(ValidationError, match="report field REPORT_DATA is"):
            validate_report(report, exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), report_data=b"X" * 64))
        with pytest.raises(ValidationError, match="report field HOST_DATA is"):
            validate_report(report, exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), host_data=b"Y" * 32))
        with pytest.raises(ValidationError, match="report field MEASUREMENT is"):
            validate_report(report, exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), measurement=b"Z" * 48))
        with pytest.raises(ValidationError, match="option ChipID must be nil or 64 bytes"):
            validate_report(report, exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), chip_id=b"\x11"))
        with pytest.raises(ValidationError, match="report field FAMILY_ID is"):
            validate_report(report, exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), family_id=b"\x01" * 16))
        validate_report(
            report, exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), chip_id=fx.GENOA_HWID, image_id=bytes(16))
        )

    def test_vmpl(self) -> None:
        exts = fx.genoa_extensions()
        validate_report(fx.make_report(vmpl=1), exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), vmpl=1))
        with pytest.raises(ValidationError, match="report VMPL 1 is not 2"):
            validate_report(fx.make_report(vmpl=1), exts, ValidationOptions(guest_policy=SnpPolicy(smt=True), vmpl=2))

    def test_platform_info(self) -> None:
        exts = fx.genoa_extensions()
        report = fx.make_report(platform_info=(1 << 0) | (1 << 3))
        validate_report(
            report,
            exts,
            ValidationOptions(
                guest_policy=SnpPolicy(smt=True), platform_info=SnpPlatformInfo(smt_enabled=True, rapl_disabled=True)
            ),
        )
        with pytest.raises(ValidationError, match="unauthorized platform feature SMT enabled"):
            validate_report(
                report,
                exts,
                ValidationOptions(guest_policy=SnpPolicy(smt=True), platform_info=SnpPlatformInfo(rapl_disabled=True)),
            )

    def test_mitigation_vectors(self) -> None:
        exts = fx.genoa_extensions()
        report = fx.make_report(launch_mit_vector=0b11, current_mit_vector=0b01)
        validate_report(
            report,
            exts,
            ValidationOptions(
                guest_policy=SnpPolicy(smt=True),
                minimum_launch_mitigation_vector=0b10,
                minimum_current_mitigation_vector=0b01,
            ),
        )
        with pytest.raises(ValidationError, match=r"launch mitigation vector \(0x3\) is missing required bits"):
            validate_report(
                report,
                exts,
                ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_launch_mitigation_vector=0b100),
            )
        with pytest.raises(ValidationError, match=r"current mitigation vector \(0x1\) is missing required bits"):
            validate_report(
                report,
                exts,
                ValidationOptions(guest_policy=SnpPolicy(smt=True), minimum_current_mitigation_vector=0b11),
            )

    def test_chip_id_binds_to_the_certificate_hwid(self) -> None:
        with pytest.raises(ValidationError, match=r"CHIP_ID .* is not the same as the VCEK certificate's HWID"):
            validate_report(fx.make_report(chip_id=b"\x22" * 64), fx.genoa_extensions(), BASE_OPTIONS)
        # An all-zero (masked) CHIP_ID is not compared.
        validate_report(fx.make_report(chip_id=bytes(64)), fx.genoa_extensions(), BASE_OPTIONS)
        # An eight-byte hardware id binds the first eight bytes.
        short = fx.genoa_extensions(hwid=b"\x11" * 8)
        validate_report(fx.make_report(chip_id=b"\x11" * 8 + bytes(56)), short, BASE_OPTIONS)
        with pytest.raises(ValidationError, match="is not the same as the VCEK certificate's HWID"):
            validate_report(fx.make_report(chip_id=b"\x11" * 7 + b"\x00" + bytes(56)), short, BASE_OPTIONS)
        with pytest.raises(ValidationError, match="HWID has unsupported size 9"):
            validate_report(fx.make_report(), fx.genoa_extensions(hwid=b"\x11" * 9), BASE_OPTIONS)

    def test_non_vcek_signers_skip_the_hwid_binding(self) -> None:
        info = compose_signer_info(SignerInfo(ReportSigner.VLEK, mask_chip_key=False, author_key_en=False))
        validate_report(fx.make_report(signer_info=info, chip_id=b"\x22" * 64), fx.genoa_extensions(), BASE_OPTIONS)
        with pytest.raises(ValidationError, match="reserved"):
            validate_report(fx.make_report(signer_info=2 << 2), fx.genoa_extensions(), BASE_OPTIONS)
