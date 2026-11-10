"""Policy validation of a decoded SEV-SNP report against caller-supplied expectations. Signatures and certificates
are not checked here."""

from __future__ import annotations

from dataclasses import dataclass, field

from tinfoil._v3.verifier._quote.sev.lib.abi import (
    CHIP_ID_SIZE,
    FAMILY_ID_SIZE,
    HOST_DATA_SIZE,
    IMAGE_ID_SIZE,
    MEASUREMENT_SIZE,
    REPORT_DATA_SIZE,
    REPORT_ID_MA_SIZE,
    REPORT_ID_SIZE,
    REPORT_VERSION_3,
    AbiError,
    Report,
    ReportSigner,
    SnpPlatformInfo,
    SnpPolicy,
    parse_signer_info,
    parse_snp_platform_info,
    parse_snp_policy,
    product_line_from_fms,
)
from tinfoil._v3.verifier._quote.sev.lib.chain import VcekExtensions
from tinfoil._v3.verifier._quote.sev.lib.tcb import (
    HWID_SIZE_VERSION_1,
    TcbError,
    TCBParts,
    TCBVersionStruct,
    new_tcb_version_struct,
    tcb_parts_le,
)

_LEGACY_PRODUCT_LINE = "Milan"
"""The layout that reports before version 3, which carry no product identity, are read in."""


class ValidationError(ValueError):
    """A report that does not satisfy the validation options."""


@dataclass(frozen=True, slots=True)
class ValidationOptions:
    """What a report must satisfy. Byte fields left None are not compared; everything else always applies."""

    guest_policy: SnpPolicy = field(default_factory=SnpPolicy)
    """The maximum acceptable guest policy: capabilities it leaves unset must be unset in the report, restrictions
    it sets must be set, and its ABI version is a floor."""
    minimum_guest_svn: int = 0
    report_data: bytes | None = None
    host_data: bytes | None = None
    image_id: bytes | None = None
    family_id: bytes | None = None
    report_id: bytes | None = None
    report_id_ma: bytes | None = None
    measurement: bytes | None = None
    chip_id: bytes | None = None
    minimum_build: int = 0
    minimum_version: int = 0
    """The minimum firmware API version, major in the high byte and minor in the low byte."""
    minimum_tcb: TCBParts = field(default_factory=TCBParts)
    """The component-wise minimum for the reported TCB, in the report's layout."""
    minimum_launch_tcb: TCBParts = field(default_factory=TCBParts)
    permit_provisional_firmware: bool = False
    """When False, the committed build, API version and TCB must equal the current ones; when True they may be
    lower."""
    platform_info: SnpPlatformInfo | None = None
    """The maximum acceptable PLATFORM_INFO; None leaves it unchecked."""
    vmpl: int | None = None
    minimum_launch_mitigation_vector: int = 0
    minimum_current_mitigation_vector: int = 0


def validate_report(report: Report, vcek: VcekExtensions, options: ValidationOptions) -> None:
    """Validate ``report`` against ``options`` with the VCEK's certified TCB and hardware id.

    In order: the guest SVN floor; the guest policy; the verbatim byte
    fields; the TCB relationships; the firmware build and version; the
    platform info; the mitigation vectors; the VMPL; and, for a VCEK-signed
    report, the CHIP_ID binding to the certificate's hardware id.
    """
    try:
        info = parse_signer_info(report.signer_info)
    except AbiError as err:
        raise ValidationError(str(err)) from err
    if report.guest_svn < options.minimum_guest_svn:
        raise ValidationError(
            f"report's GUEST_SVN {report.guest_svn} is less than the required minimum {options.minimum_guest_svn}"
        )
    validate_policy(report.policy, options.guest_policy)
    validate_verbatim_fields(report, options)
    validate_tcb(report, vcek.tcb, options)
    validate_version(report, options)
    validate_platform_info(report.platform_info, options.platform_info)
    validate_mitigation_vectors(report, options)
    if options.vmpl is not None and options.vmpl != report.vmpl:
        raise ValidationError(f"report VMPL {report.vmpl} is not {options.vmpl}")
    if info.signing_key == ReportSigner.VCEK:
        validate_vcek_chip_id(report.chip_id, vcek.hwid)


def compare_byte_versions(major0: int, minor0: int, major1: int, minor1: int) -> int:
    """Negative, zero or positive as ``major0.minor0`` is below, equal to or above ``major1.minor1``."""
    return ((major0 << 8) | minor0) - ((major1 << 8) | minor1)


def compare_policy_versions(p0: SnpPolicy, p1: SnpPolicy) -> int:
    return compare_byte_versions(p0.abi_major, p0.abi_minor, p1.abi_major, p1.abi_minor)


def validate_policy(report_policy: int, required: SnpPolicy) -> None:
    """Check the report's guest policy against the maximum acceptable one."""
    try:
        policy = parse_snp_policy(report_policy)
    except AbiError as err:
        raise ValidationError(f"could not parse SNP policy: {err}") from err
    if compare_policy_versions(required, policy) > 0:
        raise ValidationError(
            f"required policy ABI version ({required.abi_major}.{required.abi_minor}) is greater than the "
            f"report's ABI version ({policy.abi_major}.{policy.abi_minor})"
        )
    if not required.migrate_ma and policy.migrate_ma:
        raise ValidationError("found unauthorized migration agent capability")
    if not required.debug and policy.debug:
        raise ValidationError("found unauthorized debug capability")
    if not required.smt and policy.smt:
        raise ValidationError("found unauthorized symmetric multithreading (SMT) capability")
    if required.single_socket and not policy.single_socket:
        raise ValidationError("required single socket restriction not present")
    if not required.cxl_allowed and policy.cxl_allowed:
        raise ValidationError("found unauthorized CXL capability")
    if required.mem_aes256_xts and not policy.mem_aes256_xts:
        raise ValidationError("found unauthorized memory encryption mode")
    if required.rapl_dis and not policy.rapl_dis:
        raise ValidationError("found unauthorized RAPL capability")
    if required.ciphertext_hiding_dram and not policy.ciphertext_hiding_dram:
        raise ValidationError("ciphertext hiding in DRAM isn't enforced")
    if required.page_swap_disable and not policy.page_swap_disable:
        raise ValidationError("found unauthorized page swap capability")


def validate_verbatim_fields(report: Report, options: ValidationOptions) -> None:
    """Compare every byte field that the options set; each must have its field's size."""
    for option, label, size, given, required in (
        ("ReportData", "REPORT_DATA", REPORT_DATA_SIZE, report.report_data, options.report_data),
        ("HostData", "HOST_DATA", HOST_DATA_SIZE, report.host_data, options.host_data),
        ("FamilyID", "FAMILY_ID", FAMILY_ID_SIZE, report.family_id, options.family_id),
        ("ImageID", "IMAGE_ID", IMAGE_ID_SIZE, report.image_id, options.image_id),
        ("ReportID", "REPORT_ID", REPORT_ID_SIZE, report.report_id, options.report_id),
        ("ReportIDMA", "REPORT_ID_MA", REPORT_ID_MA_SIZE, report.report_id_ma, options.report_id_ma),
        ("Measurement", "MEASUREMENT", MEASUREMENT_SIZE, report.measurement, options.measurement),
        ("ChipID", "CHIP_ID", CHIP_ID_SIZE, report.chip_id, options.chip_id),
    ):
        if not required:
            continue
        if len(required) != size:
            raise ValidationError(f"option {option} must be nil or {size} bytes")
        if required != given:
            raise ValidationError(f"report field {label} is {given.hex()}. Expect {required.hex()}")


def validate_tcb(report: Report, certificate_tcb: TCBVersionStruct, options: ValidationOptions) -> None:
    """Check the TCB relationships: the report's layout matches the certificate's; committed equals current (or
    is at most current with provisional firmware); the launch TCB meets its minimum; the reported TCB equals the
    certificate's; the certificate's TCB is at most the current one; and the reported TCB meets the minimum."""
    if report.version >= REPORT_VERSION_3:
        product_line = product_line_from_fms(report.cpuid1_eax_fms)
        try:
            layout = new_tcb_version_struct(product_line, 0)
        except TcbError as err:
            raise ValidationError(f"could not determine report TCB format: {err}") from err
        if not layout.same_format(certificate_tcb):
            raise ValidationError(f"report product {product_line!r} and VCEK certificate use different TCB formats")
    else:
        layout = new_tcb_version_struct(_LEGACY_PRODUCT_LINE, 0)
        if not layout.same_format(certificate_tcb):
            raise ValidationError(f"report version {report.version} cannot be used with a non-legacy TCB format")
        layout = certificate_tcb
    reported = _parts(layout.with_tcb(report.reported_tcb))
    current = _parts(layout.with_tcb(report.current_tcb))
    committed = _parts(layout.with_tcb(report.committed_tcb))
    launch = _parts(layout.with_tcb(report.launch_tcb))
    certified = _parts(certificate_tcb)

    if options.permit_provisional_firmware:
        _require_le(committed, "report's COMMITTED_TCB", current, "report's CURRENT_TCB")
    else:
        _require_equal(committed, "report's COMMITTED_TCB", current, "report's CURRENT_TCB")
    _require_le(options.minimum_launch_tcb, "policy minimum launch TCB", launch, "report's LAUNCH_TCB")
    _require_equal(reported, "report's REPORTED_TCB", certified, "TCB of the VCEK certificate")
    _require_le(certified, "TCB of the VCEK certificate", current, "report's CURRENT_TCB")
    _require_le(options.minimum_tcb, "policy minimum TCB", reported, "report's REPORTED_TCB")


def _parts(tcb: TCBVersionStruct) -> TCBParts:
    try:
        return tcb.to_parts()
    except TcbError as err:
        raise ValidationError(str(err)) from err


def _require_equal(left: TCBParts, left_desc: str, right: TCBParts, right_desc: str) -> None:
    try:
        ltcb = left.to_version_struct()
        rtcb = right.to_version_struct()
    except TcbError as err:
        raise ValidationError(f"could not compare TCB values: {err}") from err
    if ltcb != rtcb:
        raise ValidationError(f"the {left_desc} {ltcb} does not match the {right_desc} {rtcb}")


def _require_le(lower: TCBParts, lower_desc: str, higher: TCBParts, higher_desc: str) -> None:
    if not tcb_parts_le(lower, higher):
        raise ValidationError(
            f"the {higher_desc} {higher} is lower than the {lower_desc} {lower} in at least one component"
        )


def validate_version(report: Report, options: ValidationOptions) -> None:
    """Check the firmware build and API version floors and the committed-versus-current relationship."""
    if options.minimum_build > report.current_build:
        raise ValidationError(
            f"firmware build number {report.current_build} is less than the required minimum {options.minimum_build}"
        )
    if options.minimum_version > ((report.current_major << 8) | report.current_minor):
        raise ValidationError(
            f"firmware API version ({report.current_major}.{report.current_minor}) is less than the required "
            f"minimum ({options.minimum_version >> 8}.{options.minimum_version & 0xFF})"
        )
    build_cmp = report.committed_build - report.current_build
    version_cmp = compare_byte_versions(
        report.committed_major, report.committed_minor, report.current_major, report.current_minor
    )
    if not options.permit_provisional_firmware:
        if build_cmp != 0:
            raise ValidationError(
                f"committed build number {report.committed_build} does not match the current build number "
                f"{report.current_build}"
            )
        if version_cmp != 0:
            raise ValidationError(
                f"committed API version ({report.committed_major}.{report.committed_minor}) does not match the "
                f"current API version ({report.current_major}.{report.current_minor})"
            )
    else:
        if build_cmp > 0:
            raise ValidationError(
                f"committed build number {report.committed_build} is greater than the current build number "
                f"{report.current_build}"
            )
        if version_cmp > 0:
            raise ValidationError(
                f"committed API version ({report.committed_major}.{report.committed_minor}) is greater than the "
                f"current API version ({report.current_major}.{report.current_minor})"
            )


def validate_platform_info(platform_info: int, required: SnpPlatformInfo | None) -> None:
    """Check PLATFORM_INFO against the required one: SMT and TSME may not be on unless allowed; ECC, RAPL disabling,
    ciphertext hiding, the alias check and the IOMMU write-safe fix must be on when required; TIO must match."""
    if required is None:
        return
    try:
        info = parse_snp_platform_info(platform_info)
    except AbiError as err:
        raise ValidationError(f"could not parse SNP platform info {platform_info:x}: {err}") from err
    if info.smt_enabled and not required.smt_enabled:
        raise ValidationError("unauthorized platform feature SMT enabled")
    if info.tsme_enabled and not required.tsme_enabled:
        raise ValidationError("unauthorized platform feature TSME enabled")
    if not info.ecc_enabled and required.ecc_enabled:
        raise ValidationError("required platform feature ECC not enabled")
    if not info.rapl_disabled and required.rapl_disabled:
        raise ValidationError("unauthorized platform feature RAPL enabled")
    if not info.ciphertext_hiding_dram_enabled and required.ciphertext_hiding_dram_enabled:
        raise ValidationError("required ciphertext hiding in DRAM not enforced")
    if not info.alias_check_complete and required.alias_check_complete:
        raise ValidationError("required memory alias check hasn't been completed")
    if not info.iommu_write_safe and required.iommu_write_safe:
        raise ValidationError("required IOMMU write-safe hardware mitigation is not present")
    if info.tio_enabled and not required.tio_enabled:
        raise ValidationError("unauthorized feature SEV-TIO enabled")
    if required.tio_enabled and not info.tio_enabled:
        raise ValidationError("required feature SEV-TIO not enabled")


def validate_mitigation_vectors(report: Report, options: ValidationOptions) -> None:
    """Require the launch and current mitigation vectors to carry every bit of their minimums."""
    minimum = options.minimum_launch_mitigation_vector
    if report.launch_mit_vector & minimum != minimum:
        raise ValidationError(
            f"launch mitigation vector (0x{report.launch_mit_vector:x}) is missing required bits; expected at least "
            f"(0x{minimum:x})"
        )
    minimum = options.minimum_current_mitigation_vector
    if report.current_mit_vector & minimum != minimum:
        raise ValidationError(
            f"current mitigation vector (0x{report.current_mit_vector:x}) is missing required bits; expected at "
            f"least (0x{minimum:x})"
        )


def validate_vcek_chip_id(report_chip_id: bytes, certificate_hwid: bytes) -> None:
    """Bind the report to the VCEK: CHIP_ID must equal the certificate's hardware id, or its first eight bytes
    for an eight-byte hardware id. An all-zero CHIP_ID (a masked one) is not compared."""
    if len(report_chip_id) != CHIP_ID_SIZE:
        raise ValidationError(f"report field CHIP_ID has size {len(report_chip_id)}, want {CHIP_ID_SIZE}")
    if not any(report_chip_id):
        return
    if len(certificate_hwid) == CHIP_ID_SIZE:
        report_hwid = report_chip_id
    elif len(certificate_hwid) == HWID_SIZE_VERSION_1:
        report_hwid = report_chip_id[:HWID_SIZE_VERSION_1]
    else:
        raise ValidationError(f"VCEK certificate HWID has unsupported size {len(certificate_hwid)}")
    if report_hwid != certificate_hwid:
        raise ValidationError(
            f"report field CHIP_ID {report_hwid.hex()} is not the same as the VCEK certificate's HWID "
            f"{certificate_hwid.hex()}"
        )
