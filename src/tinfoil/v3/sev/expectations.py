"""SEV-SNP policy translation and quote validation, a 1:1 port of Go
verifier/quote/sev/expectations.go plus the checks the assembled
tinfoilsh/go-sev-guest validate.SnpAttestation options perform (per-product
TCB layouts, Turin fmc_spl/iommu_write_safe rules). Every rejection raises
VerificationError("POLICY_REJECTED", ...)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

from .. import policy as policy_mod
from ..errors import POLICY_REJECTED, VerificationError
from ..policy import SEVSNPPolicy, TCB, validate_sev_snp_policy
from . import kds
from .abi import (
    VCEK_REPORT_SIGNER,
    SevReport,
    SnpPlatformInfo,
    SnpPolicy,
    check_masked_chip_id,
    parse_signer_info,
    parse_snp_platform_info,
    parse_snp_policy,
    report_signer_string,
)
from .authenticate import PRODUCT_GENOA, PRODUCT_TURIN, SevQuote


def _policy_error(message: str) -> VerificationError:
    return VerificationError(POLICY_REJECTED, message)


@dataclass
class _SevValidateOptions:
    """The go-sev-guest validate.Options fields the verifier sets; unset
    library options (report_id, report_id_ma, ID-block trust) are
    deliberately absent and never enforced."""

    guest_policy: SnpPolicy  # maximum-acceptable mask, ABI version floor
    minimum_guest_svn: int
    minimum_build: int
    minimum_version: int  # maj<<8 | min
    permit_provisional_firmware: bool
    platform_info: SnpPlatformInfo  # maximum-acceptable mask
    minimum_tcb: kds.TCBParts
    minimum_launch_tcb: kds.TCBParts
    vmpl: int
    host_data: bytes
    image_id: bytes
    family_id: bytes
    minimum_launch_mitigation_vector: int
    minimum_current_mitigation_vector: int
    measurement: bytes = b""
    report_data: bytes = b""
    chip_id: bytes = b""


@dataclass
class SevExpectations:
    """The fully translated SEV-SNP expected state, resolved at assembly so
    that validation performs no translation and no lookups. The want_* fields
    are compared by strict equality — the library options only bound them
    (Go sev.Expectations)."""

    opts: _SevValidateOptions
    want_guest_policy: SnpPolicy
    want_platform_info: SnpPlatformInfo


def _expected_guest_policy(p: SEVSNPPolicy) -> SnpPolicy:
    return SnpPolicy(
        abi_major=0,
        abi_minor=0,
        debug=p.guest_policy.debug,
        smt=p.guest_policy.smt,
        migrate_ma=p.guest_policy.migrate_ma,
        single_socket=p.guest_policy.single_socket,
        cxl_allowed=p.guest_policy.cxl_allowed,
        mem_aes256_xts=p.guest_policy.mem_aes256_xts,
        rapl_dis=p.guest_policy.rapl_dis,
        ciphertext_hiding_dram=p.guest_policy.ciphertext_hiding_dram,
        page_swap_disable=p.guest_policy.page_swap_disable,
    )


def _expected_platform_info(p: SEVSNPPolicy) -> SnpPlatformInfo:
    return SnpPlatformInfo(
        smt_enabled=p.platform_info.smt_enabled,
        tsme_enabled=p.platform_info.tsme_enabled,
        ecc_enabled=p.platform_info.ecc_enabled,
        rapl_disabled=p.platform_info.rapl_disabled,
        ciphertext_hiding_dram_enabled=p.platform_info.ciphertext_hiding_dram,
        alias_check_complete=p.platform_info.alias_check_complete,
        iommu_write_safe=p.platform_info.iommu_write_safe,
        tio_enabled=p.platform_info.tio_enabled,
    )


def _parse_version_parts(name: str, v: str) -> tuple[int, int]:
    """strconv.ParseUint(part, 10, 8) semantics on "maj.min" (Go
    parseVersionParts)."""
    major, sep, minor = v.partition(".")
    if sep == "":
        raise _policy_error(f"{name} {v!r} is not maj.min")

    def parse_u8(label: str, part: str) -> int:
        if part == "" or not all("0" <= c <= "9" for c in part):
            raise _policy_error(f"{name} {label}: invalid syntax")
        n = int(part)
        if n > 255:
            raise _policy_error(f"{name} {label}: value out of range")
        return n

    return parse_u8("major", major), parse_u8("minor", minor)


def _parse_version(name: str, v: str) -> int:
    maj, minor = _parse_version_parts(name, v)
    return (maj << 8) | minor


def _tcb_parts(field: str, product_line: str, t: TCB) -> kds.TCBParts:
    """Translate a policy TCB block into layout-tagged parts (Go tcbParts +
    kds.NewTCBParts)."""
    try:
        return kds.new_tcb_parts(
            product_line,
            fmc_spl=t.fmc_spl if t.fmc_spl is not None else 0,
            bl_spl=t.bl_spl or 0,
            tee_spl=t.tee_spl or 0,
            snp_spl=t.snp_spl or 0,
            ucode_spl=t.ucode_spl or 0,
        )
    except ValueError as e:
        raise _policy_error(f"{field}: {e}") from None


def _decode_policy_hex(name: str, value: str, size: int) -> bytes:
    try:
        return policy_mod.decode_hex(name, value, size)
    except ValueError as e:
        raise _policy_error(str(e)) from None


def _options(p: SEVSNPPolicy, product_line: str) -> _SevValidateOptions:
    """Translate the policy block into validation options for the given
    product line. GuestPolicy and PlatformInfo are maximum-acceptable masks;
    strict equality on both is enforced by the companion checks composed in
    sev_validate (Go options)."""
    err = validate_sev_snp_policy(p)
    if err is not None:
        raise _policy_error(err)
    if product_line == PRODUCT_GENOA:
        if p.minimum_tcb.fmc_spl is not None or p.minimum_launch_tcb.fmc_spl is not None:
            raise _policy_error(f"fmc_spl is not valid for product line {product_line}")
        if p.platform_info.iommu_write_safe:
            raise _policy_error(
                f"iommu_write_safe is not valid for product line {product_line}"
            )
    elif product_line == PRODUCT_TURIN:
        if p.minimum_tcb.fmc_spl is None or p.minimum_launch_tcb.fmc_spl is None:
            raise _policy_error(f"fmc_spl is required for product line {product_line}")
        if not p.platform_info.iommu_write_safe:
            raise _policy_error(
                f"iommu_write_safe is required for product line {product_line}"
            )
    else:
        raise _policy_error(f'unsupported SEV product line "{product_line}"')

    version = _parse_version("minimum_api_version", p.minimum_api_version)
    abi_major, abi_minor = _parse_version_parts("minimum_abi_version", p.minimum_abi_version)
    minimum_tcb = _tcb_parts("minimum_tcb", product_line, p.minimum_tcb)
    minimum_launch_tcb = _tcb_parts("minimum_launch_tcb", product_line, p.minimum_launch_tcb)
    host_data = _decode_policy_hex("host_data", p.host_data, 32)
    image_id = _decode_policy_hex("image_id", p.image_id, 16)
    family_id = _decode_policy_hex("family_id", p.family_id, 16)

    # The ABI floor rides in the guest policy: it is compared as a minimum
    # version, unlike the other bits.
    guest_policy = replace(_expected_guest_policy(p), abi_major=abi_major, abi_minor=abi_minor)
    return _SevValidateOptions(
        guest_policy=guest_policy,
        minimum_guest_svn=p.minimum_guest_svn,  # type: ignore[arg-type]
        minimum_build=p.minimum_build,  # type: ignore[arg-type]
        minimum_version=version,
        permit_provisional_firmware=p.permit_provisional_firmware,
        platform_info=_expected_platform_info(p),
        minimum_tcb=minimum_tcb,
        minimum_launch_tcb=minimum_launch_tcb,
        vmpl=p.vmpl,  # type: ignore[arg-type]
        host_data=host_data,
        image_id=image_id,
        family_id=family_id,
        minimum_launch_mitigation_vector=p.minimum_launch_mitigation_vector,  # type: ignore[arg-type]
        minimum_current_mitigation_vector=p.minimum_current_mitigation_vector,  # type: ignore[arg-type]
    )


def sev_assemble(
    p: SEVSNPPolicy, q: SevQuote, launch_digest: bytes, report_data: bytes
) -> SevExpectations:
    """Translate a policy block into the complete expected state for the
    quote: validation options carrying every policy field, the expected
    launch measurement, the expected REPORT_DATA, and the endorsed CHIP_ID
    the policy was selected by (Go sev.Assemble)."""
    opts = _options(p, q.product_line)
    if len(launch_digest) != 48:
        raise _policy_error(
            f"expected launch digest must be 48 bytes, got {len(launch_digest)}"
        )
    if len(report_data) != 64:
        raise _policy_error(
            f"expected report data must be 64 bytes, got {len(report_data)}"
        )
    try:
        chip_id = bytes.fromhex(q.identity)
    except ValueError as e:
        raise _policy_error(f"decoding platform identity: {e}") from None
    opts.measurement = bytes(launch_digest)
    opts.report_data = bytes(report_data)
    opts.chip_id = chip_id
    return SevExpectations(
        opts=opts,
        want_guest_policy=_expected_guest_policy(p),
        want_platform_info=_expected_platform_info(p),
    )


# --- library validation (validate.SnpAttestation with the assembled options) --


def _version_value(major: int, minor: int) -> int:
    return (major << 8) | minor


def _validate_policy(report_policy: int, required: SnpPolicy) -> None:
    """Bound the report's guest policy by the required mask and enforce the
    ABI version floor (Go validate.validatePolicy)."""
    try:
        policy = parse_snp_policy(report_policy)
    except ValueError as e:
        raise _policy_error(f"could not parse SNP policy: {e}") from None
    if _version_value(required.abi_major, required.abi_minor) > _version_value(
        policy.abi_major, policy.abi_minor
    ):
        raise _policy_error(
            f"required policy ABI version ({required.abi_major}.{required.abi_minor}) "
            f"is greater than the report's ABI version ({policy.abi_major}.{policy.abi_minor})"
        )
    if not required.migrate_ma and policy.migrate_ma:
        raise _policy_error("found unauthorized migration agent capability")
    if not required.debug and policy.debug:
        raise _policy_error("found unauthorized debug capability")
    if not required.smt and policy.smt:
        raise _policy_error("found unauthorized symmetric multithreading (SMT) capability")
    if required.single_socket and not policy.single_socket:
        raise _policy_error("required single socket restriction not present")
    if not required.cxl_allowed and policy.cxl_allowed:
        raise _policy_error("found unauthorized CXL capability")
    if required.mem_aes256_xts and not policy.mem_aes256_xts:
        raise _policy_error("found unauthorized memory encryption mode")
    if required.rapl_dis and not policy.rapl_dis:
        raise _policy_error("found unauthorized RAPL capability")
    if required.ciphertext_hiding_dram and not policy.ciphertext_hiding_dram:
        raise _policy_error("ciphertext hiding in DRAM isn't enforced")
    if required.page_swap_disable and not policy.page_swap_disable:
        raise _policy_error("found unauthorized page swap capability")


def _validate_byte_field(option: str, field: str, size: int, given: bytes, required: bytes) -> None:
    if len(required) == 0:
        return
    if len(required) != size:
        raise _policy_error(f"option {option} must be nil or {size} bytes")
    if required != given:
        raise _policy_error(
            f"report field {field} is {given.hex()}. Expect {required.hex()}"
        )


def _validate_verbatim_fields(report: SevReport, opts: _SevValidateOptions) -> None:
    """Compare the exact-match fields the options set; REPORT_ID and
    REPORT_ID_MA are unset and never enforced (Go validate.validateVerbatimFields)."""
    _validate_byte_field("ReportData", "REPORT_DATA", 64, report.report_data, opts.report_data)
    _validate_byte_field("HostData", "HOST_DATA", 32, report.host_data, opts.host_data)
    _validate_byte_field("FamilyID", "FAMILY_ID", 16, report.family_id, opts.family_id)
    _validate_byte_field("ImageID", "IMAGE_ID", 16, report.image_id, opts.image_id)
    _validate_byte_field("Measurement", "MEASUREMENT", 48, report.measurement, opts.measurement)
    _validate_byte_field("ChipID", "CHIP_ID", 64, report.chip_id, opts.chip_id)


def _tcb_ne_error(left_desc: str, left: kds.TCBParts, right_desc: str, right: kds.TCBParts) -> None:
    try:
        ltcb = kds.tcb_parts_to_version(left)
        rtcb = kds.tcb_parts_to_version(right)
    except ValueError as e:
        raise _policy_error(f"could not compare TCB values: {e}") from None
    if ltcb != rtcb:
        raise _policy_error(
            f"the {left_desc} 0x{ltcb[1]:x} does not match the {right_desc} 0x{rtcb[1]:x}"
        )


def _tcb_gt_error(lower_desc: str, want_lower: kds.TCBParts, higher_desc: str, want_higher: kds.TCBParts) -> None:
    """Enforce want_lower <= want_higher component-wise."""
    if not kds.tcb_parts_le(want_lower, want_higher):
        raise _policy_error(
            f"the {higher_desc} is lower than the {lower_desc} in at least one component"
        )


def _get_report_tcbs(
    report: SevReport, cert_tcb_version: int, cert_tcb: int
) -> tuple[kds.TCBParts, kds.TCBParts, kds.TCBParts, kds.TCBParts, kds.TCBParts]:
    """Decompose the report and certificate TCBs under the product's layout
    (Go validate.getReportTcbs): (reported, current, committed, launch, cert)."""
    if report.version >= 3:
        product_line = kds.product_line_from_fms(report.cpuid1_eax_fms)
        try:
            layout = kds.product_line_to_tcb_version(product_line)
        except ValueError as e:
            raise _policy_error(f"could not determine report TCB format: {e}") from None
        if layout != cert_tcb_version:
            raise _policy_error(
                f'report product "{product_line}" and V[CL]EK certificate use different TCB formats'
            )
    else:
        # Pre-v3 reports predate the Turin TCB layout; do not let a version-1
        # certificate reinterpret their TCB fields.
        layout = kds.TCB_STRUCT_VERSION_0
        if cert_tcb_version != layout:
            raise _policy_error(
                f"report version {report.version} cannot be used with a non-legacy TCB format"
            )
    try:
        reported = kds.decompose_tcb(layout, report.reported_tcb)
        current = kds.decompose_tcb(layout, report.current_tcb)
        committed = kds.decompose_tcb(layout, report.committed_tcb)
        launch = kds.decompose_tcb(layout, report.launch_tcb)
        cert = kds.decompose_tcb(cert_tcb_version, cert_tcb)
    except ValueError as e:
        raise _policy_error(str(e)) from None
    return reported, current, committed, launch, cert


def _validate_tcb(
    report: SevReport, cert_tcb_version: int, cert_tcb: int, opts: _SevValidateOptions
) -> None:
    """Enforce the report/certificate TCB relationships (Go validate.validateTcb):
    COMMITTED vs CURRENT, the launch and reported floors, REPORTED ==
    certificate TCB, and certificate TCB <= CURRENT."""
    reported, current, committed, launch, cert = _get_report_tcbs(
        report, cert_tcb_version, cert_tcb
    )
    if opts.permit_provisional_firmware:
        _tcb_gt_error("report's COMMITTED_TCB", committed, "report's CURRENT_TCB", current)
    else:
        _tcb_ne_error("report's COMMITTED_TCB", committed, "report's CURRENT_TCB", current)
    _tcb_gt_error("policy minimum launch TCB", opts.minimum_launch_tcb, "report's LAUNCH_TCB", launch)
    _tcb_ne_error("report's REPORTED_TCB", reported, "TCB of the V[CL]EK certificate", cert)
    _tcb_gt_error("TCB of the V[CL]EK certificate", cert, "report's CURRENT_TCB", current)
    _tcb_gt_error("policy minimum TCB", opts.minimum_tcb, "report's REPORTED_TCB", reported)


def _validate_version(report: SevReport, opts: _SevValidateOptions) -> None:
    """Enforce the firmware build/version floors and the committed/current
    relationship (Go validate.validateVersion)."""
    if opts.minimum_build > report.current_build:
        raise _policy_error(
            f"firmware build number {report.current_build} is less than the required minimum {opts.minimum_build}"
        )
    if opts.minimum_version > _version_value(report.current_major, report.current_minor):
        raise _policy_error(
            f"firmware API version ({report.current_major}.{report.current_minor}) is less "
            f"than the required minimum ({opts.minimum_version >> 8}.{opts.minimum_version & 0xFF})"
        )
    build_cmp = report.committed_build - report.current_build
    version_cmp = _version_value(report.committed_major, report.committed_minor) - _version_value(
        report.current_major, report.current_minor
    )
    if not opts.permit_provisional_firmware:
        if build_cmp != 0:
            raise _policy_error(
                f"committed build number {report.committed_build} does not match the current build number {report.current_build}"
            )
        if version_cmp != 0:
            raise _policy_error(
                f"committed API version ({report.committed_major}.{report.committed_minor}) does not "
                f"match the current API version ({report.current_major}.{report.current_minor})"
            )
    else:
        if build_cmp > 0:
            raise _policy_error(
                f"committed build number {report.committed_build} is greater than the current build number {report.current_build}"
            )
        if version_cmp > 0:
            raise _policy_error(
                f"committed API version ({report.committed_major}.{report.committed_minor}) is "
                "greater than the current API version"
            )


def _validate_platform_info(platform_info: int, required: SnpPlatformInfo) -> None:
    """Bound the report's PLATFORM_INFO by the required mask (Go
    validate.validatePlatformInfo)."""
    try:
        report_info = parse_snp_platform_info(platform_info)
    except ValueError as e:
        raise _policy_error(f"could not parse SNP platform info {platform_info:x}: {e}") from None
    if report_info.smt_enabled and not required.smt_enabled:
        raise _policy_error("unauthorized platform feature SMT enabled")
    if report_info.tsme_enabled and not required.tsme_enabled:
        raise _policy_error("unauthorized platform feature TSME enabled")
    if not report_info.ecc_enabled and required.ecc_enabled:
        raise _policy_error("required platform feature ECC not enabled")
    if not report_info.rapl_disabled and required.rapl_disabled:
        raise _policy_error("unauthorized platform feature RAPL enabled")
    if not report_info.ciphertext_hiding_dram_enabled and required.ciphertext_hiding_dram_enabled:
        raise _policy_error("required ciphertext hiding in DRAM not enforced")
    if not report_info.alias_check_complete and required.alias_check_complete:
        raise _policy_error("required memory alias check hasn't been completed")
    if not report_info.iommu_write_safe and required.iommu_write_safe:
        raise _policy_error("required IOMMU write-safe hardware mitigation is not present")
    if report_info.tio_enabled and not required.tio_enabled:
        raise _policy_error("unauthorized feature SEV-TIO enabled")


def _validate_mitigation_vectors(report: SevReport, opts: _SevValidateOptions) -> None:
    """The report's mitigation vectors must be supersets of the minimums (Go
    validate.validateMitigationVectors)."""
    if (
        report.launch_mit_vector & opts.minimum_launch_mitigation_vector
    ) != opts.minimum_launch_mitigation_vector:
        raise _policy_error(
            f"launch mitigation vector (0x{report.launch_mit_vector:x}) is missing required "
            f"bits; expected at least (0x{opts.minimum_launch_mitigation_vector:x})"
        )
    if (
        report.current_mit_vector & opts.minimum_current_mitigation_vector
    ) != opts.minimum_current_mitigation_vector:
        raise _policy_error(
            f"current mitigation vector (0x{report.current_mit_vector:x}) is missing required "
            f"bits; expected at least (0x{opts.minimum_current_mitigation_vector:x})"
        )


def _all_zero(buf: bytes) -> bool:
    return not any(buf)


def _validate_vcek_chip_id(report_chip_id: bytes, certificate_hwid: Optional[bytes]) -> None:
    """Bind a non-zero report CHIP_ID to the product-specific VCEK HWID: 64
    bytes for Genoa, 8-byte PSN-based for Turin (Go validate.validateVCEKChipID)."""
    if len(report_chip_id) != 64:
        raise _policy_error(f"report field CHIP_ID has size {len(report_chip_id)}, want 64")
    if _all_zero(report_chip_id):
        return
    hwid = certificate_hwid or b""
    if len(hwid) == 64:
        report_hwid = report_chip_id
    elif len(hwid) == 8:  # Turin and later use an 8-byte PSN-based HWID.
        report_hwid = report_chip_id[:8]
    else:
        raise _policy_error(f"VCEK certificate HWID has unsupported size {len(hwid)}")
    if report_hwid != hwid:
        raise _policy_error(
            f"report field CHIP_ID {report_hwid.hex()} is not the same as the "
            f"VCEK certificate's HWID {hwid.hex()}"
        )


def _snp_attestation_validate(q: SevQuote, opts: _SevValidateOptions) -> None:
    """Mirror validate.SnpAttestation for the assembled options.
    RequireAuthorKey/RequireIDBlock are always false (validateKeys no-op
    beyond the signer-info parse) and no cert-table options are set."""
    report = q.report
    try:
        info = parse_signer_info(report.signer_info)
    except ValueError as e:
        raise _policy_error(str(e)) from None
    try:
        exts = kds.certificate_extensions(q.vcek, info.signing_key)
    except ValueError as e:
        raise _policy_error(
            f"could not get {report_signer_string(info.signing_key)} certificate extensions: {e}"
        ) from None

    if report.guest_svn < opts.minimum_guest_svn:
        raise _policy_error(
            f"report's GUEST_SVN {report.guest_svn} is less than the required minimum {opts.minimum_guest_svn}"
        )

    _validate_policy(report.policy, opts.guest_policy)
    _validate_verbatim_fields(report, opts)
    _validate_tcb(report, exts.tcb_struct_version, exts.tcb_version, opts)
    _validate_version(report, opts)
    _validate_platform_info(report.platform_info, opts.platform_info)
    _validate_mitigation_vectors(report, opts)

    if opts.vmpl != report.vmpl:
        raise _policy_error(f"report VMPL {report.vmpl} is not {opts.vmpl}")

    # MaskChipId might be 1 for the host, so an all-zero report CHIP_ID is
    # permitted here; otherwise bind it to the product-specific VCEK HWID.
    if info.signing_key == VCEK_REPORT_SIGNER:
        _validate_vcek_chip_id(report.chip_id, exts.hwid)


def _check_signer(report: SevReport) -> None:
    """Require the report to be launched without an author key or ID block:
    ID-block launches are unsupported (policy parsing rejects require_*
    flags), and the library options cannot require absence (Go checkSigner)."""
    try:
        check_masked_chip_id(report)
    except ValueError as e:
        raise _policy_error(str(e)) from None
    try:
        signer = parse_signer_info(report.signer_info)
    except ValueError as e:
        raise _policy_error(f"parsing report SIGNER_INFO: {e}") from None
    if signer.author_key_en:
        raise _policy_error("report carries an author key; ID-block launches are unsupported")
    if not _all_zero(report.id_key_digest):
        raise _policy_error("report carries an ID block; ID-block launches are unsupported")
    if not _all_zero(report.author_key_digest):
        raise _policy_error(
            "report carries an author key digest; ID-block launches are unsupported"
        )


def sev_validate(e: SevExpectations, q: SevQuote) -> None:
    """Compare a quote against the assembled expected state: the library
    validation options plus the strict-equality companions. It is the only
    SEV enforcement entry point, so no subset of the policy can be applied
    (Go Expectations.Validate)."""
    # SEV validation short-circuits at the first failure while TDX aggregates
    # all failures (mirrors go-sev-guest vs go-tdx-guest multierr.Combine);
    # the accept/reject sets are identical, only messages differ.
    _snp_attestation_validate(q, e.opts)

    report = q.report
    try:
        got_policy = parse_snp_policy(report.policy)
    except ValueError as e2:
        raise _policy_error(f"parsing report guest policy: {e2}") from None
    # ABI major/minor are a version floor (minimum_abi_version), enforced by
    # the library's guest-policy comparison, not exact bits.
    want_policy = replace(
        e.want_guest_policy, abi_major=got_policy.abi_major, abi_minor=got_policy.abi_minor
    )
    if got_policy != want_policy:
        raise _policy_error(
            f"report guest policy {got_policy} does not equal the endorsed policy {want_policy}"
        )

    try:
        got_info = parse_snp_platform_info(report.platform_info)
    except ValueError as e2:
        raise _policy_error(f"parsing report PLATFORM_INFO: {e2}") from None
    if got_info != e.want_platform_info:
        raise _policy_error(
            f"report PLATFORM_INFO {got_info} does not equal the endorsed policy {e.want_platform_info}"
        )

    _check_signer(report)
