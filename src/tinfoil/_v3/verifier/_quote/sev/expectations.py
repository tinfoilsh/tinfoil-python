"""Translation of an endorsed SEV-SNP policy into complete validation expectations, and their one application."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from tinfoil._v3.verifier._policy import TCB, PolicyError, SEVSNPPolicy
from tinfoil._v3.verifier._quote.sev.authenticate import (
    Quote,
    SevAuthenticationError,
    reject_masked_chip_id,
)
from tinfoil._v3.verifier._quote.sev.lib.abi import (
    PRODUCT_GENOA,
    PRODUCT_TURIN,
    AbiError,
    Report,
    SnpPlatformInfo,
    SnpPolicy,
    parse_signer_info,
    parse_snp_platform_info,
    parse_snp_policy,
)
from tinfoil._v3.verifier._quote.sev.lib.chain import ChainError, vcek_certificate_extensions
from tinfoil._v3.verifier._quote.sev.lib.tcb import TcbError, TCBParts, new_tcb_parts
from tinfoil._v3.verifier._quote.sev.lib.validate import ValidationError, ValidationOptions, validate_report

REPORT_DATA_SIZE = 64
HOST_DATA_SIZE = 32
FAMILY_ID_SIZE = 16
IMAGE_ID_SIZE = 16
LAUNCH_SIZE = 48
_HEX = re.compile(r"[0-9a-fA-F]*")
_UINT8_MAX = 255


class SevPolicyError(ValueError):
    """A policy that cannot be translated for the quote's product line, or a report that does not satisfy it."""


@dataclass(frozen=True, slots=True)
class Expectations:
    """The fully translated SEV-SNP expected state, resolved at assembly so that validation performs no translation
    and no lookups.

    ``options`` holds the bounds and equalities that the library applies;
    the ``want_*`` fields are compared by strict equality on top, since
    the options treat the guest policy and platform info as maximum masks.
    """

    options: ValidationOptions
    want_guest_policy: SnpPolicy
    want_platform_info: SnpPlatformInfo


def assemble(policy: SEVSNPPolicy, quote: Quote, launch: bytes, report_data: bytes) -> Expectations:
    """Combine the policy with the launch measurement, REPORT_DATA and the authenticated CHIP_ID.

    ``launch`` is 48 bytes and ``report_data`` 64; the CHIP_ID comes from
    ``quote.identity``.
    """
    options = _options(policy, quote.product_line)
    if len(launch) != LAUNCH_SIZE:
        raise SevPolicyError(f"launch measurement must be {LAUNCH_SIZE} bytes, got {len(launch)}")
    if len(report_data) != REPORT_DATA_SIZE:
        raise SevPolicyError(f"report data must be {REPORT_DATA_SIZE} bytes, got {len(report_data)}")
    try:
        chip_id = _decode_hex("platform identity", quote.identity, len(quote.identity) // 2)
    except SevPolicyError as err:
        raise SevPolicyError(f"decoding platform identity: {err}") from err
    options = replace(options, measurement=bytes(launch), report_data=bytes(report_data), chip_id=chip_id)
    return Expectations(
        options=options,
        want_guest_policy=expected_guest_policy(policy),
        want_platform_info=expected_platform_info(policy),
    )


def validate(expectations: Expectations, quote: Quote) -> None:
    """Compare a quote against the assembled expected state: the library validation plus the strict-equality
    companions and the signer check. This is the only SEV enforcement entry point, so no subset of the policy
    can be applied.

    The guest policy is compared with the ABI version taken from the
    report (the version is a floor, enforced by the options); PLATFORM_INFO
    is compared exactly; the report must be launched without an author key
    or ID block.
    """
    report = quote.report
    try:
        extensions = vcek_certificate_extensions(quote.chain.vcek)
    except ChainError as err:
        raise SevPolicyError(f"could not get VCEK certificate extensions: {err}") from err
    try:
        validate_report(report, extensions, expectations.options)
    except ValidationError as err:
        raise SevPolicyError(str(err)) from err

    try:
        got_policy = parse_snp_policy(report.policy)
    except AbiError as err:
        raise SevPolicyError(f"parsing report guest policy: {err}") from err
    want_policy = replace(
        expectations.want_guest_policy, abi_major=got_policy.abi_major, abi_minor=got_policy.abi_minor
    )
    if got_policy != want_policy:
        raise SevPolicyError("SEV report guest policy does not match the endorsed policy")

    try:
        got_info = parse_snp_platform_info(report.platform_info)
    except AbiError as err:
        raise SevPolicyError(f"parsing report PLATFORM_INFO: {err}") from err
    if got_info != expectations.want_platform_info:
        raise SevPolicyError("SEV report PLATFORM_INFO does not match the endorsed policy")

    check_signer(report)


def check_signer(report: Report) -> None:
    """Reject a report with a masked CHIP_ID, an author key, a non-zero ID key digest or a non-zero author key
    digest: ID-block launches are unsupported."""
    try:
        reject_masked_chip_id(report)
        signer = parse_signer_info(report.signer_info)
    except (SevAuthenticationError, AbiError) as err:
        raise SevPolicyError(str(err)) from err
    if signer.author_key_en:
        raise SevPolicyError("report carries an author key; ID-block launches are unsupported")
    if any(report.id_key_digest):
        raise SevPolicyError("report carries an ID block; ID-block launches are unsupported")
    if any(report.author_key_digest):
        raise SevPolicyError("report carries an author key digest; ID-block launches are unsupported")


def expected_guest_policy(policy: SEVSNPPolicy) -> SnpPolicy:
    """The guest policy bits the policy requires, with the ABI version left at zero."""
    guest = policy.guest_policy
    return SnpPolicy(
        debug=guest.debug,
        smt=guest.smt,
        migrate_ma=guest.migrate_ma,
        single_socket=guest.single_socket,
        cxl_allowed=guest.cxl_allowed,
        mem_aes256_xts=guest.mem_aes256_xts,
        rapl_dis=guest.rapl_dis,
        ciphertext_hiding_dram=guest.ciphertext_hiding_dram,
        page_swap_disable=guest.page_swap_disable,
    )


def expected_platform_info(policy: SEVSNPPolicy) -> SnpPlatformInfo:
    """The PLATFORM_INFO bits the policy requires."""
    info = policy.platform_info
    return SnpPlatformInfo(
        smt_enabled=info.smt_enabled,
        tsme_enabled=info.tsme_enabled,
        ecc_enabled=info.ecc_enabled,
        rapl_disabled=info.rapl_disabled,
        ciphertext_hiding_dram_enabled=info.ciphertext_hiding_dram,
        alias_check_complete=info.alias_check_complete,
        iommu_write_safe=info.iommu_write_safe,
        tio_enabled=info.tio_enabled,
    )


def _options(policy: SEVSNPPolicy, product_line: str) -> ValidationOptions:
    """Translate the policy block into validation options for ``product_line``.

    The policy must validate. Genoa forbids ``fmc_spl`` and
    ``iommu_write_safe``; Turin requires both. The API and ABI versions
    parse as ``maj.min``; the TCBs translate per product line; the hex
    fields decode to their sizes; the ABI floor rides in the guest policy.
    """
    try:
        policy.validate()
    except PolicyError as err:
        raise SevPolicyError(str(err)) from err
    if product_line == PRODUCT_GENOA:
        if policy.minimum_tcb.fmc_spl is not None or policy.minimum_launch_tcb.fmc_spl is not None:
            raise SevPolicyError(f"fmc_spl is not valid for product line {product_line}")
        if policy.platform_info.iommu_write_safe:
            raise SevPolicyError(f"iommu_write_safe is not valid for product line {product_line}")
    elif product_line == PRODUCT_TURIN:
        if policy.minimum_tcb.fmc_spl is None or policy.minimum_launch_tcb.fmc_spl is None:
            raise SevPolicyError(f"fmc_spl is required for product line {product_line}")
        if not policy.platform_info.iommu_write_safe:
            raise SevPolicyError(f"iommu_write_safe is required for product line {product_line}")
    else:
        raise SevPolicyError(f"unsupported SEV product line {product_line!r}")
    version = parse_version("minimum_api_version", policy.minimum_api_version)
    abi_major, abi_minor = parse_version_parts("minimum_abi_version", policy.minimum_abi_version)
    minimum_tcb = tcb_parts("minimum_tcb", product_line, policy.minimum_tcb)
    minimum_launch_tcb = tcb_parts("minimum_launch_tcb", product_line, policy.minimum_launch_tcb)
    host_data = _decode_hex("host_data", policy.host_data, HOST_DATA_SIZE)
    image_id = _decode_hex("image_id", policy.image_id, IMAGE_ID_SIZE)
    family_id = _decode_hex("family_id", policy.family_id, FAMILY_ID_SIZE)
    guest_policy = replace(expected_guest_policy(policy), abi_major=abi_major, abi_minor=abi_minor)
    return ValidationOptions(
        guest_policy=guest_policy,
        minimum_guest_svn=_required("minimum_guest_svn", policy.minimum_guest_svn),
        minimum_build=_required("minimum_build", policy.minimum_build),
        minimum_version=version,
        permit_provisional_firmware=policy.permit_provisional_firmware,
        platform_info=expected_platform_info(policy),
        minimum_tcb=minimum_tcb,
        minimum_launch_tcb=minimum_launch_tcb,
        vmpl=_required("vmpl", policy.vmpl),
        host_data=host_data,
        image_id=image_id,
        family_id=family_id,
        minimum_launch_mitigation_vector=_required(
            "minimum_launch_mitigation_vector", policy.minimum_launch_mitigation_vector
        ),
        minimum_current_mitigation_vector=_required(
            "minimum_current_mitigation_vector", policy.minimum_current_mitigation_vector
        ),
    )


def tcb_parts(field: str, product_line: str, tcb: TCB) -> TCBParts:
    """Translate a policy TCB into the product line's TCB layout; ``field`` names it in errors."""
    parts = TCBParts(
        fmc_spl=tcb.fmc_spl or 0,
        bl_spl=_required(f"{field}.bl_spl", tcb.bl_spl),
        tee_spl=_required(f"{field}.tee_spl", tcb.tee_spl),
        snp_spl=_required(f"{field}.snp_spl", tcb.snp_spl),
        ucode_spl=_required(f"{field}.ucode_spl", tcb.ucode_spl),
    )
    try:
        return new_tcb_parts(product_line, parts)
    except TcbError as err:
        raise SevPolicyError(f"{field}: {err}") from err


def parse_version(name: str, version: str) -> int:
    """``maj.min`` as ``maj << 8 | min``."""
    major, minor = parse_version_parts(name, version)
    return (major << 8) | minor


def parse_version_parts(name: str, version: str) -> tuple[int, int]:
    """``maj.min`` as two decimal uint8 values; anything else is an error naming ``name``."""
    major, dot, minor = version.partition(".")
    if not dot:
        raise SevPolicyError(f"{name} {version!r} is not maj.min")
    return _parse_uint8(f"{name} major", major), _parse_uint8(f"{name} minor", minor)


def _parse_uint8(name: str, text: str) -> int:
    if not text or not all("0" <= c <= "9" for c in text):
        raise SevPolicyError(f"{name}: {text!r} is not a decimal number")
    value = int(text) if len(text) <= 3 else _UINT8_MAX + 1
    if value > _UINT8_MAX:
        raise SevPolicyError(f"{name}: value out of range")
    return value


def _decode_hex(name: str, value: str, size: int) -> bytes:
    """Decode hex of either case into exactly ``size`` bytes."""
    if not _HEX.fullmatch(value) or len(value) % 2:
        raise SevPolicyError(f"{name} is not hex")
    decoded = bytes.fromhex(value)
    if len(decoded) != size:
        raise SevPolicyError(f"{name} must be {size} bytes, got {len(decoded)}")
    return decoded


def _required(name: str, value: int | None) -> int:
    if value is None:
        raise SevPolicyError(f"{name} is required")
    return value
