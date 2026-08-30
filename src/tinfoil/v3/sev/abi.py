"""AMD SEV-SNP ATTESTATION_REPORT ABI: the report layout, guest-policy /
platform-info / signer-info bitfields, and CPUID product identity, ported 1:1
from the forked tinfoilsh/go-sev-guest abi package. All errors are ValueError;
the calling module assigns the rejection layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# REPORT_SIZE is the ABI-specified byte size of an SEV-SNP attestation report.
REPORT_SIZE = 0x4A0

# SIGN_ECDSA_P384_SHA384 is the SNP API value for the ECC+SHA signing algorithm.
SIGN_ECDSA_P384_SHA384 = 1

SIGNATURE_OFFSET = 0x2A0
_ECDSA_RS_SIZE = 72  # From the ECDSA-P384-SHA384 format in the SEV SNP API spec.

_POLICY_RESERVED1_BIT = 17

# Report version bounds supported by go-sev-guest.
MIN_SUPPORTED_REPORT_VERSION = 2
MAX_SUPPORTED_REPORT_VERSION = 5
REPORT_VERSION_3 = 3

# Report signer kinds (SIGNER_INFO SIGNING_KEY values).
VCEK_REPORT_SIGNER = 0
VLEK_REPORT_SIGNER = 1
NONE_REPORT_SIGNER = 7


def report_signer_string(k: int) -> str:
    if k == VCEK_REPORT_SIGNER:
        return "VCEK"
    if k == VLEK_REPORT_SIGNER:
        return "VLEK"
    if k == NONE_REPORT_SIGNER:
        return "None"
    return f"UNKNOWN({k})"


@dataclass(frozen=True)
class SnpPolicy:
    """The bitmask guest policy that governs the VM's behavior from launch
    (Go abi.SnpPolicy)."""

    abi_minor: int
    abi_major: int
    smt: bool
    migrate_ma: bool
    debug: bool
    single_socket: bool
    cxl_allowed: bool
    mem_aes256_xts: bool
    rapl_dis: bool
    ciphertext_hiding_dram: bool
    page_swap_disable: bool


def _mbz64(data: int, base: str, hi: int, lo: int) -> None:
    """Check a must-be-zero range of a u64 between bits hi..lo inclusive."""
    if (data >> lo) & ((1 << (hi - lo + 1)) - 1) != 0:
        raise ValueError(f"mbz range {base}[0x{lo:x}:0x{hi:x}] not all zero: {data:x}")


def _bit(v: int, i: int) -> bool:
    return (v >> i) & 1 != 0


def parse_snp_policy(guest_policy: int) -> SnpPolicy:
    """Interpret the guest policy bitmask (Go abi.ParseSnpPolicy)."""
    if not _bit(guest_policy, _POLICY_RESERVED1_BIT):
        raise ValueError(
            f"policy[{_POLICY_RESERVED1_BIT}] is reserved, must be 1, got 0"
        )
    _mbz64(guest_policy, "policy", 63, 26)
    return SnpPolicy(
        abi_minor=guest_policy & 0xFF,
        abi_major=(guest_policy >> 8) & 0xFF,
        smt=_bit(guest_policy, 16),
        migrate_ma=_bit(guest_policy, 18),
        debug=_bit(guest_policy, 19),
        single_socket=_bit(guest_policy, 20),
        cxl_allowed=_bit(guest_policy, 21),
        mem_aes256_xts=_bit(guest_policy, 22),
        rapl_dis=_bit(guest_policy, 23),
        ciphertext_hiding_dram=_bit(guest_policy, 24),
        page_swap_disable=_bit(guest_policy, 25),
    )


@dataclass(frozen=True)
class SnpPlatformInfo:
    """Interpretation of the PLATFORM_INFO field (Go abi.SnpPlatformInfo)."""

    smt_enabled: bool
    tsme_enabled: bool
    ecc_enabled: bool
    rapl_disabled: bool
    ciphertext_hiding_dram_enabled: bool
    alias_check_complete: bool
    iommu_write_safe: bool
    tio_enabled: bool


def parse_snp_platform_info(platform_info: int) -> SnpPlatformInfo:
    """Error on unrecognized bits (Go abi.ParseSnpPlatformInfo, bits 0-7)."""
    result = SnpPlatformInfo(
        smt_enabled=_bit(platform_info, 0),
        tsme_enabled=_bit(platform_info, 1),
        ecc_enabled=_bit(platform_info, 2),
        rapl_disabled=_bit(platform_info, 3),
        ciphertext_hiding_dram_enabled=_bit(platform_info, 4),
        alias_check_complete=_bit(platform_info, 5),
        iommu_write_safe=_bit(platform_info, 6),
        tio_enabled=_bit(platform_info, 7),
    )
    if platform_info & ~0xFF != 0:
        raise ValueError(f"unrecognized platform info bit(s): 0x{platform_info:x}")
    return result


@dataclass(frozen=True)
class SignerInfo:
    """The report signing circumstances (Go abi.SignerInfo)."""

    signing_key: int
    mask_chip_key: bool
    author_key_en: bool


def parse_signer_info(signer_info: int) -> SignerInfo:
    """Interpret report[0x48:0x4C], erroring on non-zero mbz fields (Go
    abi.ParseSignerInfo)."""
    _mbz64(signer_info, "data[0x48:0x4C]", 31, 5)
    signing_key = (signer_info >> 2) & 7
    if VLEK_REPORT_SIGNER < signing_key < NONE_REPORT_SIGNER:
        raise ValueError(
            f"signing_key values 2-6 are reserved. Got {report_signer_string(signing_key)}"
        )
    return SignerInfo(
        signing_key=signing_key,
        mask_chip_key=signer_info & 2 != 0,
        author_key_en=signer_info & 1 != 0,
    )


@dataclass
class SevReport:
    """The parsed report (Go proto sevsnp.Report)."""

    raw: bytes
    version: int
    guest_svn: int
    policy: int
    family_id: bytes
    image_id: bytes
    vmpl: int
    signature_algo: int
    current_tcb: int
    platform_info: int
    signer_info: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    report_id_ma: bytes
    reported_tcb: int
    cpuid1_eax_fms: int
    chip_id: bytes
    committed_tcb: int
    current_build: int
    current_minor: int
    current_major: int
    committed_build: int
    committed_minor: int
    committed_major: int
    launch_tcb: int
    launch_mit_vector: int
    current_mit_vector: int
    signature: bytes


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 4], "little")


def _u64(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 8], "little")


def _mbz(data: bytes, lo: int, hi: int) -> None:
    if any(data[lo:hi]):
        raise ValueError(
            f"mbz range [0x{lo:x}:0x{hi:x}] not all zero: {data[lo:hi].hex()}"
        )


def fms_to_cpuid1_eax(family: int, model: int, stepping: int) -> int:
    """The masked CPUID_1_EAX value for the given family, model, stepping
    bytes (Go abi.FmsToCpuid1Eax)."""
    extended_family = 0
    family_id = family
    if family >= 0xF:
        extended_family = family - 0xF
        family_id = 0xF
    extended_model = model >> 4
    model_id = model & 0xF
    return (
        (extended_family << 20)
        | (extended_model << 16)
        | (family_id << 8)
        | (model_id << 4)
        | (stepping & 0xF)
    )


def fms_from_cpuid1_eax(eax: int) -> tuple[int, int, int]:
    """Extract family, model, stepping (Go abi.FmsFromCpuid1Eax)."""
    extended_family = (eax >> 20) & 0xFF
    extended_model = (eax >> 16) & 0xF
    family_id = (eax >> 8) & 0xF
    model_id = (eax >> 4) & 0xF
    return (
        (extended_family + family_id) & 0xFF,
        ((extended_model << 4) | model_id) & 0xFF,
        eax & 0xF,
    )


# Family/model values from Go abi (zen3zen4Family etc.).
_ZEN3_ZEN4_FAMILY = 0x19
_ZEN5_FAMILY = 0x1A
_MILAN_MODEL = 0x01
_GENOA_MODEL = 0x11
_TURIN_MODEL = 0x02


def sev_product_name_from_cpuid1_eax(eax: int) -> str:
    """The product name represented by cpuid(1).eax: "Milan", "Genoa",
    "Turin", or "Unknown" (Go abi.SevProductFromCpuid1Eax + kds.ProductLine)."""
    family, model, _ = fms_from_cpuid1_eax(eax)
    if family == _ZEN3_ZEN4_FAMILY:
        if model == _MILAN_MODEL:
            return "Milan"
        if model == _GENOA_MODEL:
            return "Genoa"
    elif family == _ZEN5_FAMILY:
        if model == _TURIN_MODEL:
            return "Turin"
    return "Unknown"


def parse_report(data: bytes) -> SevReport:
    """Parse the little-endian ABI bytes, rejecting non-zero reserved regions
    (Go abi.ReportToProto)."""
    if len(data) < REPORT_SIZE:
        raise ValueError(
            f"array size is 0x{len(data):x}, an SEV-SNP attestation report size is 0x{REPORT_SIZE:x}"
        )
    version = _u32(data, 0x00)
    policy = _u64(data, 0x08)
    try:
        parse_snp_policy(policy)
    except ValueError as e:
        raise ValueError(f"malformed guest policy: {e}") from None
    signature_algo = _u32(data, 0x34)
    signer_info = _u32(data, 0x48)
    parse_signer_info(signer_info)
    _mbz(data, 0x4C, 0x50)

    cpuid1_eax_fms = 0
    mbz_lo = 0x188
    if version >= REPORT_VERSION_3:
        mbz_lo = 0x18B
        cpuid1_eax_fms = fms_to_cpuid1_eax(data[0x188], data[0x189], data[0x18A])
    _mbz(data, mbz_lo, 0x1A0)
    _mbz(data, 0x1EB, 0x1EC)
    _mbz(data, 0x1EF, 0x1F0)
    _mbz(data, 0x208, SIGNATURE_OFFSET)
    if signature_algo == SIGN_ECDSA_P384_SHA384:
        _mbz(data, SIGNATURE_OFFSET + 2 * _ECDSA_RS_SIZE, REPORT_SIZE)

    return SevReport(
        raw=bytes(data),
        version=version,
        guest_svn=_u32(data, 0x04),
        policy=policy,
        family_id=bytes(data[0x10:0x20]),
        image_id=bytes(data[0x20:0x30]),
        vmpl=_u32(data, 0x30),
        signature_algo=signature_algo,
        current_tcb=_u64(data, 0x38),
        platform_info=_u64(data, 0x40),
        signer_info=signer_info,
        report_data=bytes(data[0x50:0x90]),
        measurement=bytes(data[0x90:0xC0]),
        host_data=bytes(data[0xC0:0xE0]),
        id_key_digest=bytes(data[0xE0:0x110]),
        author_key_digest=bytes(data[0x110:0x140]),
        report_id=bytes(data[0x140:0x160]),
        report_id_ma=bytes(data[0x160:0x180]),
        reported_tcb=_u64(data, 0x180),
        cpuid1_eax_fms=cpuid1_eax_fms,
        chip_id=bytes(data[0x1A0:0x1E0]),
        committed_tcb=_u64(data, 0x1E0),
        current_build=data[0x1E8],
        current_minor=data[0x1E9],
        current_major=data[0x1EA],
        committed_build=data[0x1EC],
        committed_minor=data[0x1ED],
        committed_major=data[0x1EE],
        launch_tcb=_u64(data, 0x1F0),
        launch_mit_vector=_u64(data, 0x1F8),
        current_mit_vector=_u64(data, 0x200),
        signature=bytes(data[SIGNATURE_OFFSET:REPORT_SIZE]),
    )


def validate_report_format(r: bytes) -> None:
    """Reject structural violations (Go abi.ValidateReportFormat)."""
    if len(r) < REPORT_SIZE:
        raise ValueError(f"report size is {len(r)} bytes. Expected {REPORT_SIZE} bytes")
    version = _u32(r, 0x00)
    if version < MIN_SUPPORTED_REPORT_VERSION or version > MAX_SUPPORTED_REPORT_VERSION:
        raise ValueError(
            f"report version is: {version}. Expected between "
            f"{MIN_SUPPORTED_REPORT_VERSION} and {MAX_SUPPORTED_REPORT_VERSION}"
        )
    try:
        parse_snp_policy(_u64(r, 0x08))
    except ValueError as e:
        raise ValueError(f"malformed guest policy: {e}") from None


def report_signature_rs(report: bytes) -> tuple[int, int]:
    """The report's ECDSA signature (r, s) integers. The ABI stores r and s as
    72-byte little-endian values at 0x2A0 (Go abi.ReportToSignatureDER without
    the DER round trip; out-of-range components fail verification)."""
    if len(report) != REPORT_SIZE:
        raise ValueError(f"incorrect report size: {len(report):x}, want {REPORT_SIZE:x}")
    algo = _u32(report, 0x34)
    if algo != SIGN_ECDSA_P384_SHA384:
        raise ValueError(f"unknown signature algorithm: {algo}")
    sig = report[SIGNATURE_OFFSET:REPORT_SIZE]
    r = int.from_bytes(sig[0:_ECDSA_RS_SIZE], "little")
    s = int.from_bytes(sig[_ECDSA_RS_SIZE : 2 * _ECDSA_RS_SIZE], "little")
    return r, s


def signed_component(report: bytes) -> bytes:
    """The report bytes signed by the AMD-SP."""
    return report[0:SIGNATURE_OFFSET]


def check_masked_chip_id(report: SevReport) -> None:
    """Reject reports whose SIGNER_INFO masks the CHIP_ID: masked platform
    identities cannot be endorsed (Go sev.rejectMaskedChipID). ValueError;
    the caller assigns the layer (QUOTE at authenticate, POLICY in Validate)."""
    try:
        signer = parse_signer_info(report.signer_info)
    except ValueError as e:
        raise ValueError(f"parsing report SIGNER_INFO: {e}") from None
    if signer.mask_chip_key:
        raise ValueError("report masks CHIP_ID; masked platform identities are unsupported")
