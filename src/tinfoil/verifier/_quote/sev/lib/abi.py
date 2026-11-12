"""The AMD SEV-SNP attestation report ABI: the report layout, the bit fields that policy checks read, the CPUID
product identity, and the must-be-zero rules that a well-formed report satisfies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from tinfoil.verifier._x509 import der

SIGN_ECDSA_P384_SHA384 = 1
"""The SIGNATURE_ALGO value for ECDSA P-384 with SHA-384."""

REPORT_SIZE = 0x4A0
FAMILY_ID_SIZE = 16
IMAGE_ID_SIZE = 16
REPORT_DATA_SIZE = 64
MEASUREMENT_SIZE = 48
HOST_DATA_SIZE = 32
ID_KEY_DIGEST_SIZE = 48
AUTHOR_KEY_DIGEST_SIZE = 48
REPORT_ID_SIZE = 32
REPORT_ID_MA_SIZE = 32
CHIP_ID_SIZE = 64
SIGNATURE_SIZE = 512

SIGNATURE_OFFSET = 0x2A0
ECDSA_RS_SIZE = 72
"""Each of R and S in the report's ECDSA-P384-SHA384 signature: little-endian, zero-padded."""
ECDSA_P384_SHA384_SIGNATURE_SIZE = ECDSA_RS_SIZE + ECDSA_RS_SIZE

REPORT_VERSION_2 = 2
REPORT_VERSION_3 = 3
"""The first version that carries the CPUID family, model and stepping."""
REPORT_VERSION_5 = 5
MIN_SUPPORTED_REPORT_VERSION = REPORT_VERSION_2
MAX_SUPPORTED_REPORT_VERSION = REPORT_VERSION_5

POLICY_SMT_BIT = 16
POLICY_RESERVED_1_BIT = 17
POLICY_MIGRATE_MA_BIT = 18
POLICY_DEBUG_BIT = 19
POLICY_SINGLE_SOCKET_BIT = 20
POLICY_CXL_ALLOW_BIT = 21
POLICY_MEM_AES256_XTS_BIT = 22
POLICY_RAPL_DIS_BIT = 23
POLICY_CIPHERTEXT_HIDING_DRAM_BIT = 24
POLICY_PAGE_SWAP_DISABLE_BIT = 25

MAX_PLATFORM_INFO_BIT = 7

ZEN3_ZEN4_FAMILY = 0x19
ZEN5_FAMILY = 0x1A
MILAN_MODEL = 0x01
GENOA_MODEL = 0x11
TURIN_MODEL = 0x02

PRODUCT_MILAN = "Milan"
PRODUCT_GENOA = "Genoa"
PRODUCT_TURIN = "Turin"
PRODUCT_SIENA = "Siena"
PRODUCT_UNKNOWN = "Unknown"

_EXTENDED_FAMILY_SHIFT = 20
_EXTENDED_MODEL_SHIFT = 16
_FAMILY_SHIFT = 8
_MODEL_SHIFT = 4
_STEPPING_MASK = 0xF


class AbiError(ValueError):
    """A report or report field that violates the ABI."""


class ReportSigner(IntEnum):
    """The SIGNING_KEY values of SIGNER_INFO."""

    VCEK = 0
    VLEK = 1
    NONE = 7

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class SignerInfo:
    """The decoded SIGNER_INFO field."""

    signing_key: ReportSigner
    mask_chip_key: bool
    """MASK_CHIP_KEY: the firmware did not sign the report with the chip key and wrote zeros into SIGNATURE instead.

    Masking of CHIP_ID is a different host setting that no SIGNER_INFO bit
    reflects; its only trace is an all-zero CHIP_ID field.
    """
    author_key_en: bool
    """The VM was launched with an ID block that includes an author key."""


def parse_signer_info(value: int) -> SignerInfo:
    """Decode SIGNER_INFO; bits 5 to 31 must be zero and SIGNING_KEY values 2 to 6 are reserved."""
    mbz64(value, "data[0x48:0x4C]", 31, 5)
    key = (value >> 2) & 7
    if ReportSigner.VLEK < key < ReportSigner.NONE:
        raise AbiError(f"signing_key values 2-6 are reserved. Got {key}")
    return SignerInfo(signing_key=ReportSigner(key), mask_chip_key=(value & 2) != 0, author_key_en=(value & 1) != 0)


def compose_signer_info(info: SignerInfo) -> int:
    """The SIGNER_INFO field for the decoded value."""
    return int(info.author_key_en) | (int(info.mask_chip_key) << 1) | (int(info.signing_key) << 2)


@dataclass(frozen=True, slots=True)
class SnpPolicy:
    """The decoded guest POLICY field."""

    abi_minor: int = 0
    abi_major: int = 0
    smt: bool = False
    migrate_ma: bool = False
    debug: bool = False
    single_socket: bool = False
    cxl_allowed: bool = False
    mem_aes256_xts: bool = False
    rapl_dis: bool = False
    ciphertext_hiding_dram: bool = False
    page_swap_disable: bool = False


def parse_snp_policy(value: int) -> SnpPolicy:
    """Decode the guest policy; bit 17 must be set and bits 26 to 63 must be zero."""
    if value & (1 << POLICY_RESERVED_1_BIT) == 0:
        raise AbiError(f"policy[{POLICY_RESERVED_1_BIT}] is reserved, must be 1, got 0")
    mbz64(value, "policy", 63, 26)
    return SnpPolicy(
        abi_minor=value & 0xFF,
        abi_major=(value >> 8) & 0xFF,
        smt=_bit(value, POLICY_SMT_BIT),
        migrate_ma=_bit(value, POLICY_MIGRATE_MA_BIT),
        debug=_bit(value, POLICY_DEBUG_BIT),
        single_socket=_bit(value, POLICY_SINGLE_SOCKET_BIT),
        cxl_allowed=_bit(value, POLICY_CXL_ALLOW_BIT),
        mem_aes256_xts=_bit(value, POLICY_MEM_AES256_XTS_BIT),
        rapl_dis=_bit(value, POLICY_RAPL_DIS_BIT),
        ciphertext_hiding_dram=_bit(value, POLICY_CIPHERTEXT_HIDING_DRAM_BIT),
        page_swap_disable=_bit(value, POLICY_PAGE_SWAP_DISABLE_BIT),
    )


def snp_policy_to_int(policy: SnpPolicy) -> int:
    """The POLICY field for a decoded policy, with the reserved bit set."""
    value = (policy.abi_minor & 0xFF) | ((policy.abi_major & 0xFF) << 8) | (1 << POLICY_RESERVED_1_BIT)
    for flag, bit in (
        (policy.smt, POLICY_SMT_BIT),
        (policy.migrate_ma, POLICY_MIGRATE_MA_BIT),
        (policy.debug, POLICY_DEBUG_BIT),
        (policy.single_socket, POLICY_SINGLE_SOCKET_BIT),
        (policy.cxl_allowed, POLICY_CXL_ALLOW_BIT),
        (policy.mem_aes256_xts, POLICY_MEM_AES256_XTS_BIT),
        (policy.rapl_dis, POLICY_RAPL_DIS_BIT),
        (policy.ciphertext_hiding_dram, POLICY_CIPHERTEXT_HIDING_DRAM_BIT),
        (policy.page_swap_disable, POLICY_PAGE_SWAP_DISABLE_BIT),
    ):
        if flag:
            value |= 1 << bit
    return value


@dataclass(frozen=True, slots=True)
class SnpPlatformInfo:
    """The decoded PLATFORM_INFO field."""

    smt_enabled: bool = False
    tsme_enabled: bool = False
    ecc_enabled: bool = False
    rapl_disabled: bool = False
    ciphertext_hiding_dram_enabled: bool = False
    alias_check_complete: bool = False
    iommu_write_safe: bool = False
    """The platform has the hardware fix for CVE-2023-20585; platforms without it rely on the mitigation vectors."""
    tio_enabled: bool = False


def parse_snp_platform_info(value: int) -> SnpPlatformInfo:
    """Decode PLATFORM_INFO; bits above 7 must be zero."""
    if value & ~((1 << (MAX_PLATFORM_INFO_BIT + 1)) - 1):
        raise AbiError(f"unrecognized platform info bit(s): 0x{value:x}")
    return SnpPlatformInfo(
        smt_enabled=_bit(value, 0),
        tsme_enabled=_bit(value, 1),
        ecc_enabled=_bit(value, 2),
        rapl_disabled=_bit(value, 3),
        ciphertext_hiding_dram_enabled=_bit(value, 4),
        alias_check_complete=_bit(value, 5),
        iommu_write_safe=_bit(value, 6),
        tio_enabled=_bit(value, 7),
    )


@dataclass(frozen=True, slots=True)
class SevProduct:
    """A product name and machine stepping read from CPUID(1).EAX."""

    name: str
    """PRODUCT_MILAN, PRODUCT_GENOA, PRODUCT_TURIN or PRODUCT_UNKNOWN."""
    stepping: int
    """Zero for an unknown product."""


def fms_to_cpuid1_eax(family: int, model: int, stepping: int) -> int:
    """Encode family, model and stepping as the product bits of CPUID(1).EAX."""
    extended_family = 0
    family_id = family
    if family >= 0xF:
        extended_family = family - 0xF
        family_id = 0xF
    return (
        (extended_family << _EXTENDED_FAMILY_SHIFT)
        | ((model >> 4) << _EXTENDED_MODEL_SHIFT)
        | (family_id << _FAMILY_SHIFT)
        | ((model & 0xF) << _MODEL_SHIFT)
        | (stepping & _STEPPING_MASK)
    )


def fms_from_cpuid1_eax(eax: int) -> tuple[int, int, int]:
    """Decode family, model and stepping from the product bits of CPUID(1).EAX."""
    extended_family = (eax >> _EXTENDED_FAMILY_SHIFT) & 0xFF
    extended_model = (eax >> _EXTENDED_MODEL_SHIFT) & 0xF
    family_id = (eax >> _FAMILY_SHIFT) & 0xF
    model_id = (eax >> _MODEL_SHIFT) & 0xF
    return extended_family + family_id, (extended_model << 4) | model_id, eax & _STEPPING_MASK


def sev_product_from_cpuid1_eax(eax: int) -> SevProduct:
    """The product that CPUID(1).EAX identifies: Milan, Genoa or Turin, by exact family and model."""
    family, model, stepping = fms_from_cpuid1_eax(eax)
    if family == ZEN3_ZEN4_FAMILY and model == MILAN_MODEL:
        return SevProduct(PRODUCT_MILAN, stepping)
    if family == ZEN3_ZEN4_FAMILY and model == GENOA_MODEL:
        return SevProduct(PRODUCT_GENOA, stepping)
    if family == ZEN5_FAMILY and model == TURIN_MODEL:
        return SevProduct(PRODUCT_TURIN, stepping)
    return SevProduct(PRODUCT_UNKNOWN, 0)


def product_line_from_fms(fms: int) -> str:
    """The KDS product line for a CPUID(1).EAX value, by family and extended model; PRODUCT_UNKNOWN otherwise."""
    family, model, _ = fms_from_cpuid1_eax(fms)
    if family == ZEN3_ZEN4_FAMILY:
        return {0: PRODUCT_MILAN, 1: PRODUCT_GENOA, 0xA: PRODUCT_SIENA}.get(model >> 4, PRODUCT_UNKNOWN)
    if family == ZEN5_FAMILY and (model >> 4) in (0, 1):
        return PRODUCT_TURIN
    return PRODUCT_UNKNOWN


@dataclass(frozen=True, slots=True)
class Report:
    """A decoded attestation report. ``raw`` is the complete report as it was signed."""

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
    """The product bits of CPUID(1).EAX; zero below report version 3."""
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
    raw: bytes


def parse_report(data: bytes) -> Report:
    """Decode a report of exactly REPORT_SIZE bytes, checking the guest policy, SIGNER_INFO and every reserved range.

    The CPUID stepping byte must fit the four bits that CPUID(1).EAX
    holds for it, so that the product identity reproduces the report.
    """
    if len(data) != REPORT_SIZE:
        raise AbiError(f"array size is 0x{len(data):x}, an SEV-SNP attestation report size is 0x{REPORT_SIZE:x}")
    version = _u32(data, 0x00)
    policy = _u64(data, 0x08)
    try:
        parse_snp_policy(policy)
    except AbiError as err:
        raise AbiError(f"malformed guest policy: {err}") from err
    signer_info = _u32(data, 0x48)
    parse_signer_info(signer_info)
    mbz(data, 0x4C, 0x50)
    cpuid1_eax_fms = 0
    mbz_lo = 0x188
    if version >= REPORT_VERSION_3:
        mbz_lo = 0x18B
        if data[0x18A] > _STEPPING_MASK:
            raise AbiError(f"CPUID stepping 0x{data[0x18A]:x} does not fit four bits")
        cpuid1_eax_fms = fms_to_cpuid1_eax(data[0x188], data[0x189], data[0x18A])
    mbz(data, mbz_lo, 0x1A0)
    mbz(data, 0x1EB, 0x1EC)
    mbz(data, 0x1EF, 0x1F0)
    mbz(data, 0x208, SIGNATURE_OFFSET)
    signature_algo = _u32(data, 0x34)
    if signature_algo == SIGN_ECDSA_P384_SHA384:
        mbz(data, SIGNATURE_OFFSET + ECDSA_P384_SHA384_SIGNATURE_SIZE, REPORT_SIZE)
    return Report(
        version=version,
        guest_svn=_u32(data, 0x04),
        policy=policy,
        family_id=data[0x10:0x20],
        image_id=data[0x20:0x30],
        vmpl=_u32(data, 0x30),
        signature_algo=signature_algo,
        current_tcb=_u64(data, 0x38),
        platform_info=_u64(data, 0x40),
        signer_info=signer_info,
        report_data=data[0x50:0x90],
        measurement=data[0x90:0xC0],
        host_data=data[0xC0:0xE0],
        id_key_digest=data[0xE0:0x110],
        author_key_digest=data[0x110:0x140],
        report_id=data[0x140:0x160],
        report_id_ma=data[0x160:0x180],
        reported_tcb=_u64(data, 0x180),
        cpuid1_eax_fms=cpuid1_eax_fms,
        chip_id=data[0x1A0:0x1E0],
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
        signature=data[SIGNATURE_OFFSET:REPORT_SIZE],
        raw=bytes(data),
    )


def validate_report_format(data: bytes) -> None:
    """Check the structural rules that a report must satisfy before its signature is checked: the size, a supported
    version and a well-formed guest policy."""
    if len(data) < REPORT_SIZE:
        raise AbiError(f"report size is {len(data)} bytes. Expected {REPORT_SIZE} bytes")
    version = _u32(data, 0x00)
    if not MIN_SUPPORTED_REPORT_VERSION <= version <= MAX_SUPPORTED_REPORT_VERSION:
        raise AbiError(
            f"report version is: {version}. Expected between {MIN_SUPPORTED_REPORT_VERSION} and "
            f"{MAX_SUPPORTED_REPORT_VERSION}"
        )
    try:
        parse_snp_policy(_u64(data, 0x08))
    except AbiError as err:
        raise AbiError(f"malformed guest policy: {err}") from err


def signed_component(data: bytes) -> bytes:
    """The bytes of a report that the AMD secure processor signs: everything before the signature."""
    return data[:SIGNATURE_OFFSET]


def report_signature_der(report: Report) -> bytes:
    """The report's ECDSA signature as a DER ECDSA-Sig-Value; the algorithm must be ECDSA P-384 with SHA-384."""
    if report.signature_algo != SIGN_ECDSA_P384_SHA384:
        raise AbiError(f"unknown signature algorithm: {report.signature_algo}")
    r = bytes(reversed(report.signature[:ECDSA_RS_SIZE]))
    s = bytes(reversed(report.signature[ECDSA_RS_SIZE:ECDSA_P384_SHA384_SIGNATURE_SIZE]))
    return der.raw_signature_to_der(r + s, ECDSA_RS_SIZE)


def mbz(data: bytes, lo: int, hi: int) -> None:
    """Require ``data[lo:hi]`` to be all zero."""
    if any(data[lo:hi]):
        raise AbiError(f"mbz range [0x{lo:x}:0x{hi:x}] not all zero: {data[lo:hi].hex()}")


def mbz64(value: int, name: str, hi: int, lo: int) -> None:
    """Require bits ``hi`` down to ``lo`` (inclusive) of ``value`` to be zero."""
    if (value >> lo) & ((1 << (hi - lo + 1)) - 1):
        raise AbiError(f"mbz range {name}[0x{lo:x}:0x{hi:x}] not all zero: {value:x}")


def _bit(value: int, bit: int) -> bool:
    return (value >> bit) & 1 == 1


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "little")
