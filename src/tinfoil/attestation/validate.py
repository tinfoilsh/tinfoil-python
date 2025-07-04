from dataclasses import dataclass, field
from typing import Optional, List, Dict

from .abi_sevsnp import (
    Report,
    TCBParts,
    SnpPolicy,
    SnpPlatformInfo,
    ReportSigner,
)
from .verify import CertificateChain

@dataclass
class ValidationOptions:
    """
    Verification options for an SEV-SNP attestation report.
    Any attribute left as ``None`` / empty will not be checked
    by the validation routine.
    """
    # Policy / version constraints
    guest_policy: Optional[SnpPolicy] = None
    minimum_guest_svn: Optional[int] = None
    minimum_build: Optional[int] = None          # Firmware build (uint8)
    minimum_version: Optional[int] = None        # Firmware API version (uint16)

    # TCB requirements
    minimum_tcb: Optional[TCBParts] = None
    minimum_launch_tcb: Optional[TCBParts] = None
    permit_provisional_firmware: bool = False

    # Field equality checks (length is not enforced here; caller must ensure correctness)
    report_data: Optional[bytes] = None          # 64 bytes
    host_data: Optional[bytes] = None            # 32 bytes
    image_id: Optional[bytes] = None             # 16 bytes
    family_id: Optional[bytes] = None            # 16 bytes
    report_id: Optional[bytes] = None            # 32 bytes
    report_id_ma: Optional[bytes] = None         # 32 bytes
    measurement: Optional[bytes] = None          # 48 bytes
    chip_id: Optional[bytes] = None              # 64 bytes

    # Misc
    platform_info: Optional[SnpPlatformInfo] = None
    vmpl: Optional[int] = None                  # Expected VMPL (0-3)

    # TODO: ID-block / author key requirements
    require_author_key: bool = False
    require_id_block: bool = False
    # trusted_author_keys: List[x509.Certificate] = field(default_factory=list)
    # trusted_author_key_hashes: List[bytes] = field(default_factory=list)
    # trusted_id_keys: List[x509.Certificate] = field(default_factory=list)
    # trusted_id_key_hashes: List[bytes] = field(default_factory=list)

    # TODO:Extended certificate-table options
    # cert_table_options: Dict[str, CertEntryOption] = field(default_factory=dict)


def validate_report(report: Report, chain: CertificateChain, options: ValidationOptions):
    """
    Validate the supplied SEV-SNP attestation report according to *options*.
    Raises ValueError if validation fails.
    """
    
    # Policy constraints
    if options.guest_policy is not None:
        _validate_policy(report.policy_parsed, options.guest_policy)
    
    if options.minimum_guest_svn is not None:
        if report.guest_svn < options.minimum_guest_svn:
            raise ValueError(f"Guest SVN {report.guest_svn} is less than minimum required {options.minimum_guest_svn}")
    
    if options.minimum_build is not None:
        if report.current_build < options.minimum_build:
            raise ValueError(f"Current SNP firmware build number {report.current_build} is less than minimum required {options.minimum_build}")
        if report.committed_build < options.minimum_build:
            raise ValueError(f"Committed SNP firmware build number {report.committed_build} is less than minimum required {options.minimum_build}")
        
    if options.minimum_version is not None:
        # Combine major/minor into single version number for comparison
        current_version = (report.current_major << 8) | report.current_minor
        committed_version = (report.committed_major << 8) | report.committed_minor
        if current_version < options.minimum_version:
            raise ValueError(f"Current SNP firmwareversion {report.current_major}.{report.current_minor} is less than minimum required {options.minimum_version >> 8}.{options.minimum_version & 0xff}")
        if committed_version < options.minimum_version:
            raise ValueError(f"Committed SNP firmware version {report.committed_major}.{report.committed_minor} is less than minimum required {options.minimum_version >> 8}.{options.minimum_version & 0xff}")

    # TCB requirements
    if options.minimum_tcb is not None:
        current_tcb_parts = TCBParts.from_int(report.current_tcb)
        committed_tcb_parts = TCBParts.from_int(report.committed_tcb)
        reported_tcb_parts = TCBParts.from_int(report.reported_tcb)
        if not current_tcb_parts.meets_minimum(options.minimum_tcb):
            raise ValueError(f"Current TCB {current_tcb_parts} does not meet minimum requirements {options.minimum_tcb}")
        if not committed_tcb_parts.meets_minimum(options.minimum_tcb):
            raise ValueError(f"Committed TCB {committed_tcb_parts} does not meet minimum requirements {options.minimum_tcb}")
        if not reported_tcb_parts.meets_minimum(options.minimum_tcb):
            raise ValueError(f"Reported TCB {reported_tcb_parts} does not meet minimum requirements {options.minimum_tcb}")
        
    # VCEK-specific TCB check
    chain.validate_vcek_tcb(TCBParts.from_int(report.reported_tcb))
    
    if options.minimum_launch_tcb is not None:
        launch_tcb_parts = TCBParts.from_int(report.launch_tcb)
        if not launch_tcb_parts.meets_minimum(options.minimum_launch_tcb):
            raise ValueError(f"Launch TCB {launch_tcb_parts} does not meet minimum requirements {options.minimum_launch_tcb}")
    
    # Field equality checks
    if options.report_data is not None:
        if len(report.report_data) != 64:
            raise ValueError(f"Report data length is {len(report.report_data)}, expected 64 bytes")
        if report.report_data != options.report_data:
            raise ValueError(f"Report data mismatch: got {report.report_data.hex()}, expected {options.report_data.hex()}")
    
    if options.host_data is not None:
        if len(report.host_data) != 32:
            raise ValueError(f"Host data length is {len(report.host_data)}, expected 32 bytes")
        if report.host_data != options.host_data:
            raise ValueError(f"Host data mismatch: got {report.host_data.hex()}, expected {options.host_data.hex()}")
    
    if options.image_id is not None:
        if len(report.image_id) != 16:
            raise ValueError(f"Image ID length is {len(report.image_id)}, expected 16 bytes")
        if report.image_id != options.image_id:
            raise ValueError(f"Image ID mismatch: got {report.image_id.hex()}, expected {options.image_id.hex()}")
    
    if options.family_id is not None:
        if len(report.family_id) != 16:
            raise ValueError(f"Family ID length is {len(report.family_id)}, expected 16 bytes")
        if report.family_id != options.family_id:
            raise ValueError(f"Family ID mismatch: got {report.family_id.hex()}, expected {options.family_id.hex()}")
    
    if options.report_id is not None:
        if len(report.report_id) != 32:
            raise ValueError(f"Report ID length is {len(report.report_id)}, expected 32 bytes")
        if report.report_id != options.report_id:
            raise ValueError(f"Report ID mismatch: got {report.report_id.hex()}, expected {options.report_id.hex()}")
    
    if options.report_id_ma is not None:
        if len(report.report_id_ma) != 32:
            raise ValueError(f"Report ID MA length is {len(report.report_id_ma)}, expected 32 bytes")
        if report.report_id_ma != options.report_id_ma:
            raise ValueError(f"Report ID MA mismatch: got {report.report_id_ma.hex()}, expected {options.report_id_ma.hex()}")
    
    if options.measurement is not None:
        if len(report.measurement) != 48:
            raise ValueError(f"Measurement length is {len(report.measurement)}, expected 48 bytes")
        if report.measurement != options.measurement:
            raise ValueError(f"Measurement mismatch: got {report.measurement.hex()}, expected {options.measurement.hex()}")
    
    if options.chip_id is not None:
        if len(report.chip_id) != 64:
            raise ValueError(f"Chip ID length is {len(report.chip_id)}, expected 64 bytes")
        if report.chip_id != options.chip_id:
            raise ValueError(f"Chip ID mismatch: got {report.chip_id.hex()}, expected {options.chip_id.hex()}")
    
    # VCEK-specific CHIP_ID ↔ HWID equality check
    if report.signer_info_parsed.signingKey == ReportSigner.VcekReportSigner:
        if report.signer_info_parsed.maskChipKey and any(report.chip_id):
            raise ValueError("maskChipKey is set but CHIP_ID is not zeroed")
        if not report.signer_info_parsed.maskChipKey:
            chain.validate_vcek_hwid(report.chip_id)
    
    # Platform info check
    if options.platform_info is not None:
        _validate_platform_info(report.platform_info_parsed, options.platform_info)
    
    # VMPL check
    if options.vmpl is not None: # Must be between 0 and 3 and equal to the expected value
        if not (0 <= report.vmpl <= 3):
            raise ValueError(f"VMPL {report.vmpl} is not in valid range 0-3")
        if report.vmpl != options.vmpl:
            raise ValueError(f"VMPL mismatch: got {report.vmpl}, expected {options.vmpl}")
    
    # Provisional firmware check - we only support permit_provisional_firmware = False
    if options.permit_provisional_firmware:
        # Not supported - reject any request for provisional firmware
        raise ValueError("Provisional firmware is not supported")
    
    # When permit_provisional_firmware = False, committed and current values must be equal
    if report.committed_build != report.current_build:
        raise ValueError(f"Committed build {report.committed_build} does not match current build {report.current_build}")
    if report.committed_minor != report.current_minor:
        raise ValueError(f"Committed minor version {report.committed_minor} does not match current minor version {report.current_minor}")
    if report.committed_major != report.current_major:
        raise ValueError(f"Committed major version {report.committed_major} does not match current major version {report.current_major}")
    if report.committed_tcb != report.current_tcb:
        raise ValueError(f"Committed TCB 0x{report.committed_tcb:x} does not match current TCB 0x{report.current_tcb:x}")
    
    # ID-block / author key requirements
    if options.require_author_key or options.require_id_block:
        # Not supported yet
        raise ValueError("ID-block and author key requirements are not supported yet")


def _validate_policy(report_policy: SnpPolicy, required: SnpPolicy):
    """
    Validate policy with security-aware checks.
    
    Logic follows Go reference implementation:
    - Check ABI version compatibility
    - Reject unauthorized capabilities (report has them, required doesn't allow)
    - Reject missing required restrictions/features
    
    Raises ValueError if validation fails.
    """
    # ABI version check - required version must not be greater than report version
    if _compare_policy_versions(required, report_policy) > 0:
        raise ValueError(f"Required ABI version ({required.abi_major}.{required.abi_minor}) is greater than report's ABI version ({report_policy.abi_major}.{report_policy.abi_minor})")
    
    # Unauthorized capabilities (report has them enabled, but required doesn't allow)
    if not required.migrate_ma and report_policy.migrate_ma:
        raise ValueError(f"Found unauthorized migration agent capability. Report policy: {report_policy}, Required policy: {required}")
    
    if not required.debug and report_policy.debug:
        raise ValueError(f"Found unauthorized debug capability. Report policy: {report_policy}, Required policy: {required}")
    
    if not required.smt and report_policy.smt:
        raise ValueError(f"Found unauthorized symmetric multithreading (SMT) capability. Report policy: {report_policy}, Required policy: {required}")
    
    if not required.cxl_allowed and report_policy.cxl_allowed:
        raise ValueError(f"Found unauthorized CXL capability. Report policy: {report_policy}, Required policy: {required}")
    
    if not required.mem_aes256_xts and report_policy.mem_aes256_xts:
        raise ValueError(f"Found unauthorized memory encryption mode. Report policy: {report_policy}, Required policy: {required}")
    
    # Required restrictions/features (report lacks what required mandates)
    if required.single_socket and not report_policy.single_socket:
        raise ValueError(f"Required single socket restriction not present. Report policy: {report_policy}, Required policy: {required}")
    
    if required.mem_aes256_xts and not report_policy.mem_aes256_xts:
        raise ValueError(f"Found unauthorized memory encryption mode. Report policy: {report_policy}, Required policy: {required}")
    
    if required.rapl_dis and not report_policy.rapl_dis:
        raise ValueError(f"Found unauthorized RAPL capability. Report policy: {report_policy}, Required policy: {required}")
    
    if required.ciphertext_hiding_dram and not report_policy.ciphertext_hiding_dram:
        raise ValueError(f"Ciphertext hiding in DRAM isn't enforced. Report policy: {report_policy}, Required policy: {required}")

    if required.page_swap_disabled and not report_policy.page_swap_disabled:
        raise ValueError(f"Page swap isn't disabled. Report policy: {report_policy}, Required policy: {required}")

def _compare_policy_versions(required: SnpPolicy, report: SnpPolicy) -> int:
    """
    Compare policy ABI versions.
    Returns:
        > 0 if required version is greater than report version
        = 0 if versions are equal
        < 0 if required version is less than report version
    """
    # Compare major version first
    if required.abi_major != report.abi_major:
        return required.abi_major - report.abi_major
    
    # If major versions are equal, compare minor versions
    return required.abi_minor - report.abi_minor


def _validate_platform_info(report_info: SnpPlatformInfo, required: SnpPlatformInfo):
    """
    Validate platform info with security-aware checks.
    
    Logic follows Go reference implementation:
    - If report has a feature enabled that required doesn't allow -> FAIL
    - If report lacks a feature that required mandates -> FAIL
    
    Raises ValueError if validation fails.
    """
    # Unauthorized features (report has it enabled, but required doesn't allow it)
    if report_info.smt_enabled and not required.smt_enabled:
        raise ValueError(f"Unauthorized platform feature SMT enabled. Report platform info: {report_info}, Required platform info: {required}")
    
    # Required features (report lacks something that required mandates)
    if not report_info.ecc_enabled and required.ecc_enabled:
        raise ValueError(f"Required platform feature ECC not enabled. Report platform info: {report_info}, Required platform info: {required}")
    
    if not report_info.tsme_enabled and required.tsme_enabled:
        raise ValueError(f"Required platform feature TSME not enabled. Report platform info: {report_info}, Required platform info: {required}") 
    
    if not report_info.rapl_disabled and required.rapl_disabled:
        raise ValueError(f"Required platform feature RAPL not disabled. Report platform info: {report_info}, Required platform info: {required}")
    
    if not report_info.ciphertext_hiding_dram_enabled and required.ciphertext_hiding_dram_enabled:
        raise ValueError(f"Required ciphertext hiding in DRAM not enforced. Report platform info: {report_info}, Required platform info: {required}")
    
    if not report_info.alias_check_complete and required.alias_check_complete:
        raise ValueError(f"Required memory alias check hasn't been completed. Report platform info: {report_info}, Required platform info: {required}")

    if not report_info.tio_enabled and required.tio_enabled:
        raise ValueError(f"Required TIO not enabled. Report platform info: {report_info}, Required platform info: {required}")