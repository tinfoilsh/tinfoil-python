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


def validate_report(report: Report, chain: CertificateChain, options: ValidationOptions) -> bool:
    """
    Validate the supplied SEV-SNP attestation report according to *options*.
    """
    
    # Policy constraints
    if options.guest_policy is not None:
        if not _validate_policy(report.policy_parsed, options.guest_policy):
            return False
    
    if options.minimum_guest_svn is not None:
        if report.guest_svn < options.minimum_guest_svn:
            return False
    
    if options.minimum_build is not None:
        if report.current_build < options.minimum_build or report.committed_build < options.minimum_build:
            return False
        
    if options.minimum_version is not None:
        # Combine major/minor into single version number for comparison
        current_version = (report.current_major << 8) | report.current_minor
        committed_version = (report.committed_major << 8) | report.committed_minor
        if current_version < options.minimum_version or committed_version < options.minimum_version:
            return False

    # TCB requirements
    if options.minimum_tcb is not None:
        current_tcb_parts = TCBParts.from_int(report.current_tcb)
        committed_tcb_parts = TCBParts.from_int(report.committed_tcb)
        reported_tcb_parts = TCBParts.from_int(report.reported_tcb)
        if not current_tcb_parts.meets_minimum(options.minimum_tcb) or not committed_tcb_parts.meets_minimum(options.minimum_tcb) or not reported_tcb_parts.meets_minimum(options.minimum_tcb):
            return False
        
    # VCEK-specific TCB check
    if not chain.validate_vcek_tcb(TCBParts.from_int(report.reported_tcb)):
        return False
    
    if options.minimum_launch_tcb is not None:
        launch_tcb_parts = TCBParts.from_int(report.launch_tcb)
        if not launch_tcb_parts.meets_minimum(options.minimum_launch_tcb):
            return False
    
    # Field equality checks
    if options.report_data is not None:
        if len(report.report_data) != 64 or report.report_data != options.report_data:
            return False
    
    if options.host_data is not None:
        if len(report.host_data) != 32 or report.host_data != options.host_data:
            return False
    
    if options.image_id is not None:
        if len(report.image_id) != 16 or report.image_id != options.image_id:
            return False
    
    if options.family_id is not None:
        if len(report.family_id) != 16 or report.family_id != options.family_id:
            return False
    
    if options.report_id is not None:
        if len(report.report_id) != 32 or report.report_id != options.report_id:
            return False
    
    if options.report_id_ma is not None:
        if len(report.report_id_ma) != 32 or report.report_id_ma != options.report_id_ma:
            return False
    
    if options.measurement is not None:
        if len(report.measurement) != 48 or report.measurement != options.measurement:
            return False
    
    if options.chip_id is not None:
        if len(report.chip_id) != 64 or report.chip_id != options.chip_id:
            return False
    
    # VCEK-specific CHIP_ID ↔ HWID equality check
    if report.signer_info_parsed.signingKey == ReportSigner.VcekReportSigner:
        if any(report.chip_id): # at least one byte is non-zero
            if not chain.validate_vcek_hwid(report.chip_id):
                return False
    
    # Platform info check
    if options.platform_info is not None:
        if not _validate_platform_info(report.platform_info_parsed, options.platform_info):
            return False
    
    # VMPL check
    if options.vmpl is not None: # Must be between 0 and 3 and equal to the expected value
        if not (0 <= report.vmpl <= 3):
            return False
        if report.vmpl != options.vmpl:
            return False
    
    # Provisional firmware check - we only support permit_provisional_firmware = False
    if options.permit_provisional_firmware:
        # Not supported - reject any request for provisional firmware
        return False
    
    # When permit_provisional_firmware = False, committed and current values must be equal
    if (report.committed_build != report.current_build or
        report.committed_minor != report.current_minor or
        report.committed_major != report.current_major or
        report.committed_tcb != report.current_tcb):
        return False
    
    # ID-block / author key requirements
    if options.require_author_key or options.require_id_block:
        # Not supported yet
        return False
    
    return True


def _validate_policy(report_policy: SnpPolicy, required: SnpPolicy) -> bool:
    """
    Validate policy with security-aware checks.
    
    Logic follows Go reference implementation:
    - Check ABI version compatibility
    - Reject unauthorized capabilities (report has them, required doesn't allow)
    - Reject missing required restrictions/features
    """
    # ABI version check - required version must not be greater than report version
    if _compare_policy_versions(required, report_policy) > 0:
        return False  # Required ABI version is greater than report's ABI version
    
    # Unauthorized capabilities (report has them enabled, but required doesn't allow)
    if not required.migrate_ma and report_policy.migrate_ma:
        return False  # "found unauthorized migration agent capability"
    
    if not required.debug and report_policy.debug:
        return False  # "found unauthorized debug capability"
    
    if not required.smt and report_policy.smt:
        return False  # "found unauthorized symmetric multithreading (SMT) capability"
    
    if not required.cxl_allowed and report_policy.cxl_allowed:
        return False  # "found unauthorized CXL capability"
    
    if not required.mem_aes256_xts and report_policy.mem_aes256_xts:
        return False  # "found unauthorized memory encryption mode"
    
    # Required restrictions/features (report lacks what required mandates)
    if required.single_socket and not report_policy.single_socket:
        return False  # "required single socket restriction not present"
    
    if required.mem_aes256_xts and not report_policy.mem_aes256_xts:
        return False  # "found unauthorized memory encryption mode"
    
    if required.rapl_dis and not report_policy.rapl_dis:
        return False  # "found unauthorized RAPL capability"
    
    if required.ciphertext_hiding_dram and not report_policy.ciphertext_hiding_dram:
        return False  # "ciphertext hiding in DRAM isn't enforced"
    
    return True


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


def _validate_platform_info(report_info: SnpPlatformInfo, required: SnpPlatformInfo) -> bool:
    """
    Validate platform info with security-aware checks.
    
    Logic follows Go reference implementation:
    - If report has a feature enabled that required doesn't allow -> FAIL
    - If report lacks a feature that required mandates -> FAIL
    """
    # Unauthorized features (report has it enabled, but required doesn't allow it)
    if report_info.smt_enabled and not required.smt_enabled:
        return False  # "unauthorized platform feature SMT enabled"
    
    if report_info.ecc_enabled and not required.ecc_enabled:
        return False  # "unauthorized platform feature ECC enabled"
    
    # Required features (report lacks something that required mandates)
    if not report_info.tsme_enabled and required.tsme_enabled:
        return False  # "required platform feature TSME not enabled"
    
    if not report_info.rapl_disabled and required.rapl_disabled:
        return False  # "required platform feature RAPL not disabled"
    
    if not report_info.ciphertext_hiding_dram_enabled and required.ciphertext_hiding_dram_enabled:
        return False  # "required ciphertext hiding in DRAM not enforced"
    
    if not report_info.alias_check_complete and required.alias_check_complete:
        return False  # "required memory alias check hasn't been completed"
    
    return True 