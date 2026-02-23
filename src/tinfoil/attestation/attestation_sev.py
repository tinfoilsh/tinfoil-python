"""
AMD SEV-SNP Attestation Orchestration Module.

This module provides the high-level entry point for AMD SEV-SNP attestation verification.

"""

import base64
from typing import Optional

from .abi_sev import TCBParts, SnpPolicy, SnpPlatformInfo, Report
from .types import Measurement, Verification, PredicateType, TLS_KEY_FP_SIZE, HPKE_KEY_SIZE, safe_gzip_decompress
from .verify_sev import verify_attestation, CertificateChain
from .validate_sev import validate_report, ValidationOptions


class SevAttestationError(Exception):
    """Raised when SEV-SNP attestation verification fails."""
    pass


# =============================================================================
# Orchestration Constants
# =============================================================================

# Minimum TCB requirements for AMD SEV-SNP
min_tcb = TCBParts(
    bl_spl=0x7,
    tee_spl=0,
    snp_spl=0xe,
    ucode_spl=0x48,
)

# Default validation options for AMD SEV-SNP attestation
default_validation_options = ValidationOptions(
    guest_policy=SnpPolicy(
        abi_minor=0,
        abi_major=0,
        smt=True,
        migrate_ma=False,
        debug=False,
        single_socket=False,
        cxl_allowed=False,
        mem_aes256_xts=False,
        rapl_dis=False,
        ciphertext_hiding_dram=False,
        page_swap_disabled=False,
    ),
    minimum_guest_svn=0,
    minimum_build=21,
    minimum_version=(1 << 8) | 55,  # 1.55
    minimum_tcb=min_tcb,
    minimum_launch_tcb=min_tcb,
    permit_provisional_firmware=False,
    platform_info=SnpPlatformInfo(
        smt_enabled=True,
        tsme_enabled=False,
        ecc_enabled=False,
        rapl_disabled=False,
        ciphertext_hiding_dram_enabled=False,
        alias_check_complete=False,
        tio_enabled=False,
    ),
    require_author_key=False,
    require_id_block=False,
)


# =============================================================================
# Main Entry Points
# =============================================================================

def verify_sev_attestation_v2(attestation_doc: str) -> Verification:
    """Verify SEV attestation document (v2 format) and return verification result.

    Raises:
        ValueError: If verification fails
    """
    try:
        report = verify_sev_report(attestation_doc)
    except SevAttestationError as e:
        raise ValueError(f"SEV attestation verification failed: {e}") from e

    # Create measurement object
    measurement = Measurement(
        type=PredicateType.SEV_GUEST_V2,
        registers=[
            report.measurement.hex()
        ]
    )

    keys = report.report_data
    required_len = TLS_KEY_FP_SIZE + HPKE_KEY_SIZE
    if len(keys) < required_len:
        raise ValueError(
            f"report_data too short: {len(keys)} bytes, need at least {required_len}"
        )
    tls_key_fp = keys[0:TLS_KEY_FP_SIZE]
    hpke_public_key = keys[TLS_KEY_FP_SIZE:TLS_KEY_FP_SIZE + HPKE_KEY_SIZE]

    return Verification(
        measurement=measurement,
        public_key_fp=tls_key_fp.hex(),
        hpke_public_key=hpke_public_key.hex()
    )


def verify_sev_report(
    attestation_doc: str,
    is_compressed: bool = True,
    validation_options: Optional[ValidationOptions] = None,
) -> Report:
    """Verify SEV attestation document and return the parsed report.

    Args:
        attestation_doc: Base64-encoded attestation document
        is_compressed: Whether the document is gzip-compressed (default True)
        validation_options: Custom validation options; uses module defaults if None
    """
    options = validation_options if validation_options is not None else default_validation_options

    try:
        att_doc_bytes = base64.b64decode(attestation_doc)
    except Exception as e:
        raise SevAttestationError(f"Failed to decode base64: {e}") from e

    if is_compressed:
        try:
            att_doc_bytes = safe_gzip_decompress(att_doc_bytes)
        except SevAttestationError:
            raise
        except Exception as e:
            raise SevAttestationError(f"Failed to decompress attestation document: {e}") from e

    try:
        report = Report(att_doc_bytes)
    except Exception as e:
        raise SevAttestationError(f"Failed to parse report: {e}") from e

    try:
        chain = CertificateChain.from_report(report)
    except Exception as e:
        raise SevAttestationError(f"Failed to build certificate chain: {e}") from e

    try:
        res = verify_attestation(chain, report)
    except Exception as e:
        raise SevAttestationError(f"Failed to verify attestation: {e}") from e

    if not res:
        raise SevAttestationError("Attestation verification failed!")

    try:
        validate_report(report, chain, options)
    except Exception as e:
        raise SevAttestationError(f"Failed to validate report: {e}") from e

    return report

