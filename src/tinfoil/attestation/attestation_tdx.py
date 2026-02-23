"""
TDX Attestation Orchestration Module.

This module provides the high-level entry point for TDX attestation verification.
It coordinates between:
- Quote parsing (abi_tdx)
- Cryptographic verification (verify_tdx)
- Policy validation (validate_tdx)
- Collateral validation (collateral_tdx)

Usage:
    from tinfoil.attestation.attestation_tdx import verify_tdx_attestation

    result = verify_tdx_attestation(attestation_doc)
    # result.measurements contains the 5 TDX measurements
    # result.tls_key_fp contains the TLS key fingerprint
"""

import base64
from dataclasses import dataclass, field
from typing import Optional

from .abi_tdx import (
    parse_quote,
    QuoteV4,
    TdxQuoteParseError,
    INTEL_QE_VENDOR_ID,
    MR_CONFIG_ID_SIZE,
    MR_OWNER_SIZE,
    MR_OWNER_CONFIG_SIZE,
)
from .types import TLS_KEY_FP_SIZE, HPKE_KEY_SIZE, Measurement, Verification, PredicateType, HardwareMeasurement, HardwareMeasurementError, TDX_MRTD_IDX, TDX_RTMR0_IDX, TDX_REGISTER_COUNT, safe_gzip_decompress
from .verify_tdx import (
    verify_tdx_quote,
    TdxVerificationError,
    PCKCertificateChain,
)
from .validate_tdx import (
    validate_tdx_policy,
    PolicyOptions,
    TdQuoteBodyOptions,
    HeaderOptions,
    TdxValidationError,
)
from .pck_extensions import PckExtensions
from .collateral_tdx import (
    validate_collateral,
    CollateralError,
    TdxCollateral,
    TcbLevel,
)


# =============================================================================
# Orchestration Constants
# =============================================================================

# Minimum required tcbEvaluationDataNumber.
# This prevents accepting collateral issued before critical security updates.
# See: https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html
#
# This value should be set using:
#   from tinfoil.attestation.collateral_tdx import calculate_min_tcb_evaluation_data_number
#   min_num = calculate_min_tcb_evaluation_data_number()
#
# The function queries Intel PCS and returns the lowest tcbEvaluationDataNumber
# whose TCB recovery event date is within the last year.
#
# Current value 18 corresponds to TCB recovery event date 2024-11-12.
DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER = 18

# Expected values for policy validation
# TdAttributes: All zeros except SEPT_VE_DISABLE=1
EXPECTED_TD_ATTRIBUTES = bytes.fromhex("0000001000000000")
# XFam: Enable FP, SSE, AVX, AVX512, PK, AMX
EXPECTED_XFAM = bytes.fromhex("e702060000000000")
# MinimumTeeTcbSvn: 3.1.2
EXPECTED_MINIMUM_TEE_TCB_SVN = bytes.fromhex("03010200000000000000000000000000")

# Accepted MR_SEAM values from Intel TDX module releases
# https://github.com/intel/confidential-computing.tdx.tdx-module/releases
ACCEPTED_MR_SEAMS: tuple[bytes, ...] = (
    bytes.fromhex("476a2997c62bccc78370913d0a80b956e3721b24272bc66c4d6307ced4be2865c40e26afac75f12df3425b03eb59ea7c"),  # TDX Module 2.0.08
    bytes.fromhex("7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d"),  # TDX Module 1.5.16
    bytes.fromhex("685f891ea5c20e8fa27b151bf34bf3b50fbaf7143cc53662727cbdb167c0ad8385f1f6f3571539a91e104a1c96d75e04"),  # TDX Module 2.0.02
    bytes.fromhex("49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6"),  # TDX Module 1.5.08
)


# =============================================================================
# Orchestration Config
# =============================================================================

@dataclass(frozen=True)
class TdxVerificationConfig:
    """
    Configuration for TDX attestation verification.

    All fields have sensible defaults matching the current hardcoded values.
    Override individual fields to customise verification policy.
    """
    min_tcb_evaluation_data_number: int = DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER
    accepted_mr_seams: tuple[bytes, ...] = ACCEPTED_MR_SEAMS
    policy_options: Optional[PolicyOptions] = None
    expected_td_attributes: bytes = EXPECTED_TD_ATTRIBUTES
    expected_xfam: bytes = EXPECTED_XFAM
    expected_minimum_tee_tcb_svn: bytes = EXPECTED_MINIMUM_TEE_TCB_SVN


_DEFAULT_CONFIG = TdxVerificationConfig()


# =============================================================================
# Orchestration Error Type
# =============================================================================

class TdxAttestationError(Exception):
    """
    Raised when TDX attestation verification fails.
    """
    pass


# =============================================================================
# Orchestration Result Type
# =============================================================================

@dataclass
class TdxAttestationResult:
    """
    Result of TDX attestation verification.

    Contains the verified quote, measurements, and TCB status.
    """
    quote: QuoteV4
    pck_chain: PCKCertificateChain
    pck_extensions: PckExtensions
    collateral: TdxCollateral
    tcb_level: TcbLevel
    measurements: list[str]  # [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
    tls_key_fp: str
    hpke_public_key: str


# =============================================================================
# Main Entry Point
# =============================================================================

def verify_tdx_attestation(
    attestation_doc: str,
    is_compressed: bool = True,
    config: Optional[TdxVerificationConfig] = None,
) -> TdxAttestationResult:
    """
    Verify a TDX attestation document.

    This is the main entry point for TDX attestation verification.
    It performs the complete verification flow:

    1. Decode and decompress the attestation document
    2. Parse the TDX quote
    3. Verify cryptographic signatures (PCK chain, quote, QE report)
    4. Policy validation (XFAM, TD_ATTRIBUTES, SEAM, MR_SEAM whitelist)
    5. Fetch and validate collateral (PCK extensions, TCB status, QE identity, revocation)
    6. Extract measurements and report data

    Args:
        attestation_doc: Base64-encoded attestation document
        is_compressed: Whether the document is gzip compressed
        config: Optional verification config. Uses sensible defaults if None.

    Returns:
        TdxAttestationResult containing verified data

    Raises:
        TdxAttestationError: If any verification step fails
    """
    if config is None:
        config = _DEFAULT_CONFIG
    # Step 1: Decode the attestation document
    try:
        raw_bytes = base64.b64decode(attestation_doc)
    except Exception as e:
        raise TdxAttestationError(f"Failed to decode base64: {e}") from e

    if is_compressed:
        try:
            raw_bytes = safe_gzip_decompress(raw_bytes)
        except Exception as e:
            raise TdxAttestationError(f"Failed to decompress: {e}") from e

    # Step 2: Parse the TDX quote
    try:
        quote = parse_quote(raw_bytes)
    except TdxQuoteParseError as e:
        raise TdxAttestationError(f"Failed to parse TDX quote: {e}") from e

    # Step 3: Verify cryptographic signatures
    try:
        pck_chain = verify_tdx_quote(quote, raw_bytes)
    except TdxVerificationError as e:
        raise TdxAttestationError(f"TDX quote verification failed: {e}") from e

    # Step 4: Policy validation (mirrors Go's validate.TdxQuote)
    if config.policy_options is not None:
        policy_options = config.policy_options
    else:
        policy_options = PolicyOptions(
            header=HeaderOptions(
                qe_vendor_id=INTEL_QE_VENDOR_ID,
            ),
            td_quote_body=TdQuoteBodyOptions(
                minimum_tee_tcb_svn=config.expected_minimum_tee_tcb_svn,
                td_attributes=config.expected_td_attributes,
                xfam=config.expected_xfam,
                mr_config_id=b'\x00' * MR_CONFIG_ID_SIZE,
                mr_owner=b'\x00' * MR_OWNER_SIZE,
                mr_owner_config=b'\x00' * MR_OWNER_CONFIG_SIZE,
                any_mr_seam=config.accepted_mr_seams,
            ),
        )

    try:
        validate_tdx_policy(quote, policy_options)
    except TdxValidationError as e:
        raise TdxAttestationError(f"Policy validation failed: {e}") from e

    # Step 5: Validate collateral (PCK extensions, TCB status, QE identity, revocation)
    try:
        collateral_result = validate_collateral(
            quote=quote,
            pck_chain=pck_chain,
            min_tcb_evaluation_data_number=config.min_tcb_evaluation_data_number,
        )
    except CollateralError as e:
        raise TdxAttestationError(f"Collateral validation failed: {e}") from e

    # Step 6: Extract measurements and report data
    measurements = quote.td_quote_body.get_measurements()
    measurements_hex = [m.hex() for m in measurements]

    report_data = quote.td_quote_body.report_data
    required_len = TLS_KEY_FP_SIZE + HPKE_KEY_SIZE
    if len(report_data) < required_len:
        raise TdxAttestationError(
            f"report_data too short: {len(report_data)} bytes, need at least {required_len}"
        )
    tls_key_fp = report_data[0:TLS_KEY_FP_SIZE].hex()
    hpke_public_key = report_data[TLS_KEY_FP_SIZE:TLS_KEY_FP_SIZE + HPKE_KEY_SIZE].hex()

    return TdxAttestationResult(
        quote=quote,
        pck_chain=pck_chain,
        pck_extensions=collateral_result.pck_extensions,
        collateral=collateral_result.collateral,
        tcb_level=collateral_result.tcb_level,
        measurements=measurements_hex,
        tls_key_fp=tls_key_fp,
        hpke_public_key=hpke_public_key,
    )


def verify_tdx_attestation_v2(attestation_doc: str) -> Verification:
    """
    Verify TDX attestation document (v2 format) and return verification result.

    v2 format: report_data contains TLS key fingerprint (32 bytes) + HPKE public key (32 bytes).

    Args:
        attestation_doc: Base64-encoded, gzip-compressed TDX quote

    Returns:
        Verification containing measurements, public key fingerprint, and HPKE public key

    Raises:
        ValueError: If verification fails
    """
    try:
        result = verify_tdx_attestation(attestation_doc, is_compressed=True)
    except TdxAttestationError as e:
        raise ValueError(f"TDX attestation verification failed: {e}") from e

    measurement = Measurement(
        type=PredicateType.TDX_GUEST_V2,
        registers=result.measurements,
    )

    return Verification(
        measurement=measurement,
        public_key_fp=result.tls_key_fp,
        hpke_public_key=result.hpke_public_key,
    )


def verify_tdx_hardware(
    hardware_measurements: list[HardwareMeasurement],
    enclave_measurement: Measurement,
) -> HardwareMeasurement:
    """
    Verify that the enclave's MRTD and RTMR0 match a known hardware platform.

    Args:
        hardware_measurements: List of known-good hardware measurements from Sigstore
        enclave_measurement: The measurement from the TDX enclave attestation

    Returns:
        The matching HardwareMeasurement

    Raises:
        HardwareMeasurementError: If no matching hardware platform is found
        ValueError: If enclave measurement is invalid
    """
    if enclave_measurement is None:
        raise ValueError("enclave measurement is None")

    if enclave_measurement.type != PredicateType.TDX_GUEST_V2:
        raise ValueError(f"unsupported enclave platform: {enclave_measurement.type}")

    if len(enclave_measurement.registers) != TDX_REGISTER_COUNT:
        raise ValueError(f"expected {TDX_REGISTER_COUNT} TDX registers, got {len(enclave_measurement.registers)}")

    enclave_mrtd = enclave_measurement.registers[TDX_MRTD_IDX]
    enclave_rtmr0 = enclave_measurement.registers[TDX_RTMR0_IDX]

    for hw in hardware_measurements:
        if hw.mrtd == enclave_mrtd and hw.rtmr0 == enclave_rtmr0:
            return hw

    raise HardwareMeasurementError("no matching hardware platform found")
