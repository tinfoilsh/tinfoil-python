from dataclasses import dataclass
from enum import Enum
import json

import base64
import gzip
import hashlib
import ssl
from typing import List, Optional
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .validate import validate_report, ValidationOptions
from .verify import Report, verify_attestation, CertificateChain
from .abi_sevsnp import TCBParts, SnpPolicy, SnpPlatformInfo
from .validate_tdx import verify_tdx_attestation, TdxValidationError


class PredicateType(str, Enum):
    """Predicate types for attestation"""
    SEV_GUEST_V1 = "https://tinfoil.sh/predicate/sev-snp-guest/v1"  # Deprecated
    SEV_GUEST_V2 = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
    TDX_GUEST_V1 = "https://tinfoil.sh/predicate/tdx-guest/v1"  # Deprecated
    TDX_GUEST_V2 = "https://tinfoil.sh/predicate/tdx-guest/v2"
    SNP_TDX_MULTIPLATFORM_v1 = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
    HARDWARE_MEASUREMENTS_V1 = "https://tinfoil.sh/predicate/hardware-measurements/v1"

ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation"

# RTMR3 should always be zeros (48 bytes = 96 hex chars)
RTMR3_ZERO = "0" * 96

class AttestationError(Exception):
    """Base class for attestation errors"""
    pass

class FormatMismatchError(AttestationError):
    """Raised when attestation formats don't match"""
    pass

class MeasurementMismatchError(AttestationError):
    """Raised when measurements don't match"""
    pass

class Rtmr3NotZeroError(AttestationError):
    """Raised when RTMR3 is not zeros"""
    pass

class HardwareMeasurementError(AttestationError):
    """Raised when hardware measurement verification fails"""
    pass

@dataclass
class HardwareMeasurement:
    """Represents hardware platform measurements (MRTD and RTMR0 for TDX)"""
    id: str  # platform@digest
    mrtd: str
    rtmr0: str

@dataclass
class Measurement:
    """Represents measurement data"""
    type: PredicateType
    registers: List[str]

    def fingerprint(self) -> str:
        """
        Computes the SHA-256 hash of all measurements, 
        or returns the single measurement if there is only one
        """
        if len(self.registers) == 1:
            return self.registers[0]

        all_data = str(self.type) + "".join(self.registers)
        return hashlib.sha256(all_data.encode()).hexdigest()

    def equals(self, other: 'Measurement') -> None:
        """
        Checks if this measurement equals another measurement with multi-platform support
        Raises appropriate error if they don't match
        """
        # Direct comparison for same types
        if self.type == other.type:
            if len(self.registers) != len(other.registers) or self.registers != other.registers:
                raise MeasurementMismatchError()
            return

        # TDX v1 and v2 are equivalent for measurement comparison
        tdx_types = (PredicateType.TDX_GUEST_V1, PredicateType.TDX_GUEST_V2)
        if self.type in tdx_types and other.type in tdx_types:
            if len(self.registers) != len(other.registers) or self.registers != other.registers:
                raise MeasurementMismatchError()
            return

        # Multi-platform comparison support
        if self.type == PredicateType.SNP_TDX_MULTIPLATFORM_v1:
            # Multi-platform format: [SNP_measurement, RTMR1, RTMR2]
            if other.type in tdx_types and len(other.registers) == 5:
                # Compare with TDX: check RTMR1 and RTMR2 (indices 2 and 3 in TDX)
                if (len(self.registers) != 3 or
                    self.registers[1] != other.registers[2] or
                    self.registers[2] != other.registers[3]):
                    raise MeasurementMismatchError()
                # Check RTMR3 is zeros
                if other.registers[4] != RTMR3_ZERO:
                    raise Rtmr3NotZeroError(f"RTMR3 must be zeros, got {other.registers[4]}")
                return
            elif other.type == PredicateType.SEV_GUEST_V2 and len(other.registers) == 1:
                # Compare with AMD: check SNP measurement
                if len(self.registers) != 3 or self.registers[0] != other.registers[0]:
                    raise MeasurementMismatchError()
                return

        # Reverse comparisons
        if other.type == PredicateType.SNP_TDX_MULTIPLATFORM_v1:
            # Delegate to the other measurement's equals method
            try:
                other.equals(self)
                return
            except (FormatMismatchError, MeasurementMismatchError):
                raise

        # If we get here, the formats are incompatible
        raise FormatMismatchError()
    
    def __str__(self) -> str:
        """Returns a human-readable string representation of the measurement"""
        if self.type == PredicateType.SEV_GUEST_V2 and len(self.registers) == 1:
            return f"Measurement(type={self.type.value}, snp_measurement={self.registers[0][:16]}...)"

        elif self.type in (PredicateType.TDX_GUEST_V1, PredicateType.TDX_GUEST_V2) and len(self.registers) == 5:
            labels = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
            parts = [f"{label}={reg[:16]}..." for label, reg in zip(labels, self.registers)]
            return f"Measurement(type={self.type.value}, {', '.join(parts)})"

        elif self.type == PredicateType.SNP_TDX_MULTIPLATFORM_v1 and len(self.registers) == 3:
            labels = ["snp_measurement", "rtmr1", "rtmr2"]
            parts = [f"{label}={reg[:16]}..." for label, reg in zip(labels, self.registers)]
            return f"Measurement(type={self.type.value}, {', '.join(parts)})"

        # Default representation for unknown formats
        return f"Measurement(type={self.type.value}, registers={len(self.registers)} items)"

@dataclass
class Verification:
    """Represents verification results"""
    measurement: Measurement
    public_key_fp: str
    hpke_public_key: Optional[str] = None


def verify_hardware(
    hardware_measurements: List[HardwareMeasurement],
    enclave_measurement: Measurement
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

    # Only TDX measurements have hardware-specific MRTD/RTMR0
    tdx_types = (PredicateType.TDX_GUEST_V1, PredicateType.TDX_GUEST_V2)
    if enclave_measurement.type not in tdx_types:
        raise ValueError(f"unsupported enclave platform: {enclave_measurement.type}")

    if len(enclave_measurement.registers) < 2:
        raise ValueError(f"enclave provided fewer registers than expected: {len(enclave_measurement.registers)}")

    enclave_mrtd = enclave_measurement.registers[0]
    enclave_rtmr0 = enclave_measurement.registers[1]

    for hw in hardware_measurements:
        if hw.mrtd == enclave_mrtd and hw.rtmr0 == enclave_rtmr0:
            return hw

    raise HardwareMeasurementError("no matching hardware platform found")


@dataclass
class Document:
    """Represents an attestation document"""
    format: PredicateType
    body: str

    def hash(self) -> str:
        """Returns the SHA-256 hash of the attestation document"""
        all_data = str(self.format) + self.body
        return hashlib.sha256(all_data.encode()).hexdigest()

    def verify(self) -> Verification:
        """
        Checks the attestation document against its trust root
        and returns the inner measurements
        """
        if self.format == PredicateType.SEV_GUEST_V2:
            return verify_sev_attestation_v2(self.body)
        elif self.format == PredicateType.TDX_GUEST_V1:
            return verify_tdx_attestation_v1(self.body)
        elif self.format == PredicateType.TDX_GUEST_V2:
            return verify_tdx_attestation_v2(self.body)
        else:
            raise ValueError(f"Unsupported attestation format: {self.format}")

def verify_attestation_json(json_data: bytes) -> Verification:
    """Verifies an attestation document in JSON format and returns the inner measurements"""
    doc_dict = json.loads(json_data)
    doc = Document(
        format=PredicateType(doc_dict["format"]),
        body=doc_dict["body"]
    )
    return doc.verify()

def key_fp(public_key: ec.EllipticCurvePublicKey) -> str:
    """Returns the fingerprint of a given ECDSA public key"""
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(key_bytes).hexdigest()

def cert_pubkey_fp(cert: x509.Certificate) -> str:
    """Returns the fingerprint of the public key of a given certificate"""
    pub_key = cert.public_key()
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise ValueError(f"Unsupported public key type: {type(pub_key)}")
    
    return key_fp(pub_key)

def connection_cert_fp(ssl_socket: ssl.SSLSocket) -> str:
    """Gets the KeyFP of the public key of a TLS connection"""
    cert_bin = ssl_socket.getpeercert(binary_form=True)
    if not cert_bin:
        raise ValueError("No peer certificates")
    
    cert = x509.load_der_x509_certificate(cert_bin)
    return cert_pubkey_fp(cert)

def fetch_attestation(host: str) -> Document:
    """Retrieves the attestation document from a given enclave hostname"""
    url = f"https://{host}{ATTESTATION_ENDPOINT}"
    response = requests.get(url)
    response.raise_for_status()
    
    doc_dict = response.json()
    return Document(
        format=PredicateType(doc_dict["format"]),
        body=doc_dict["body"]
    )

min_tcb = TCBParts(
    bl_spl=0x7,
    tee_spl=0,
    snp_spl=0xe,
    ucode_spl=0x48,
)

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
    permit_provisional_firmware=False,  # We only support False per your requirement
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

def verify_sev_attestation_v2(attestation_doc: str) -> Verification:
    """Verify SEV attestation document and return verification result."""
    report = verify_sev_report(attestation_doc, True)

    # Create measurement object
    measurement = Measurement(
        type=PredicateType.SEV_GUEST_V2,
        registers=[
            report.measurement.hex()
        ]
    )

    keys = report.report_data
    tls_key_fp = keys[0:32]
    hpke_public_key = keys[32:64]

    return Verification(
        measurement=measurement,
        public_key_fp=tls_key_fp.hex(),
        hpke_public_key=hpke_public_key.hex()
    )


def verify_tdx_attestation_v1(attestation_doc: str) -> Verification:
    """
    Verify TDX attestation document (v1 format) and return verification result.

    Args:
        attestation_doc: Base64-encoded, gzip-compressed TDX quote

    Returns:
        Verification containing measurements and public key fingerprint

    Raises:
        ValueError: If verification fails
    """
    try:
        result = verify_tdx_attestation(attestation_doc, is_compressed=True)
    except TdxValidationError as e:
        raise ValueError(f"TDX attestation verification failed: {e}")

    # Create measurement object with 5 TDX registers:
    # [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
    measurement = Measurement(
        type=PredicateType.TDX_GUEST_V1,
        registers=result.measurements,
    )

    return Verification(
        measurement=measurement,
        public_key_fp=result.tls_key_fp,
        hpke_public_key=result.hpke_public_key,
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
    except TdxValidationError as e:
        raise ValueError(f"TDX attestation verification failed: {e}")

    # Create measurement object with 5 TDX registers:
    # [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
    measurement = Measurement(
        type=PredicateType.TDX_GUEST_V2,
        registers=result.measurements,
    )

    return Verification(
        measurement=measurement,
        public_key_fp=result.tls_key_fp,
        hpke_public_key=result.hpke_public_key,
    )


def verify_sev_report(attestation_doc: str, is_compressed: bool) -> Report:
    """Verify SEV attestation document and return verification result."""
    try:
        att_doc_bytes = base64.b64decode(attestation_doc)
    except Exception as e:
        raise ValueError(f"Failed to decode base64: {e}")
    
    if is_compressed:
        att_doc_bytes = gzip.decompress(att_doc_bytes)

    # Parse the report
    try:
        report = Report(att_doc_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse report: {e}")
    
    # Get attestation chain
    chain: CertificateChain = CertificateChain.from_report(report)

    # Verify attestation
    try:
        res = verify_attestation(chain, report)
    except Exception as e:
        raise ValueError(f"Failed to verify attestation: {e}")

    if not res:
        raise ValueError("Attestation verification failed!")
    
    # Validate report
    try:
        validate_report(report, chain, default_validation_options)
    except Exception as e:
        raise ValueError(f"Failed to validate report: {e}")

    return report

def from_snp_digest(snp_digest: str) -> dict:
    """
    Convert an SNP launch digest string to measurement format.
    
    Args:
        snp_digest: The SNP launch digest as a hex string
        
    Returns:
        Dictionary in the format expected by SecureClient measurement parameter
        
    Example:
        from tinfoil.attestation import from_snp_digest
        measurement = from_snp_digest("abcdef")
        client = TinfoilAI(measurement=measurement)
    """
    return {
        "snp_measurement": snp_digest
    }
