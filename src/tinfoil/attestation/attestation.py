from dataclasses import dataclass
from enum import Enum
import json

import base64
import hashlib
import ssl
from typing import List, Optional
from urllib.parse import urlparse, urlunparse
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .verify import Report, verify_attestation, CertificateChain

class PredicateType(str, Enum):
    """Predicate types for attestation"""
    AWS_NITRO_ENCLAVE_V1 = "https://tinfoil.sh/predicate/aws-nitro-enclave/v1"
    SEV_GUEST_V1 = "https://tinfoil.sh/predicate/sev-snp-guest/v1"

ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation"

class AttestationError(Exception):
    """Base class for attestation errors"""
    pass

class FormatMismatchError(AttestationError):
    """Raised when attestation formats don't match"""
    pass

class MeasurementMismatchError(AttestationError):
    """Raised when measurements don't match"""
    pass

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
        Checks if this measurement equals another measurement
        Raises appropriate error if they don't match
        """
        if self.type != other.type:
            raise FormatMismatchError()
        if len(self.registers) != len(other.registers) or self.registers != other.registers:
            raise MeasurementMismatchError()

@dataclass
class Verification:
    """Represents verification results"""
    measurement: Measurement
    public_key_fp: str

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
        if self.format == PredicateType.SEV_GUEST_V1:
            return verify_sev_attestation(self.body)
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

def verify_sev_attestation(attestation_doc: str) -> Verification:
    """Verify SEV attestation document and return verification result."""
    try:
        att_doc_bytes = base64.b64decode(attestation_doc)
    except Exception as e:
        raise ValueError(f"Failed to decode base64: {e}")
    
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
    
    if res!= True:
        raise ValueError("Attestation verification failed!")

    # Create measurement object
    measurement = Measurement(
        type=PredicateType.SEV_GUEST_V1,
        registers=[
            report.measurement.hex()
        ]
    )

    # The public key fingerprint is at the start of the report (32 bytes)
    kfp = report.report_data.decode()

    return Verification(
        measurement=measurement,
        public_key_fp=kfp
    )