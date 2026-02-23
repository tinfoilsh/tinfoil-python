import hashlib
import json
import ssl
from dataclasses import dataclass

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .types import (
    PredicateType,
    Measurement,
    Verification,
)
from .attestation_tdx import verify_tdx_attestation_v2
from .attestation_sev import verify_sev_attestation_v2

ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation"
REQUEST_TIMEOUT_SECONDS = 15


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
        elif self.format == PredicateType.TDX_GUEST_V2:
            return verify_tdx_attestation_v2(self.body)
        else:
            raise ValueError(f"Unsupported attestation format: {self.format}")

def verify_attestation_json(json_data: bytes) -> Verification:
    """Verifies an attestation document in JSON format and returns the inner measurements"""
    try:
        doc_dict = json.loads(json_data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid attestation JSON: {e}") from e

    if not isinstance(doc_dict, dict) or "format" not in doc_dict or "body" not in doc_dict:
        raise ValueError("Attestation JSON must contain 'format' and 'body' fields")

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
    response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    
    doc_dict = response.json()
    if not isinstance(doc_dict, dict) or "format" not in doc_dict or "body" not in doc_dict:
        raise ValueError(f"Invalid attestation response from {host}: missing 'format' or 'body'")

    return Document(
        format=PredicateType(doc_dict["format"]),
        body=doc_dict["body"]
    )
