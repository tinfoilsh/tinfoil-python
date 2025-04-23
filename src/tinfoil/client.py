import http.client
import json
import ssl
import urllib.request
import socket
from dataclasses import dataclass
from typing import Dict, Optional, List
from urllib.parse import urlparse
import cryptography.x509
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
import hashlib

from .attestation import fetch_attestation
from .github import fetch_latest_digest, fetch_attestation_bundle
from .sigstore import verify_attestation


@dataclass
class GroundTruth:
    """Represents the "known good" verified state of the enclave"""
    public_key: str  # Changed from cert_fingerprint to public_key
    digest: str
    measurement: str


class Response:
    """Represents an HTTP response"""
    def __init__(self, status: str, status_code: int, body: bytes):
        self.status = status
        self.status_code = status_code
        self.body = body


class TLSBoundHTTPSHandler(urllib.request.HTTPSHandler):
    """Custom HTTPS handler that verifies certificate public keys"""
    
    def __init__(self, expected_pubkey: str):
        super().__init__()
        self.expected_pubkey = expected_pubkey

    def https_open(self, req):
        return self.do_open(self._create_connection, req)

    def _create_connection(self, host, **kwargs):
        conn = super().do_open(http.client.HTTPSConnection, host, **kwargs)
        if not conn.sock:
            raise ValueError("No TLS connection")
        
        cert = conn.sock.getpeercert(binary_form=True)
        if not cert:
            raise ValueError("No valid certificate")
        
        public_key = cert.public_key()
        # Get the public key in PKIX/DER format
        public_key_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        # Hash the public key
        cert_fp = hashlib.sha256(public_key_der).hexdigest()

        if cert_fp != self.expected_pubkey:
            raise ValueError(f"Certificate public key fingerprint mismatch: expected {self.expected_pubkey}, got {cert_fp}")
        
        return conn


class SecureClient:
    """A client that verifies and communicates with secure enclaves"""
    
    def __init__(self, enclave: str, repo: str):
        self.enclave = enclave
        self.repo = repo
        self._ground_truth: Optional[GroundTruth] = None

    @property
    def ground_truth(self) -> Optional[GroundTruth]:
        """Returns the last verified enclave state"""
        return self._ground_truth

    def verify(self) -> GroundTruth:
        """
        Fetches the latest verification information from GitHub and Sigstore
        and stores the ground truth results in the client
        """
        try:
            # Fetch and verify all required information
            digest = fetch_latest_digest(self.repo)
            sigstore_bundle = fetch_attestation_bundle(self.repo, digest)
            
            code_measurements = verify_attestation(
                sigstore_bundle, 
                digest, 
                self.repo
            )
            
            enclave_attestation = fetch_attestation(self.enclave)
            verification = enclave_attestation.verify()
            
            # Verify measurements match
            for (i, code_measurement) in enumerate(code_measurements.registers):
                if code_measurement != verification.measurement.registers[i]:
                    raise ValueError("Code measurements do not match")

            # Build ground truth from the verified attestation
            self._ground_truth = GroundTruth(
                public_key=verification.public_key_fp,
                digest=digest,
                measurement=verification.measurement
            )
            return self._ground_truth
        
        except Exception as e:
            raise e

    def _get_http_client(self) -> urllib.request.OpenerDirector:
        """Returns an HTTP client that only accepts TLS connections to the verified enclave"""
        if not self._ground_truth:
            ground_truth, err = self.verify()
            if err:
                raise err
            if not ground_truth:
                raise ValueError("Failed to verify enclave")
        
        handler = TLSBoundHTTPSHandler(self._ground_truth.public_key)
        return urllib.request.build_opener(handler)

    def _make_request(self, req: urllib.request.Request) -> Response:
        """Makes an HTTP request using the secure client"""
        client = self._get_http_client()
        
        # If URL doesn't have a host, assume it's relative to the enclave
        if not urlparse(req.full_url).netloc:
            req.full_url = f"https://{self.enclave}{req.full_url}"
        
        with client.open(req) as resp:
            return Response(
                status=f"{resp.status} {resp.reason}",
                status_code=resp.status,
                body=resp.read()
            )

    def post(self, url: str, headers: Dict[str, str], body: bytes) -> Response:
        """Makes an HTTP POST request"""
        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method="POST"
        )
        return self._make_request(req)

    def get(self, url: str, headers: Dict[str, str]) -> Response:
        """Makes an HTTP GET request"""
        req = urllib.request.Request(
            url,
            headers=headers,
            method="GET"
        )
        return self._make_request(req)
