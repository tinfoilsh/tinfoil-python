import http.client
import json
import ssl
import urllib.request
import httpx
import random
from dataclasses import dataclass
from typing import Dict, Optional
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
        return self.do_open(self._get_connection, req)

    def _get_connection(self, host, timeout=None):
        """Create an HTTPS connection with certificate verification"""
        conn = http.client.HTTPSConnection(host, timeout=timeout)
        conn.connect()
        
        if not conn.sock:
            raise ValueError("No TLS connection")
        
        cert_binary = conn.sock.getpeercert(binary_form=True)
        if not cert_binary:
            raise ValueError("No valid certificate")
        
        # Parse the certificate using cryptography
        cert = cryptography.x509.load_der_x509_certificate(cert_binary)
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
    
    def __init__(self, enclave: str = "", repo: str = "tinfoilsh/confidential-model-router", measurement: Optional[dict] = None):
        # Hardcoded measurement takes precedence over repo
        if measurement is not None:
            repo = ""

        # Ensure at least one verification method is provided
        if measurement is None and (repo == "" or repo is None):
            raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")

        # If enclave is empty, fetch a random one from the routers API
        if enclave == "" or enclave is None:
            enclave = get_router_address()

        self.enclave = enclave
        self.repo = repo
        self.measurement = measurement
        self._ground_truth: Optional[GroundTruth] = None

    @property
    def ground_truth(self) -> Optional[GroundTruth]:
        """Returns the last verified enclave state"""
        return self._ground_truth

    def make_secure_http_client(self) -> httpx.Client:
        """
        Build an httpx.Client that pins the enclave's TLS cert
        """
        expected_fp = self.verify().public_key
        wrap_socket = self._create_socket_wrapper(expected_fp)

        ctx = ssl.create_default_context()
        ctx.wrap_socket = wrap_socket
        return httpx.Client(verify=ctx, follow_redirects=True)

    def _create_socket_wrapper(self, expected_fp: str):
        """
        Creates a socket wrapper function that verifies the certificate's public key fingerprint
        matches the expected fingerprint.
        """
        def wrap_socket(*args, **kwargs) -> ssl.SSLSocket:
            sock = ssl.create_default_context().wrap_socket(*args, **kwargs)
            cert_binary = sock.getpeercert(binary_form=True)
            if not cert_binary:
                raise Exception("No certificate found")
            cert = cryptography.x509.load_der_x509_certificate(cert_binary)
            pub_der = cert.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            pk_fp = hashlib.sha256(pub_der).hexdigest()
            if pk_fp != expected_fp:
                raise Exception(f"Certificate fingerprint mismatch: expected {expected_fp}, got {pk_fp}")
            return sock
        return wrap_socket

    def make_secure_async_http_client(self) -> httpx.AsyncClient:
        """
        Build an httpx.AsyncClient that pins the enclave's TLS cert.
        """
        expected_fp = self.verify().public_key
        wrap_socket = self._create_socket_wrapper(expected_fp)

        ctx = ssl.create_default_context()
        ctx.wrap_socket = wrap_socket
        return httpx.AsyncClient(verify=ctx, follow_redirects=True)

    def verify(self) -> GroundTruth:
        """
        Fetches the latest verification information from GitHub and Sigstore
        and stores the ground truth results in the client
        """

        enclave_attestation = fetch_attestation(self.enclave)
        verification = enclave_attestation.verify()

        if self.measurement is not None:
            # Use provided measurement directly
            # Verify the SNP measurement matches the provided one
            expected_snp_measurement = self.measurement.get("snp_measurement")
            if expected_snp_measurement is None:
                raise ValueError("snp_measurement not found in provided measurement")
            
            # Get the actual measurement from the attestation
            actual_measurement = verification.measurement.registers[0]  # SNP measurement is the first register
            
            if actual_measurement != expected_snp_measurement:
                raise ValueError(f"SNP measurement mismatch: expected {expected_snp_measurement}, got {actual_measurement}")
            
            # Build ground truth from the verified attestation
            self._ground_truth = GroundTruth(
                public_key=verification.public_key_fp,
                digest="pinned_no_digest",  # No digest when using direct measurement
                measurement=verification.measurement
            )
            return self._ground_truth
        else:
            # GitHub-based verification
            digest = fetch_latest_digest(self.repo)
            sigstore_bundle = fetch_attestation_bundle(self.repo, digest)
            
            code_measurements = verify_attestation(
                sigstore_bundle, 
                digest, 
                self.repo
            )
            
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

    def get_http_client(self) -> urllib.request.OpenerDirector:
        """Returns an HTTP client that only accepts TLS connections to the verified enclave"""
        if not self._ground_truth:
            self._ground_truth = self.verify()
        
        handler = TLSBoundHTTPSHandler(self._ground_truth.public_key)
        return urllib.request.build_opener(handler)

    def make_request(self, req: urllib.request.Request) -> Response:
        """Makes an HTTP request using the secure client"""
        client = self.get_http_client()
        
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
        return self.make_request(req)

    def get(self, url: str, headers: Dict[str, str] = {}) -> Response:
        """Makes an HTTP GET request"""
        req = urllib.request.Request(
            url,
            headers=headers,
            method="GET"
        )
        return self.make_request(req)

def get_router_address() -> str:
    """
    Fetches the list of available routers from the ATC API
    and returns a randomly selected address.
    """

    routers_url = "https://atc.tinfoil.sh/routers?platform=snp"

    with urllib.request.urlopen(routers_url) as response:
        routers = json.loads(response.read().decode('utf-8'))
        if len(routers) == 0:
            raise ValueError("No routers found in the response")
        
        return random.choice(routers)
