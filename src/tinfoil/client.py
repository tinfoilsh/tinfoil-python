import http.client
import json
import ssl
import urllib.error
import urllib.request
import httpx
import random
from dataclasses import dataclass, field
from typing import Dict, Literal, Optional
from urllib.parse import urlparse, urlencode
import cryptography.x509
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
import hashlib

from .attestation import fetch_attestation, TDX_TYPES
from .attestation.attestation_tdx import verify_tdx_hardware
from .attestation.types import Measurement, HardwareMeasurement, Verification
from .github import fetch_latest_digest, fetch_attestation_bundle
from .sigstore import verify_attestation, fetch_latest_hardware_measurements


@dataclass
class GroundTruth:
    """Represents the "known good" verified state of the enclave"""
    public_key: str  # Changed from cert_fingerprint to public_key
    digest: str
    measurement: str


@dataclass
class VerificationStepState:
    """Represents the state of a single verification step"""
    status: Literal["pending", "success", "failed", "skipped"]
    error: Optional[str] = None


@dataclass
class VerificationDocument:
    """Captures the full result and per-step status of enclave verification"""
    config_repo: str = ""
    enclave_host: str = ""
    release_digest: str = ""
    code_measurement: Optional[Measurement] = None
    enclave_measurement: Optional[Verification] = None
    tls_public_key: str = ""
    hpke_public_key: str = ""
    hardware_measurement: Optional[HardwareMeasurement] = None
    code_fingerprint: str = ""
    enclave_fingerprint: str = ""
    selected_router_endpoint: str = ""
    security_verified: bool = False
    steps: Dict[str, VerificationStepState] = field(default_factory=lambda: {
        "fetch_digest": VerificationStepState(status="pending"),
        "verify_code": VerificationStepState(status="pending"),
        "verify_enclave": VerificationStepState(status="pending"),
        "compare_measurements": VerificationStepState(status="pending"),
    })


def _attach_verification_document(exc: Exception, verification_document: VerificationDocument) -> None:
    try:
        setattr(exc, "verification_document", verification_document)
    except Exception:
        pass


class Response:
    """Represents an HTTP response"""
    def __init__(self, status: str, status_code: int, body: bytes):
        self.status = status
        self.status_code = status_code
        self.body = body


def _verify_peer_fingerprint(cert_binary: Optional[bytes], expected_fp: str) -> None:
    """Verify that a certificate's public key fingerprint matches the expected value."""
    if not cert_binary:
        raise ValueError("No certificate found")
    cert = cryptography.x509.load_der_x509_certificate(cert_binary)
    pub_der = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    pk_fp = hashlib.sha256(pub_der).hexdigest()
    if pk_fp != expected_fp:
        raise ValueError(f"Certificate fingerprint mismatch: expected {expected_fp}, got {pk_fp}")


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
        
        _verify_peer_fingerprint(
            conn.sock.getpeercert(binary_form=True), self.expected_pubkey
        )
        
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
        self._verification_document: Optional[VerificationDocument] = None

    @property
    def ground_truth(self) -> Optional[GroundTruth]:
        """Returns the last verified enclave state"""
        return self._ground_truth

    def get_verification_document(self) -> Optional[VerificationDocument]:
        """Returns the detailed verification document from the last verify() call"""
        return self._verification_document

    def _create_socket_wrapper(self, expected_fp: str):
        """
        Creates a socket wrapper function that verifies the certificate's public key fingerprint
        matches the expected fingerprint.
        """
        def wrap_socket(*args, **kwargs) -> ssl.SSLSocket:
            sock = ssl.create_default_context().wrap_socket(*args, **kwargs)
            _verify_peer_fingerprint(
                sock.getpeercert(binary_form=True), expected_fp
            )
            return sock
        return wrap_socket

    def _create_bio_wrapper(self, original_wrap_bio, expected_fp: str):
        """
        Creates a wrap_bio replacement that verifies the certificate's public key fingerprint
        after the TLS handshake completes.
        """
        def pinned_wrap_bio(*args, **kwargs):
            ssl_object = original_wrap_bio(*args, **kwargs)
            original_do_handshake = ssl_object.do_handshake

            def checked_do_handshake():
                result = original_do_handshake()
                _verify_peer_fingerprint(
                    ssl_object.getpeercert(binary_form=True), expected_fp
                )
                return result

            ssl_object.do_handshake = checked_do_handshake
            return ssl_object
        return pinned_wrap_bio

    def make_secure_http_client(self) -> httpx.Client:
        """
        Build an httpx.Client that pins the enclave's TLS cert
        """
        expected_fp = self.verify().public_key
        wrap_socket = self._create_socket_wrapper(expected_fp)

        ctx = ssl.create_default_context()
        ctx.wrap_socket = wrap_socket
        return httpx.Client(verify=ctx, follow_redirects=True)

    def make_secure_async_http_client(self) -> httpx.AsyncClient:
        """
        Build an httpx.AsyncClient that pins the enclave's TLS cert
        """
        expected_fp = self.verify().public_key

        ctx = ssl.create_default_context()
        ctx.wrap_bio = self._create_bio_wrapper(ctx.wrap_bio, expected_fp)
        return httpx.AsyncClient(verify=ctx, follow_redirects=True)

    def verify(self) -> GroundTruth:
        """
        Fetches the latest verification information from GitHub and Sigstore
        and stores the ground truth results in the client.

        Also populates the verification document with per-step status.
        """
        doc = VerificationDocument(
            config_repo=self.repo or "",
            enclave_host=self.enclave,
            selected_router_endpoint=self.enclave,
        )
        self._verification_document = doc

        # Step 1: Verify enclave (fetch attestation, verify cryptographically, verify hardware)
        try:
            enclave_attestation = fetch_attestation(self.enclave)
            verification = enclave_attestation.verify()

            # For TDX, also verify hardware measurements
            if verification.measurement.type in TDX_TYPES and self.measurement is None:
                hw_measurements = fetch_latest_hardware_measurements()
                doc.hardware_measurement = verify_tdx_hardware(hw_measurements, verification.measurement)

            doc.enclave_measurement = verification
            doc.tls_public_key = verification.public_key_fp
            doc.hpke_public_key = verification.hpke_public_key or ""
            doc.enclave_fingerprint = verification.measurement.fingerprint()
            doc.steps["verify_enclave"] = VerificationStepState(status="success")
        except Exception as e:
            doc.steps["verify_enclave"] = VerificationStepState(status="failed", error=str(e))
            _attach_verification_document(e, doc)
            raise

        if self.measurement is not None:
            # Pinned measurement mode — code steps not applicable
            doc.steps["fetch_digest"] = VerificationStepState(status="skipped")
            doc.steps["verify_code"] = VerificationStepState(status="skipped")

            try:
                expected_snp_measurement = self.measurement.get("snp_measurement")
                if expected_snp_measurement is None:
                    raise ValueError("snp_measurement not found in provided measurement")
                if not verification.measurement.registers:
                    raise ValueError("No measurement registers found in attestation")
                actual_measurement = verification.measurement.registers[0]
                if actual_measurement != expected_snp_measurement:
                    raise ValueError(f"SNP measurement mismatch: expected {expected_snp_measurement}, got {actual_measurement}")
                doc.steps["compare_measurements"] = VerificationStepState(status="success")
            except Exception as e:
                doc.steps["compare_measurements"] = VerificationStepState(status="failed", error=str(e))
                _attach_verification_document(e, doc)
                raise

            doc.release_digest = "pinned_no_digest"
            doc.security_verified = True
            self._ground_truth = GroundTruth(
                public_key=verification.public_key_fp,
                digest="pinned_no_digest",
                measurement=verification.measurement,
            )
            return self._ground_truth
        else:
            # GitHub-based verification

            # Step 2: Fetch release digest
            try:
                digest = fetch_latest_digest(self.repo)
                doc.release_digest = digest
                doc.steps["fetch_digest"] = VerificationStepState(status="success")
            except Exception as e:
                doc.steps["fetch_digest"] = VerificationStepState(status="failed", error=str(e))
                _attach_verification_document(e, doc)
                raise

            # Step 3: Verify code via Sigstore
            try:
                sigstore_bundle = fetch_attestation_bundle(self.repo, digest)
                code_measurements = verify_attestation(sigstore_bundle, digest, self.repo)
                doc.code_measurement = code_measurements
                doc.code_fingerprint = code_measurements.fingerprint()
                doc.steps["verify_code"] = VerificationStepState(status="success")
            except Exception as e:
                doc.steps["verify_code"] = VerificationStepState(status="failed", error=str(e))
                _attach_verification_document(e, doc)
                raise

            # Step 4: Compare code and enclave measurements
            try:
                code_measurements.assert_equal(verification.measurement)
                doc.steps["compare_measurements"] = VerificationStepState(status="success")
            except Exception as e:
                doc.steps["compare_measurements"] = VerificationStepState(status="failed", error=str(e))
                _attach_verification_document(e, doc)
                raise

            doc.security_verified = True
            self._ground_truth = GroundTruth(
                public_key=verification.public_key_fp,
                digest=digest,
                measurement=verification.measurement,
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

def get_router_address(platform: Optional[str] = None) -> str:
    """
    Fetches the list of available routers from the ATC API
    and returns a randomly selected address.

    Args:
        platform: Optional platform filter (e.g. "snp", "tdx").
                  If None, returns routers for any platform.
    """
    routers_url = "https://atc.tinfoil.sh/routers"
    if platform:
        routers_url += "?" + urlencode({"platform": platform})

    try:
        with urllib.request.urlopen(routers_url, timeout=15) as response:
            routers = json.loads(response.read().decode('utf-8'))
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to fetch router addresses: {e}") from e

    if not isinstance(routers, list) or len(routers) == 0:
        raise ValueError("No routers found in the response")

    return random.choice(routers)
