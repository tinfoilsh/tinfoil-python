import asyncio
import contextlib
import http.client
import json
import ssl
import threading
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


_CERTIFICATE_VERIFY_ERROR_MARKERS = (
    "certificate_verify_failed",
    "certificate verify failed",
)


class _PinMismatchError(ValueError):
    """
    Raised when the enclave's TLS certificate fails our pin check (wrong
    public-key fingerprint, missing cert, or no TLS connection).

    Subclasses ValueError so existing callers that do `except ValueError`
    keep working; existence as a distinct type lets `_is_certificate_error`
    detect pin failures via `isinstance` instead of string-matching.
    """


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
        raise _PinMismatchError("No certificate found")
    cert = cryptography.x509.load_der_x509_certificate(cert_binary)
    pub_der = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    pk_fp = hashlib.sha256(pub_der).hexdigest()
    if pk_fp != expected_fp:
        raise _PinMismatchError(f"Certificate fingerprint mismatch: expected {expected_fp}, got {pk_fp}")


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
            raise _PinMismatchError("No TLS connection")
        
        _verify_peer_fingerprint(
            conn.sock.getpeercert(binary_form=True), self.expected_pubkey
        )
        
        return conn


def _is_certificate_error(exc: BaseException) -> bool:
    """
    Detect whether an exception originated from TLS certificate verification,
    including the fingerprint pin check raised by `_verify_peer_fingerprint`.

    Only certificate verification and pinning failures are safe to use as a
    re-verification signal: they happen while establishing the connection,
    before HTTP request bytes are sent. Generic ssl.SSLError instances can occur
    later during request/response I/O and must not be retried automatically.
    """
    current: Optional[BaseException] = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))

        if isinstance(current, _PinMismatchError):
            return True

        if isinstance(current, ssl.SSLCertVerificationError):
            return True

        if isinstance(current, ssl.SSLError):
            msg = str(current).lower()
            if any(marker in msg for marker in _CERTIFICATE_VERIFY_ERROR_MARKERS):
                return True

        # httpx wraps low-level errors; walk the cause/context chain.
        current = current.__cause__ or current.__context__
    return False


class _ReVerifyingTransport(httpx.BaseTransport):
    """
    Wraps an httpx transport and transparently re-verifies the enclave's
    attestation when a TLS certificate error is encountered.

    This makes long-lived `TinfoilAI` / `SecureClient` instances resilient to
    server certificate rotation (for example, after an enclave or router
    restart), mirroring the behaviour of the Go and JavaScript SDKs.
    """

    def __init__(self, secure_client: "SecureClient", inner: httpx.BaseTransport):
        self._secure_client = secure_client
        self._inner = inner
        self._lock = threading.Lock()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        inner = self._inner
        try:
            return inner.handle_request(request)
        except Exception as exc:
            if not _is_certificate_error(exc):
                raise

            old_inner: Optional[httpx.BaseTransport] = None
            retry_inner: Optional[httpx.BaseTransport] = None
            reverify_failed = False
            with self._lock:
                if self._inner is inner:
                    try:
                        retry_inner = self._secure_client._rebuild_sync_transport()
                    except Exception:
                        # Re-verification failed; surface the original error so
                        # the caller sees the genuine TLS failure rather than a
                        # confusing re-verification failure.
                        reverify_failed = True
                    else:
                        old_inner = self._inner
                        self._inner = retry_inner
                else:
                    retry_inner = self._inner

            if reverify_failed:
                raise

            assert retry_inner is not None
            try:
                return retry_inner.handle_request(request)
            finally:
                if old_inner is not None:
                    with contextlib.suppress(Exception):
                        old_inner.close()

    def close(self) -> None:
        self._inner.close()


class _AsyncReVerifyingTransport(httpx.AsyncBaseTransport):
    """Async counterpart to :class:`_ReVerifyingTransport`."""

    def __init__(self, secure_client: "SecureClient", inner: httpx.AsyncBaseTransport):
        self._secure_client = secure_client
        self._inner = inner
        self._lock = asyncio.Lock()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        inner = self._inner
        try:
            return await inner.handle_async_request(request)
        except Exception as exc:
            if not _is_certificate_error(exc):
                raise

            old_inner: Optional[httpx.AsyncBaseTransport] = None
            retry_inner: Optional[httpx.AsyncBaseTransport] = None
            reverify_failed = False
            async with self._lock:
                if self._inner is inner:
                    try:
                        retry_inner = await self._secure_client._rebuild_async_transport()
                    except Exception:
                        reverify_failed = True
                    else:
                        old_inner = self._inner
                        self._inner = retry_inner
                else:
                    retry_inner = self._inner

            if reverify_failed:
                raise

            assert retry_inner is not None
            try:
                return await retry_inner.handle_async_request(request)
            finally:
                if old_inner is not None:
                    with contextlib.suppress(Exception):
                        await old_inner.aclose()

    async def aclose(self) -> None:
        await self._inner.aclose()


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

    def _build_sync_ssl_context(self, expected_fp: str) -> ssl.SSLContext:
        wrap_socket = self._create_socket_wrapper(expected_fp)
        ctx = ssl.create_default_context()
        ctx.wrap_socket = wrap_socket
        return ctx

    def _build_async_ssl_context(self, expected_fp: str) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.wrap_bio = self._create_bio_wrapper(ctx.wrap_bio, expected_fp)
        return ctx

    def _rebuild_sync_transport(self) -> httpx.BaseTransport:
        """Re-run attestation and return a fresh sync httpx transport."""
        expected_fp = self.verify().public_key
        ctx = self._build_sync_ssl_context(expected_fp)
        return httpx.HTTPTransport(verify=ctx)

    async def _rebuild_async_transport(self) -> httpx.AsyncBaseTransport:
        """Re-run attestation without blocking the event loop."""
        expected_fp = (await asyncio.to_thread(self.verify)).public_key
        ctx = self._build_async_ssl_context(expected_fp)
        return httpx.AsyncHTTPTransport(verify=ctx)

    def make_secure_http_client(self) -> httpx.Client:
        """
        Build an httpx.Client that pins the enclave's TLS cert.

        The returned client is suitable for long-lived use: if the enclave
        rotates its TLS certificate (for example after a server-side restart),
        the underlying transport will automatically re-verify attestation and
        retry the request once.
        """
        expected_fp = self.verify().public_key
        ctx = self._build_sync_ssl_context(expected_fp)
        inner = httpx.HTTPTransport(verify=ctx)
        transport = _ReVerifyingTransport(self, inner)
        return httpx.Client(transport=transport, follow_redirects=True)

    def make_secure_async_http_client(self) -> httpx.AsyncClient:
        """
        Build an httpx.AsyncClient that pins the enclave's TLS cert.

        The returned client is suitable for long-lived use: if the enclave
        rotates its TLS certificate (for example after a server-side restart),
        the underlying transport will automatically re-verify attestation and
        retry the request once.
        """
        expected_fp = self.verify().public_key
        ctx = self._build_async_ssl_context(expected_fp)
        inner = httpx.AsyncHTTPTransport(verify=ctx)
        transport = _AsyncReVerifyingTransport(self, inner)
        return httpx.AsyncClient(transport=transport, follow_redirects=True)

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
