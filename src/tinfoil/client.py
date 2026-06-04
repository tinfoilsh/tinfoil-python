import asyncio
import base64
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

from ehbp import (
    AsyncEHBPTransport,
    EHBPTransport,
    KeyConfigMismatchError,
)

from .attestation import (
    Bundle,
    fetch_attestation,
    fetch_bundle_from,
    verify_certificate,
    TDX_TYPES,
)
from .attestation.attestation_tdx import verify_tdx_hardware
from .attestation.types import Measurement, HardwareMeasurement, Verification
from .github import fetch_latest_digest, fetch_attestation_bundle
from .sigstore import verify_attestation, fetch_latest_hardware_measurements

# Header that tells a proxy which enclave to forward an encrypted request to, so
# the request reaches the same enclave the client verified.
ENCLAVE_URL_HEADER = "X-Tinfoil-Enclave-Url"

DEFAULT_CONFIG_REPO = "tinfoilsh/confidential-model-router"


_CERTIFICATE_VERIFY_ERROR_MARKERS = (
    "certificate_verify_failed",
    "certificate verify failed",
)

# Transport mode for secure communication with the enclave.
#
# - "ehbp" encrypts request bodies end-to-end with HPKE via the Encrypted HTTP
#   Body Protocol, so only the verified enclave can decrypt them. It works
#   through proxies and is the default.
# - "tls" pins the enclave's TLS certificate, which requires a direct connection.
TransportMode = Literal["ehbp", "tls"]
DEFAULT_TRANSPORT_MODE: TransportMode = "ehbp"


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
    hpke_public_key: str = ""


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


class _EHBPReVerifyingTransport(httpx.BaseTransport):
    """
    Wraps an EHBP transport and transparently re-verifies the enclave's
    attestation when the server rotates its HPKE key (surfaced as
    :class:`ehbp.KeyConfigMismatchError`).

    The mismatch is reported before the request is processed, so it is safe to
    rebuild the transport from the freshly attested key and retry the request
    once. This mirrors the certificate rotation handling of
    :class:`_ReVerifyingTransport`.
    """

    def __init__(self, secure_client: "SecureClient", inner: httpx.BaseTransport):
        self._secure_client = secure_client
        self._inner = inner
        self._lock = threading.Lock()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        inner = self._inner
        try:
            return inner.handle_request(request)
        except KeyConfigMismatchError:
            old_inner: Optional[httpx.BaseTransport] = None
            retry_inner: Optional[httpx.BaseTransport] = None
            reverify_failed = False
            with self._lock:
                if self._inner is inner:
                    try:
                        retry_inner = self._secure_client._build_ehbp_sync_transport()
                    except Exception:
                        # Re-verification failed; surface the original mismatch.
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


class _AsyncEHBPReVerifyingTransport(httpx.AsyncBaseTransport):
    """Async counterpart to :class:`_EHBPReVerifyingTransport`."""

    def __init__(self, secure_client: "SecureClient", inner: httpx.AsyncBaseTransport):
        self._secure_client = secure_client
        self._inner = inner
        self._lock = asyncio.Lock()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        inner = self._inner
        try:
            return await inner.handle_async_request(request)
        except KeyConfigMismatchError:
            old_inner: Optional[httpx.AsyncBaseTransport] = None
            retry_inner: Optional[httpx.AsyncBaseTransport] = None
            reverify_failed = False
            async with self._lock:
                if self._inner is inner:
                    try:
                        retry_inner = await self._secure_client._build_ehbp_async_transport()
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


def _enclave_url_header(base_url: str, enclave: str) -> tuple[str, bool]:
    """
    Returns the X-Tinfoil-Enclave-Url header value and whether it should be
    injected. The header is only needed when requests are routed through a proxy
    whose origin differs from the verified enclave's.
    """
    if not base_url or not enclave:
        return "", False
    enclave_url = f"https://{enclave}"
    proxy = urlparse(base_url)
    if not proxy.netloc:
        return "", False
    enclave_parsed = urlparse(enclave_url)
    if (proxy.scheme, proxy.netloc) == (enclave_parsed.scheme, enclave_parsed.netloc):
        return "", False
    return enclave_url, True


class _EnclaveURLHeaderTransport(httpx.BaseTransport):
    """
    Injects the X-Tinfoil-Enclave-Url header before delegating to the wrapped
    transport. EHBP leaves request headers in plaintext, so the header reaches
    the proxy while the body stays sealed to the enclave's HPKE key.

    The header is recomputed for every request from the client's current
    enclave, so it stays correct after a re-verification swaps in a different
    enclave (for example when attesting from a bundle behind a proxy).
    """

    def __init__(self, inner: httpx.BaseTransport, client: "SecureClient"):
        self._inner = inner
        self._client = client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        header_value, inject = _enclave_url_header(self._client.base_url, self._client.enclave)
        if inject:
            request.headers[ENCLAVE_URL_HEADER] = header_value
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


class _AsyncEnclaveURLHeaderTransport(httpx.AsyncBaseTransport):
    """Async counterpart of _EnclaveURLHeaderTransport."""

    def __init__(self, inner: httpx.AsyncBaseTransport, client: "SecureClient"):
        self._inner = inner
        self._client = client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        header_value, inject = _enclave_url_header(self._client.base_url, self._client.enclave)
        if inject:
            request.headers[ENCLAVE_URL_HEADER] = header_value
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


class SecureClient:
    """A client that verifies and communicates with secure enclaves"""
    
    def __init__(self, enclave: str = "", repo: str = DEFAULT_CONFIG_REPO, measurement: Optional[dict] = None, transport: TransportMode = DEFAULT_TRANSPORT_MODE, base_url: str = "", attestation_bundle_url: str = ""):
        # Hardcoded measurement takes precedence over repo
        if measurement is not None:
            repo = ""

        # Ensure at least one verification method is provided
        if measurement is None and (repo == "" or repo is None):
            raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")

        if transport not in ("ehbp", "tls"):
            raise ValueError(f"Unknown transport mode: {transport!r}. Use 'ehbp' or 'tls'.")

        # A pinned measurement and an attestation bundle are mutually exclusive
        # verification methods: the bundle carries its own Sigstore code
        # measurement, so honoring a pinned measurement would be ambiguous.
        if measurement is not None and attestation_bundle_url:
            raise ValueError(
                "Cannot combine 'measurement' with 'attestation_bundle_url'; "
                "the bundle provides its own code measurement."
            )

        # EHBP and TLS pinning leave request headers (which may carry the API
        # key) in plaintext, so a proxy base URL must be https.
        if base_url and urlparse(base_url).scheme != "https":
            raise ValueError(f"base_url must use https; got {base_url!r}")

        # The attestation bundle is the entire trust root for verification.
        # Fetching it over plaintext would let an attacker substitute the bundle
        # (MITM), so the bundle URL must be https.
        if attestation_bundle_url and urlparse(attestation_bundle_url).scheme != "https":
            raise ValueError(
                f"attestation_bundle_url must use https; got {attestation_bundle_url!r}"
            )

        # Routing through a proxy base URL relies on EHBP sealing the body to the
        # enclave; TLS certificate pinning would reject the proxy's certificate.
        if base_url and transport != "ehbp":
            raise ValueError("base_url is only supported with the 'ehbp' transport")

        # If enclave is empty, fetch a random one from the routers API. When
        # attesting from a bundle, the enclave host comes from the verified
        # bundle, so no router lookup is needed.
        if (enclave == "" or enclave is None) and not attestation_bundle_url:
            enclave = get_router_address()

        self.enclave = enclave or ""
        self.repo = repo
        self.measurement = measurement
        self.transport = transport
        self.base_url = base_url
        self.attestation_bundle_url = attestation_bundle_url
        self._ground_truth: Optional[GroundTruth] = None
        self._verification_document: Optional[VerificationDocument] = None
        self._low_level_http_client: Optional[httpx.Client] = None

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

    def _require_hpke_public_key(self) -> str:
        """Re-run attestation and return the attested HPKE public key."""
        ground_truth = self.verify()
        if not ground_truth.hpke_public_key:
            raise ValueError(
                "Enclave did not expose an HPKE public key; cannot use the "
                "EHBP transport. Use transport='tls' instead."
            )
        return ground_truth.hpke_public_key

    def _build_ehbp_sync_transport(self) -> httpx.BaseTransport:
        """Build a sync EHBP transport bound to the attested HPKE public key."""
        hpke_public_key = self._require_hpke_public_key()
        return EHBPTransport.from_public_key_hex(hpke_public_key, inner=httpx.HTTPTransport())

    async def _build_ehbp_async_transport(self) -> httpx.AsyncBaseTransport:
        """Build an async EHBP transport without blocking the event loop."""
        hpke_public_key = await asyncio.to_thread(self._require_hpke_public_key)
        return AsyncEHBPTransport.from_public_key_hex(hpke_public_key, inner=httpx.AsyncHTTPTransport())

    def make_secure_http_client(self) -> httpx.Client:
        """
        Build an httpx.Client that securely communicates with the enclave.

        In the default "ehbp" transport mode, request bodies are encrypted
        end-to-end with the enclave's attested HPKE public key. In "tls" mode,
        the enclave's TLS certificate is pinned instead.

        The returned client is suitable for long-lived use: if the enclave
        rotates its key (for example after a server-side restart), the
        underlying transport automatically re-verifies attestation and retries
        the request once.

        Redirects are not followed: a redirect target bypasses the enclave/proxy
        host binding, so following one could leak plaintext headers (including
        the API key) to an arbitrary host.
        """
        if self.transport == "ehbp":
            inner = self._build_ehbp_sync_transport()
            transport: httpx.BaseTransport = _EHBPReVerifyingTransport(self, inner)
            if self.base_url:
                transport = _EnclaveURLHeaderTransport(transport, self)
            return httpx.Client(transport=transport, follow_redirects=False)

        expected_fp = self.verify().public_key
        ctx = self._build_sync_ssl_context(expected_fp)
        inner = httpx.HTTPTransport(verify=ctx)
        transport = _ReVerifyingTransport(self, inner)
        return httpx.Client(transport=transport, follow_redirects=False)

    def make_secure_async_http_client(self) -> httpx.AsyncClient:
        """
        Build an httpx.AsyncClient that securely communicates with the enclave.

        In the default "ehbp" transport mode, request bodies are encrypted
        end-to-end with the enclave's attested HPKE public key. In "tls" mode,
        the enclave's TLS certificate is pinned instead.

        The returned client is suitable for long-lived use: if the enclave
        rotates its key (for example after a server-side restart), the
        underlying transport automatically re-verifies attestation and retries
        the request once.

        Redirects are not followed: a redirect target bypasses the enclave/proxy
        host binding, so following one could leak plaintext headers (including
        the API key) to an arbitrary host.
        """
        if self.transport == "ehbp":
            hpke_public_key = self._require_hpke_public_key()
            inner = AsyncEHBPTransport.from_public_key_hex(hpke_public_key, inner=httpx.AsyncHTTPTransport())
            transport: httpx.AsyncBaseTransport = _AsyncEHBPReVerifyingTransport(self, inner)
            if self.base_url:
                transport = _AsyncEnclaveURLHeaderTransport(transport, self)
            return httpx.AsyncClient(transport=transport, follow_redirects=False)

        expected_fp = self.verify().public_key
        ctx = self._build_async_ssl_context(expected_fp)
        inner = httpx.AsyncHTTPTransport(verify=ctx)
        transport = _AsyncReVerifyingTransport(self, inner)
        return httpx.AsyncClient(transport=transport, follow_redirects=False)

    def verify(self) -> GroundTruth:
        """
        Fetches the latest verification information from GitHub and Sigstore
        and stores the ground truth results in the client.

        Also populates the verification document with per-step status.
        """
        # When an attestation bundle URL is configured, attest from the bundle so
        # the enclave does not need to be reached directly (proxy-friendly). Ask
        # for an enclave/repo-specific bundle when either is set.
        if self.attestation_bundle_url:
            repo = self.repo if self.repo != DEFAULT_CONFIG_REPO else ""
            return self.verify_from_bundle(
                fetch_bundle_from(self.attestation_bundle_url, enclave=self.enclave, repo=repo)
            )

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
                hpke_public_key=verification.hpke_public_key or "",
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
                hpke_public_key=verification.hpke_public_key or "",
            )
            return self._ground_truth

    def verify_from_bundle(self, bundle: Bundle) -> GroundTruth:
        """
        Verifies a pre-fetched attestation bundle entirely client-side and
        stores the ground truth. The bundle supplies the enclave attestation
        report, release digest, Sigstore bundle, AMD VCEK, and enclave TLS
        certificate, so verification needs no direct connection to the enclave.
        """
        doc = VerificationDocument(
            config_repo=self.repo or "",
            enclave_host=bundle.domain,
            selected_router_endpoint=bundle.domain,
        )
        self._verification_document = doc

        # Step 1: Verify code measurement from the bundled Sigstore bundle
        try:
            code_measurements = verify_attestation(bundle.sigstore_bundle, bundle.digest, self.repo)
            doc.release_digest = bundle.digest
            doc.code_measurement = code_measurements
            doc.code_fingerprint = code_measurements.fingerprint()
            doc.steps["fetch_digest"] = VerificationStepState(status="success")
            doc.steps["verify_code"] = VerificationStepState(status="success")
        except Exception as e:
            doc.steps["fetch_digest"] = VerificationStepState(status="failed", error=str(e))
            doc.steps["verify_code"] = VerificationStepState(status="failed", error=str(e))
            _attach_verification_document(e, doc)
            raise

        # Step 2: Verify the enclave attestation report using the bundled VCEK
        try:
            vcek_der = base64.b64decode(bundle.vcek) if bundle.vcek else None
            verification = bundle.enclave_attestation_report.verify(vcek_der=vcek_der)
            # For TDX, also verify the firmware/early-boot hardware measurements
            # (mrtd, rtmr0), matching the direct attestation path; the bundle's
            # multi-platform code measurement does not cover them.
            if verification.measurement.type in TDX_TYPES:
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

        # Step 3: Compare code and enclave measurements
        try:
            code_measurements.assert_equal(verification.measurement)
            doc.steps["compare_measurements"] = VerificationStepState(status="success")
        except Exception as e:
            doc.steps["compare_measurements"] = VerificationStepState(status="failed", error=str(e))
            _attach_verification_document(e, doc)
            raise

        # Step 4: Bind the enclave certificate to the verified attestation
        try:
            if not bundle.enclave_cert:
                raise ValueError("attestation bundle is missing the enclave certificate")
            verify_certificate(
                bundle.enclave_cert,
                bundle.domain,
                bundle.enclave_attestation_report,
                verification.hpke_public_key or "",
            )
        except Exception as e:
            _attach_verification_document(e, doc)
            raise

        # Attestation came from the bundle; adopt its domain as the enclave host.
        self.enclave = bundle.domain
        doc.security_verified = True
        self._ground_truth = GroundTruth(
            public_key=verification.public_key_fp,
            digest=bundle.digest,
            measurement=verification.measurement,
            hpke_public_key=verification.hpke_public_key or "",
        )
        return self._ground_truth

    def get_http_client(self) -> urllib.request.OpenerDirector:
        """
        Returns a urllib opener that pins the enclave's TLS certificate.

        This accessor is specific to the "tls" transport mode. In the default
        "ehbp" mode there is no certificate to pin (the connection is
        proxy-friendly and the body is encrypted end-to-end instead), so use
        make_secure_http_client() or construct the client with transport="tls".
        """
        if not self._ground_truth:
            self._ground_truth = self.verify()

        if self.transport == "ehbp":
            raise ValueError(
                "get_http_client() pins the enclave's TLS certificate and is "
                "only available with transport='tls'. Use "
                "make_secure_http_client() for the EHBP transport."
            )

        handler = TLSBoundHTTPSHandler(self._ground_truth.public_key)
        return urllib.request.build_opener(handler)

    def _secure_http_client(self) -> httpx.Client:
        """Lazily build the mode-aware httpx client backing get()/post()."""
        if self._low_level_http_client is None:
            self._low_level_http_client = self.make_secure_http_client()
        return self._low_level_http_client

    def _allowed_request_endpoints(self) -> set:
        """(host, port) pairs a request may target: the attested enclave and, if set, the proxy."""
        endpoints = set()
        enclave = urlparse(f"//{self.enclave}")
        if enclave.hostname:
            endpoints.add((enclave.hostname, enclave.port or 443))
        if self.base_url:
            proxy = urlparse(self.base_url)
            if proxy.hostname:
                endpoints.add((proxy.hostname, proxy.port or 443))
        return endpoints

    def assert_request_allowed(self, url: str) -> None:
        """
        Guards the low-level escape hatches. Neither EHBP nor TLS pinning
        encrypts request headers (which may carry the API key), so a request may
        only target the attested enclave or the configured proxy, and only over
        https. The port is part of the binding so headers cannot be diverted to a
        different service listening on an allowed host. Raises ValueError otherwise.
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"refusing to send request over non-https URL {url!r}")
        if (parsed.hostname, parsed.port or 443) not in self._allowed_request_endpoints():
            raise ValueError(
                f"refusing to send request to host {parsed.hostname!r}: this "
                f"secure client is bound to enclave {self.enclave!r}"
            )

    def make_request(self, req: urllib.request.Request) -> Response:
        """
        Makes an HTTP request using the secure client, honoring the configured
        transport mode: in "ehbp" mode the request body is encrypted end-to-end
        to the enclave, and in "tls" mode the enclave's certificate is pinned.
        """
        # Build the client first so attestation runs and populates self.enclave.
        # When attesting from a bundle the enclave host is only known after
        # verification, so relative URLs must be resolved afterwards.
        client = self._secure_http_client()

        url = req.full_url
        parsed = urlparse(url)
        # If URL doesn't have a host, assume it's relative to the proxy (when
        # configured) or the enclave.
        if not parsed.netloc:
            if self.base_url:
                proxy = urlparse(self.base_url)
                url = f"{proxy.scheme}://{proxy.netloc}{url}"
            else:
                url = f"https://{self.enclave}{url}"
        self.assert_request_allowed(url)

        response = client.request(
            req.get_method(),
            url,
            headers=dict(req.header_items()),
            content=req.data,
            timeout=None,  # match the prior urllib path, which had no timeout
        )
        return Response(
            status=f"{response.status_code} {response.reason_phrase}",
            status_code=response.status_code,
            body=response.content,
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
