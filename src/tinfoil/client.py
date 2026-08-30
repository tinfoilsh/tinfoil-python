import asyncio
import contextlib
import copy
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
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version

from ehbp import (
    AsyncEHBPTransport,
    EHBPTransport,
    KeyConfigMismatchError,
)

from .attestation.types import (
    AttestationError,
    HardwareMeasurement,
    Measurement,
    PredicateType,
    Verification,
)
from .user_cache_secret import (
    resolve_user_cache_secret,
    _AsyncUserCacheSecretTransport,
    _UserCacheSecretTransport,
)

# The v3 verification engine, consumed through its public Tier-1 surface
# (SDK_SURFACE_SPEC §2; these are the exact names re-exported from the
# package root). The v3 document carries all attestation collateral, so the
# enclave round-trip is the only network request the verify flow makes.
from .v3 import measurement as v3_measurement
from .v3.client import hpke_public_key, tls_public_key_fp, verify_document_v3
from .v3.errors import POLICY_REJECTED, PROVENANCE_REJECTED, VerificationError
from .v3.fetch import fetch_attestation, random_nonce

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


def _parse_http_url(url: str, parameter: str, *, https_only: bool = False):
    try:
        parsed = urlparse(url)
        parsed.port
    except ValueError as exc:
        raise ValueError(f"{parameter} must be a valid absolute URL; got {url!r}") from exc

    scheme = parsed.scheme.lower()
    allowed_schemes = ("https",) if https_only else ("http", "https")
    if scheme not in allowed_schemes or not parsed.netloc or not parsed.hostname:
        requirement = "https" if https_only else "http or https"
        raise ValueError(
            f"{parameter} must be a valid absolute URL using {requirement}; got {url!r}"
        )
    return parsed


def _url_origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    port = parsed.port if parsed.port is not None else default_port
    return scheme, parsed.hostname or "", port


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


@dataclass(frozen=True)
class SoftwareIdentity:
    name: str
    version: str


def _verifier_identity() -> SoftwareIdentity:
    try:
        package_version = version("tinfoil")
    except PackageNotFoundError:
        package_version = "unknown"
    return SoftwareIdentity(name="tinfoil", version=package_version)


def _verified_at_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
    schema_version: int = 1
    release_tag: Optional[str] = None
    verifier: SoftwareIdentity = field(default_factory=_verifier_identity)
    verified_at: Optional[str] = None

    def to_dict(self) -> dict:
        def measurement(value: Measurement) -> dict:
            return {"type": value.type.value, "registers": list(value.registers)}

        result = {
            "schemaVersion": self.schema_version,
            "configRepo": self.config_repo,
            "enclaveHost": self.enclave_host,
            "releaseTag": self.release_tag,
            "releaseDigest": self.release_digest,
            "codeMeasurement": measurement(self.code_measurement) if self.code_measurement else None,
            "enclaveMeasurement": {
                key: value
                for key, value in {
                    "measurement": measurement(self.enclave_measurement.measurement),
                    "tlsPublicKeyFingerprint": self.enclave_measurement.public_key_fp,
                    "hpkePublicKey": self.enclave_measurement.hpke_public_key,
                }.items()
                if value is not None
            } if self.enclave_measurement else None,
            "tlsPublicKey": self.tls_public_key,
            "hpkePublicKey": self.hpke_public_key,
            "hardwareMeasurement": {
                "ID": self.hardware_measurement.id,
                "MRTD": self.hardware_measurement.mrtd,
                "RTMR0": self.hardware_measurement.rtmr0,
            } if self.hardware_measurement else None,
            "codeFingerprint": self.code_fingerprint,
            "enclaveFingerprint": self.enclave_fingerprint,
            "selectedRouterEndpoint": self.selected_router_endpoint,
            "securityVerified": self.security_verified,
            "verifier": {"name": self.verifier.name, "version": self.verifier.version},
            "verifiedAt": self.verified_at,
            "steps": {
                {
                    "fetch_digest": "fetchDigest",
                    "verify_code": "verifyCode",
                    "verify_enclave": "verifyEnclave",
                    "compare_measurements": "compareMeasurements",
                    "other_error": "otherError",
                }.get(name, name): {
                    key: value
                    for key, value in {"status": step.status, "error": step.error}.items()
                    if value is not None
                }
                for name, step in self.steps.items()
            },
        }
        return {key: value for key, value in result.items() if value is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def _step_for_layer(layer: str) -> str:
    """Maps a v3 rejection layer to the verification-document step it fails
    (JS: stepForLayer): code provenance to the code step, policy appraisal to
    the measurement-comparison step, envelope/quote to the enclave step."""
    if layer == PROVENANCE_REJECTED:
        return "verify_code"
    if layer == POLICY_REJECTED:
        return "compare_measurements"
    return "verify_enclave"  # ENVELOPE_REJECTED, QUOTE_REJECTED


def _measurement_from_v3(m: v3_measurement.Measurement) -> Measurement:
    """Projects a v3 measurement onto the document's legacy measurement type;
    the predicate URLs are shared between the two engines."""
    return Measurement(type=PredicateType(m.type), registers=list(m.registers))


def _attach_verification_document(exc: Exception, verification_document: VerificationDocument) -> None:
    try:
        setattr(exc, "verification_document", copy.deepcopy(verification_document))
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
    if _url_origin(base_url) == _url_origin(enclave_url):
        return "", False
    return enclave_url, True


class _EnclaveURLHeaderTransport(httpx.BaseTransport):
    """
    Injects the X-Tinfoil-Enclave-Url header before delegating to the wrapped
    transport. EHBP leaves request headers in plaintext, so the header reaches
    the proxy while the body stays sealed to the enclave's HPKE key.

    The header is recomputed for every request from the client's current
    enclave, so it stays correct after a re-verification swaps in a different
    enclave (for example when router discovery happens at verify time).
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


class _HostBoundTransport(httpx.BaseTransport):
    """Rejects requests outside the verified enclave or configured proxy."""

    def __init__(self, inner: httpx.BaseTransport, client: "SecureClient"):
        self._inner = inner
        self._client = client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self._client.assert_request_allowed(str(request.url))
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


class _AsyncHostBoundTransport(httpx.AsyncBaseTransport):
    """Async counterpart of _HostBoundTransport."""

    def __init__(self, inner: httpx.AsyncBaseTransport, client: "SecureClient"):
        self._inner = inner
        self._client = client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._client.assert_request_allowed(str(request.url))
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


class SecureClient:
    """A client that verifies and communicates with secure enclaves"""
    
    def __init__(self, enclave: str = "", repo: str = DEFAULT_CONFIG_REPO, measurement: Optional[dict] = None, transport: TransportMode = DEFAULT_TRANSPORT_MODE, base_url: Optional[str] = None, attestation_bundle_url: str = "", user_cache_secret: Optional[str] = None):
        # Hardcoded measurement takes precedence over repo
        if measurement is not None:
            repo = ""

        # Ensure at least one verification method is provided
        if measurement is None and (repo == "" or repo is None):
            raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")

        if transport not in ("ehbp", "tls"):
            raise ValueError(f"Unknown transport mode: {transport!r}. Use 'ehbp' or 'tls'.")

        # A pinned measurement and an ATC service URL remain mutually
        # exclusive, as they were when the URL served attestation bundles.
        if measurement is not None and attestation_bundle_url:
            raise ValueError(
                "Cannot combine 'measurement' with 'attestation_bundle_url'."
            )

        if base_url is not None:
            _parse_http_url(base_url, "base_url")

        # The ATC service selects which enclave gets verified, so reaching it
        # over plaintext would let an attacker steer discovery (MITM); the URL
        # must be https.
        if attestation_bundle_url:
            _parse_http_url(
                attestation_bundle_url,
                "attestation_bundle_url",
                https_only=True,
            )

        # If enclave is empty, fetch a random one from the routers API. When
        # an ATC service URL is configured, discovery is deferred to verify()
        # so it can use that service (the v3 document carries all attestation
        # collateral, so the ATC service now serves only router discovery).
        if (enclave == "" or enclave is None) and not attestation_bundle_url:
            enclave = get_router_address()

        self.enclave = enclave or ""
        self.repo = repo
        self.measurement = measurement
        self.transport = transport
        self.base_url = base_url or ""
        self.attestation_bundle_url = attestation_bundle_url
        # The client-level prompt-cache secret, resolved once per client: the
        # non-empty explicit parameter beats the
        # TINFOIL_USER_CACHE_SECRET environment variable, which beats the
        # secret persisted at ~/.tinfoil/user_cache_secret. Empty values are
        # treated as unset.
        self._user_cache_secret = resolve_user_cache_secret(user_cache_secret)
        self._ground_truth: Optional[GroundTruth] = None
        self._verification_document: Optional[VerificationDocument] = None
        self._low_level_http_client: Optional[httpx.Client] = None
        self._validate_tls_base_url()

    @property
    def ground_truth(self) -> Optional[GroundTruth]:
        """Returns the last verified enclave state"""
        return self._ground_truth

    def get_verification_document(self) -> Optional[VerificationDocument]:
        """Returns the detailed verification document from the last verify() call"""
        return copy.deepcopy(self._verification_document)

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
        self._validate_tls_base_url()
        ctx = self._build_sync_ssl_context(expected_fp)
        return httpx.HTTPTransport(verify=ctx)

    async def _rebuild_async_transport(self) -> httpx.AsyncBaseTransport:
        """Re-run attestation without blocking the event loop."""
        expected_fp = (await asyncio.to_thread(self.verify)).public_key
        self._validate_tls_base_url()
        ctx = self._build_async_ssl_context(expected_fp)
        return httpx.AsyncHTTPTransport(verify=ctx)

    def _validate_tls_base_url(self) -> None:
        if self.transport != "tls" or not self.base_url or not self.enclave:
            return
        enclave_url = f"https://{self.enclave}"
        enclave_origin = _url_origin(enclave_url)
        if _url_origin(self.base_url) != enclave_origin:
            raise ValueError(
                "TLS base_url must use the verified enclave origin "
                f"{enclave_url!r}"
            )

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

    def _wrap_sync_transport(
        self, transport: httpx.BaseTransport
    ) -> httpx.BaseTransport:
        if self._user_cache_secret:
            transport = _UserCacheSecretTransport(self._user_cache_secret, transport)
        if self.transport == "ehbp" and self.base_url:
            transport = _EnclaveURLHeaderTransport(transport, self)
        return _HostBoundTransport(transport, self)

    def _wrap_async_transport(
        self, transport: httpx.AsyncBaseTransport
    ) -> httpx.AsyncBaseTransport:
        if self._user_cache_secret:
            transport = _AsyncUserCacheSecretTransport(
                self._user_cache_secret, transport
            )
        if self.transport == "ehbp" and self.base_url:
            transport = _AsyncEnclaveURLHeaderTransport(transport, self)
        return _AsyncHostBoundTransport(transport, self)

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

        Redirects are not followed, and every request is bound to the verified
        enclave or configured proxy before any plaintext headers are sent.
        """
        if self.transport == "ehbp":
            inner = self._build_ehbp_sync_transport()
            transport: httpx.BaseTransport = _EHBPReVerifyingTransport(self, inner)
            transport = self._wrap_sync_transport(transport)
            return httpx.Client(transport=transport, follow_redirects=False)

        expected_fp = self.verify().public_key
        self._validate_tls_base_url()
        ctx = self._build_sync_ssl_context(expected_fp)
        inner = httpx.HTTPTransport(verify=ctx)
        transport = _ReVerifyingTransport(self, inner)
        transport = self._wrap_sync_transport(transport)
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

        Redirects are not followed, and every request is bound to the verified
        enclave or configured proxy before any plaintext headers are sent.
        """
        if self.transport == "ehbp":
            hpke_public_key = self._require_hpke_public_key()
            inner = AsyncEHBPTransport.from_public_key_hex(hpke_public_key, inner=httpx.AsyncHTTPTransport())
            transport: httpx.AsyncBaseTransport = _AsyncEHBPReVerifyingTransport(self, inner)
            transport = self._wrap_async_transport(transport)
            return httpx.AsyncClient(transport=transport, follow_redirects=False)

        expected_fp = self.verify().public_key
        self._validate_tls_base_url()
        ctx = self._build_async_ssl_context(expected_fp)
        inner = httpx.AsyncHTTPTransport(verify=ctx)
        transport = _AsyncReVerifyingTransport(self, inner)
        transport = self._wrap_async_transport(transport)
        return httpx.AsyncClient(transport=transport, follow_redirects=False)

    def _finalize_verification(
        self,
        doc: VerificationDocument,
        verification: Verification,
        digest: str,
    ) -> GroundTruth:
        doc.release_digest = digest
        doc.security_verified = True
        doc.verified_at = _verified_at_now()
        self._ground_truth = GroundTruth(
            public_key=verification.public_key_fp,
            digest=digest,
            measurement=verification.measurement,
            hpke_public_key=verification.hpke_public_key or "",
        )
        return self._ground_truth

    def verify(self) -> GroundTruth:
        """
        Attests the enclave with the v3 single-request flow (Go:
        SecureClient.verifyV3): fresh nonce → fetch the attestation document
        (evidence + collateral in one request) → verify it offline against
        the embedded roots → recover the endorsed channel keys. Stores the
        ground truth and populates the verification document with per-step
        status. The enclave fetch is the only network request.
        """
        # The v3 engine always authenticates code provenance from the trusted
        # repo; there is no pinned-measurement seam (Go/JS parity).
        if self.measurement is not None:
            raise ValueError(
                "Pinned 'measurement' verification is not supported by the v3 "
                "attestation flow; provide 'repo' instead."
            )

        # v3 needs the enclave host before the document fetch. The constructor
        # defers discovery when an ATC service URL is configured, so resolve a
        # router through that service here.
        if not self.enclave:
            self.enclave = get_router_address(
                atc_base_url=self.attestation_bundle_url or None
            )

        doc = VerificationDocument(
            config_repo=self.repo or "",
            enclave_host=self.enclave,
            selected_router_endpoint=self.enclave,
        )
        self._verification_document = doc

        # Fetch phase: the enclave round-trip is the only network request;
        # all Sigstore collateral travels inside the document.
        try:
            nonce = random_nonce()
            doc_bytes = fetch_attestation(self.enclave, nonce)
            doc.steps["fetch_digest"] = VerificationStepState(status="success")
        except Exception as e:
            doc.steps["fetch_digest"] = VerificationStepState(status="failed", error=str(e))
            _attach_verification_document(e, doc)
            raise

        # Verify phase: offline, embedded production roots, current time. A
        # rejection is attributed to the step matching its layer and raised in
        # the SDK's error taxonomy; unexpected errors propagate untouched.
        try:
            verified = verify_document_v3(doc_bytes, nonce, self.repo)
            doc.steps["verify_code"] = VerificationStepState(status="success")
            doc.steps["verify_enclave"] = VerificationStepState(status="success")
            doc.steps["compare_measurements"] = VerificationStepState(status="success")
        except VerificationError as e:
            doc.steps[_step_for_layer(e.layer)] = VerificationStepState(status="failed", error=str(e))
            wrapped = AttestationError(f"Attestation verification failed: {e}")
            _attach_verification_document(wrapped, doc)
            raise wrapped from e
        except Exception as e:
            doc.steps["other_error"] = VerificationStepState(status="failed", error=str(e))
            _attach_verification_document(e, doc)
            raise

        # Binding phase: both endorsed channel keys are hard requirements (Go
        # mirrors these as "binding:" errors). EHBP binds request bodies to
        # the HPKE key; the "tls" transport pins the fingerprint on every
        # connection it opens — no eager dial happens at verify time.
        try:
            tls_fp = tls_public_key_fp(verified)
            hpke_key = hpke_public_key(verified)
        except Exception as e:
            doc.steps["other_error"] = VerificationStepState(status="failed", error=f"binding: {e}")
            wrapped = AttestationError(f"binding: {e}")
            _attach_verification_document(wrapped, doc)
            raise wrapped from e

        # Fingerprints mirror the legacy flow for consumers that display or
        # compare them. TDX fingerprints incorporate the platform registers,
        # which in v3 come from the verified quote itself (their values were
        # already appraised against the endorsed platform measurements).
        enclave_m = verified.enclave_measurement
        hw: Optional[HardwareMeasurement] = None
        if enclave_m.type == v3_measurement.TDX_GUEST_V2 and len(enclave_m.registers) >= 2:
            hw = HardwareMeasurement(id="", mrtd=enclave_m.registers[0], rtmr0=enclave_m.registers[1])
        try:
            code_fingerprint = v3_measurement.fingerprint(verified.code_measurement, hw, enclave_m.type)
            enclave_fingerprint = v3_measurement.fingerprint(enclave_m, hw, enclave_m.type)
            code_measurement = _measurement_from_v3(verified.code_measurement)
            verification = Verification(
                measurement=_measurement_from_v3(enclave_m),
                public_key_fp=tls_fp,
                hpke_public_key=hpke_key,
            )
        except Exception as e:
            doc.steps["other_error"] = VerificationStepState(status="failed", error=f"measurements: {e}")
            wrapped = AttestationError(f"measurements: failed to compute fingerprint: {e}")
            _attach_verification_document(wrapped, doc)
            raise wrapped from e

        doc.release_tag = verified.code_tag
        doc.code_measurement = code_measurement
        doc.code_fingerprint = code_fingerprint
        doc.enclave_measurement = verification
        doc.tls_public_key = tls_fp
        doc.hpke_public_key = hpke_key
        doc.hardware_measurement = hw
        doc.enclave_fingerprint = enclave_fingerprint
        return self._finalize_verification(doc, verification, verified.code_digest)

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
        self._validate_tls_base_url()

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

    def _allowed_request_origins(self) -> set:
        """Origins a request may target: the attested enclave and, if set, the proxy."""
        origins = set()
        if self.enclave:
            origins.add(_url_origin(f"https://{self.enclave}"))
        if self.base_url:
            origins.add(_url_origin(self.base_url))
        return origins

    def assert_request_allowed(self, url: str) -> None:
        """
        Guards the low-level escape hatches. EHBP does not encrypt request
        headers end-to-end; TLS encrypts them in transit, but another endpoint
        would still receive them. A request may therefore only target the
        attested enclave or configured proxy over its exact HTTP(S) origin. The
        scheme and port are part of the binding. Raises ValueError otherwise.
        """
        parsed = urlparse(url)
        if _url_origin(url) not in self._allowed_request_origins():
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
        # When router discovery is deferred to verify() the enclave host is
        # only known afterwards, so relative URLs must be resolved afterwards.
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

def get_router_address(platform: Optional[str] = None, atc_base_url: Optional[str] = None) -> str:
    """
    Fetches the list of available routers from the ATC API
    and returns a randomly selected address.

    Args:
        platform: Optional platform filter (e.g. "snp", "tdx").
                  If None, returns routers for any platform.
        atc_base_url: Optional base URL of the ATC service to query;
                      defaults to the production service.
    """
    base = (atc_base_url or "https://atc.tinfoil.sh").rstrip("/")
    routers_url = f"{base}/routers"
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
