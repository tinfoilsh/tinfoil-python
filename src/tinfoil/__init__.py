from typing import Optional
from openai import OpenAI, AsyncOpenAI, NOT_GIVEN, NotGiven
from openai.resources.chat import Chat as OpenAIChat
from openai.resources.embeddings import Embeddings as OpenAIEmbeddings
from openai.resources.audio import Audio as OpenAIAudio
import httpx

from .client import (
    DEFAULT_TRANSPORT_MODE,
    SecureClient,
    TransportMode,
    VerificationDocument,
    get_router_address,
)

# v3 Tier-1 verification surface (SDK_SURFACE_SPEC §2). No name collides with
# the v2 exports above; tinfoil.attestation.fetch_attestation (v2, one-arg) is
# unaffected — it stays on its subpackage and is not re-exported here.
from .v3.client import (
    VerifiedDocumentV3,
    hpke_public_key,
    tls_public_key_fp,
    verify_document_v3,
)
from .v3.errors import VerificationError
from .v3.fetch import NONCE_SIZE, fetch_attestation, random_nonce

class TinfoilAI:
    chat: OpenAIChat
    embeddings: OpenAIEmbeddings
    audio: OpenAIAudio
    api_key: str
    enclave: str

    def __init__(
        self,
        enclave: str = "",
        repo: str = "tinfoilsh/confidential-model-router",
        api_key: str = "tinfoil",
        measurement: Optional[dict] = None,
        timeout: float | httpx.Timeout | None | NotGiven = NOT_GIVEN,
        transport: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: Optional[str] = None,
        attestation_bundle_url: str = "",
        user_cache_secret: Optional[str] = None,
    ):
        if measurement is not None:
            repo = ""

        # Ensure at least one verification method is provided
        if measurement is None and (repo == "" or repo is None):
            raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")

        # If enclave is empty, fetch a random one from the routers API. When
        # an ATC service URL is configured, SecureClient defers discovery to
        # verification so it can use that service.
        if (enclave == "" or enclave is None) and not attestation_bundle_url:
            enclave = get_router_address()

        self.api_key = api_key
        self._secure_client = SecureClient(enclave, repo, measurement, transport=transport, base_url=base_url, attestation_bundle_url=attestation_bundle_url, user_cache_secret=user_cache_secret)
        secure_http = self._secure_client.make_secure_http_client()
        # Building the secure transport verifies attestation, so the enclave host
        # is now known even when discovery was deferred to verification.
        self.enclave = self._secure_client.enclave
        self.client = OpenAI(
            base_url=base_url or f"https://{self.enclave}/v1/",
            api_key=api_key,
            timeout=timeout,
            http_client=secure_http,
        )
        self.chat = self.client.chat
        self.embeddings = self.client.embeddings
        self.audio = self.client.audio

    def get_verification_document(self) -> Optional[VerificationDocument]:
        """Returns the detailed verification document with per-step status"""
        return self._secure_client.get_verification_document()

class AsyncTinfoilAI:
    """
    Exactly like TinfoilAI, but fully async using AsyncOpenAI and httpx.AsyncClient.
    """
    chat: OpenAIChat
    embeddings: OpenAIEmbeddings
    audio: OpenAIAudio
    api_key: str
    enclave: str

    def __init__(
        self,
        enclave: str = "",
        repo: str = "tinfoilsh/confidential-model-router",
        api_key: str = "tinfoil",
        measurement: Optional[dict] = None,
        timeout: float | httpx.Timeout | None | NotGiven = NOT_GIVEN,
        transport: TransportMode = DEFAULT_TRANSPORT_MODE,
        base_url: Optional[str] = None,
        attestation_bundle_url: str = "",
        user_cache_secret: Optional[str] = None,
    ):
        if measurement is not None:
            repo = ""

        # Ensure at least one verification method is provided
        if measurement is None and (repo == "" or repo is None):
            raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")

        # If enclave is empty, fetch a random one from the routers API. When
        # an ATC service URL is configured, SecureClient defers discovery to
        # verification so it can use that service.
        if (enclave == "" or enclave is None) and not attestation_bundle_url:
            enclave = get_router_address()

        self.api_key = api_key
        # verifier client remains sync; only used to fetch the expected public key
        self._secure_client = SecureClient(enclave, repo, measurement, transport=transport, base_url=base_url, attestation_bundle_url=attestation_bundle_url, user_cache_secret=user_cache_secret)
        async_http = self._secure_client.make_secure_async_http_client()
        # Building the secure transport verifies attestation, so the enclave host
        # is now known even when discovery was deferred to verification.
        self.enclave = self._secure_client.enclave
        self.client = AsyncOpenAI(
            base_url=base_url or f"https://{self.enclave}/v1/",
            api_key=api_key,
            timeout=timeout,
            http_client=async_http,
        )
        self.chat = self.client.chat
        self.embeddings = self.client.embeddings
        self.audio = self.client.audio

    def get_verification_document(self) -> Optional[VerificationDocument]:
        """Returns the detailed verification document with per-step status"""
        return self._secure_client.get_verification_document()

class _HTTPSecureClient:
    """Low-level HTTP client with enclave-pinned TLS."""
    def __init__(self, enclave: str, tf_client: SecureClient):
        self._tf_client = tf_client
        self._http_client = tf_client.make_secure_http_client()
        # Building the transport verifies attestation; when discovery is
        # deferred to verification the enclave host is only known afterwards.
        self.enclave = tf_client.enclave or enclave

    def get(self, url: str, headers: Optional[dict] = None, params: Optional[dict] = None, timeout: Optional[int] = None) -> httpx.Response:
        self._tf_client.assert_request_allowed(url)
        return self._http_client.get(url, headers=headers, params=params, timeout=timeout)

    def post(
        self,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> httpx.Response:
        self._tf_client.assert_request_allowed(url)
        return self._http_client.post(url, headers=headers, data=data, json=json, timeout=timeout)

    def get_verification_document(self) -> Optional[VerificationDocument]:
        """Returns the detailed verification document with per-step status"""
        return self._tf_client.get_verification_document()


def NewSecureClient(enclave: str = "", repo: str = "tinfoilsh/confidential-model-router", measurement: Optional[dict] = None, transport: TransportMode = DEFAULT_TRANSPORT_MODE, base_url: Optional[str] = None, attestation_bundle_url: str = "", user_cache_secret: Optional[str] = None):
    """Create a secure HTTP client for direct GET/POST through the Tinfoil enclave."""
    if measurement is not None:
        repo = ""

    # Ensure at least one verification method is provided
    if measurement is None and (repo == "" or repo is None):
        raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")

    # If enclave is empty, fetch a random one from the routers API. When an
    # ATC service URL is configured, SecureClient defers discovery to verification.
    if (enclave == "" or enclave is None) and not attestation_bundle_url:
        enclave = get_router_address()

    tf_client = SecureClient(enclave, repo, measurement, transport=transport, base_url=base_url, attestation_bundle_url=attestation_bundle_url, user_cache_secret=user_cache_secret)
    return _HTTPSecureClient(tf_client.enclave, tf_client)

__all__ = [
    "TinfoilAI",
    "AsyncTinfoilAI",
    "NewSecureClient",
    "SecureClient",
    "VerificationDocument",
    "TransportMode",
    # v3 Tier-1 surface
    "verify_document_v3",
    "VerifiedDocumentV3",
    "tls_public_key_fp",
    "hpke_public_key",
    "fetch_attestation",
    "random_nonce",
    "NONCE_SIZE",
    "VerificationError",
]
