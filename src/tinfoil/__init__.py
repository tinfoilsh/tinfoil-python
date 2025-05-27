import hashlib
import ssl
import cryptography.x509
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

import httpx
from openai import OpenAI, AsyncOpenAI
from openai.resources.chat import Chat as OpenAIChat
from openai.resources.embeddings import Embeddings as OpenAIEmbeddings
from openai.resources.audio import Audio as OpenAIAudio

from .client import SecureClient

def _make_secure_http_client(tf_client) -> httpx.Client:
    """
    Build an httpx.Client that pins the enclave's TLS cert
    via tf_client.Verify().PublicKey.
    """
    expected_fp = tf_client.verify().public_key

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

    ctx = ssl.create_default_context()
    ctx.wrap_socket = wrap_socket
    return httpx.Client(verify=ctx, follow_redirects=True)

def _make_secure_async_http_client(tf_client) -> httpx.AsyncClient:
    """
    Build an httpx.AsyncClient that pins the enclave's TLS cert.
    """
    expected_fp = tf_client.verify().public_key

    def wrap_socket(*args, **kwargs) -> ssl.SSLSocket:
        sock = ssl.create_default_context().wrap_socket(*args, **kwargs)
        cert_binary = sock.getpeercert(binary_form=True)
        if not cert_binary:
            raise Exception("No certificate found")
        cert = cryptography.x509.load_der_x509_certificate(cert_binary)
        pub_der = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        actual_fp = hashlib.sha256(pub_der).hexdigest()
        if actual_fp != expected_fp:
            raise Exception(f"Certificate fingerprint mismatch: {actual_fp}")
        return sock

    ctx = ssl.create_default_context()
    ctx.wrap_socket = wrap_socket
    return httpx.AsyncClient(verify=ctx, follow_redirects=True)

class TinfoilAI:
    chat: OpenAIChat
    embeddings: OpenAIEmbeddings
    audio: OpenAIAudio
    api_key: str
    enclave: str

    def __init__(self, enclave: str, repo: str, api_key: str = "tinfoil"):
        self.enclave = enclave
        self.api_key = api_key
        tf_client = SecureClient(enclave, repo)
        secure_http = _make_secure_http_client(tf_client)
        self.client = OpenAI(
            base_url=f"https://{enclave}/v1/",
            api_key=api_key,
            http_client=secure_http,
        )
        self.chat = self.client.chat
        self.embeddings = self.client.embeddings
        self.audio = self.client.audio

class AsyncTinfoilAI:
    """
    Exactly like TinfoilAI, but fully async using AsyncOpenAI and httpx.AsyncClient.
    """
    chat: OpenAIChat
    embeddings: OpenAIEmbeddings
    audio: OpenAIAudio
    api_key: str
    enclave: str

    def __init__(self, enclave: str, repo: str, api_key: str = "tinfoil"):
        self.enclave = enclave
        self.api_key = api_key
        # verifier client remains sync; only used to fetch the expected public key
        tf_client = SecureClient(enclave, repo)
        async_http = _make_secure_async_http_client(tf_client)
        self.client = AsyncOpenAI(
            base_url=f"https://{enclave}/v1/",
            api_key=api_key,
            http_client=async_http,
        )
        self.chat = self.client.chat
        self.embeddings = self.client.embeddings
        self.audio = self.client.audio

class _HTTPSecureClient:
    """Low-level HTTP client with enclave-pinned TLS."""
    def __init__(self, enclave: str, tf_client, api_key: str):
        self.enclave = enclave
        self._tf_client = tf_client
        self._http_client = _make_secure_http_client(tf_client)
        self._api_key = api_key

    def get(self, url: str, headers: dict = None, params: dict = None, timeout: int = None):
        return self._http_client.get(url, headers=headers, params=params, timeout=timeout)

    def post(
        self,
        url: str,
        headers: dict = None,
        data: dict = None,
        json: dict = None,
        timeout: int = None,
    ):
        return self._http_client.post(url, headers=headers, data=data, json=json, timeout=timeout)


def NewSecureClient(enclave: str, repo: str, api_key: str = "tinfoil"):
    """
    Create a secure HTTP client for direct GET/POST through the Tinfoil enclave.
    """
    tf_client = SecureClient(enclave, repo)
    return _HTTPSecureClient(enclave, tf_client, api_key)

__all__ = ["TinfoilAI", "AsyncTinfoilAI", "NewSecureClient"]