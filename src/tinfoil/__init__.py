import hashlib
import ssl
import cryptography.x509
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

import httpx
from openai import OpenAI
from openai.resources.chat import Chat as OpenAIChat
from openai.resources.embeddings import Embeddings as OpenAIEmbeddings

from .client import SecureClient

class TinfoilAI:
    chat: OpenAIChat
    embeddings: OpenAIEmbeddings
    api_key: str
    enclave: str

    def __init__(self, enclave: str, repo: str, api_key: str = "tinfoil"):
        self.enclave = enclave
        self.api_key = api_key
        self.client = self._create_client(enclave, repo)
        self.chat = self.client.chat
        self.embeddings = self.client.embeddings

    def _create_client(self, enclave: str, repo: str) -> OpenAI:
        tf_client = SecureClient(enclave, repo)
        expected_fp = tf_client.verify().public_key_fp

        def wrap_socket(*args, **kwargs) -> ssl.SSLSocket:
            ssl_socket = ssl.create_default_context().wrap_socket(*args, **kwargs)
            cert_binary = ssl_socket.getpeercert(binary_form=True)
            if not cert_binary:
                raise Exception("No certificate found")

            # Parse the certificate and extract the public key
            cert = cryptography.x509.load_der_x509_certificate(cert_binary)
            public_key = cert.public_key()
            # Get the public key in PKIX/DER format
            public_key_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            # Hash the public key
            cert_fp = hashlib.sha256(public_key_der).hexdigest()
            
            if cert_fp != expected_fp:
                raise Exception(f"Certificate fingerprint mismatch")

            return ssl_socket

        ctx = ssl.create_default_context()
        ctx.wrap_socket = wrap_socket
        http_client = httpx.Client(
            verify=ctx,
            follow_redirects=True,
        )

        return OpenAI(
            base_url=f"https://{self.enclave}/v1/",
            api_key=self.api_key,
            http_client=http_client,
        )