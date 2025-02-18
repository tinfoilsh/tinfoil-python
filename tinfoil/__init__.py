import hashlib
import httpx
import openai
import ssl
from openai import OpenAI
from tinfoil_verifier import client as tinfoil_verifier_client


class Chat:
    def __init__(self, client):
        self._client = client

    def __getattr__(self, name):
        return getattr(self._client.chat, name)


class TinfoilAI:
    def __init__(self, enclave: str, repo: str):
        self._enclave = enclave
        self._repo = repo
        self._client = self._create_client()
        self.chat = Chat(self._client)

    def _create_client(self) -> OpenAI:
        tf_client = tinfoil_verifier_client.NewSecureClient(self._enclave, self._repo)
        expected_fp = tf_client.Verify().CertFingerprint.__bytes__().hex()

        def wrap_socket(*args, **kwargs):
            ssl_socket = ssl.create_default_context().wrap_socket(*args, **kwargs)
            cert_binary = ssl_socket.getpeercert(binary_form=True)
            if not cert_binary:
                raise Exception("No certificate found")

            cert_fp = hashlib.sha256(cert_binary).hexdigest()
            if cert_fp != expected_fp:
                raise Exception(f"Certificate fingerprint mismatch")

            return ssl_socket

        ctx = ssl.create_default_context()
        ctx.wrap_socket = wrap_socket
        http_client = httpx.Client(
            verify=ctx,
            timeout=openai.DEFAULT_TIMEOUT,
            limits=openai.DEFAULT_CONNECTION_LIMITS,
            follow_redirects=True,
        )

        return OpenAI(
            base_url=f"https://{self._enclave}/v1/",
            api_key="tinfoil",
            http_client=http_client,
        )
