from openai import OpenAI, AsyncOpenAI
from openai.resources.chat import Chat as OpenAIChat
from openai.resources.embeddings import Embeddings as OpenAIEmbeddings
from openai.resources.audio import Audio as OpenAIAudio

from .client import SecureClient, get_router_address

class TinfoilAI:
    chat: OpenAIChat
    embeddings: OpenAIEmbeddings
    audio: OpenAIAudio
    api_key: str
    enclave: str

    def __init__(self, enclave: str = "", repo: str = "tinfoilsh/confidential-model-router", api_key: str = "tinfoil", measurement: dict = None):
        if measurement is not None:
            repo = ""
        
        # Ensure at least one verification method is provided
        if measurement is None and (repo == "" or repo is None):
            raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")
        
        # If enclave is empty, fetch a random one from the routers API
        if enclave == "" or enclave is None:
            enclave = get_router_address()
        
        self.enclave = enclave
        self.api_key = api_key
        tf_client = SecureClient(enclave, repo, measurement)
        secure_http = tf_client.make_secure_http_client()
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

    def __init__(self, enclave: str = "", repo: str = "tinfoilsh/confidential-model-router", api_key: str = "tinfoil", measurement: dict = None):
        if measurement is not None:
            repo = ""
        
        # Ensure at least one verification method is provided
        if measurement is None and (repo == "" or repo is None):
            raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")
        
        # If enclave is empty, fetch a random one from the routers API
        if enclave == "" or enclave is None:
            enclave = get_router_address()
        
        self.enclave = enclave
        self.api_key = api_key
        # verifier client remains sync; only used to fetch the expected public key
        tf_client = SecureClient(enclave, repo, measurement)
        async_http = tf_client.make_secure_async_http_client()
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
        self._http_client = tf_client.make_secure_http_client()
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


def NewSecureClient(enclave: str = "", repo: str = "tinfoilsh/confidential-model-router", api_key: str = "tinfoil", measurement: dict = None):
    """
    Create a secure HTTP client for direct GET/POST through the Tinfoil enclave.
    """
    if measurement is not None:
        repo = ""
    
    # Ensure at least one verification method is provided
    if measurement is None and (repo == "" or repo is None):
        raise ValueError("Must provide either 'measurement' or 'repo' parameter for verification.")
    
    # If enclave is empty, fetch a random one from the routers API
    if enclave == "" or enclave is None:
        enclave = get_router_address()
    
    tf_client = SecureClient(enclave, repo, measurement)
    return _HTTPSecureClient(enclave, tf_client, api_key)

__all__ = ["TinfoilAI", "AsyncTinfoilAI", "NewSecureClient"]
