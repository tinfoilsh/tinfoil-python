import hashlib
import os
import ssl
import sys
import platform

import httpx
from openai import OpenAI
from openai.resources.chat import Chat as OpenAIChat
from openai.resources.embeddings import Embeddings as OpenAIEmbeddings

# Add path to module directory for more reliable imports
_module_dir = os.path.dirname(os.path.abspath(__file__))
_verifier_dir = os.path.join(_module_dir, "tinfoil_verifier")
if os.path.exists(_verifier_dir) and _verifier_dir not in sys.path:
    sys.path.insert(0, _verifier_dir)

# Function to provide detailed error information
def _get_debug_info():
    info = [
        f"Platform: {platform.platform()}",
        f"Python: {platform.python_version()}",
        f"Architecture: {platform.machine()}",
        f"Module directory: {_module_dir}",
        f"Verifier exists: {os.path.exists(_verifier_dir)}"
    ]
    
    if os.path.exists(_verifier_dir):
        info.append("Verifier directory contents:")
        for item in os.listdir(_verifier_dir):
            info.append(f"  - {item}")
    
    return "\n".join(info)

# Try to import the client module with detailed error handling
try:
    from .tinfoil_verifier import client as tinfoil_verifier_client
except ImportError as e:
    error_msg = f"""
Failed to import tinfoil_verifier client module.
{_get_debug_info()}
Error: {str(e)}

This could be due to platform compatibility issues. The current version
supports Linux (amd64), MacOS 13 (Intel), and MacOS 14 (Apple Silicon)
with Python 3.10 through 3.13.
"""
    raise ImportError(error_msg) from e
except Exception as e:
    error_msg = f"""
Unexpected error importing tinfoil_verifier client module.
{_get_debug_info()}
Error: {str(e)}
"""
    raise Exception(error_msg) from e


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
        try:
            tf_client = tinfoil_verifier_client.NewSecureClient(enclave, repo)
            expected_fp = tf_client.Verify().CertFingerprint.__bytes__().hex()
        except Exception as e:
            # More specific error for this critical operation
            error_msg = f"Failed to create secure client: {str(e)}"
            raise RuntimeError(error_msg) from e

        def wrap_socket(*args, **kwargs) -> ssl.SSLSocket:
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
            follow_redirects=True,
        )

        return OpenAI(
            base_url=f"https://{self.enclave}/v1/",
            api_key=self.api_key,
            http_client=http_client,
        )