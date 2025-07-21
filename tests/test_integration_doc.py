import os
import pytest
from tinfoil import SecureClient

@pytest.fixture(scope="session")
def client() -> SecureClient:
    return SecureClient(
        enclave="doc-upload.model.tinfoil.sh",
        repo="tinfoilsh/confidential-doc-upload",
    )

def test_doc_upload(client):
    """Test synchronous doc upload."""
    httpx_client = client.make_secure_http_client()

    with open("tests/dummy.pdf", "rb") as file:
        response = httpx_client.post(
            "https://doc-upload.model.tinfoil.sh/v1/convert/file", 
            files={'files': file},
            timeout=30,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"

@pytest.mark.asyncio
async def test_doc_upload_async(client):
    """Test asynchronous doc upload."""
    httpx_client = client.make_secure_async_http_client()

    with open("tests/dummy.pdf", "rb") as file:
        response = await httpx_client.post(
            "https://doc-upload.model.tinfoil.sh/v1/convert/file", 
            files={'files': file},
            timeout=30,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
