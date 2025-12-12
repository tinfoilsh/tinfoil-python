import os
import pytest
from tinfoil import SecureClient, get_router_address

@pytest.fixture(scope="session")
def client() -> SecureClient:
    return SecureClient()

@pytest.fixture(scope="session")
def base_url() -> str:
    return get_router_address()

def test_doc_upload(client, base_url):
    """Test synchronous doc upload."""
    httpx_client = client.make_secure_http_client()

    with open("tests/dummy.pdf", "rb") as file:
        response = httpx_client.post(
            f"https://{base_url}/v1/convert/file",
            files={'files': file},
            timeout=30,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"

@pytest.mark.asyncio
async def test_doc_upload_async(client, base_url):
    """Test asynchronous doc upload."""
    httpx_client = client.make_secure_async_http_client()

    with open("tests/dummy.pdf", "rb") as file:
        response = await httpx_client.post(
            f"https://{base_url}/v1/convert/file",
            files={'files': file},
            timeout=30,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
