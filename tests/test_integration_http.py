import os
import pytest
from tinfoil import NewSecureClient, get_router_address

REPO    = "tinfoilsh/confidential-model-router"
API_KEY = os.getenv("TINFOIL_API_KEY", "tinfoil")

pytestmark = pytest.mark.integration

def test_http_integration():
    enclave = get_router_address()
    client = NewSecureClient(enclave, REPO, api_key=API_KEY)

    url = f"https://{enclave}/v1/chat/completions"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    payload = {
        "model": "llama3-3-70b",
        "messages": [{"role": "user", "content": "Hello from integration test"}],
    }

    resp = client.post(url, headers=headers, json=payload, timeout=30)
    assert resp.status_code == 200

    data = resp.json()
    assert "choices" in data
    assert data["choices"][0]["message"]["content"]

if __name__ == "__main__":
    pytest.main([__file__])
