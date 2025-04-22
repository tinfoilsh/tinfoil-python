import os
import pytest
from tinfoil import NewSecureClient

ENCLAVE = os.getenv("TINFOIL_ENCLAVE")
REPO    = os.getenv("TINFOIL_REPO")
API_KEY = os.getenv("TINFOIL_API_KEY", "tinfoil")

pytestmark = pytest.mark.integration

@pytest.fixture(autouse=True)
def skip_if_no_env():
    if not ENCLAVE or not REPO:
        pytest.skip("Missing TINFOIL_* env vars", allow_module_level=True)

def test_http_integration():
    client = NewSecureClient(ENCLAVE, REPO, api_key=API_KEY)

    url = f"https://{ENCLAVE}/v1/chat/completions"
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
