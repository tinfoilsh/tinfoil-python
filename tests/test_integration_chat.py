"""
Run only when TINFOIL_* environment variables are present.
The job that sets those vars lives in .github/workflows/integration.yml.
"""

import os
import pytest
from tinfoil import TinfoilAI

pytestmark = pytest.mark.integration  # allows pytest -m integration filtering

ENCLAVE = os.getenv("TINFOIL_ENCLAVE")
REPO    = os.getenv("TINFOIL_REPO")
if not ENCLAVE or not REPO:            # Skip locally unless dev opts‑in
    pytest.skip("Missing Tinfoil integration settings", allow_module_level=True)


@pytest.fixture(scope="session")
def client() -> TinfoilAI:
    return TinfoilAI(
        enclave=ENCLAVE,
        repo=REPO,
        api_key=os.getenv("TINFOIL_API_KEY", "tinfoil"),
    )


def test_basic_chat_completion(client):
    response = client.chat.completions.create(
        messages=[{"role": "user", "content": "Say hello to integration tests"}],
        model="llama3-3-70b",
    )
    assert response.choices[0].message.content  # non‑empty string

