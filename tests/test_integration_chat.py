"""
Run only when TINFOIL_* environment variables are present.
The job that sets those vars lives in .github/workflows/integration.yml.
"""

import os
import pytest
from tinfoil import TinfoilAI

pytestmark = pytest.mark.integration  # allows pytest -m integration filtering

TEST_USER_CACHE_SECRET = "python-live-integration-cache-secret"

@pytest.fixture(scope="session")
def client() -> TinfoilAI:
    return TinfoilAI(
        api_key=os.getenv("TINFOIL_API_KEY", "tinfoil"),
        user_cache_secret=TEST_USER_CACHE_SECRET,
    )


def test_basic_chat_completion_with_cache_secret(client):
    response = client.chat.completions.create(
        messages=[{"role": "user", "content": "Hi"}],
        model="llama3-3-70b",
    )
    assert response.choices[0].message.content  # non‑empty string
    print(response.choices[0].message.content)

if __name__ == "__main__":
    pytest.main([__file__])