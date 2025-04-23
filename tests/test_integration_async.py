# tests/test_integration_async.py
import os
import pytest
from tinfoil import AsyncTinfoilAI

pytestmark = pytest.mark.integration

ENCLAVE = os.getenv("TINFOIL_ENCLAVE")
REPO    = os.getenv("TINFOIL_REPO")
API_KEY = os.getenv("TINFOIL_API_KEY", "tinfoil")

@pytest.fixture(autouse=True)
def skip_if_no_env():
    if not ENCLAVE or not REPO:
        pytest.skip("Missing TINFOIL_* env vars", allow_module_level=True)

@pytest.mark.asyncio
async def test_async_chat_integration():
    client = AsyncTinfoilAI(
        enclave=ENCLAVE,
        repo=REPO,
        api_key=API_KEY,
    )
    # perform a streaming chat completion
    stream = await client.chat.completions.create(
        model="llama3-3-70b",
        messages=[{"role": "user", "content": "Hello from async integration"}],
        stream=True,
    )
    collected = []
    async for chunk in stream:
        if chunk.choices[0].delta.content is not None:
            collected.append(chunk.choices[0].delta.content)
    output = "".join(collected)
    assert output, "Expected non-empty response from async streaming API"
