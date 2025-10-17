# tests/test_integration_async.py
import os
import pytest
from tinfoil import AsyncTinfoilAI, get_router_address

pytestmark = pytest.mark.integration

REPO    = "tinfoilsh/confidential-model-router"
API_KEY = os.getenv("TINFOIL_API_KEY", "tinfoil")

@pytest.mark.asyncio
async def test_async_chat_integration():
    enclave = get_router_address()
    assert enclave is not None

    client = AsyncTinfoilAI(
        enclave=enclave,
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
