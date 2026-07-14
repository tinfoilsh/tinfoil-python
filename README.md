# Tinfoil Python Library

![PyPI - Version](https://img.shields.io/pypi/v/tinfoil)
[![SDK Test](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/python-sdk)

A Python client for secure AI model inference through Tinfoil.

## Installation

```bash
# With uv
uv add tinfoil

# With pip
pip install tinfoil
```

## Usage

The Tinfoil SDK automatically selects a router enclave and verifies it against the official GitHub repository. You just need to provide your API key:

```python
import os
from tinfoil import TinfoilAI

client = TinfoilAI(
    api_key=os.getenv("TINFOIL_API_KEY")
)

chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[
        {
            "role": "user",
            "content": "Hi",
        }
    ],
)
print(chat_completion.choices[0].message.content)
```

### Audio Transcription with Whisper

You can transcribe audio files using OpenAI's Whisper model:

```python
import os
from tinfoil import TinfoilAI

client = TinfoilAI(
    api_key=os.getenv("TINFOIL_API_KEY")
)

with open("audio.mp3", "rb") as audio_file:
    transcription = client.audio.transcriptions.create(
        file=audio_file,
        model="whisper-large-v3-turbo",
    )
print(transcription.text)
```

## Async Usage

Simply import `AsyncTinfoilAI` instead of `TinfoilAI` and use `await` with each API call:

```python
import os
import asyncio
from tinfoil import AsyncTinfoilAI

client = AsyncTinfoilAI(
    api_key=os.getenv("TINFOIL_API_KEY")
)

async def main() -> None:
    stream = await client.chat.completions.create(
        model="llama3-3-70b",
        messages=[{"role": "user", "content": "Say this is a test"}],
        stream=True,
    )
    async for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content is not None:
            print(chunk.choices[0].delta.content, end="", flush=True)
    print()

asyncio.run(main())
```

Functionality between the synchronous and asynchronous clients is otherwise identical.

## Low-level HTTP Endpoints

You can also perform arbitrary GET/POST requests that are verified:

```python
import os
from tinfoil import NewSecureClient

api_key = os.getenv("TINFOIL_API_KEY")
tfclient = NewSecureClient()

# GET example
resp = tfclient.get(
    "https://example.com/health",
    headers={"Authorization": f"Bearer {api_key}"},
    params={"query": "value"},
    timeout=30,
)
print(resp.status_code, resp.text)

# POST example
payload = {"key": "value"}
resp = tfclient.post(
    "https://example.com/analyze",
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    },
    json=payload,
    timeout=30,
)
print(resp.status_code, resp.text)
```

## Prompt Cache Scoping

The inference router partitions its prompt cache per API identity, so your cached prompts are never observable by other tenants. Within your tenant, the SDK scopes caching further with a `user_cache_secret`: requests carrying the same secret share cached prompt prefixes, requests carrying different secrets cannot observe each other's cache timing. The secret never reaches the model — the router consumes it to derive the cache namespace and strips it from the request.

By default the SDK generates a random secret and persists it at `~/.tinfoil/user_cache_secret` (mode `0600`, shared with the other Tinfoil SDKs on the same machine), so caching just works with per-machine scoping. You can control it explicitly:

```python
from tinfoil import TinfoilAI

# Pin the secret for this client (e.g. one stable value per end user)
client = TinfoilAI(api_key=api_key, user_cache_secret=secret)

# Or provision it via the environment
#   TINFOIL_USER_CACHE_SECRET=<secret>   use this value

# Servers that hold many end users' conversations should scope per request;
# a non-empty field set here wins over the client-level secret:
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Hi"}],
    extra_body={"user_cache_secret": per_user_secret},
)
```

`AsyncTinfoilAI` and `NewSecureClient` accept the same `user_cache_secret` parameter. Empty client or environment values are treated as unset. If the secret cannot be persisted (no home directory, read-only filesystem), the SDK falls back to an in-memory secret and warns once: cache continuity then resets on every process restart. Containerized deployments should set `TINFOIL_USER_CACHE_SECRET` to a stable non-empty value wherever cache sharing is intended.

## Security

Please report security vulnerabilities by emailing [security@tinfoil.sh](mailto:security@tinfoil.sh).

We aim to respond to (legitimate) security reports within 24 hours.

## Development

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) before following these instructions.

```bash
# Set up the development environment and install the package
uv sync

# Run all tests (requires the TINFOIL_API_KEY environment variable)
export TINFOIL_API_KEY="..."
uv run pytest

# Run unit tests
uv run pytest -m "not integration"

# Run integration tests (requires the TINFOIL_API_KEY environment variable)
export TINFOIL_API_KEY="..."
uv run pytest -m integration
```
