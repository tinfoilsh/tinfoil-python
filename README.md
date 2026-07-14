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

The inference router partitions prompt-prefix caches using both the authenticated API identity and `user_cache_secret`. Cache reuse requires the same identity, secret, model, and matching prompt prefix. Changing the identity or secret selects a different cache namespace, so those requests do not share cache entries or cache-hit timing.

`user_cache_secret` is sensitive application data used only for cache partitioning. It is not an API credential or encryption key. Do not log or expose it unnecessarily: a caller who can send requests with the same API identity and secret joins that cache namespace and can observe its cache-hit timing. The SDK adds it to eligible request bodies before they are protected for transport to the verified enclave.

By default, the SDK generates a random secret and persists it at `~/.tinfoil/user_cache_secret`, requesting mode `0600` where supported. Tinfoil SDKs using the same home directory reuse this value. This default is suitable for a single-user application, but it does not separate end users who share one application process or home directory. You can control the scope explicitly:

```python
from tinfoil import TinfoilAI

# Pin a stable, non-empty, opaque secret for this client.
client = TinfoilAI(api_key=api_key, user_cache_secret=secret)

# Or provision it via the environment
#   TINFOIL_USER_CACHE_SECRET=<secret>   use this value

# Multi-user services should scope every request to its end user;
# a non-empty string field set here wins over the client-level secret:
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Hi"}],
    extra_body={"user_cache_secret": per_user_secret},
)
```

`AsyncTinfoilAI` and `NewSecureClient` accept the same `user_cache_secret` parameter. Resolution order is a non-empty per-request string, a non-empty client value, a non-empty `TINFOIL_USER_CACHE_SECRET`, then the generated default. Empty client or environment values are treated as unset, and an empty per-request string is replaced with the resolved client value. The SDK leaves non-string values unchanged, and applications should not use them for cache scoping.

Multi-user services must provide a stable, non-empty, opaque value for each user (or group whose members may share cache-hit timing) on every eligible request. Do not use a raw user identifier, API key, or encryption key. A single client, environment, or generated value groups all requests using it under the same API identity. If persistence is unavailable, the SDK uses an in-memory value and cache continuity ends when the process exits.

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
