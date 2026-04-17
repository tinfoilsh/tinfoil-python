# Tinfoil Python Library

![PyPI - Version](https://img.shields.io/pypi/v/tinfoil)
[![SDK Test](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/sdk-test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/sdk-test.yml)
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
