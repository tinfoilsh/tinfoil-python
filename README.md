# Tinfoil Python Library

![PyPI - Version](https://img.shields.io/pypi/v/tinfoil)
[![Integration](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/integration.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/integration.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/python-sdk)

A Python client for secure AI model inference through Tinfoil.

## Installation

```bash
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

tfclient = NewSecureClient(
    enclave="df-demo.model.tinfoil.sh",
    repo="tinfoilsh/confidential-df-demo",
    api_key=os.getenv("TINFOIL_API_KEY"),
)

# GET example
resp = tfclient.get(
    "https://df-demo.model.tinfoil.sh/health",
    params={"query": "value"},
    timeout=30,
)
print(resp.status_code, resp.text)

# POST example
payload = {"key": "value"}
resp = tfclient.post(
    "https://df-demo.model.tinfoil.sh/analyze",
    headers={"Content-Type": "application/json"},
    json=payload,
    timeout=30,
)
print(resp.status_code, resp.text)
```

## Requirements

- Python 3.10 through 3.13

## Testing

Run unit and integration tests:

```bash
pytest -q
```

Integration tests require the `TINFOIL_API_KEY` environment variable:

```bash
export TINFOIL_API_KEY="..."
pytest -q -m integration
```
