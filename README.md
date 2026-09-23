# Tinfoil Python Client

![PyPI - Version](https://img.shields.io/pypi/v/tinfoil)
[![SDK Test](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/python-sdk)

A Python client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Python client](https://github.com/openai/openai-python) with the same API, and before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it.

For complete documentation, see the [Python SDK documentation](https://docs.tinfoil.sh/sdk/python-sdk).

## Installation

```bash
uv add tinfoil
# or
pip install tinfoil
```

## Quick Start

```python
import os
from tinfoil import TinfoilAI

client = TinfoilAI(api_key=os.environ["TINFOIL_API_KEY"])

# Enclave verification and encryption happen automatically.
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",  # see https://docs.tinfoil.sh/models/catalog
    messages=[{"role": "user", "content": "Hi"}],
)
print(chat_completion.choices[0].message.content)
```

### Async and streaming

Use `AsyncTinfoilAI` and `await` each call; the API is otherwise identical.

```python
import asyncio
import os
from tinfoil import AsyncTinfoilAI

client = AsyncTinfoilAI(api_key=os.environ["TINFOIL_API_KEY"])

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

### Audio transcription

```python
with open("audio.mp3", "rb") as audio_file:
    transcription = client.audio.transcriptions.create(
        file=audio_file,
        model="whisper-large-v3-turbo",
    )
print(transcription.text)
```

## Verification document

```python
document = client.get_verification_document()

print(document.release_tag)  # None when verifying against a pinned measurement
print(document.release_digest)
print(document.code_fingerprint)
print(document.enclave_fingerprint)
print(document.verifier)
print(document.verified_at)
```

`verified_at` is recorded from the local clock after successful verification. It is not an attested timestamp or a freshness guarantee.

## Prompt Cache Scoping

The router partitions prompt caches by API identity and a `user_cache_secret` that the SDK adds to eligible requests. By default it generates one and persists it at `~/.tinfoil/user_cache_secret`, which is suitable for single-user applications. Multi-user services should scope each request to its end user:

```python
# Pin a stable, opaque secret for this client (or set TINFOIL_USER_CACHE_SECRET).
client = TinfoilAI(api_key=api_key, user_cache_secret=secret)

# A per-request value wins over the client-level secret.
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Hi"}],
    extra_body={"user_cache_secret": per_user_secret},
)
```

`AsyncTinfoilAI` and `NewSecureClient` accept the same parameter. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching) for resolution order and guidance on choosing a scope.

## Advanced Functionality

`NewSecureClient` makes verified GET and POST requests to any path on the enclave. Requests to other origins are rejected.

```python
import os
from tinfoil import NewSecureClient

api_key = os.environ["TINFOIL_API_KEY"]
tfclient = NewSecureClient()

resp = tfclient.get(
    f"https://{tfclient.enclave}/health",
    headers={"Authorization": f"Bearer {api_key}"},
    timeout=30,
)
print(resp.status_code, resp.text)
```

## API Documentation

This library is a drop-in replacement for the [official OpenAI Python client](https://github.com/openai/openai-python). All methods and types are identical; see the [OpenAI Python client documentation](https://github.com/openai/openai-python) for API usage.

## Development

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
uv sync
uv run pytest -m "not integration"

# Integration tests require TINFOIL_API_KEY
export TINFOIL_API_KEY="..."
uv run pytest -m integration
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
