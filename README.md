# Tinfoil Python Library

![PyPI - Version](https://img.shields.io/pypi/v/tinfoil)

A Python client for secure AI model inference through Tinfoil.

## Installation

```bash
pip install tinfoil
```

## Usage

```python
from tinfoil import TinfoilAI

client = TinfoilAI(
    enclave="llama3-3-70b.model.tinfoil.sh",
    repo="tinfoilsh/confidential-llama3-3-70b",
    api_key="<API_KEY>",
)

chat_completion = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": "Hi",
        }
    ],
    model="llama3-3-70b",
)
print(chat_completion.choices[0].message.content)
```

## Async Usage

Simply import `AsyncTinfoilAI` instead of `TinfoilAI` and use `await` with each API call:

```python
import os
import asyncio
from tinfoil import AsyncTinfoilAI

client = AsyncTinfoilAI(
    enclave="llama3-3-70b.model.tinfoil.sh",
    repo="tinfoilsh/confidential-llama3-3-70b",
    api_key=os.environ.get("TINFOIL_API_KEY"),
)

async def main() -> None:
    # start a streaming chat completion
    stream = await client.chat.completions.create(
        model="llama3-3-70b",
        messages=[{"role": "user", "content": "Say this is a test"}],
        stream=True,
    )
    async for chunk in stream:
        print(chunk.choices[0].message.content, end="")
    print()

asyncio.run(main())
```

Functionality between the synchronous and asynchronous clients is otherwise identical.

## Low-level HTTP Endpoints

You can also perform arbitrary GET/POST requests that are verified:

```python
from tinfoil import NewSecureClient

tfclient = NewSecureClient(
    enclave="df-demo.model.tinfoil.sh",
    repo="tinfoilsh/confidential-df-demo",
    api_key="<API_KEY>",
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

- Linux
- Python 3.10 through 3.13

## Testing

Run unit and integration tests:

```bash
pytest -q
```

Integration tests require environment variables:

```bash
export TINFOIL_ENCLAVE="..."
export TINFOIL_REPO="..."
export TINFOIL_API_KEY="..."
pytest -q -m integration
```
