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
