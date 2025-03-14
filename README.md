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
    enclave="inference.delta.tinfoil.sh",
    repo="tinfoilsh/provably-private-deepseek-r1",
    api_key="<API_KEY>",
)

chat_completion = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": "Hi",
        }
    ],
    model="deepseek-r1:70b",
)
print(chat_completion.choices[0].message.content)
```

## Requirements

- Linux
- Python 3.10 through 3.13
