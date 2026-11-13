# Tinfoil Python Client

![PyPI - Version](https://img.shields.io/pypi/v/tinfoil)
[![SDK Test](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/python-sdk)

A Python client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Python client](https://github.com/openai/openai-python) with the same API, and before sending any request it verifies the enclave's attestation. The enclave and router clients then pin the TLS connection to the attested key, so only the verified enclave can read the request, headers included. To send their requests through your own proxy, set `transport_mode="ehbp"`, which encrypts request and response bodies to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp) but leaves the method, URL and headers visible to the proxy. The gateway clients always use EHBP, so Tinfoil's gateway sees the method, URL and headers of their requests.

Coming from 0.15? The client API and the verifier are new; [MIGRATION.md](MIGRATION.md) maps every old name to its replacement.

## Installation

Requires Python 3.11 or later.

```bash
pip install tinfoil
```

## Quick Start

```python
import os

from tinfoil import create_client

client = create_client(api_key=os.environ["TINFOIL_API_KEY"])

# Enclave verification and encryption happen automatically.
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",  # see https://docs.tinfoil.sh/models/catalog
    messages=[{"role": "user", "content": "Hi"}],
)
print(chat_completion.choices[0].message.content)
```

`create_client` discovers Tinfoil's router, verifies it and returns an `openai.OpenAI` subclass that sends every request over the attested connection. It takes the `openai` package's options (`api_key`, `timeout`, `max_retries`, `default_headers` and so on) and nothing else; the route options below belong to `RouterOpenAIClient`, which it is built on. The `openai` options that would choose another base URL or exchange a token outside the attested connection, `data_residency`, `provider`, `websocket_base_url` and `workload_identity`, raise `ConfigurationError` on every OpenAI client and copy when they are set; a value of `None` counts as unset and is ignored. Every method and type of the OpenAI client is unchanged, except the websocket entry points: the `realtime` resource and the `connect` methods of `responses`, `beta.responses`, `live`, `live.sideband` and `live.forks` raise `ConfigurationError`, because a websocket can't use the attested HTTP client and would bypass the attested connection. The HTTP methods of those resources, such as `responses.create`, work as before.

### Async

`create_async_client` returns an `openai.AsyncOpenAI` subclass; `await` it and each call.

```python
import asyncio
import os

from tinfoil import create_async_client


async def main() -> None:
    client = await create_async_client(api_key=os.environ["TINFOIL_API_KEY"])
    async with client:
        chat_completion = await client.chat.completions.create(
            model="llama3-3-70b",
            messages=[{"role": "user", "content": "Hi"}],
        )
    print(chat_completion.choices[0].message.content)


asyncio.run(main())
```

### Streaming

```python
import os

from tinfoil import create_client

client = create_client(api_key=os.environ["TINFOIL_API_KEY"])

stream = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Say this is a test"}],
    stream=True,
)
for chunk in stream:
    if chunk.choices and chunk.choices[0].delta.content is not None:
        print(chunk.choices[0].delta.content, end="", flush=True)
print()
```

### Audio transcription

```python
import os

from tinfoil import create_client

client = create_client(api_key=os.environ["TINFOIL_API_KEY"])

with open("audio.mp3", "rb") as audio_file:
    transcription = client.audio.transcriptions.create(
        file=audio_file,
        model="whisper-large-v3-turbo",
    )
print(transcription.text)
```

## Talking to one enclave

`create_client` sends to the router that discovery chooses. To talk to one enclave instead, name its host and the repository that it must be running; the client verifies the enclave against that repository before it returns.

```python
import os

from tinfoil import EnclaveOpenAIClient

client = EnclaveOpenAIClient(
    "inference.tinfoil.sh",
    "tinfoilsh/confidential-model-router",
    api_key=os.environ["TINFOIL_API_KEY"],
)
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Hi"}],
)
```

For requests outside the OpenAI API, `EnclaveHTTPClient` verifies the same enclave and exposes an `httpx.Client` whose requests reach only it; a request to any other origin is refused. Build URLs from `base_url`, which ends in a slash:

```python
from tinfoil import EnclaveHTTPClient

client = EnclaveHTTPClient("inference.tinfoil.sh", "tinfoilsh/confidential-model-router")

response = client.http_client.get(client.base_url + "v1/models", timeout=30)
print(response.status_code, response.text)
```

`RouterHTTPClient()` is the same client for the router that discovery chooses. Each OpenAI client exposes the attested client that it sends through as `client.http_client`, so the facts below are read the same way from either.

## Sending through a proxy

A pinned TLS connection cannot pass through a proxy, so a proxy needs the `"ehbp"` transport mode, which seals request and response bodies to the attested key instead. The proxy forwards the bodies without being able to read them, but the method, URL and headers, the API key included, stay visible to it, so it must be one that you trust with them and must use HTTPS (plain HTTP is accepted only for a loopback address). Requests carry an `X-Tinfoil-Enclave-Url` header that names the enclave to forward to.

```python
import os

from tinfoil import RouterOpenAIClient

client = RouterOpenAIClient(
    transport_mode="ehbp",
    base_url="https://proxy.example.com/v1/",
    api_key=os.environ["TINFOIL_API_KEY"],
)
```

On the OpenAI clients `base_url` is this route option, not the `openai` package's: it is the URL that requests are sent to, verbatim, so it carries the API prefix that the proxy expects. On the HTTP clients it becomes `base_url` as well. `EnclaveOpenAIClient` and `EnclaveHTTPClient` take the same two options.

## The gateway

Tinfoil's gateway serves many models behind one URL; a gateway client seals each request to a verified replica of the model that the request names. `model_pins` pins a model to the repository that its replicas must run, and `pinned_models_only=True` refuses models that are not pinned. The gateway clients are experimental and may change in a later release.

```python
import os

from tinfoil import GatewayOpenAIClient, ModelPin

client = GatewayOpenAIClient(
    model_pins={"glm-5-3": ModelPin("tinfoilsh/confidential-glm5-3-nvfp4")},
    pinned_models_only=True,
    api_key=os.environ["TINFOIL_API_KEY"],
)
```

`GatewayHTTPClient` is the `httpx` form, with `models()` for the catalog's model names and `ensure_verified(model)` for a model's verification.

## Reading the verification

On an enclave or router client, `client.http_client.current` is the last successful verification, or `None` before the first; `ensure_verified()` returns one that is valid now, verifying again first if the cached one has expired. Both are a `tinfoil.verifier.Verification`: the facts that the attestation document proved, such as `code_tag`, `code_digest`, `config_repo`, `enclave_measurement`, `tls_public_key_fp`, `hpke_public_key` and `freshness_expires_at`, with `metadata.verified_at` recorded from the local clock. `to_json()` serializes the record.

```python
import os

from tinfoil import create_client

client = create_client(api_key=os.environ["TINFOIL_API_KEY"])

verified = client.http_client.ensure_verified()
print(verified.code_tag, verified.code_digest)
print(verified.to_json(indent=2))

current = client.http_client.current  # the same record, or None before the first verification
if current is not None:
    print(current.freshness_expires_at)
```

A gateway client verifies one replica per model, so its accessors differ: `ensure_verified(model)` returns a valid verification of a replica serving `model`, and `current` is a list of `ReplicaVerification` records, one per replica used so far and retained by the client (a replica reached by redirect may not be in the catalog), each with the replica's `host`, the `models` requested through it, the `reference` it was verified against and its `verification`.

To reject a verified enclave by its facts, pass `verification_check=` to a route client. To change what the verifier itself requires, pass `verifier=` a `tinfoil.verifier.Verifier`: `Verifier(pinned_registers=...)` pins registers that the enclave must have measured, `freshness_max_age` bounds how old a witness or approval may be, and the trust options supply your own roots.

## Errors

The client raises three errors, and the category alone says what to do: `ConfigurationError` for invalid options or a closed client (fix the caller), `NetworkError` when attestation material or the router list could not be fetched (retry later), and `AttestationError` when the enclave could not be trusted (do not proceed). All three subclass `TinfoilError`; `str(err)` is the message and `err.category` names the category. They reach a call on the OpenAI client as themselves, not wrapped in the `openai` package's `APIConnectionError`, and `max_retries` does not retry them: the `openai` package retries only the errors of its own HTTP stack. Its own errors pass through unchanged and are re-exported from `tinfoil`, so one import covers both.

```python
import os

from tinfoil import APIStatusError, AttestationError, ConfigurationError, NetworkError, create_client

try:
    client = create_client(api_key=os.environ["TINFOIL_API_KEY"], max_retries=2)
    chat_completion = client.chat.completions.create(
        model="llama3-3-70b",
        messages=[{"role": "user", "content": "Hi"}],
    )
except ConfigurationError as err:
    print("fix the caller:", err)
except NetworkError as err:
    print("retry later:", err)
except AttestationError as err:
    print("do not proceed:", err)
except APIStatusError as err:
    print("the service answered", err.status_code)
```

`tinfoil_error(err)` finds the client error that another exception was raised from, for code that wraps errors of its own.

## Prompt cache scoping

The router partitions prompt caches by API identity and a `user_cache_secret` that the client adds to eligible requests. The router and gateway clients, `create_client` included, take the secret from the `TINFOIL_USER_CACHE_SECRET` environment variable or from `~/.tinfoil/user_cache_secret`, generating and persisting one there if needed, which is suitable for single-user applications. Multi-user services should scope each request to its end user, with a per-request value or a client-level one on `RouterOpenAIClient`:

```python
import os

from tinfoil import RouterOpenAIClient

secret = os.environ["MY_CACHE_SECRET"]
per_user_secret = os.environ["MY_USER_CACHE_SECRET"]

# A stable, opaque secret for this client.
client = RouterOpenAIClient(user_cache_secret=secret, api_key=os.environ["TINFOIL_API_KEY"])

# A per-request value wins over the client-level secret.
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Hi"}],
    extra_body={"user_cache_secret": per_user_secret},
)
```

An enclave client uses only the value that it is given, since other enclaves do not read the field. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching) for the resolution order and guidance on choosing a scope.

## Timeouts

`timeout=` on any OpenAI client is the `openai` package's per-request timeout, as it is on `openai.OpenAI`. `http_timeout=` on `EnclaveOpenAIClient`, `RouterOpenAIClient` and `GatewayOpenAIClient` is the `httpx` timeout of the attested client: the attestation fetches, which are bounded as a whole at 30 seconds besides, and the requests sent through `client.http_client` directly. The HTTP clients call the same option `timeout=`. Both default to `DEFAULT_HTTP_TIMEOUT`, five seconds to connect and ten minutes for each read.

```python
import os

import httpx

from tinfoil import RouterOpenAIClient

client = RouterOpenAIClient(
    http_timeout=httpx.Timeout(60.0, connect=5.0),  # the attested client's
    timeout=120.0,  # the openai package's, per request
    api_key=os.environ["TINFOIL_API_KEY"],
)
```

## Closing

Every client is a context manager and has `close()`. Closing releases the connections and stops re-verification; afterward, verification and catalog methods raise `ConfigurationError`, while requests through the closed `http_client` (including OpenAI requests) raise `RuntimeError`. Copies made with `with_options` share the attested client, so closing a copy closes the original's too.

```python
import os

from tinfoil import create_client

with create_client(api_key=os.environ["TINFOIL_API_KEY"]) as client:
    models = client.models.list()
```

## Verifying attestation documents yourself

The verifier that every client uses is its own package, `tinfoil.verifier`. It appraises an attestation document that you fetched against the repository that you trust and returns the facts that it proved; it opens no connections. See [its README](src/tinfoil/verifier/README.md) for the API.

```python
from tinfoil.verifier import Verifier, random_nonce

verifier = Verifier()
nonce = random_nonce()
```

### Pinning your own TLS connection

In the default TLS transport mode, the enclave and router clients pin their TLS connections for you; in EHBP mode, and in the gateway clients, they seal request bodies to the attested key instead. If you bring your own transport, check that the connection presents the attested key yourself: after the handshake and before the first byte is written, compare `tinfoil.verifier.cert_pubkey_fp` of the peer certificate with the verification's `tls_public_key_fp`. That is `None` when the document endorses no TLS key, so refuse the connection then too. The check adds to the certificate validation that the TLS context performs; it does not replace it.

```python
import socket
import ssl

from tinfoil.verifier import Verification, cert_pubkey_fp


def open_pinned(host: str, verified: Verification) -> ssl.SSLSocket:
    expected = verified.tls_public_key_fp
    if expected is None:
        raise RuntimeError("the attestation document endorses no TLS key")
    context = ssl.create_default_context()
    raw = socket.create_connection((host, 443), timeout=10)
    try:
        tls = context.wrap_socket(raw, server_hostname=host)  # runs do_handshake()
    except BaseException:
        raw.close()
        raise
    try:
        leaf = tls.getpeercert(binary_form=True)
        if leaf is None or cert_pubkey_fp(leaf) != expected:
            raise RuntimeError("the enclave did not present the attested TLS key")
    except BaseException:
        tls.close()  # also when cert_pubkey_fp rejects a certificate that does not parse
        raise
    return tls  # only now send the request
```

## Development

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy
uv run pytest -m "not integration"

# Integration tests send inference requests with TINFOIL_API_KEY; verification itself needs no key.
export TINFOIL_API_KEY="..."
uv run pytest -m integration
```

The cross-SDK conformance suite runs against `conformance/tinfoil_conformance.py`. With a checkout of [tinfoil-conformance](https://github.com/tinfoilsh/tinfoil-conformance) beside this repository:

```bash
python3 ../tinfoil-conformance/tools/run_adapter.py --adapter "uv run python conformance/tinfoil_conformance.py"
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
