# Tinfoil Python Client

![PyPI - Version](https://img.shields.io/pypi/v/tinfoil)
[![SDK Test](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-python/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/python-sdk)

A Python client for verifiably private AI inference with Tinfoil. Its HTTP clients verify the enclave's attestation before sending any request, and an OpenAI client built on top of them gives you the [OpenAI Python client](https://github.com/openai/openai-python)'s API. The enclave and router clients pin the TLS connection to the attested key by default, so only the verified enclave can read the request, headers included. To send their requests through your own proxy, use `transport=EHBP(proxy_url=...)`, which encrypts request and response bodies to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp) but leaves the method, URL and headers visible to the proxy. The gateway clients always use EHBP, so Tinfoil's gateway sees the method, URL and headers of their requests.

Coming from 0.15 or an earlier 0.16 pre-release? [MIGRATION.md](MIGRATION.md) maps every old name to its replacement.

## Installation

Requires Python 3.11 or later.

```bash
pip install 'tinfoil[openai]'
```

The `openai` extra installs the [OpenAI Python client](https://github.com/openai/openai-python), which the OpenAI clients need. `pip install tinfoil` alone installs the verifier and the HTTP clients; importing an OpenAI name from it then raises a `ModuleNotFoundError` that names the extra.

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

`create_client` discovers Tinfoil's router, verifies it and returns an `OpenAIClient`, an `openai.OpenAI` subclass that sends every request over the attested connection. It takes the `openai` package's options (`api_key`, `timeout`, `max_retries`, `default_headers` and so on) and nothing else; for the route options below, create a `RouterHTTPClient` and pass it to `OpenAIClient`. The SDK sets the base URL of every OpenAI client itself, so a `base_url` or `data_residency` option, or `OPENAI_BASE_URL` in the environment, has no effect. The `openai` options that would choose a websocket URL or exchange a token outside the attested connection, `provider`, `websocket_base_url` and `workload_identity`, raise `ConfigurationError` on every OpenAI client and copy when they are set; a value of `None` counts as unset and is ignored. Every method and type of the OpenAI client is unchanged, except the websocket entry points: the `realtime` resource, its `beta.realtime` alias, and the `connect` methods of `responses`, `beta.responses`, `live`, `live.sideband` and `live.forks` raise `ConfigurationError`, because a websocket can't use the attested HTTP client and would bypass the attested connection. The HTTP methods of those resources, such as `responses.create`, work as before.

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

## The HTTP clients and the OpenAI client

The SDK is layered. An HTTP client carries a route, its verification and its transport: `EnclaveHTTPClient` for one enclave, `RouterHTTPClient` for the router that discovery chooses, and `GatewayHTTPClient` for the gateway. Each exposes an `httpx.Client` as `http_client`, whose requests reach only the verified route; a request to any other origin is refused. `OpenAIClient(http_client)` builds an `openai.OpenAI` client on top of any of them, without network I/O, and `AsyncOpenAIClient` does the same for the asynchronous HTTP clients. An OpenAI client takes only these HTTP clients; anything else is a `ConfigurationError`.

## Talking to one enclave

`create_client` sends to the router that discovery chooses. To talk to one enclave instead, name its host and what it must be running; the client verifies the enclave before it returns. The second argument, the trust, names who vouches for the enclave's config:

| Trust | Accepts |
| --- | --- |
| `RepoPin(repo)` | v2 collateral for a GitHub repository, `owner/name[@tag][@sha256:digest]` |
| `ProjectPin(project, registry_ids=None)` | v3 collateral for a config registry project, `org/project[@revision][@sha256:digest]`, that Tinfoil's public registry endorses, or one of `registry_ids`. An empty list is a `ConfigurationError`; list `tinfoil.verifier.PUBLIC_REGISTRY_ID` to keep the public registry beside your own |
| `SignedBy(keys, project=None)` | v3 configs that your own ECDSA P-256 keys signed, optionally restricted to `project` |
| `AuthorizedBy(authorize)` | v3 configs that your callback accepts |
| `EmbeddedConfig(data, name="")` | v3 collateral for exactly the JSON config bytes that you supply |
| `EitherPin(repo, project)` | v2 collateral for `repo` or v3 collateral for `project`, for the migration from v2 to v3 |

Each is a frozen dataclass, and a value of any other type, such as a bare string, is a `ConfigurationError`.

```python
import os

from tinfoil import EitherPin, EnclaveHTTPClient, OpenAIClient

http_client = EnclaveHTTPClient(
    "inference.tinfoil.sh",
    EitherPin("tinfoilsh/confidential-model-router", "tinfoilsh/confidential-model-router"),
)
client = OpenAIClient(http_client, api_key=os.environ["TINFOIL_API_KEY"])
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Hi"}],
)

# Requests outside the OpenAI API go through the HTTP client; build URLs from base_url, which ends in a slash.
response = http_client.http_client.get(http_client.base_url + "v1/models", timeout=30)
print(response.status_code, response.text)
```

The OpenAI client sends to `/v1/` under the HTTP client's `base_url`: the enclave's origin on a direct connection, the proxy URL with EHBP (see below), or the gateway's URL. Pass `api_path="/openai/v1"` to `OpenAIClient` for an API mounted elsewhere. It must be an RFC 3986 absolute path without a query, a fragment, an encoded slash or backslash or a `.` or `..` segment; anything else, including an empty path, is a `ConfigurationError`, so leave `api_path` out for `/v1/`. `client.http_client` is the HTTP client that an OpenAI client sends through, and `http_client.trust` is the trust that the enclave is verified under. `RouterHTTPClient()` takes no trust: the router is always verified against its own repository.

## Sending through a proxy

A pinned TLS connection cannot pass through a proxy, so a proxy needs the EHBP transport, which seals request and response bodies to the attested key instead. The proxy forwards the bodies without being able to read them, but the method, URL and headers, the API key included, stay visible to it, so it must be one that you trust with them and must use HTTPS (plain HTTP is accepted only for a loopback address). Requests carry an `X-Tinfoil-Enclave-Url` header that names the enclave to forward to.

```python
import os

from tinfoil import EHBP, OpenAIClient, RouterHTTPClient

http_client = RouterHTTPClient(transport=EHBP(proxy_url="https://proxy.example.com/tinfoil"))
client = OpenAIClient(http_client, api_key=os.environ["TINFOIL_API_KEY"])
```

The proxy URL is where the proxy is mounted, not the API's base URL: the OpenAI client above sends to `https://proxy.example.com/tinfoil/v1/`, and the HTTP client's `base_url` is `https://proxy.example.com/tinfoil/`. `EnclaveHTTPClient` takes the same `transport`, and refuses a proxy URL on the enclave's own origin; leave the proxy URL unset to connect directly. `transport=TLS()` is the default.

## Reaching only your own origin

An attestation document and the router list are fetched directly by default: from each enclave, and from `https://atc.tinfoil.sh/routers`. A client that may reach only one origin, such as one behind a strict content security policy, or one that should not reveal its IP address to enclaves, fetches them through relays on that origin instead, beside an EHBP proxy for the requests themselves:

```python
import os

from tinfoil import EHBP, AttestationRelay, OpenAIClient, RouterHTTPClient, RouterListRelay

http_client = RouterHTTPClient(
    transport=EHBP(proxy_url="https://app.example.com/tinfoil"),
    fetch_attestation=AttestationRelay("https://app.example.com/attestation"),
    fetch_router_list=RouterListRelay("https://app.example.com/atc"),
)
client = OpenAIClient(http_client, api_key=os.environ["TINFOIL_API_KEY"])
```

The attestation relay serves `GET {url}/.well-known/tinfoil-attestation?nonce=...&enclave=...` by forwarding it to the enclave that `enclave` names, and the router-list relay serves `GET {url}/routers` by forwarding it to `https://atc.tinfoil.sh/routers`. Relay URLs follow the proxy URL's rules (HTTPS, or HTTP to a loopback address) and are checked when the client is created. `EnclaveHTTPClient` takes `fetch_attestation` too.

`fetch_attestation` and `fetch_router_list` also take your own callables: `fetch_attestation(host, nonce)` returns the raw document, and `fetch_router_list()` the candidate hosts; the asynchronous clients take `async` callables. Neither is trusted. The client verifies every document as it verifies one that it fetched itself, so a fetcher can make verification fail but cannot make an enclave pass; discovery shuffles the list, verifies each router that it tries and falls back to `inference.tinfoil.sh`. An exception from a document fetcher is a `NetworkError` caused by it, unless it already is a client error, such as an `AttestationError`, which passes through unchanged; an exception from a router-list fetcher counts as an empty list. Since a document does not name the host that serves it, the list source is trusted not to name a host that would relay another router's attestation: with EHBP, that host would see the request headers, the API key included, although not the sealed bodies.

## The gateway

Tinfoil's gateway serves many models behind one URL; a gateway client seals each request to a verified replica of the model that the request names. `model_pins` pins a model to the repository that its replicas must run. A gateway client serves only the models that it has pins for, so it requires at least one pin, and a request for any other model fails with a `ConfigurationError` without contacting a replica. `policy` applies to the pins that set none; a pin's own `policy` replaces it. The gateway clients are experimental and may change in a later release.

```python
import os

from tinfoil import GatewayHTTPClient, ModelPin, OpenAIClient

http_client = GatewayHTTPClient(
    model_pins={"glm-5-3": ModelPin("tinfoilsh/confidential-glm5-3-nvfp4")},
)
client = OpenAIClient(http_client, api_key=os.environ["TINFOIL_API_KEY"])
```

The gateway's `url` is its origin, `https://inference-gateway.tinfoil.sh/` by default, or the URL that it is mounted under, never the API path: as under an EHBP proxy URL, `OpenAIClient` joins its `api_path`, `/v1/` by default, under it, and the client fetches the catalog and relays attestation under it too, so that `url="https://gateway.example.com/tinfoil"` sends chat completions to `https://gateway.example.com/tinfoil/v1/chat/completions`. `GatewayHTTPClient` also has `models()` for the catalog's model names and `ensure_verified(model)` for the report of a model's verification.

## Reading the verification

Each verification produces a verification report, a `tinfoil.verifier.VerificationReport`: the outcome of each step (`envelope`, `provenance`, `quote` and `policy`), its `verified_facts` when no step failed (a step may be skipped, as provenance is when every reference value is embedded), `metadata.verified_at`, recorded from the local clock, and, in a report that a client hands out, `metadata.host`, the host that the client contacted for the document: the enclave, the router that a router client chose, or a gateway replica. The host is what the client connected to, not an attested fact, so it proves nothing about the enclave; a report from the verifier itself has no host. The verified facts, a `VerifiedFacts`, are what the attestation document proved, such as `code_tag`, `code_digest`, `config_repo`, `enclave_measurement`, `tls_public_key_fp`, `hpke_public_key` and `freshness_expires_at`. `to_dict()` and `to_json()` write a report in the JSON form that every Tinfoil SDK writes, so that a report can be shown or passed on, for example to a browser: snake_case keys, a `schema_version`, lowercase hex and RFC 3339 times in UTC. The JSON is for display and transport only, and it never authorizes anything: no API reads it back into a report, anyone can write one, and a client binds a connection only to the verified facts of a verification that it ran itself.

On an enclave or router client, `client.http_client.ensure_verified()` returns the report of a verification that is valid now, verifying again first if the cached one is no longer valid, and `reverify()` verifies again even if the cached one is still valid. Without I/O, `current_verification()` returns the report of the verification that requests are bound to now, or `None`: before the first success, after a failure discarded the verification (an `AttestationError` on re-verification, or a key rejection), and once its freshness deadline has passed. A `NetworkError` or another failure that keeps the cached verification leaves it unchanged while that verification is fresh. `last_verification_attempt()` returns the most recent attempt, without I/O, as a `(report, error)` tuple: the report and `None` when it passed, and `None` and the error that the client raised when it failed, or `(None, None)` before the first attempt. Every attempt counts: the first verification, its retry, a refresh after expiry or a key rotation, and `reverify()`. A report that it returns may have expired since.

Which to use when: a health or readiness check calls `ensure_verified()`, which returns at once while the cached verification is valid and verifies when it isn't. The clients don't verify again in the background, so `current_verification()` is `None` between a verification's expiry and the next request, and a check that reads it would fail then. A status display shows `current_verification()` for the verification that requests use and `last_verification_attempt()` for the outcome of the latest attempt. Live status and logging use `on_verification_attempt=`, which sees every attempt, including retries that `last_verification_attempt()` has already moved past.

When the verifier rejects a document, the client raises an `AttestationError` whose `__cause__` is the verifier's `VerificationError`, and that error's `report` shows the step that failed and the partial facts that the steps before it established: the expected facts that provenance authenticated, and the facts that the document claims, such as its key fingerprints and, once the quote authenticated, its CPU measurement. The key fingerprints in a failed report are unverified, and a failed report holds the keys only as fingerprints: channel keys come only from the `verified_facts` of a report that passed, and only they can bind a connection. A failed fetch is a `NetworkError`, and a `verification_check` rejection an `AttestationError` of its own, so neither has a report.

When a re-verification fails with an `AttestationError`, whether it is a call to `reverify()` or a refresh that the client makes on its own, the client discards the verification that it was replacing and that verification's connections, so that no later request is sent under it: the next request verifies again, and fails if the enclave still doesn't verify. A newer verification that was published while the failed re-verification ran is kept. A `NetworkError`, a `ConfigurationError` or a cancellation keeps a cached verification that is still fresh.

```python
import os

from tinfoil import AttestationError, create_client
from tinfoil.verifier import VerificationError

client = create_client(api_key=os.environ["TINFOIL_API_KEY"])

report = client.http_client.ensure_verified()
facts = report.verified_facts
assert facts is not None
print(facts.code_tag, facts.code_digest)
print(report.to_json(indent=2))

try:
    client.http_client.reverify()
except AttestationError as err:
    if isinstance(err.__cause__, VerificationError) and err.__cause__.report is not None:
        print(err.__cause__.report.failed_step)

current = client.http_client.current_verification()  # what requests are bound to now, or None
last, error = client.http_client.last_verification_attempt()  # the most recent attempt
```

To watch every attempt as it happens, pass `on_verification_attempt=` to an HTTP client: it is called with the host of the enclave that was verified and the attempt's report and error, the same pair that `last_verification_attempt()` returns, once for each attempt, including each router that discovery tries and each gateway replica. The client holds none of its locks while it calls it, so the callback may call the client. It cannot change the outcome: an exception that it raises is logged to the `tinfoil` logger and otherwise ignored, so that a failing callback never turns a verification into a failure or makes the client skip a router or replica. A decision about trust belongs in `verification_check`.

```python
from tinfoil import RouterHTTPClient
from tinfoil.verifier import VerificationReport


def log(host: str, report: VerificationReport | None, error: Exception | None) -> None:
    print(host, "verified" if report is not None else f"failed: {error}")


http_client = RouterHTTPClient(on_verification_attempt=log)
```

A gateway client verifies one replica per model, so its accessors differ: `ensure_verified(model)` returns the report of a valid verification of a replica serving `model`, and `reverify(model)` verifies again the replica that `ensure_verified(model)` would return, moving on to the next replica in the same order when an `AttestationError` discards one. `replicas()` is a list of `ReplicaVerification` records, one per replica that the client has tried and still retains (a replica reached by redirect may not be in the catalog), failed replicas included, each with the replica's `host`, the `models` requested through it, the `reference` that it was verified against, the `pinned_model`, its `current` verification, which follows the rule of `current_verification()` for that replica, and its `last_attempt` as a `(report, error)` tuple.

To reject a verified enclave by its facts, pass `verification_check=` to an HTTP client; it receives the `VerifiedFacts` of each verification that passes the verifier. To change what the verifier itself requires, pass `policy=` a `tinfoil.verifier.Policy`: `pinned_registers` pins registers that the enclave must have measured, `freshness_max_age` bounds how old a witness or approval may be, and `artifacts` supplies your own runtime and platform artifacts or freshness keys. Every HTTP client takes `policy`, and a gateway `ModelPin` takes one that replaces the gateway's for that model. The client builds its verifier from the trust and the policy, so an invalid policy is a `ConfigurationError` before any network I/O.

```python
from tinfoil import EnclaveHTTPClient, RepoPin
from tinfoil.verifier import Policy, parse_expected_sevsnp

http_client = EnclaveHTTPClient(
    "enclave.example.com",
    RepoPin("acme/inference"),
    policy=Policy(pinned_registers=parse_expected_sevsnp("ab" * 48)),
)
```

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

The router partitions prompt caches by API identity and a `user_cache_secret` that the client adds to eligible requests. The router and gateway clients, `create_client` included, take the secret from their `user_cache_secret` option and otherwise use a random secret that is generated in memory once per process and shared by every client in it. The SDK reads no environment variable or file for the secret, so prompt-cache hits are not shared across processes unless the application passes a stable `user_cache_secret` itself. The exception is a process created with `os.fork` after its parent has generated the secret, for example by creating a client: it keeps the parent's secret, so prefork workers of one application share a cache namespace. Multi-user services should scope each request to its end user, with a per-request value or a client-level one on `RouterHTTPClient`:

```python
import os

from tinfoil import OpenAIClient, RouterHTTPClient

secret = os.environ["MY_CACHE_SECRET"]
per_user_secret = os.environ["MY_USER_CACHE_SECRET"]

# A stable, opaque secret for this client.
client = OpenAIClient(RouterHTTPClient(user_cache_secret=secret), api_key=os.environ["TINFOIL_API_KEY"])

# A per-request value wins over the client-level secret.
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Hi"}],
    extra_body={"user_cache_secret": per_user_secret},
)
```

An enclave client has no cache-secret option and sends request bodies as they are, since other enclaves do not read the field; to scope the prompt cache through an enclave client that points at a router, set `user_cache_secret` in each request body, as with `extra_body` above. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching) for the resolution order and guidance on choosing a scope.

## Timeouts

`timeout=` on an OpenAI client is the `openai` package's per-request timeout, as it is on `openai.OpenAI`. `timeout=` on an HTTP client is the `httpx` timeout of the attested client: the attestation fetches, which are bounded as a whole at 30 seconds besides, and the requests sent through its `http_client` directly. It defaults to `DEFAULT_HTTP_TIMEOUT`, five seconds to connect and ten minutes for each read.

```python
import os

import httpx

from tinfoil import OpenAIClient, RouterHTTPClient

client = OpenAIClient(
    RouterHTTPClient(timeout=httpx.Timeout(60.0, connect=5.0)),  # the attested client's
    timeout=120.0,  # the openai package's, per request
    api_key=os.environ["TINFOIL_API_KEY"],
)
```

## Closing

Every client is a context manager and has `close()`. Closing releases the connections and stops re-verification; afterward, verification and catalog methods raise `ConfigurationError`, while requests through the closed `http_client` (including OpenAI requests) raise `RuntimeError`. Closing an OpenAI client closes the HTTP client that it sends through, as the `openai` package closes an `http_client` that it is given, and copies made with `with_options` share it, so closing a copy closes the original's too.

```python
import os

from tinfoil import create_client

with create_client(api_key=os.environ["TINFOIL_API_KEY"]) as client:
    models = client.models.list()
```

## Verifying attestation documents yourself

The verifier that every client uses is its own package, `tinfoil.verifier`. It appraises an attestation document that you fetched against the repository or registry project that you trust and returns a verification report whose verified facts are what the document proved, or raises a `VerificationError` that carries the report of the rejection; it opens no connections. See [its README](src/tinfoil/verifier/README.md) for the API.

```python
from tinfoil.verifier import Verifier, random_nonce

verifier = Verifier()
nonce = random_nonce()
```

### Pinning your own TLS connection

In the default TLS transport mode, the enclave and router clients pin their TLS connections for you; in EHBP mode, and in the gateway clients, they seal request bodies to the attested key instead. If you bring your own transport, check that the connection presents the attested key yourself: after the handshake and before the first byte is written, compare `tinfoil.verifier.cert_pubkey_fp` of the peer certificate with the `tls_public_key_fp` of the report's verified facts. That is `None` when the document endorses no TLS key, so refuse the connection then too. The check adds to the certificate validation that the TLS context performs; it does not replace it.

```python
import socket
import ssl

from tinfoil.verifier import VerifiedFacts, cert_pubkey_fp


def open_pinned(host: str, verified: VerifiedFacts) -> ssl.SSLSocket:
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
