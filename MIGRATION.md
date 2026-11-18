# Migrating from 0.15 to the v3 client

The client verifies enclaves with version 3 of Tinfoil's attestation format, through a verifier that is its own package, `tinfoil.verifier`. The OpenAI wrappers are now `openai` client subclasses, so every resource of the `openai` package is available and the wrapper is the OpenAI client itself; the low-level clients are `httpx` clients. The table maps each name and option of 0.15 to its replacement; a sentence follows where the mapping is not one to one.

| 0.15 | v3 |
| --- | --- |
| `TinfoilAI(api_key=k)` | `create_client(api_key=k)` |
| `TinfoilAI(enclave=host, repo=r, api_key=k)` | `EnclaveOpenAIClient(host, Pin(repo=r), api_key=k)`. `host` and the pin are positional and required. The pin is a `tinfoil.Pin`: `Pin(repo=r)` for a GitHub repository, `Pin(project=p)` for a config registry project, or both to accept either. A call that passed a string, `EnclaveHTTPClient(host, "org/app")`, becomes `EnclaveHTTPClient(host, Pin(repo="org/app"))`; a bare string or `None` is a `ConfigurationError` (a `UsageError` from the verifier), and so is `Pin()` unless the `verifier` configures its own config trust. The clients' `repo` property is `pin`. |
| `AsyncTinfoilAI(...)` | `await create_async_client(...)` for the router, `await AsyncEnclaveOpenAIClient.create(host, Pin(repo=r), ...)` for one enclave. Every asynchronous client is built with `await Cls.create(...)`, since the constructor verifies. |
| `client.chat`, `client.embeddings`, `client.audio` | Unchanged, and every other resource of the `openai` package with them, except the websocket entry points: `realtime`, its `beta.realtime` alias and the `connect` methods of `responses`, `beta.responses`, `live`, `live.sideband` and `live.forks` raise `ConfigurationError`, because a websocket can't use the attested HTTP client and would bypass the attested connection. The `websocket_base_url` option is refused for the same reason when it is set; `None` counts as unset. |
| `client.client` | The client itself: it is an `openai.OpenAI`. |
| `client.enclave` | `client.http_client.enclave` |
| `NewSecureClient().get(url, headers, timeout)`, `.post(...)` | `RouterHTTPClient()`, or `EnclaveHTTPClient(host, Pin(repo=repo))`, then `c.http_client.get(c.base_url + "v1/...", headers=..., timeout=...)`, which returns an `httpx.Response`. `http_client` is an `httpx.Client` with every method, and `base_url` ends in a slash. |
| `SecureClient`, `make_secure_http_client()`, `make_secure_async_http_client()` | `EnclaveHTTPClient(host, Pin(repo=repo)).http_client` and `(await AsyncEnclaveHTTPClient.create(host, Pin(repo=repo))).http_client`. |
| `SecureClient.verify()`, `assert_request_allowed()` | `ensure_verified()` returns a verification that is valid now and `reverify()` forces a fresh one; the origin guard is built into `http_client`, which refuses requests to any other origin. |
| `get_router_address(platform)` | Removed. `RouterHTTPClient()` and `create_client()` discover, verify and keep the router; `.enclave` on the HTTP client names it. |
| `measurement=` | `verifier=Verifier(pinned_registers=ExpectedSEVSNP(...))` or `ExpectedTDX(...)` pins registers on top of the repository's release; `embedded_references=` on the `Verifier` supplies an embedded config instead of an endorsed one. Both are `tinfoil.verifier` names. |
| `attestation_bundle_url=` | Removed. v3 documents carry their provenance, so there is no bundle to fetch. |
| `transport=` | `transport_mode=`, with the same values and `"tls"` as the default. |
| `base_url=` | The same name on the enclave and router clients. An enclave client accepts a path on the enclave's own origin in `"tls"` mode, and a proxy on another origin requires `"ehbp"`; the router client requires `"ehbp"`. On the OpenAI clients it is this route option, not the `openai` package's: requests go to the URL verbatim. |
| `user_cache_secret=` | The same name. The router and gateway clients use a random secret that is generated once per process when it is unset; pass a value for a secret that is stable across processes. An enclave client uses only the explicit value. |
| `timeout=` on `TinfoilAI` | `timeout=`, which is the `openai` package's per-request timeout, and `http_timeout=`, the attested client's: the attestation fetch and requests through `http_client`. The HTTP clients call the latter `timeout=`. |
| `get_verification_document()`, `VerificationDocument` | `client.http_client.current`, a `tinfoil.verifier.Verification` with `code_tag`, `code_digest`, `config_repo`, `enclave_measurement`, `tls_public_key_fp`, `hpke_public_key`, `freshness_expires_at`, `metadata.verified_at` and `to_json()`. It is `None` before the first verification; `ensure_verified()` always returns one. |
| `ValueError` on bad options | `ConfigurationError`, beside `AttestationError` (the enclave could not be trusted) and `NetworkError` (attestation material could not be fetched). All three subclass `TinfoilError`. The `openai` package's errors are unchanged, and re-exported from `tinfoil`. |
| `tinfoil.attestation`, `tinfoil.sigstore`, `tinfoil.github` | `tinfoil.verifier`: `Verifier().verify_v3(document, nonce, Pin(repo=repo, project=project))` returns a `Verification`, or raises `VerificationError` when the evidence is rejected and `UsageError` when the call is invalid, as when `Pin()` meets a verifier with default config trust. |

## Examples

The router, with a chat completion:

```python
import os

from tinfoil import create_client

client = create_client(api_key=os.environ["TINFOIL_API_KEY"])
chat_completion = client.chat.completions.create(
    model="llama3-3-70b",
    messages=[{"role": "user", "content": "Hi"}],
)
```

One enclave, with the verification read back:

```python
import os

from tinfoil import EnclaveOpenAIClient, Pin

client = EnclaveOpenAIClient(
    "inference.tinfoil.sh",
    Pin(repo="tinfoilsh/confidential-model-router", project="tinfoilsh/confidential-model-router"),
    api_key=os.environ["TINFOIL_API_KEY"],
)
verified = client.http_client.ensure_verified()
print(verified.code_tag, verified.tls_public_key_fp)
print(verified.to_json())
```

A request outside the OpenAI API:

```python
from tinfoil import RouterHTTPClient

client = RouterHTTPClient()
response = client.http_client.get(client.base_url + "v1/models", timeout=30)
print(response.status_code)
```

Pinned registers, in place of `measurement=`:

```python
import os

from tinfoil import EnclaveOpenAIClient, Pin
from tinfoil.verifier import Verifier, parse_expected_sevsnp

launch = os.environ["EXPECTED_LAUNCH_MEASUREMENT"]  # 96 hex characters
client = EnclaveOpenAIClient(
    "inference.tinfoil.sh",
    Pin(repo="tinfoilsh/confidential-model-router", project="tinfoilsh/confidential-model-router"),
    verifier=Verifier(pinned_registers=parse_expected_sevsnp(launch)),
    api_key=os.environ["TINFOIL_API_KEY"],
)
```

The errors:

```python
import os

from tinfoil import AttestationError, ConfigurationError, NetworkError, create_client

try:
    client = create_client(api_key=os.environ["TINFOIL_API_KEY"])
except ConfigurationError as err:
    print("fix the options:", err)
except NetworkError as err:
    print("retry later:", err)
except AttestationError as err:
    print("the router could not be trusted:", err)
```
