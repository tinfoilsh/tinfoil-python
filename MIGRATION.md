# Migrating to the v3 client

The client verifies enclaves with version 3 of Tinfoil's attestation format, through a verifier that is its own package, `tinfoil.verifier`. The low-level clients are `httpx` clients for one route each, and `OpenAIClient` is an `openai` client subclass built on top of one of them, so every HTTP resource of the `openai` package is available and the OpenAI client is the client itself; the websocket entry points are refused, as the table below says. The OpenAI clients need the optional `openai` extra: install `tinfoil[openai]`.

## From 0.16.0rc3 and earlier pre-releases

The pre-releases configured clients with options that were checked against each other at run time. Settings that only make sense together are now one value: the trust argument, the `Transport` option and the verifier's config trust and `Policy` are each a frozen dataclass of one variant, so a combination that would be invalid can no longer be written.

| 0.16.0rc3 | Now |
| --- | --- |
| `pip install tinfoil` for the OpenAI clients | `pip install 'tinfoil[openai]'`. Without the extra, the verifier and the HTTP clients work, and an OpenAI name raises a `ModuleNotFoundError` that names it |
| `EnclaveHTTPClient(host, Pin(repo=r))` | `EnclaveHTTPClient(host, RepoPin(r))` |
| `Pin(project=p)` | `ProjectPin(p)` |
| `Pin(repo=r, project=p)` | `EitherPin(r, p)` |
| `Pin()` with a verifier that trusts the config itself | The trust variant that names that trust: `SignedBy(keys, project=None)`, `AuthorizedBy(authorize)` or `EmbeddedConfig(data, name)` |
| `verifier=Verifier(config_registry_ids=ids)` with `Pin(project=p)` | `ProjectPin(p, registry_ids=ids)`. `None` trusts the public registry and an empty list is a `ConfigurationError` |
| `tinfoil.Pin` | Removed; `tinfoil.verifier.Pin` stays for the verifier |
| `client.pin` | `client.trust` on the enclave clients, which returns the trust argument. The router clients have neither: the router's trust is fixed |
| `verifier=Verifier(...)` on a client | `policy=Policy(...)`, a `tinfoil.verifier.Policy`; the client builds the verifier, and an invalid policy is a `ConfigurationError` |
| `ModelPin(repo, verifier)` | `ModelPin(repo, policy)`; `None` inherits the gateway's policy |
| `pinned_models_only=True` on a gateway client | Removed; a gateway client always serves only the models that it has pins for. `model_pins` is required and must be non-empty, and a request for an unpinned model is a `ConfigurationError`. The gateway's `policy` applies to the pins that set none |
| `transport_mode="tls"` | `transport=TLS()`, or nothing: it is the default |
| `transport_mode="ehbp"` | `transport=EHBP()` |
| `transport_mode="ehbp", base_url=proxy` | `transport=EHBP(proxy_url=mount)`, where `mount` is where the proxy is mounted, without the API path: `base_url="https://proxy.example/v1/"` becomes `proxy_url="https://proxy.example/"`, and the OpenAI client adds `/v1/` |
| `base_url=` a path on the enclave's own origin | Removed; pass `api_path=` to `OpenAIClient` for an API that is not at `/v1/` |
| `TransportMode`, `DEFAULT_TRANSPORT_MODE` | `Transport`, `TLS`, `EHBP` |
| `user_cache_secret=` on an enclave client | Removed; the enclave client sends bodies as they are. Set `user_cache_secret` in each request body, for example with `extra_body`. The router and gateway clients keep the option |
| `EnclaveOpenAIClient(host, pin, <HTTP options>, http_timeout=t, **openai)` | `OpenAIClient(EnclaveHTTPClient(host, trust, <HTTP options>, timeout=t), **openai)` |
| `RouterOpenAIClient(...)`, `GatewayOpenAIClient(...)` | `OpenAIClient(RouterHTTPClient(...), ...)`, `OpenAIClient(GatewayHTTPClient(...), ...)` |
| `await AsyncEnclaveOpenAIClient.create(...)` and the other async OpenAI clients | `AsyncOpenAIClient(await AsyncEnclaveHTTPClient.create(...), ...)`; the OpenAI client does no network I/O, so it has a plain constructor |
| `create_client`, `Client`, `create_async_client`, `AsyncClient` | Unchanged; `Client` is now an `OpenAIClient` over a `RouterHTTPClient` |
| `base_url=` or `data_residency=` among the `openai` options | Ignored rather than refused: the SDK sets the base URL itself, after the caller's options, and `OPENAI_BASE_URL` has no effect either |
| `Verifier(config_registry_ids=ids)` | `Verifier(Registries(ids))`; list `PUBLIC_REGISTRY_ID` to keep the public registry |
| `Verifier(config_signing_keys=keys)` | `Verifier(ConfigSigningKeys(keys))` |
| `Verifier(config_authorizer=f)` | `Verifier(ConfigAuthorizer(f))`; `ConfigAuthorizer` is now this dataclass rather than the callable's type |
| `Verifier(embedded_references=EmbeddedReferences(config=c, runtime=r, platform=p))` | `Verifier(c, Policy(artifacts=EmbeddedArtifacts(runtime=r, platform=p)))`, with `c` an `EmbeddedConfig` or `EmbeddedConfigReference` |
| `Verifier(freshness_signing_keys=keys)` | `Verifier(policy=Policy(artifacts=EndorsedArtifacts(freshness_keys=keys)))`, or `freshness_keys` on `EmbeddedArtifacts` |
| `Verifier(pinned_registers=e, freshness_max_age=a)` | `Verifier(policy=Policy(pinned_registers=e, freshness_max_age=a))` |
| `freshness_max_age=timedelta(0)`, a bound of zero | A `UsageError` (a `ConfigurationError` from a client), since it would reject every witness; `None` still selects the seven-day default |
| `Verifier.caller_authorizes_config` | Removed |
| `verify_v3(...)` and `verify_v3_at(...)` returning a `Verification` | A `VerificationReport`; the facts are its `verified_facts`, a `VerifiedFacts`, which is `Verification` renamed without `metadata`. The metadata is the report's `metadata`. A `VerificationError` carries the rejection's report as `report` |
| `verification_check` called with a `Verification` | Called with the `VerifiedFacts` |
| `client.current`, the last successful verification | `client.last_verification()`, the most recent attempt as `(report, error)`: a later failure replaces an earlier success. On a gateway client it is a list of `ReplicaVerification`, whose `verification` field is replaced by `report`, set when the replica's last attempt passed, and `error`, set when it failed |
| `ensure_verified()` and `reverify()` returning a `Verification` | A `VerificationReport`; read its `verified_facts` |
| Watching verifications | `on_verification=` on every HTTP client, called with the host, the report and the error of every attempt |

The checks that rejected conflicting options are gone with them, since those combinations can no longer be written. The one check that spans two fields that remains is `EmbeddedArtifacts` with both artifacts embedded and `freshness_keys` set, since nothing would be left for the keys to verify.

## From 0.15

The table maps each name and option of 0.15 to its replacement; a sentence follows where the mapping is not one to one.

| 0.15 | v3 |
| --- | --- |
| `TinfoilAI(api_key=k)` | `create_client(api_key=k)` |
| `TinfoilAI(enclave=host, repo=r, api_key=k)` | `OpenAIClient(EnclaveHTTPClient(host, RepoPin(r)), api_key=k)`. `host` and the trust are positional and required. The trust names what vouches for the enclave's config: `RepoPin(r)` for a GitHub repository, `ProjectPin(p)` for a config registry project, `EitherPin(r, p)` to accept either, or `SignedBy`, `AuthorizedBy` or `EmbeddedConfig` for configs that you vouch for yourself. A bare string or `None` is a `ConfigurationError`. The HTTP client's `repo` property is `trust`. |
| `AsyncTinfoilAI(...)` | `await create_async_client(...)` for the router, `AsyncOpenAIClient(await AsyncEnclaveHTTPClient.create(host, RepoPin(r)), ...)` for one enclave. Every asynchronous HTTP client is built with `await Cls.create(...)`, since it verifies. |
| `client.chat`, `client.embeddings`, `client.audio` | Unchanged, and every other resource of the `openai` package with them, except the websocket entry points: `realtime`, its `beta.realtime` alias and the `connect` methods of `responses`, `beta.responses`, `live`, `live.sideband` and `live.forks` raise `ConfigurationError`, because a websocket can't use the attested HTTP client and would bypass the attested connection. The `websocket_base_url` option is refused for the same reason when it is set; `None` counts as unset. |
| `client.client` | The client itself: it is an `openai.OpenAI`. |
| `client.enclave` | `client.http_client.enclave` |
| `NewSecureClient().get(url, headers, timeout)`, `.post(...)` | `RouterHTTPClient()`, or `EnclaveHTTPClient(host, RepoPin(repo))`, then `c.http_client.get(c.base_url + "v1/...", headers=..., timeout=...)`, which returns an `httpx.Response`. `http_client` is an `httpx.Client` with every method, and `base_url` ends in a slash. |
| `SecureClient`, `make_secure_http_client()`, `make_secure_async_http_client()` | `EnclaveHTTPClient(host, RepoPin(repo)).http_client` and `(await AsyncEnclaveHTTPClient.create(host, RepoPin(repo))).http_client`. |
| `SecureClient.verify()`, `assert_request_allowed()` | `ensure_verified()` returns a verification that is valid now and `reverify()` forces a fresh one; the origin guard is built into `http_client`, which refuses requests to any other origin. |
| `get_router_address(platform)` | Removed. `RouterHTTPClient()` and `create_client()` discover, verify and keep the router; `.enclave` on the HTTP client names it. |
| `measurement=` | `policy=Policy(pinned_registers=ExpectedSEVSNP(...))` or `ExpectedTDX(...)` pins registers on top of the repository's release; `EmbeddedConfig(data)` as the trust supplies an embedded config instead of an endorsed one. `Policy` and the register types are `tinfoil.verifier` names. |
| `attestation_bundle_url=` | Removed. v3 documents carry their provenance, so there is no bundle to fetch. |
| `transport=` | `transport=TLS()`, the default, or `transport=EHBP()`. |
| `base_url=` | `transport=EHBP(proxy_url=...)` for a proxy, where the URL is where the proxy is mounted; `api_path=` on `OpenAIClient` for an API path other than `/v1/`. A `base_url` among the `openai` options has no effect. |
| `user_cache_secret=` | The same name on the router and gateway clients, which use a random secret that is generated once per process when it is unset; pass a value for a secret that is stable across processes. An enclave client has no cache-secret option. |
| `timeout=` on `TinfoilAI` | `timeout=` on `OpenAIClient`, which is the `openai` package's per-request timeout, and `timeout=` on the HTTP client, the attested client's: the attestation fetch and requests through `http_client`. |
| `get_verification_document()`, `VerificationDocument` | `client.http_client.ensure_verified()`, a `tinfoil.verifier.VerificationReport` whose `verified_facts` have `code_tag`, `code_digest`, `config_repo`, `enclave_measurement`, `tls_public_key_fp`, `hpke_public_key` and `freshness_expires_at`, with `metadata.verified_at` and `to_json()` on the report. `last_verification()` returns the most recent attempt, as `(report, error)`, without I/O. |
| `ValueError` on bad options | `ConfigurationError`, beside `AttestationError` (the enclave could not be trusted) and `NetworkError` (attestation material could not be fetched). All three subclass `TinfoilError`. The `openai` package's errors are unchanged, and re-exported from `tinfoil`. |
| `tinfoil.attestation`, `tinfoil.sigstore`, `tinfoil.github` | `tinfoil.verifier`: `Verifier().verify_v3(document, nonce, Pin(repo=repo, project=project))` returns a `VerificationReport` whose `verified_facts` are what the document proved, or raises `VerificationError`, which carries the report of the rejection, when the evidence is rejected and `UsageError` when the call is invalid, as when `Pin()` meets a verifier with default config trust. |

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

from tinfoil import EitherPin, EnclaveHTTPClient, OpenAIClient

http_client = EnclaveHTTPClient(
    "inference.tinfoil.sh",
    EitherPin("tinfoilsh/confidential-model-router", "tinfoilsh/confidential-model-router"),
)
client = OpenAIClient(http_client, api_key=os.environ["TINFOIL_API_KEY"])
verified = http_client.ensure_verified().verified_facts
assert verified is not None
print(verified.code_tag, verified.tls_public_key_fp)
print(verified.to_json())
```

A proxy, in place of `transport_mode="ehbp", base_url=...`:

```python
import os

from tinfoil import EHBP, OpenAIClient, RouterHTTPClient

http_client = RouterHTTPClient(transport=EHBP(proxy_url="https://proxy.example.com/tinfoil"))
client = OpenAIClient(http_client, api_key=os.environ["TINFOIL_API_KEY"])  # sends to .../tinfoil/v1/
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

from tinfoil import EitherPin, EnclaveHTTPClient, OpenAIClient
from tinfoil.verifier import Policy, parse_expected_sevsnp

launch = os.environ["EXPECTED_LAUNCH_MEASUREMENT"]  # 96 hex characters
http_client = EnclaveHTTPClient(
    "inference.tinfoil.sh",
    EitherPin("tinfoilsh/confidential-model-router", "tinfoilsh/confidential-model-router"),
    policy=Policy(pinned_registers=parse_expected_sevsnp(launch)),
)
client = OpenAIClient(http_client, api_key=os.environ["TINFOIL_API_KEY"])
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
