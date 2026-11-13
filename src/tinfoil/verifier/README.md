# tinfoil.verifier

Offline verification of Tinfoil enclave attestation documents. The verifier
takes a document that you fetched, the nonce that you bound it to and the
repository that you trust, and returns the facts that the document proved:
the endorsed TLS key fingerprint and HPKE public key, the measured registers
and the deadline after which the result must not be reused. It opens no
connections and keeps no state.

## Install and import

```sh
pip install tinfoil
```

```python
from tinfoil.verifier import Verifier, random_nonce
```

Every name documented here is importable from `tinfoil.verifier`, except
the `tinfoil.`-qualified client names that it points to; the
`_`-prefixed submodules are implementation detail and may change without
notice.

## Fetch, then verify

Verification is three steps: generate a nonce, fetch the document for that
nonce from the enclave, and verify it against the repository that you expect
the enclave to run. The verifier does not fetch; any HTTP client works.

```python
import urllib.request

from tinfoil.verifier import Verification, Verifier, random_nonce


def fetch_and_verify(host: str, repo: str | None) -> Verification:
    nonce = random_nonce()
    url = f"https://{host}/.well-known/tinfoil-attestation?nonce={nonce.hex()}"
    with urllib.request.urlopen(url, timeout=10) as response:
        document = response.read()
    return Verifier().verify_v3(document, nonce, repo)
```

`repo` is `org/repo`, optionally pinned to a revision or a digest as
`org/repo@v1.2.3` or `org/repo@sha256:<hex>`. An empty string or `None`
pins no repository. A document that carries v3 collateral is then accepted
on any config that the verifier's configured config trust authorizes: the
public registry by default, or, when the verifier was built with one, the
caller's config signing keys, config authorizer or embedded config. One that
carries v2 collateral requires a repository pin, so the call is a
`UsageError`.

A successful return is not the end of the caller's job. The returned
`Verification` proves facts about the enclave that served the document; the
caller must bind its traffic to them:

- `verified.tls_public_key_fp`: pin every TLS connection to the enclave to
  this SPKI fingerprint (see `tinfoil.pin_tls_key`). A connection whose leaf
  certificate carries another key is not the attested enclave.
- `verified.hpke_public_key`: encrypt request bodies to this key when the
  transport uses HPKE.
- `verified.freshness_expires_at`: stop using the result at this instant
  and verify a fresh document. It is `None` when no endorsed reference
  value supplied an approval deadline, which happens when every reference
  value was embedded by the caller, and also when a caller-authorized
  config is combined with embedded runtime and platform references. Then
  renewal is the caller's own policy, and `None` is not a promise that the
  evidence stays valid.

```python
from datetime import UTC, datetime


def still_usable(verified: Verification) -> bool:
    expires = verified.freshness_expires_at
    return expires is None or datetime.now(UTC) < expires
```

### Archived documents

`verify_v3` reads the clock once. `verify_v3_at` takes that instant from the
caller, which is how an archived document is re-verified as of the time it
was received:

```python
from datetime import UTC, datetime

received_at = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
verified = Verifier().verify_v3_at(archived_document, archived_nonce, "org/repo", received_at)
```

Authenticate that instant yourself. Every time-bound check, from the
freshness witnesses to the vendor certificate and CRL validity windows, is
made as of `verification_time`, so a time that an attacker can choose
accepts collateral that has since expired or been revoked. A naive datetime
is a `UsageError`.

## Options

`Verifier()` with no arguments uses the embedded production trust roots,
Tinfoil's public config and artifact signing keys, and a seven-day
freshness bound. Every option is keyword-only:

| Option | Effect |
| --- | --- |
| `pinned_registers` | Registers that the enclave must have measured, on top of what the release fixes. |
| `freshness_max_age` | How old a witness or approval may be. `None` keeps seven days; `timedelta(0)` accepts only a witness that is no older than the verification instant. |
| `config_signing_keys` | ECDSA P-256 keys that replace the public config trust. |
| `freshness_signing_keys` | ECDSA P-256 keys that replace the public keys for runtime and platform freshness approvals. |
| `config_registry_ids` | The registries whose certified approvals are accepted, in place of the public registry alone. |
| `config_authorizer` | Caller policy that replaces config endorsement verification. |
| `embedded_references` | Caller-trusted config, runtime manifest or platform artifact that replace endorsement checks for those components. |

Keys come from `load_public_key`, which accepts a PEM `PUBLIC KEY` block as
text or bytes, or SPKI DER, and rejects anything that is not an ECDSA P-256
key:

```python
from datetime import timedelta

from tinfoil.verifier import Verifier, load_public_key

verifier = Verifier(
    config_signing_keys=[load_public_key(signing_key_pem)],
    freshness_max_age=timedelta(days=1),
)
```

Some options exclude each other; each conflict is a `UsageError` from the
constructor:

| | embedded config | `config_signing_keys` | `config_authorizer` | `config_registry_ids` |
| --- | --- | --- | --- | --- |
| embedded config | | conflict | conflict | conflict |
| `config_signing_keys` | conflict | | conflict | conflict |
| `config_authorizer` | conflict | conflict | | conflict |
| `config_registry_ids` | conflict | conflict | conflict | |

`freshness_signing_keys` conflicts with embedding both the runtime and the
platform, since no endorsed artifact remains for the keys to verify. Any
explicit key set, registry list, authorizer or embedded reference requires
`attestation-collaterals/v3` collateral; a document that carries v2
collateral is then rejected at the provenance layer.

### Pinning registers

`pinned_registers` takes an `ExpectedSEVSNP` or an `ExpectedTDX`. Each set
register must match the enclave; an unset one (`None`, or `""` to the
parsers) is left to the release. A pin for one platform rejects every
enclave on the other.

```python
from tinfoil.verifier import Verifier, parse_expected_tdx

rtmr3 = "ab" * 48
pinned = Verifier(pinned_registers=parse_expected_tdx("", "", "", "", rtmr3))
```

To pin an enclave to exactly what it measured today, take the expectations
from a verified record:

```python
locked = Verifier(pinned_registers=verified.enclave_measurement.expected())
```

## Reading the record

`Verification` is a frozen record. The measurements are a tagged union, so
`match` on the class:

```python
from tinfoil.verifier import SEVSNP, TDX, Measurement


def describe(measurement: Measurement) -> str:
    match measurement:
        case SEVSNP(launch=launch):
            return f"SEV-SNP launch {launch.hex()}"
        case TDX(mrtd=mrtd, rtmr3=rtmr3):
            return f"TDX mrtd {mrtd.hex()} rtmr3 {rtmr3.hex()}"


summary = describe(verified.enclave_measurement)
```

`code_measurement` is what the release fixes (`Expected*`, with `None` for
a register left to the platform) and `enclave_measurement` what the
hardware measured (`SEVSNP` or `TDX`, every register set). `config`,
`runtime` and `platform` say which reference values were accepted and on
whose authority (`source` is `"endorsement"`, `"embedded"` or `"policy"`);
a string fact that was not established is `""` and a time is `None`.

`to_dict()` and `to_json()` give a plain copy with registers as lowercase
hex and times as ISO 8601 in UTC:

```python
as_dict = verified.to_dict()
compact = verified.to_json()
pretty = verified.to_json(indent=2)
```

The TLS fingerprint and HPKE key are the two crypto-material items that
every client needs, and the record names them. Any endorsed item is also
read by id and format; the TLS item carries the SPKI fingerprint format:

```python
from tinfoil.verifier import KEY_SPKI_FP_SHA256_V1_FORMAT

tls_fp = verified.tls_public_key_fp
same_fp = verified.crypto_material_data("tls", KEY_SPKI_FP_SHA256_V1_FORMAT)
```

`None` means that the document endorses no such item.

## Errors

Every error that the verifier raises is a `VerifyError`, with two
subclasses that call for different responses:

- `UsageError`: the verifier was built or called with invalid inputs. Fix
  the caller; retrying will not help. `str(err)` is the message. It is also
  a `ValueError`.
- `VerificationError`: the document must not be trusted. `err.layer` names
  the layer that rejected it, one of `LAYER_ENVELOPE`, `LAYER_PROVENANCE`,
  `LAYER_QUOTE` and `LAYER_POLICY` today, and `err.message` says why;
  `str(err)` is `"<layer>: <message>"`.

```python
from tinfoil.verifier import LAYER_PROVENANCE, UsageError, VerificationError, Verifier


def classify(document: bytes, nonce: bytes, repo: str | None) -> str:
    try:
        Verifier().verify_v3(document, nonce, repo)
    except UsageError as err:
        return f"bug in the caller: {err.message}"
    except VerificationError as err:
        if err.layer == LAYER_PROVENANCE:
            return f"reference values rejected, possibly a stale witness: {err.message}"
        return f"rejected at {err.layer}: {err.message}"
    return "verified"
```

A rejection at the provenance layer may be transient: a freshness witness
that has gone stale reads the same as a forged one, and a fresh document
from the enclave may verify. The message is the only distinction today.

A failure inside a layer that is not one of the verifier's own errors is
reported as a `VerificationError` at that layer with the underlying
exception as `__cause__`; an unfamiliar message may mean that the verifier
failed rather than that the document was forged. A `UsageError` raised
inside the pipeline passes through unwrapped.

The measurement parsers (`parse_register`, `parse_expected_sevsnp`,
`parse_expected_tdx`) and the measurement records raise a plain
`ValueError` for a malformed register, naming the field:

```python
from tinfoil.verifier import parse_expected_tdx

try:
    parse_expected_tdx("", "", "", "", "not hex")
except ValueError as err:
    problem = str(err)  # "rtmr3: register must be 96 hex characters, got 7"
```

## Pinning the TLS connection

`cert_pubkey_fp(cert_der)` computes the SPKI fingerprint of a DER
certificate in the form that `tls_public_key_fp` reports. The checks that
read the peer certificate off a live connection belong to the transport, so
they live in the client package: see `tinfoil.pin_tls_key` and
`tinfoil.connection_cert_fp` in the [client README](../../../README.md#pinning-your-own-tls-connection).

## What is not here

The package verifies; it does not fetch documents, cache verifications,
renew them before `freshness_expires_at`, or speak HTTP. Those live in the
`tinfoil` package's clients: `create_client` and `RouterOpenAIClient` for
Tinfoil's router, `EnclaveHTTPClient` and `EnclaveOpenAIClient` for one
enclave, and `GatewayHTTPClient` for the gateway. The enclave clients
verify a document before they return; the router client verifies the
router it discovers, or its fallback host on first use; the gateway client
verifies each model's replica on that model's first request. Every one
pins its transport to `tls_public_key_fp` or encrypts to `hpke_public_key`
as its transport mode calls for, and verifies again before the deadline. Use the verifier directly when you bring your own
transport.

## Auditing the code

The pipeline runs in `_verifier.py`: envelope, then reference values, then
the CPU quote, then policy. Each stage is its own subpackage:

| Subpackage | What it does |
| --- | --- |
| `_document` | Parses the attestation document with a strict JSON reader, checks the nonce binding and decodes each collateral entry by its format. |
| `_endorsement` | Authenticates reference values: release references, provenance bundles, config and artifact approvals and freshness witnesses, against the Sigstore trust root. |
| `_policy` | The platform policy artifact: which machines are endorsed, which configurations they may run and what each must satisfy. |
| `_quote/sev` | Authenticates an AMD SEV-SNP attestation report against the embedded AMD roots, the VCEK chain and CRL, and reads its measurement. |
| `_quote/tdx` | Authenticates an Intel TDX quote against the embedded Intel root, the PCK chain and PCS collateral, and reads its registers. |
| `_sigstore` | Sigstore bundles, keyed and certified signatures, RFC 3161 timestamps and the trusted root. |
| `_x509` | A strict DER decoder and the certificate, chain and CRL checks that the rest builds on. |
| `_verifier` | The `Verifier` type, its options and the pipeline that joins the stages; `_verification.py` holds the record. |

Trust anchors are embedded under `_trust`: the AMD Genoa and Turin
certificate chains, the Intel SGX root, the Sigstore trusted root and the
public signing keys. The public constructor accepts no replacements for
them.
