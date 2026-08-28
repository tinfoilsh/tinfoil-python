# v3 port: tinfoil-go `feat/v3` → tinfoil-python, 1:1

Follow /Users/g/tinfoil/tinfoil-conformance/docs/PORTING_PLAYBOOK.md. Reference
implementation: /Users/g/tinfoil/tinfoil-go on branch `feat/v3-conformance-harness`
(= current feat/v3 **including Turin support** #115 and deferred binding #118,
plus tag-gated seams) — port the CURRENT semantics: per-product AMD roots
(Genoa+Turin), iommu_write_safe/fmc_spl invalid-for-Genoa/required-for-Turin,
forked `tinfoilsh/go-sev-guest` behavior. Second opinion: /Users/g/tinfoil/tinfoil-js
`packages/verifier/src/v3/` (worked port, incl. full TDX DCAP; note it predates
Turin — Go wins on any divergence). Same names snake_cased, same check order,
same error conditions. Comments: small and direct.

Python facts: ≥3.10, `cryptography` (x509/RSA-PSS/ECDSA/CRL), official
`sigstore` ≥4.3, `pyasn1` available; ints are exact (no 2^53 pitfall — still
range-check per Go). Sync code (no asyncio) — the adapter is a CLI.

## Module map and ownership (one agent per row; do not edit others' files)

| owner | files (src/tinfoil/v3/) | Go source |
|---|---|---|
| foundation | `errors.py`, `bytesutil.py`, `strictjson.py`, `envelope.py`, `measurement.py`, `policy.py`, `__init__.py` + `src/tinfoil/conformance/` CLI skeleton + pyproject script | `verifier/envelope/`, `verifier/measurement/`, `verifier/policy/`, `verifier/internal/strictjson` |
| provenance | `provenance/{provenance,freshness,bundle_format}.py` | `verifier/provenance/*.go` |
| sev | `sev/*.py` | `verifier/quote/sev/*.go` (+ tinfoilsh/go-sev-guest configured subset; Turin included) |
| tdx | `tdx/*.py` | `verifier/quote/tdx/*.go` (+ go-tdx-guest configured subset) |
| integration | `quote.py`, `client.py`, `fetch.py`, final `conformance/{run,cli,capabilities}.py` | `verifier/quote/quote.go`, `verifier/client/verify.go`, `verifier/conformance/` |

Embedded roots: `src/tinfoil/v3/embedded_roots.py` (TRUSTED_ROOT_JSON,
GENOA_CERT_CHAIN_PEM, TURIN_CERT_CHAIN_PEM, SGX_ROOT_CA_PEM) — byte-identical
to Go's go:embed files. Default when no override.

## Fixed interfaces (code against these exactly)

```python
# errors.py
class VerificationError(Exception):
    layer: str  # ENVELOPE_REJECTED | PROVENANCE_REJECTED | QUOTE_REJECTED | POLICY_REJECTED

# envelope.py — strict parse (unknown/duplicate members reject, Go check order)
NONCE_SIZE = 32
def parse_document(doc_bytes: bytes) -> Document: ...
def check(doc_bytes: bytes, expected_nonce: bytes) -> tuple[Document, bytes]:  # (doc, report_data[64])
def reference_values_collateral(doc: Document, fmt: str) -> SigstoreCollateral: ...  # .repo .tag .digest .sigstore_bundle
def freshness_collateral(doc: Document, id_: str) -> bytes: ...                      # sigstore_bundle
def endorsement_collateral(doc: Document, fmt: str, subject: str): ...
def crypto_material_items(doc: Document) -> list[CryptoMaterialItem]: ...            # .id .format .data

# policy.py
def parse_artifact(artifact_json: bytes) -> Artifact: ...   # fail-closed
def policy_for(a: Artifact, identity: str, platform: str) -> tuple[str, Policy]: ...
def resolve_platform_measurement(...): ...                  # mirror Go

# provenance/  (opts: trust_root_json: bytes | None = None → embedded)
def authenticate_code(bundle_json, repo, tag, hex_digest, trust_root_json=None) -> Code: ...
def authenticate_platform_endorsements(bundle_json, repo, tag, hex_digest, trust_root_json=None) -> PlatformEndorsements: ...
def authenticate_freshness(bundle_json, expected: AuthenticatedArtifact, now: datetime, trust_root_json=None) -> datetime: ...

# sev/ and tdx/  (root_pem: str | None = None → embedded per-product; now: datetime | None)
def sev_authenticate(doc: Document, root_pem=None, now=None) -> SevQuote: ...  # .identity .measurement .report .product_line
def sev_assemble(policy, quote, launch_digest, report_data) -> SevExpectations: ...
def sev_validate(expectations, quote) -> None: ...          # raises POLICY_REJECTED
def tdx_authenticate(doc: Document, root_pem=None, now=None) -> TdxQuote: ...  # .identity .measurement .tcb_evaluation_data_number .body
def tdx_assemble(...) / tdx_validate(...) -> None: ...

# quote.py / client.py / fetch.py (integration)
def quote_authenticate(doc, amd_root_pem=None, intel_root_pem=None, now=None) -> Authenticated: ...
def assemble_and_validate(endorsements, code_measurement, shape, report_data, auth) -> None: ...
def verify_document_v3(doc_bytes, nonce, repo, *, sigstore_root_json=None,
                       amd_root_pem=None, intel_root_pem=None,
                       verification_time=None) -> VerifiedDocumentV3: ...
def tls_public_key_fp(v: VerifiedDocumentV3) -> str: ...    # raises when absent/mismatched format
def hpke_public_key(v: VerifiedDocumentV3) -> str: ...
def fetch_attestation(host: str, nonce: bytes) -> bytes: ...
def random_nonce() -> bytes: ...
```

Measurement constants: `SEV_GUEST_V2`, `TDX_GUEST_V2`, `SNP_TDX_MULTI_PLATFORM_V1`
(exact Go URI values); `Measurement(type: str, registers: list[str])`.

## Adapter (src/tinfoil/conformance/)

Wire contract: /Users/g/tinfoil/tinfoil-conformance/docs/CONFORMANCE_ADAPTER_SPEC.md
(v1.1 — includes live-verify §7) + schemas/v3/. Entry point `tinfoil-conformance`
(pyproject [project.scripts] → conformance.cli:main). run.py holds runStage logic
(pure), cli.py the stdin/stdout/exit wrapper. capabilities: sdk "tinfoil-python",
all five stages, synthetic_roots all true, freshness_enforced true, live_verify
true, channel_binding "tls-spki" (python product client pins TLS — mirror Go).

## Acceptance harness

```
cd /Users/g/tinfoil/tinfoil-python && uv sync && uv run tinfoil-conformance capabilities
python3 /Users/g/tinfoil/tinfoil-conformance/tools/run_adapter.py \
  --adapter "uv run --project /Users/g/tinfoil/tinfoil-python tinfoil-conformance" --dirs <slice>
```

Per-slice gates as in the playbook; final = full suite + compare_adapters vs
the Go report + live-verify (parity check: the live facts — accepted output
or rejection — must be IDENTICAL to Go's and JS's).

## Python pitfalls (in addition to the playbook's list)

- `json.loads` accepts duplicate keys (last wins), NaN/Infinity, huge floats —
  strictjson.py must be a hand parser like Go's/JS's: unknown members reject,
  duplicates reject on DECODED names with unpaired surrogates → U+FFFD first,
  ints parsed from the raw literal, canonical-base64/lowercase-hex helpers,
  no trailing data. Port the JS strictjson.ts design.
- `cryptography` is DER-strict but verify: UTCTime Z, PSS salt length 48
  explicit, raw r‖s ↔ DER conversion for ECDSA (utils.decode_dss_signature /
  encode_dss_signature), little-endian SEV report signature.
- Lone surrogates survive in python str from JSON escapes — normalize like Go.
- No float use anywhere in verification decisions.
