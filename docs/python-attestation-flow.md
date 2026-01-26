# Python Client Attestation Flow

This document describes the attestation verification flow in the Tinfoil Python client.

## High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           USER CODE                                              │
│                                                                                  │
│   client = TinfoilAI(enclave="...", repo="org/repo", api_key="...")             │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  __init__.py: TinfoilAI.__init__()                                              │
│                                                                                  │
│  1. get_router_address()  ←─────────── if enclave empty, fetch from             │
│     └─► GET https://atc.tinfoil.sh/routers?platform=snp                         │
│                                                                                  │
│  2. SecureClient(enclave, repo)                                                 │
│  3. tf_client.make_secure_http_client()  ──────────────────────────────────────┐│
└──────────────────────────────────────────────────────────────────────────────│─┘
                                                                               │
                                        ┌──────────────────────────────────────┘
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  client.py: SecureClient.make_secure_http_client()                              │
│                                                                                  │
│  expected_fp = self.verify()  ───────────────────────────────────────────────┐  │
│                                                                              │  │
│  return httpx.Client(verify=ssl_ctx_with_pinned_cert)                        │  │
└──────────────────────────────────────────────────────────────────────────────│──┘
                                        ┌──────────────────────────────────────┘
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  client.py: SecureClient.verify()                                               │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ STEP 1: Runtime Attestation from Enclave                                   │ │
│  │                                                                            │ │
│  │  enclave_attestation = fetch_attestation(self.enclave)                     │ │
│  │  verification = enclave_attestation.verify()                               │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                         │                                                       │
│                         ▼                                                       │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ STEP 2: Code Measurement from GitHub + Sigstore                            │ │
│  │                                                                            │ │
│  │  digest = fetch_latest_digest(self.repo)                                   │ │
│  │  sigstore_bundle = fetch_attestation_bundle(self.repo, digest)             │ │
│  │  code_measurements = verify_attestation(sigstore_bundle, digest, repo)     │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                         │                                                       │
│                         ▼                                                       │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │ STEP 3: Compare Measurements                                               │ │
│  │                                                                            │ │
│  │  if code_measurement != verification.measurement:                          │ │
│  │      raise ValueError("Code measurements do not match")                    │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                         │                                                       │
│                         ▼                                                       │
│  return GroundTruth(public_key=verification.public_key_fp, ...)                │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Detailed Sub-flows

### Step 1: Runtime Attestation (from Enclave)

```
attestation.py: fetch_attestation(host)
│
├─► GET https://{host}/.well-known/tinfoil-attestation
│   Returns: { format: "sev-snp-guest/v2", body: "<base64-gzipped>" }
│
└─► Returns Document(format, body)


attestation.py: Document.verify()
│
└─► verify_sev_attestation_v2(body)
    │
    ├─► base64.decode() → gzip.decompress()
    │
    ├─► verify.py: Report(raw_bytes)           # Parse SEV-SNP report structure
    │
    ├─► verify.py: CertificateChain.from_report(report)
    │   │
    │   ├─► Load embedded ARK_CERT, ASK_CERT   # AMD root certs (genoa_cert_chain.py)
    │   │
    │   └─► Fetch VCEK cert from AMD KDS
    │       GET https://kds-proxy.tinfoil.sh/vcek/v1/{product}/{chip_id}?...
    │       (cached locally: ~/.cache/tinfoil/)
    │
    ├─► verify.py: verify_attestation(chain, report)
    │   │
    │   ├─► chain.verify_chain()               # ARK → ASK → VCEK chain validation
    │   │
    │   └─► _verify_report_signature()         # ECDSA P-384 signature check
    │
    └─► validate.py: validate_report()         # Policy validation (TCB, version, etc.)

    Returns: Verification(measurement, public_key_fp, hpke_public_key)
```

### Step 2: Code Measurement (from GitHub + Sigstore)

```
github.py: fetch_latest_digest(repo)
│
├─► GET https://api-github-proxy.tinfoil.sh/repos/{repo}/releases/latest
│
└─► Parse "Digest: `{hash}`" from release body
    Returns: digest (sha256 hex string)


github.py: fetch_attestation_bundle(repo, digest)
│
├─► Check local cache: ~/.cache/tinfoil/bundle_{repo}_{digest}.json
│
└─► GET https://api-github-proxy.tinfoil.sh/repos/{repo}/attestations/sha256:{digest}
    Returns: sigstore bundle JSON


sigstore.py: verify_attestation(bundle_json, digest, repo)
│
├─► Bundle.from_json(bundle_json)
│
├─► Verifier.production()                      # Use Sigstore public good instance
│
├─► verifier.verify_dsse(bundle, policy)       # Verify signature + Rekor log
│   │
│   └─► Policy: OIDC issuer = GitHub Actions
│              + Workflow repo = {repo}
│              + Workflow ref = refs/tags/*
│
├─► Verify digest matches subject[0].digest.sha256
│
└─► Extract measurement from predicate
    Returns: Measurement(type=SNP_TDX_MULTIPLATFORM_v1, registers=[...])
```

### TLS Pinning (after verification)

```
client.py: _create_socket_wrapper(expected_fp)
│
└─► For each TLS connection:
    │
    ├─► sock.getpeercert(binary_form=True)
    │
    ├─► SHA256(cert.public_key.DER)
    │
    └─► if fingerprint != expected_fp:
            raise Exception("Certificate fingerprint mismatch")
```

## Data Flow Summary

```
                    ┌─────────────┐
                    │   Enclave   │
                    │  (runtime)  │
                    └──────┬──────┘
                           │ attestation doc
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   Verification = {                                           │
│     measurement: [snp_measurement],                          │
│     public_key_fp: SHA256(TLS_pubkey),  ◄─── Used for TLS   │
│     hpke_public_key: ...                     pinning         │
│   }                                                          │
│                                                              │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            │ compare
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   Code Measurement = {                                       │
│     type: SNP_TDX_MULTIPLATFORM_v1,                         │
│     registers: [snp_measurement, rtmr1, rtmr2]              │
│   }                                                          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
                           ▲
                           │ sigstore bundle
                    ┌──────┴──────┐
                    │   GitHub    │
                    │  + Sigstore │
                    └─────────────┘
```

## Key Files

| File | Purpose |
|------|---------|
| `src/tinfoil/__init__.py` | Entry points: `TinfoilAI`, `AsyncTinfoilAI`, `NewSecureClient` |
| `src/tinfoil/client.py` | `SecureClient` - orchestrates verification and TLS pinning |
| `src/tinfoil/attestation/attestation.py` | `Document`, `Measurement`, `fetch_attestation()` |
| `src/tinfoil/attestation/verify.py` | `CertificateChain`, SEV-SNP signature verification |
| `src/tinfoil/attestation/validate.py` | Policy validation (TCB levels, versions) |
| `src/tinfoil/attestation/abi_sevsnp.py` | SEV-SNP binary format parsing (`Report` class) |
| `src/tinfoil/attestation/genoa_cert_chain.py` | Embedded AMD ARK/ASK root certificates |
| `src/tinfoil/github.py` | `fetch_latest_digest()`, `fetch_attestation_bundle()` |
| `src/tinfoil/sigstore.py` | `verify_attestation()` - Sigstore/Rekor verification |

## External Dependencies

- **Enclave**: `/.well-known/tinfoil-attestation` endpoint
- **AMD KDS**: `kds-proxy.tinfoil.sh/vcek/v1/...` for VCEK certificates
- **GitHub API**: `api-github-proxy.tinfoil.sh/repos/.../releases/latest`
- **Sigstore**: Public good instance for DSSE verification
- **Local cache**: `~/.cache/tinfoil/` for VCEK certs and attestation bundles
