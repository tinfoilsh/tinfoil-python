# TDX Implementation Analysis for Python Client

This document analyzes the TDX verification logic in the Go `verifier` and `go-tdx-guest` projects to identify what needs to be implemented in the Python client.

## Current State

The Python client currently only supports **AMD SEV-SNP** attestation. To support TDX, we need to port the verification logic from the Go implementation.

## High-Level TDX Verification Flow (Go)

```
verifier/attestation/attestation.go: Document.Verify()
│
└─► verifyTdxAttestationV2(attestationDoc)  [tdx.go]
    │
    ├─► base64.decode() → gzip.decompress()
    │
    ├─► abi.QuoteToProto(bytes)             [go-tdx-guest/abi/abi.go]
    │   └─► Parse TDX QuoteV4 binary format
    │
    ├─► verify.TdxQuote(quote, opts)        [go-tdx-guest/verify/verify.go]
    │   │
    │   ├─► Extract PCK certificate chain from quote
    │   ├─► Fetch collateral (TCB info, QE identity) from embedded cache
    │   ├─► Verify PCK cert chain against Intel SGX Root CA
    │   ├─► Verify quote signature using attestation key
    │   ├─► Verify QE report signature using PCK cert
    │   ├─► Verify collateral signatures
    │   └─► Check TCB status
    │
    ├─► validate.TdxQuote(quote, valOpts)   [go-tdx-guest/validate/validate.go]
    │   │
    │   ├─► Check MrSeam against accepted values
    │   ├─► Check TdAttributes, Xfam
    │   ├─► Check minimum TEE TCB SVN
    │   └─► Check QE/PCE SVN minimums
    │
    └─► Extract measurements: [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
        Return: Verification(measurement, tls_key_fp, hpke_public_key)
```

## Components to Implement

### 1. TDX Quote Parsing (`abi_tdx.py`)

Port the binary parsing logic from `go-tdx-guest/abi/abi.go`.

**Key structures:**

```python
# QuoteV4 structure (Intel TDX DCAP format)
@dataclass
class TdxHeader:
    version: int           # 2 bytes, must be 4
    attestation_key_type: int  # 2 bytes, must be 2 (ECDSA-256)
    tee_type: int          # 4 bytes, must be 0x81 (TDX)
    pce_svn: bytes         # 2 bytes
    qe_svn: bytes          # 2 bytes
    qe_vendor_id: bytes    # 16 bytes (Intel: 939a7233-f79c-4ca9-940a-0db3957f0607)
    user_data: bytes       # 20 bytes

@dataclass
class TdQuoteBody:
    tee_tcb_svn: bytes     # 16 bytes
    mr_seam: bytes         # 48 bytes - SEAM module measurement
    mr_signer_seam: bytes  # 48 bytes
    seam_attributes: bytes # 8 bytes
    td_attributes: bytes   # 8 bytes
    xfam: bytes            # 8 bytes
    mr_td: bytes           # 48 bytes - TD identity (MRTD)
    mr_config_id: bytes    # 48 bytes
    mr_owner: bytes        # 48 bytes
    mr_owner_config: bytes # 48 bytes
    rtmrs: List[bytes]     # 4 x 48 bytes (RTMR0-3)
    report_data: bytes     # 64 bytes (TLS key FP + HPKE key)

@dataclass
class QuoteV4:
    header: TdxHeader
    td_quote_body: TdQuoteBody
    signed_data_size: int
    signed_data: SignedData  # Contains signature, attestation key, cert chain
```

**Binary offsets (from Go):**

| Field | Start | End | Size |
|-------|-------|-----|------|
| Header | 0x00 | 0x30 | 48 |
| TdQuoteBody | 0x30 | 0x278 | 584 |
| SignedDataSize | 0x278 | 0x27C | 4 |
| SignedData | 0x27C | ... | variable |

**TdQuoteBody offsets:**

| Field | Offset | Size |
|-------|--------|------|
| tee_tcb_svn | 0x00 | 16 |
| mr_seam | 0x10 | 48 |
| mr_signer_seam | 0x40 | 48 |
| seam_attributes | 0x70 | 8 |
| td_attributes | 0x78 | 8 |
| xfam | 0x80 | 8 |
| mr_td | 0x88 | 48 |
| mr_config_id | 0xB8 | 48 |
| mr_owner | 0xE8 | 48 |
| mr_owner_config | 0x118 | 48 |
| rtmrs | 0x148 | 192 (4×48) |
| report_data | 0x208 | 64 |

### 2. Certificate Chain Verification (`verify_tdx.py`)

Port from `go-tdx-guest/verify/verify.go`.

**Key tasks:**
1. Extract PCK certificate chain from quote (embedded in SignedData)
2. Parse 3 PEM certificates: PCK Leaf → Intermediate CA → Root CA
3. Verify chain against embedded Intel SGX Root CA
4. Extract PCK certificate extensions (FMSPC, PCEID, TCB components)

**Intel SGX Root CA:**
- Embedded in `verifier/attestation/sgx_root_ca.pem`
- URL: `https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem`

**Certificate chain structure:**
```
Intel SGX Root CA (embedded trust anchor)
    └─► Intel SGX PCK Platform CA (intermediate)
        └─► Intel SGX PCK Certificate (leaf, from quote)
```

### 3. Signature Verification

**Quote signature verification:**
```python
# 1. Get attestation key from quote (64 bytes, raw ECDSA P-256)
attestation_key = quote.signed_data.ecdsa_attestation_key

# 2. Get signature (64 bytes, raw R||S format)
signature = quote.signed_data.signature

# 3. Message = Header || TdQuoteBody (bytes 0x00-0x278)
message = header_bytes + td_quote_body_bytes
hashed_message = sha256(message)

# 4. Verify ECDSA-P256-SHA256
verify(attestation_key, signature, hashed_message)
```

**QE Report signature verification:**
```python
# Verify QE report using PCK leaf certificate
qe_report = quote.signed_data.certification_data.qe_report
qe_signature = quote.signed_data.certification_data.qe_report_signature
pck_cert = chain.pck_certificate

# ECDSA-P256-SHA256
pck_cert.public_key().verify(qe_signature, qe_report)
```

### 4. Collateral Verification (`collateral_tdx.py`)

The Go implementation embeds collateral (TCB info, QE identity) to avoid network calls.

**Embedded collateral files (from `verifier/attestation/collateral/`):**
- `qe_identity.json` - QE Identity from Intel PCS
- `qe_identity_chain.txt` - Signing certificate chain
- `tcb_info_<fmspc>.json` - TCB info per FMSPC
- `tcb_info_<fmspc>_chain.txt` - Signing certificate chain
- `root_ca.crl` - Root CA CRL
- `pck_crl_processor.crl` / `pck_crl_platform.crl` - PCK CRLs

**Collateral verification:**
1. Parse TCB info JSON, verify signature using chain
2. Parse QE identity JSON, verify signature using chain
3. Compare quote's TEE TCB SVN against TCB levels
4. Compare QE report fields against QE identity

### 5. Policy Validation (`validate_tdx.py`)

Port from `go-tdx-guest/validate/validate.go`.

**Validation checks:**

```python
# From verifier/attestation/tdx.go
validation_options = {
    # Header checks
    "minimum_qe_svn": 0,      # Should be 8 when Intel fixes packages
    "minimum_pce_svn": 0,     # Should be 13 when Intel fixes packages
    "qe_vendor_id": INTEL_QE_VENDOR_ID,  # 939a7233-f79c-...

    # TD Quote Body checks
    "minimum_tee_tcb_svn": [0x03, 0x01, 0x02, 0x00, ...],  # 16 bytes
    "accepted_mr_seams": [
        bytes.fromhex("49b66faa451d19eb..."),  # TDX module v1
        bytes.fromhex("685f891ea5c20e8f..."),  # TDX module v2
    ],
    "td_attributes": bytes.fromhex("0000001000000000"),  # SEPT_VE_DISABLE=1
    "xfam": bytes.fromhex("e702060000000000"),  # FP,SSE,AVX,AVX512,PK,AMX
    "mr_config_id": bytes(48),  # All zeros
    "mr_owner": bytes(48),      # All zeros
    "mr_owner_config": bytes(48),  # All zeros
}
```

### 6. Measurement Comparison Updates

**Current Python (SEV-SNP):**
```python
class Measurement:
    type: PredicateType  # SEV_GUEST_V2
    registers: List[str]  # [snp_measurement]
```

**Required for TDX:**
```python
class Measurement:
    type: PredicateType  # TDX_GUEST_V2 or SNP_TDX_MULTIPLATFORM_v1
    registers: List[str]  # [MRTD, RTMR0, RTMR1, RTMR2, RTMR3] for TDX
```

**Multi-platform comparison logic (from Go):**
```python
def equals(code: Measurement, enclave: Measurement) -> bool:
    if code.type == SNP_TDX_MULTIPLATFORM_v1:
        # code.registers = [snp_measurement, rtmr1, rtmr2]
        if enclave.type == TDX_GUEST_V2:
            # enclave.registers = [mrtd, rtmr0, rtmr1, rtmr2, rtmr3]
            return (
                code.registers[1] == enclave.registers[2] and  # RTMR1
                code.registers[2] == enclave.registers[3] and  # RTMR2
                enclave.registers[4] == "00" * 48              # RTMR3 = zeros
            )
        elif enclave.type == SEV_GUEST_V2:
            return code.registers[0] == enclave.registers[0]  # SNP measurement
```

### 7. Hardware Measurements (`hardware_measurements.py`)

For TDX, MRTD and RTMR0 are platform-specific (not deterministic like RTMR1/RTMR2).

**Verification flow:**
1. Fetch hardware measurements from `tinfoilsh/hardware-measurements` repo
2. Match enclave's MRTD + RTMR0 against known valid platforms
3. Only compare RTMR1/RTMR2 with code measurements from Sigstore

```python
@dataclass
class HardwareMeasurement:
    id: str      # platform@digest
    mrtd: str    # 48 bytes hex
    rtmr0: str   # 48 bytes hex

def verify_hardware(
    hardware_measurements: List[HardwareMeasurement],
    enclave_measurement: Measurement
) -> HardwareMeasurement:
    """Find matching hardware platform for TDX enclave."""
    for hw in hardware_measurements:
        if (hw.mrtd == enclave_measurement.registers[0] and
            hw.rtmr0 == enclave_measurement.registers[1]):
            return hw
    raise ValueError("No matching hardware platform found")
```

## Implementation Plan

### Phase 1: Core Quote Parsing

1. Create `abi_tdx.py` with QuoteV4 parsing
2. Add Intel SGX Root CA to `intel_root_ca.py`
3. Implement basic quote structure validation
4. **Quote version handling**: Detect v4 vs v5 quotes and reject v5 with clear error
   - V5 uses `TDQuoteBodyDescriptor` with different structure
   - Can add v5 support later if needed

### Phase 2: Cryptographic Verification

1. Implement PCK certificate chain extraction and validation
2. Implement quote signature verification (ECDSA P-256)
3. Implement QE report signature verification using PCK leaf cert
4. **QE report data binding** (critical security check):
   - Verify `SHA256(attestation_key || auth_data)` matches QE report data
   - Go ref: `verify.go` → `verifyHash256()`
   - Without this, an attacker could substitute a different attestation key
5. **PCK certificate extension parsing**:
   - Extract FMSPC (6 bytes), PCEID (2 bytes), TCB component SVNs
   - OIDs under `1.2.840.113741.1.13.1.*`
   - Required for TCB level matching in Phase 3
6. **CRL selection**:
   - Select processor vs platform CRL based on PCK issuer CN
   - Verify PCK cert not revoked

### Phase 3: Collateral & Policy

1. Embed collateral files (TCB info, QE identity, CRLs)
2. Implement collateral signature verification
3. **Collateral freshness validation**:
   - Check `tcbEvaluationDataNumber >= MIN_THRESHOLD`
   - Go ref: `tdx.go` → freshness check
   - Prevents use of outdated collateral with known vulnerabilities
4. Implement TCB status checking using PCK extensions from Phase 2
5. Implement policy validation (MrSeam, attributes, etc.)

### Phase 4: Integration

1. Update `Measurement` class for TDX registers
2. Update `Document.verify()` to route TDX quotes
3. **Update predicate version**: Use `tdx-guest/v2` (not v1)
4. Implement hardware measurement matching
5. **Update Sigstore integration**:
   - Parse `tdx_measurement.rtmr1`/`rtmr2` fields
   - Support multi-platform format with 3 registers
6. **Router platform selection**:
   - Current: SNP-only (`platform=snp`)
   - Options: query both, config preference, or auto-detect from enclave

## Key Differences from SEV-SNP

| Aspect | AMD SEV-SNP | Intel TDX |
|--------|-------------|-----------|
| Root cert | AMD ARK (embedded) | Intel SGX Root CA (embedded) |
| Intermediate | AMD ASK (embedded) | Fetched from collateral or embedded |
| Leaf cert | VCEK (fetched from KDS) | PCK cert (embedded in quote) |
| Signature | ECDSA P-384 | ECDSA P-256 |
| Measurement | 1 register (48 bytes) | 5 registers (MRTD + 4 RTMRs) |
| Collateral | VCEK only | TCB info + QE identity + CRLs |
| Policy | TCB version, guest policy | TEE TCB SVN, MrSeam, TdAttributes |

## Files to Create

```
src/tinfoil/attestation/
├── abi_tdx.py              # TDX quote binary parsing
├── verify_tdx.py           # TDX signature verification
├── validate_tdx.py         # TDX policy validation
├── collateral_tdx.py       # Intel collateral handling
├── intel_root_ca.py        # Embedded Intel SGX Root CA
└── hardware_measurements.py # Platform measurement matching
```

## Testing Strategy

1. **Unit tests with synthetic data**: Generate valid-looking TDX quotes for parsing tests
2. **Real quote tests**: Capture real TDX quotes from test enclaves
3. **Integration tests**: End-to-end verification against live TDX enclaves

## Security-Critical Checklist

These checks are **required** for a secure implementation. Skipping any of them creates vulnerabilities:

| Check | Phase | Go Reference | Risk if Skipped |
|-------|-------|--------------|-----------------|
| Quote signature verification | 2 | `verifyQuoteSignature()` | Attacker can forge quote |
| QE report signature verification | 2 | `verifyQeReportSignature()` | Attacker can forge QE report |
| **QE report data binding** | 2 | `verifyHash256()` | Attacker can substitute attestation key |
| PCK chain to Intel root | 2 | `verifyPckChain()` | Attacker can use fake certificates |
| PCK extension parsing | 2 | `parsePckExtensions()` | Cannot determine TCB level |
| TCB status check | 3 | `checkTcbStatus()` | May accept vulnerable/revoked TCB |
| Collateral signature | 3 | `verifyCollateralSignature()` | Attacker can forge TCB info |

**Should have** (defense in depth):

| Check | Phase | Go Reference | Risk if Skipped |
|-------|-------|--------------|-----------------|
| Collateral freshness | 3 | `validateFreshness()` | May use outdated collateral |
| CRL revocation check | 2 | `checkCrl()` | May accept revoked certificates |
| Quote v5 rejection | 1 | `TDQuoteBodyDescriptor` | Parsing errors or silent failures |

## Go Function References

Key functions in `go-tdx-guest/verify/verify.go` to port:

| Function | Purpose | Approx Lines |
|----------|---------|--------------|
| `TdxQuote()` | Main entry point | ~50 |
| `verifyQuoteSignature()` | Quote ECDSA verification | ~30 |
| `verifyQeReportSignature()` | QE report verification | ~25 |
| `verifyHash256()` | QE report data binding | ~15 |
| `getPckCertificateChain()` | Extract certs from quote | ~40 |
| `verifyPckChain()` | Chain validation | ~60 |
| `parsePckExtensions()` | FMSPC/PCEID extraction | ~80 |
| `checkTcbStatus()` | TCB level determination | ~100 |
| `verifyCollateral()` | TCB info/QE identity sigs | ~70 |

Total: ~470 lines of core verification logic to port.
