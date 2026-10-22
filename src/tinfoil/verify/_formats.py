"""Format, role and identifier registry of the v3 attestation document.

Public modules re-export the identifiers callers need; everything else is
shared only within this package.
"""

# The document and its endorsed sections.
ATTESTATION_V3 = "https://tinfoil.sh/predicate/attestation/v3"
REPORT_DATA_V1 = "https://tinfoil.sh/report-data/v1"
CRYPTO_MATERIAL_V1 = "https://tinfoil.sh/crypto-material/v1"
DEVICE_EVIDENCE_V1 = "https://tinfoil.sh/device-evidence/v1"

# CPU and device evidence.
SEV_SNP_REPORT_V1 = "https://tinfoil.sh/format/sev-snp-report/v1"
TDX_QUOTE_V1 = "https://tinfoil.sh/format/tdx-quote/v1"
NVIDIA_GPU_EVIDENCE_V1 = "https://tinfoil.sh/format/nvidia-gpu-evidence/v1"

# Endorsed key material.
KEY_SPKI_FP_SHA256_V1 = "https://tinfoil.sh/key/spki-fp-sha256/v1"
KEY_SPKI_V1 = "https://tinfoil.sh/key/spki/v1"
KEY_X25519_HPKE_V1 = "https://tinfoil.sh/key/x25519-hpke/v1"
CRYPTO_MATERIAL_ID_TLS = "tls"
CRYPTO_MATERIAL_ID_HPKE = "hpke"

# Collateral formats. COLLATERAL_V2 is the legacy GitHub workload-release
# collateral, and also what a document without collateral_format carries.
COLLATERAL_V2 = "https://tinfoil.sh/predicate/attestation-collaterals/v2"
COLLATERAL_V3 = "https://tinfoil.sh/predicate/attestation-collaterals/v3"

AMD_VCEK_V1 = "https://tinfoil.sh/collateral/amd-vcek/v1"
AMD_CRL_V1 = "https://tinfoil.sh/collateral/amd-crl/v1"
INTEL_PCS_V1 = "https://tinfoil.sh/collateral/intel-pcs/v1"
NVIDIA_GPU_V1 = "https://tinfoil.sh/collateral/nvidia-gpu/v1"
SIGSTORE_CODE_V1 = "https://tinfoil.sh/collateral/sigstore-code/v1"
SIGSTORE_PLATFORM_V1 = "https://tinfoil.sh/collateral/sigstore-platform/v1"
SIGSTORE_FRESHNESS_V1 = "https://tinfoil.sh/collateral/sigstore-freshness/v1"
ARTIFACT_FRESHNESS_V1 = "https://tinfoil.sh/collateral/artifact-freshness/v1"
CONFIG_ENDORSEMENT_V1 = "https://tinfoil.sh/collateral/config-endorsement/v1"
CONFIG_V1 = "https://tinfoil.sh/collateral/config/v1"
IGVM_RUNTIME_V1 = "https://tinfoil.sh/collateral/igvm-runtime/v1"

# Collateral roles (RATS, RFC 9334).
ROLE_ENDORSEMENT = "endorsement"
ROLE_REFERENCE_VALUES = "reference-values"

# Reserved collateral identifiers.
SUBJECT_CPU = "cpu"
FRESHNESS_ID_CODE = "code-freshness"
FRESHNESS_ID_PLATFORM = "platform-freshness"
FRESHNESS_ID_RUNTIME = "runtime-freshness"
CONFIG_ID = "tinfoil-config"
RUNTIME_ID = "runtime"
PLATFORM_ID = "platform"
RUNTIME_REPO = "tinfoilsh/cvmimage"
