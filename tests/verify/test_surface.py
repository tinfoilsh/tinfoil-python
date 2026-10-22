"""The public surface applications program against (SDK_SURFACE_SPEC.md)."""

import importlib

import pytest

PUBLIC = {
    "tinfoil.verify": {
        "Error",
        "Layer",
        "SoftwareIdentity",
        "UsageError",
        "Verification",
        "VerificationError",
        "VerificationMetadata",
        "crypto_material_data",
    },
    "tinfoil.verify.document": {
        "CPUEvidence",
        "CRYPTO_MATERIAL_ID_HPKE",
        "CRYPTO_MATERIAL_ID_TLS",
        "CryptoMaterialItem",
        "DeviceEvidenceItem",
        "Document",
        "InvalidInputError",
        "KEY_SPKI_FP_SHA256_V1_FORMAT",
        "KEY_SPKI_V1_FORMAT",
        "KEY_X25519_HPKE_V1_FORMAT",
        "NONCE_SIZE",
        "NVIDIA_GPU_EVIDENCE_V1_FORMAT",
        "SEV_SNP_REPORT_V1_FORMAT",
        "TDX_QUOTE_V1_FORMAT",
        "compute_report_data",
        "parse",
        "random_nonce",
    },
    "tinfoil.verify.collateral": {
        "AmdCrl",
        "AmdVcek",
        "CPUEndorsements",
        "Freshness",
        "IntelPcs",
        "PcsResponse",
        "SigstoreRef",
    },
    "tinfoil.verify.measurement": {"Measurement", "PredicateType"},
}


@pytest.mark.parametrize("module_name", sorted(PUBLIC))
def test_public_names(module_name):
    module = importlib.import_module(module_name)
    assert set(module.__all__) == PUBLIC[module_name]
    for name in module.__all__:
        assert hasattr(module, name), name
