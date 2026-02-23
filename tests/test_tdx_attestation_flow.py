"""
Integration test for TDX attestation verification flow.

Tests the complete verification using the SecureClient API.

Configure via environment variables:
    TINFOIL_TEST_REPO    - GitHub repo (e.g., tinfoilsh/confidential-gpt-oss-120b-free)
    TINFOIL_TEST_ENCLAVE - Enclave hostname (e.g., gpt-oss-120b-free.inf5.tinfoil.sh)

Example:
    TINFOIL_TEST_REPO=tinfoilsh/confidential-deepseek-r1-0528 \
    TINFOIL_TEST_ENCLAVE=deepseek-r1-0528.inf9.tinfoil.sh \
    python -m pytest tests/test_tdx_attestation_flow.py -v -s
"""

import os
import pytest

from tinfoil.client import SecureClient
from tinfoil.attestation import PredicateType, TDX_TYPES

pytestmark = pytest.mark.integration  # allows pytest -m integration filtering

# Test configuration from environment or defaults
REPO = os.environ.get("TINFOIL_TEST_REPO", "tinfoilsh/confidential-gpt-oss-120b-free")
ENCLAVE = os.environ.get("TINFOIL_TEST_ENCLAVE", "gpt-oss-120b-free.inf5.tinfoil.sh")


def test_tdx_full_verification_flow():
    """
    Tests the complete TDX attestation verification flow using SecureClient.
    
    SecureClient.verify() performs:
    1. Fetch runtime attestation from enclave
    2. Verify attestation (cryptographic + policy validation)
    3. Fetch latest digest from GitHub
    4. Fetch and verify sigstore attestation bundle
    5. For TDX: verify hardware measurements (MRTD, RTMR0)
    6. Compare code measurements with runtime measurements
    """
    print(f"\nVerifying TDX enclave: {ENCLAVE}")
    print(f"Against repo: {REPO}")
    
    client = SecureClient(enclave=ENCLAVE, repo=REPO)
    ground_truth = client.verify()
    
    # Check this is actually TDX
    if ground_truth.measurement.type not in TDX_TYPES:
        pytest.skip(
            f"Enclave returned {ground_truth.measurement.type}, not TDX. "
            "This test is specifically for TDX enclaves."
        )
    
    print(f"\n✓ TDX Verification successful!")
    print(f"  Measurement type: {ground_truth.measurement.type}")
    print(f"  Measurement fingerprint: {ground_truth.measurement.fingerprint()}")
    print(f"  Public key fingerprint: {ground_truth.public_key}")
    print(f"  Digest: {ground_truth.digest}")
    
    # Print TDX-specific measurements
    regs = ground_truth.measurement.registers
    print("\n  TDX Measurements:")
    print(f"    MRTD:  {regs[0][:32]}...")
    print(f"    RTMR0: {regs[1][:32]}...")
    print(f"    RTMR1: {regs[2][:32]}...")
    print(f"    RTMR2: {regs[3][:32]}...")
    print(f"    RTMR3: {regs[4][:32]}...")


def test_tdx_secure_http_client():
    """
    Tests that SecureClient creates a working pinned HTTP client for TDX enclaves.
    """
    print(f"\nCreating secure HTTP client for: {ENCLAVE}")
    
    client = SecureClient(enclave=ENCLAVE, repo=REPO)
    http_client = client.make_secure_http_client()
    
    ground_truth = client.ground_truth
    assert ground_truth is not None
    
    if ground_truth.measurement.type not in TDX_TYPES:
        http_client.close()
        pytest.skip(f"Enclave returned {ground_truth.measurement.type}, not TDX.")
    
    print(f"\n✓ Secure HTTP client created successfully!")
    print(f"  TLS pinned to: {ground_truth.public_key}")
    
    http_client.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
