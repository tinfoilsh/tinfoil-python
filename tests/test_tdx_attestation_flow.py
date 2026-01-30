"""
Integration test for TDX attestation verification flow.

Mirrors test_attestation_flow.py but specifically for TDX enclaves.
"""

import pytest

from tinfoil.github import fetch_latest_digest, fetch_attestation_bundle
from tinfoil.sigstore import verify_attestation
from tinfoil.attestation import fetch_attestation, PredicateType
from tinfoil.client import get_router_address

pytestmark = pytest.mark.integration  # allows pytest -m integration filtering

REPO = "tinfoilsh/confidential-model-router"

# Both TDX predicate types (V1 is deprecated but may still be in use)
TDX_TYPES = (PredicateType.TDX_GUEST_V1, PredicateType.TDX_GUEST_V2)


def test_tdx_full_verification_flow():
    """
    Tests the complete TDX attestation verification flow:
    1. Fetch latest digest for the repository.
    2. Fetch the sigstore attestation bundle for that digest.
    3. Verify the sigstore bundle to get code measurements.
    4. Fetch the runtime attestation from the enclave.
    5. Verify it's a TDX attestation (skip if SNP).
    6. Verify the runtime attestation.
    7. Compare code measurements with runtime measurements.
    """
    try:
        # Fetch enclave address
        try:
            # enclave = get_router_address()
            enclave = "router.inf9.tinfoil.sh"
        except Exception as e:
            pytest.skip(f"Could not fetch router address from ATC service: {e}")
            return

        # Fetch latest release digest
        print(f"\n1. Fetching latest release for {REPO}")
        digest = fetch_latest_digest(REPO)
        print(f"   Found digest: {digest}")

        # Fetch attestation bundle
        print(f"\n2. Fetching attestation bundle for {REPO}@{digest}")
        sigstore_bundle = fetch_attestation_bundle(REPO, digest)
        assert sigstore_bundle is not None

        # Verify attested measurements from sigstore bundle
        print(f"\n3. Verifying attested measurements for {REPO}@{digest}")
        code_measurements = verify_attestation(
            sigstore_bundle,
            digest,
            REPO
        )
        assert code_measurements is not None
        print(f"   Code measurements type: {code_measurements.type}")
        print(f"   Code measurements fingerprint: {code_measurements.fingerprint()}")

        # Fetch runtime attestation from the enclave
        print(f"\n4. Fetching runtime attestation from {enclave}")
        enclave_attestation = fetch_attestation(enclave)
        assert enclave_attestation is not None
        print(f"   Attestation format: {enclave_attestation.format}")

        # Check if this is a TDX attestation
        if enclave_attestation.format not in TDX_TYPES:
            pytest.skip(
                f"Enclave returned {enclave_attestation.format}, not TDX. "
                "This test is specifically for TDX enclaves."
            )
            return

        print(f"   ✓ Confirmed TDX attestation ({enclave_attestation.format})")

        # Verify enclave measurements from runtime attestation
        print("\n5. Verifying TDX enclave measurements")
        runtime_verification = enclave_attestation.verify()
        assert runtime_verification is not None
        print(f"   Runtime measurement type: {runtime_verification.measurement.type}")
        print(f"   Runtime measurement fingerprint: {runtime_verification.measurement.fingerprint()}")
        print(f"   Public key fingerprint: {runtime_verification.public_key_fp}")

        # Print TDX-specific measurements
        regs = runtime_verification.measurement.registers
        print("\n   TDX Measurements:")
        print(f"     MRTD:  {regs[0][:32]}...")
        print(f"     RTMR0: {regs[1][:32]}...")
        print(f"     RTMR1: {regs[2][:32]}...")
        print(f"     RTMR2: {regs[3][:32]}...")
        print(f"     RTMR3: {regs[4][:32]}...")

        # Compare measurements (handles cross-platform comparison)
        print("\n6. Comparing measurements")
        print(f"   Code type: {code_measurements.type}")
        print(f"   Runtime type: {runtime_verification.measurement.type}")
        code_measurements.equals(runtime_verification.measurement)

        print("\n✓ TDX Verification successful!")
        print(f"  Public key fingerprint: {runtime_verification.public_key_fp}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        pytest.fail(f"TDX verification flow failed with exception: {e}")


def test_tdx_policy_validation_in_flow():
    """
    Tests that TDX policy validation is applied during verification.

    This test verifies that the policy checks (XFAM, TD_ATTRIBUTES,
    SEAM_ATTRIBUTES, MR_SIGNER_SEAM, MR_SEAM whitelist) are actually
    being applied in the verification flow.
    """
    try:
        # Fetch enclave address
        try:
            enclave = get_router_address()
        except Exception as e:
            pytest.skip(f"Could not fetch router address from ATC service: {e}")
            return

        # Fetch runtime attestation
        print(f"\nFetching runtime attestation from {enclave}")
        enclave_attestation = fetch_attestation(enclave)
        assert enclave_attestation is not None

        # Check if this is a TDX attestation
        if enclave_attestation.format not in TDX_TYPES:
            pytest.skip(
                f"Enclave returned {enclave_attestation.format}, not TDX."
            )
            return

        # Verify - this should run all policy validations
        print("Verifying TDX attestation (includes policy validation)")
        runtime_verification = enclave_attestation.verify()

        # If we get here, all policy checks passed:
        # - validate_xfam() passed
        # - validate_td_attributes() passed
        # - validate_seam_attributes() passed
        # - validate_mr_signer_seam() passed
        # - validate_mr_seam_whitelist() passed
        # - All exact byte matches passed
        # - Collateral validation passed

        print("✓ All TDX policy validations passed")
        print(f"  Measurement: {runtime_verification.measurement.fingerprint()}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        pytest.fail(f"TDX policy validation test failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
