import pytest

# Adjust these imports based on your project structure
from tinfoil.github import fetch_latest_digest, fetch_attestation_bundle
from tinfoil.sigstore import verify_attestation
from tinfoil.attestation import fetch_attestation
from tinfoil.client import get_router_address

pytestmark = pytest.mark.integration  # allows pytest -m integration filtering

# Fetch config from environment variables, falling back to defaults
# Use the same env vars as the other integration test for consistency
REPO = "tinfoilsh/confidential-model-router"

def test_full_verification_flow():
    """
    Tests the complete attestation verification flow:
    1. Fetch latest digest for the repository.
    2. Fetch the sigstore attestation bundle for that digest.
    3. Verify the sigstore bundle to get code measurements.
    4. Fetch the runtime attestation from the enclave.
    5. Verify the runtime attestation.
    6. Compare code measurements with runtime measurements.
    """
    try:
        # Fetch enclave address lazily inside the test to avoid import-time network calls
        try:
            enclave = get_router_address()
        except Exception as e:
            pytest.skip(f"Could not fetch router address from ATC service: {e}")
            return

        # Fetch latest release digest
        print(f"Fetching latest release for {REPO}")
        digest = fetch_latest_digest(REPO)
        print(f"Found digest: {digest}")

        # Fetch attestation bundle
        print(f"Fetching attestation bundle for {REPO}@{digest}")
        sigstore_bundle = fetch_attestation_bundle(REPO, digest)
        assert sigstore_bundle is not None # Basic check

        # Verify attested measurements from sigstore bundle
        print(f"Verifying attested measurements for {REPO}@{digest}")
        code_measurements = verify_attestation(
            sigstore_bundle,
            digest,
            REPO
        )
        assert code_measurements is not None # Basic check
        print(f"Code measurements fingerprint: {code_measurements.fingerprint()}")


        # Fetch runtime attestation from the enclave
        print(f"Fetching runtime attestation from {enclave}")
        enclave_attestation = fetch_attestation(enclave)
        assert enclave_attestation is not None # Basic check

        # Verify enclave measurements from runtime attestation
        print("Verifying enclave measurements")
        runtime_verification = enclave_attestation.verify()
        assert runtime_verification is not None # Basic check
        print(f"Runtime measurement fingerprint: {runtime_verification.measurement.fingerprint()}")
        print(f"Public key fingerprint: {runtime_verification.public_key_fp}")


        # Compare measurements
        print("Comparing measurements")
        assert len(code_measurements.registers) == len(runtime_verification.measurement.registers), \
            "Number of measurement registers differ"

        for i, code_reg in enumerate(code_measurements.registers):
            runtime_reg = runtime_verification.measurement.registers[i]
            assert code_reg == runtime_reg, \
                f"Measurement register {i} mismatch: Code='{code_reg}' vs Runtime='{runtime_reg}'"

        print("Verification successful!")
        print(f"Public key fingerprint: {runtime_verification.public_key_fp}")
        print(f"Measurement: {code_measurements.fingerprint()}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        pytest.fail(f"Verification flow failed with exception: {e}")


if __name__ == "__main__":
    # Allow running the test directly using `python tests/test_verification_flow.py`
    pytest.main([__file__])
