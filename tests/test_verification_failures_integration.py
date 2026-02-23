"""
Integration tests for verification failure handling.

These tests verify that REAL verification failures are properly caught
at the integration level - not with mocks, but with actual enclaves
and mismatched repos.

This guards against bugs like the Go verifier issue where hardware
measurement mismatches would silently continue instead of failing.
"""

import pytest

from tinfoil.client import SecureClient, get_router_address
from tinfoil.attestation import MeasurementMismatchError

pytestmark = pytest.mark.integration

# Router runs confidential-model-router, use gpt-oss as wrong repo
CORRECT_REPO = "tinfoilsh/confidential-model-router"
WRONG_REPO = "tinfoilsh/confidential-gpt-oss-120b-free"


@pytest.fixture(scope="module")
def router_enclave():
    """Fetch a router enclave address, skip all tests if unavailable."""
    try:
        return get_router_address()
    except Exception as e:
        pytest.skip(f"Could not fetch router address: {e}")


class TestMeasurementMismatchIntegration:
    """
    Tests that measurement mismatches between enclave and repo
    are properly caught at the integration level.
    """

    def test_wrong_repo_fails_verification(self, router_enclave):
        """
        Verifying an enclave against the WRONG repo must fail.

        This test:
        1. Gets a real router enclave
        2. Tries to verify it against gpt-oss-120b-free repo (WRONG)
        3. Expects MeasurementMismatchError

        This catches bugs where measurement comparison is skipped.
        """
        print(f"\nTesting: {router_enclave}")
        print(f"Against WRONG repo: {WRONG_REPO}")
        print("Expected: MeasurementMismatchError")

        client = SecureClient(enclave=router_enclave, repo=WRONG_REPO)

        with pytest.raises(MeasurementMismatchError):
            client.verify()

        print("✓ Correctly rejected mismatched measurements")

    def test_wrong_repo_blocks_http_client(self, router_enclave):
        """
        make_secure_http_client() must fail if measurements don't match.

        This catches bugs where HTTP client is created despite failed verification.
        """
        client = SecureClient(enclave=router_enclave, repo=WRONG_REPO)

        with pytest.raises(MeasurementMismatchError):
            client.make_secure_http_client()

        # Ground truth should NOT be set if verification failed
        assert client.ground_truth is None, \
            "ground_truth was set despite verification failure!"

        print("✓ HTTP client correctly blocked on mismatch")

    def test_correct_repo_passes_verification(self, router_enclave):
        """
        Sanity check: correct repo should pass verification.
        """
        client = SecureClient(enclave=router_enclave, repo=CORRECT_REPO)
        ground_truth = client.verify()

        assert ground_truth is not None
        assert ground_truth.public_key is not None
        assert ground_truth.measurement is not None

        print(f"✓ Correct repo verified successfully")
        print(f"  Measurement: {ground_truth.measurement.fingerprint()[:32]}...")


class TestDirectMeasurementIntegration:
    """
    Tests for the direct measurement verification path.
    """

    def test_wrong_pinned_measurement_fails(self, router_enclave):
        """
        If user provides a specific measurement that doesn't match
        the enclave, verification must fail.
        """
        # This is clearly a fake measurement
        fake_measurement = {
            "snp_measurement": "0000000000000000000000000000000000000000000000000000000000000000"
        }

        client = SecureClient(enclave=router_enclave, measurement=fake_measurement)

        with pytest.raises(ValueError, match="measurement mismatch"):
            client.verify()

        print("✓ Correctly rejected fake pinned measurement")


class TestNoSilentFailures:
    """
    Tests that verification failures are NEVER silently ignored.
    """

    def test_verification_required_before_request(self, router_enclave):
        """
        Any attempt to use the client must trigger verification.
        If verification would fail, the request must also fail.
        """
        client = SecureClient(enclave=router_enclave, repo=WRONG_REPO)

        # Try to get HTTP client - should fail
        with pytest.raises(MeasurementMismatchError):
            client.get_http_client()

        # Try to make request - should also fail
        import urllib.request
        req = urllib.request.Request(f"https://{router_enclave}/health")

        with pytest.raises(MeasurementMismatchError):
            client.make_request(req)

        print("✓ All client methods properly block on verification failure")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
