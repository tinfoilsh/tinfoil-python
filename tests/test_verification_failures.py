"""
Tests to ensure verification failures are properly propagated.

These tests ensure that if any verification step fails:
1. The error is raised, not silently ignored
2. No HTTP client is created
3. No connection to the enclave is made

This guards against bugs where failed verification would still allow
connections to proceed.
"""

import pytest
from unittest.mock import patch, MagicMock

from tinfoil.client import SecureClient
from tinfoil.attestation import (
    Measurement,
    PredicateType,
    MeasurementMismatchError,
    HardwareMeasurementError,
    verify_tdx_hardware,
    HardwareMeasurement,
)


class TestMeasurementMismatch:
    """Tests that measurement mismatches raise errors and block connections."""

    def test_measurement_equals_raises_on_mismatch(self):
        """Measurement.assert_equal() must raise MeasurementMismatchError on mismatch."""
        m1 = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["abc123"]
        )
        m2 = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["different"]
        )

        with pytest.raises(MeasurementMismatchError):
            m1.assert_equal(m2)

    def test_measurement_equals_raises_on_register_count_mismatch(self):
        """Measurement.assert_equal() must raise if register counts differ."""
        m1 = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["abc123"]
        )
        m2 = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["abc123", "extra"]
        )

        with pytest.raises(MeasurementMismatchError):
            m1.assert_equal(m2)

    def test_measurement_equals_passes_on_match(self):
        """Measurement.assert_equal() must not raise if measurements match."""
        m1 = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["abc123"]
        )
        m2 = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["abc123"]
        )

        # Should not raise
        m1.assert_equal(m2)


class TestHardwareMeasurementVerification:
    """Tests that hardware measurement failures raise errors."""

    def test_verify_hardware_raises_on_no_match(self):
        """verify_tdx_hardware() must raise HardwareMeasurementError if no match."""
        hardware_measurements = [
            HardwareMeasurement(
                id="platform1@digest1",
                mrtd="known_mrtd_1",
                rtmr0="known_rtmr0_1"
            ),
            HardwareMeasurement(
                id="platform2@digest2",
                mrtd="known_mrtd_2",
                rtmr0="known_rtmr0_2"
            ),
        ]

        enclave_measurement = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=["unknown_mrtd", "unknown_rtmr0", "rtmr1", "rtmr2", "rtmr3"]
        )

        with pytest.raises(HardwareMeasurementError, match="no matching hardware platform"):
            verify_tdx_hardware(hardware_measurements, enclave_measurement)

    def test_verify_hardware_passes_on_match(self):
        """verify_tdx_hardware() must return the matching measurement."""
        hardware_measurements = [
            HardwareMeasurement(
                id="platform1@digest1",
                mrtd="known_mrtd",
                rtmr0="known_rtmr0"
            ),
        ]

        enclave_measurement = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=["known_mrtd", "known_rtmr0", "rtmr1", "rtmr2", "rtmr3"]
        )

        result = verify_tdx_hardware(hardware_measurements, enclave_measurement)
        assert result.id == "platform1@digest1"


class TestSecureClientVerificationFailures:
    """Tests that SecureClient properly blocks on verification failures."""

    @patch('tinfoil.client.fetch_attestation')
    def test_attestation_failure_blocks_verify(self, mock_fetch):
        """If attestation fetch fails, verify() must raise."""
        mock_fetch.side_effect = Exception("Attestation fetch failed")

        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")

        with pytest.raises(Exception, match="Attestation fetch failed"):
            client.verify()

    @patch('tinfoil.client.fetch_attestation')
    def test_attestation_verification_failure_blocks_verify(self, mock_fetch):
        """If attestation verification fails, verify() must raise."""
        mock_doc = MagicMock()
        mock_doc.verify.side_effect = ValueError("TDX attestation verification failed")
        mock_fetch.return_value = mock_doc

        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")

        with pytest.raises(ValueError, match="TDX attestation verification failed"):
            client.verify()

    @patch('tinfoil.client.fetch_attestation')
    @patch('tinfoil.client.fetch_latest_digest')
    @patch('tinfoil.client.fetch_attestation_bundle')
    @patch('tinfoil.client.verify_attestation')
    def test_measurement_mismatch_blocks_verify(
        self, mock_verify_att, mock_fetch_bundle, mock_fetch_digest, mock_fetch_attestation
    ):
        """If code measurements don't match runtime, verify() must raise."""
        # Setup mocks
        mock_fetch_digest.return_value = "test_digest"
        mock_fetch_bundle.return_value = {}

        # Runtime measurement from enclave
        runtime_measurement = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["runtime_measurement"]
        )
        mock_verification = MagicMock()
        mock_verification.measurement = runtime_measurement
        mock_doc = MagicMock()
        mock_doc.verify.return_value = mock_verification
        mock_fetch_attestation.return_value = mock_doc

        # Code measurement from sigstore (different!)
        code_measurement = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["different_code_measurement"]
        )
        mock_verify_att.return_value = code_measurement

        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")

        with pytest.raises(MeasurementMismatchError):
            client.verify()

    @patch('tinfoil.client.fetch_attestation')
    @patch('tinfoil.client.fetch_latest_digest')
    @patch('tinfoil.client.fetch_attestation_bundle')
    @patch('tinfoil.client.verify_attestation')
    @patch('tinfoil.client.fetch_latest_hardware_measurements')
    @patch('tinfoil.client.verify_tdx_hardware')
    def test_hardware_mismatch_blocks_verify(
        self, mock_verify_hw, mock_fetch_hw, mock_verify_att,
        mock_fetch_bundle, mock_fetch_digest, mock_fetch_attestation
    ):
        """If TDX hardware measurements don't match, verify() must raise."""
        # Setup mocks
        mock_fetch_digest.return_value = "test_digest"
        mock_fetch_bundle.return_value = {}

        # TDX runtime measurement from enclave
        runtime_measurement = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
        )
        mock_verification = MagicMock()
        mock_verification.measurement = runtime_measurement
        mock_doc = MagicMock()
        mock_doc.verify.return_value = mock_verification
        mock_fetch_attestation.return_value = mock_doc

        # Code measurement from sigstore
        code_measurement = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
        )
        mock_verify_att.return_value = code_measurement

        # Hardware verification fails
        mock_fetch_hw.return_value = []
        mock_verify_hw.side_effect = HardwareMeasurementError("no matching hardware platform")

        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")

        with pytest.raises(HardwareMeasurementError, match="no matching hardware platform"):
            client.verify()

    @patch('tinfoil.client.fetch_attestation')
    def test_http_client_not_created_on_verification_failure(self, mock_fetch):
        """make_secure_http_client() must not return a client if verify() fails."""
        mock_fetch.side_effect = Exception("Attestation failed")

        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")

        with pytest.raises(Exception, match="Attestation failed"):
            client.make_secure_http_client()

        # Verify ground_truth was never set
        assert client.ground_truth is None

    @patch('tinfoil.client.fetch_attestation')
    def test_async_http_client_not_created_on_verification_failure(self, mock_fetch):
        """make_secure_async_http_client() must not return a client if verify() fails."""
        mock_fetch.side_effect = Exception("Attestation failed")

        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")

        with pytest.raises(Exception, match="Attestation failed"):
            client.make_secure_async_http_client()

        # Verify ground_truth was never set
        assert client.ground_truth is None

    @patch('tinfoil.client.fetch_attestation')
    def test_get_http_client_calls_verify_first(self, mock_fetch):
        """get_http_client() must call verify() before returning client."""
        mock_fetch.side_effect = Exception("Verification failed")

        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")

        with pytest.raises(Exception, match="Verification failed"):
            client.get_http_client()

    @patch('tinfoil.client.fetch_attestation')
    def test_make_request_calls_verify_first(self, mock_fetch):
        """make_request() must call verify() before making request."""
        import urllib.request

        mock_fetch.side_effect = Exception("Verification failed")

        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")
        req = urllib.request.Request("https://test.enclave.sh/api")

        with pytest.raises(Exception, match="Verification failed"):
            client.make_request(req)


class TestDirectMeasurementVerification:
    """Tests for direct measurement verification (no repo)."""

    @patch('tinfoil.client.fetch_attestation')
    def test_snp_measurement_mismatch_raises(self, mock_fetch):
        """If SNP measurement doesn't match provided measurement, must raise."""
        # Runtime measurement from enclave
        runtime_measurement = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["actual_snp_measurement"]
        )
        mock_verification = MagicMock()
        mock_verification.measurement = runtime_measurement
        mock_doc = MagicMock()
        mock_doc.verify.return_value = mock_verification
        mock_fetch.return_value = mock_doc

        # Expect different measurement
        client = SecureClient(
            enclave="test.enclave.sh",
            measurement={"snp_measurement": "expected_snp_measurement"}
        )

        with pytest.raises(ValueError, match="SNP measurement mismatch"):
            client.verify()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
