"""
Tests to ensure verification failures are properly propagated.

These tests ensure that if any verification step fails:
1. The error is raised, not silently ignored
2. No HTTP client is created
3. No connection to the enclave is made

This guards against bugs where failed verification would still allow
connections to proceed.
"""

import ssl

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


class TestVerifyPeerFingerprint:
    """Tests for SecureClient._verify_peer_fingerprint static method."""

    def test_raises_on_none_cert(self):
        """Must raise ValueError when cert_binary is None."""
        with pytest.raises(ValueError, match="No certificate found"):
            SecureClient._verify_peer_fingerprint(None, "abc123")

    def test_raises_on_empty_cert(self):
        """Must raise ValueError when cert_binary is empty bytes."""
        with pytest.raises(ValueError, match="No certificate found"):
            SecureClient._verify_peer_fingerprint(b"", "abc123")

    def test_raises_on_fingerprint_mismatch(self):
        """Must raise ValueError when public key fingerprint doesn't match."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        import datetime

        # Generate a self-signed cert to get valid DER bytes
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        from cryptography.hazmat.primitives.serialization import Encoding as CryptoEncoding
        cert_der = cert.public_bytes(CryptoEncoding.DER)

        with pytest.raises(ValueError, match="Certificate fingerprint mismatch"):
            SecureClient._verify_peer_fingerprint(cert_der, "wrong_fingerprint")

    def test_passes_on_fingerprint_match(self):
        """Must not raise when public key fingerprint matches."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding as CryptoEncoding, PublicFormat as CryptoPublicFormat
        from cryptography.x509.oid import NameOID
        import datetime
        import hashlib

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_der = cert.public_bytes(CryptoEncoding.DER)

        # Compute the expected fingerprint the same way the code does
        pub_der = key.public_key().public_bytes(
            CryptoEncoding.DER, CryptoPublicFormat.SubjectPublicKeyInfo
        )
        expected_fp = hashlib.sha256(pub_der).hexdigest()

        # Should not raise
        SecureClient._verify_peer_fingerprint(cert_der, expected_fp)


class TestAsyncTLSPinning:
    """Tests that the async httpx client correctly pins TLS certificates via wrap_bio."""

    FAKE_FP = "a" * 64

    def _make_client_with_fake_verify(self):
        """Create a SecureClient that returns a fake fingerprint from verify()."""
        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")
        ground_truth = MagicMock()
        ground_truth.public_key = self.FAKE_FP
        client.verify = MagicMock(return_value=ground_truth)
        return client

    def _get_ssl_context(self, async_http_client):
        """Extract the SSL context from an httpx.AsyncClient."""
        return async_http_client._transport._pool._ssl_context

    def _call_pinned_wrap_bio(self, ssl_ctx, fake_ssl_object):
        """
        Call the patched wrap_bio on ssl_ctx, intercepting the real
        original_wrap_bio so it returns our fake_ssl_object instead of
        attempting a real SSL operation.

        The pinned_wrap_bio closure holds a reference to original_wrap_bio
        (the real ctx.wrap_bio at creation time). We patch the underlying
        ctx._wrap_bio C method so that the call chain
        pinned_wrap_bio -> original_wrap_bio -> SSLContext.wrap_bio -> _wrap_bio
        returns our fake.
        """
        with patch.object(ssl_ctx, '_wrap_bio', create=True) as mock_inner:
            # ssl.SSLContext.wrap_bio calls sslobject_class._create which
            # calls context._wrap_bio. We need to go one level deeper and
            # patch SSLObject._create to just return our fake.
            with patch('ssl.SSLObject._create', return_value=fake_ssl_object):
                return ssl_ctx.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO())

    def test_wrap_bio_is_monkey_patched(self):
        """make_secure_async_http_client() must replace ctx.wrap_bio."""
        client = self._make_client_with_fake_verify()
        async_http = client.make_secure_async_http_client()

        # The underlying SSL context's wrap_bio should no longer be the
        # original C-level method — it should be our pinned_wrap_bio closure.
        ssl_ctx = self._get_ssl_context(async_http)
        assert ssl_ctx.wrap_bio is not ssl.SSLContext.wrap_bio

    def test_do_handshake_verifies_fingerprint_match(self):
        """After handshake, matching fingerprint must not raise."""
        client = self._make_client_with_fake_verify()
        async_http = client.make_secure_async_http_client()
        ssl_ctx = self._get_ssl_context(async_http)

        fake_ssl_object = MagicMock()
        fake_ssl_object.do_handshake = MagicMock(return_value=None)

        with patch.object(SecureClient, '_verify_peer_fingerprint') as mock_verify:
            result = self._call_pinned_wrap_bio(ssl_ctx, fake_ssl_object)

            # do_handshake should have been replaced with the checked version
            result.do_handshake()

            mock_verify.assert_called_once_with(
                fake_ssl_object.getpeercert(binary_form=True),
                self.FAKE_FP,
            )

    def test_do_handshake_rejects_fingerprint_mismatch(self):
        """After handshake, mismatched fingerprint must raise ValueError."""
        client = self._make_client_with_fake_verify()
        async_http = client.make_secure_async_http_client()
        ssl_ctx = self._get_ssl_context(async_http)

        fake_ssl_object = MagicMock()
        fake_ssl_object.do_handshake = MagicMock(return_value=None)
        fake_ssl_object.getpeercert.return_value = b"fake_cert_bytes"

        with patch.object(
            SecureClient, '_verify_peer_fingerprint',
            side_effect=ValueError("Certificate fingerprint mismatch"),
        ):
            result = self._call_pinned_wrap_bio(ssl_ctx, fake_ssl_object)

            with pytest.raises(ValueError, match="Certificate fingerprint mismatch"):
                result.do_handshake()

    def test_do_handshake_rejects_missing_cert(self):
        """After handshake, missing peer cert must raise ValueError."""
        client = self._make_client_with_fake_verify()
        async_http = client.make_secure_async_http_client()
        ssl_ctx = self._get_ssl_context(async_http)

        fake_ssl_object = MagicMock()
        fake_ssl_object.do_handshake = MagicMock(return_value=None)
        fake_ssl_object.getpeercert.return_value = None

        result = self._call_pinned_wrap_bio(ssl_ctx, fake_ssl_object)

        with pytest.raises(ValueError, match="No certificate found"):
            result.do_handshake()

    def test_ssl_want_read_propagates_without_cert_check(self):
        """SSLWantReadError during handshake must propagate without checking cert."""
        client = self._make_client_with_fake_verify()
        async_http = client.make_secure_async_http_client()
        ssl_ctx = self._get_ssl_context(async_http)

        fake_ssl_object = MagicMock()
        fake_ssl_object.do_handshake = MagicMock(side_effect=ssl.SSLWantReadError())

        result = self._call_pinned_wrap_bio(ssl_ctx, fake_ssl_object)

        with pytest.raises(ssl.SSLWantReadError):
            result.do_handshake()

        # getpeercert should NOT have been called — handshake isn't done yet
        fake_ssl_object.getpeercert.assert_not_called()

    def test_ssl_want_write_propagates_without_cert_check(self):
        """SSLWantWriteError during handshake must propagate without checking cert."""
        client = self._make_client_with_fake_verify()
        async_http = client.make_secure_async_http_client()
        ssl_ctx = self._get_ssl_context(async_http)

        fake_ssl_object = MagicMock()
        fake_ssl_object.do_handshake = MagicMock(side_effect=ssl.SSLWantWriteError())

        result = self._call_pinned_wrap_bio(ssl_ctx, fake_ssl_object)

        with pytest.raises(ssl.SSLWantWriteError):
            result.do_handshake()

        fake_ssl_object.getpeercert.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
