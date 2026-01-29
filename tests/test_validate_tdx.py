"""
Integration tests for TDX attestation validation (validate_tdx.py).
"""

import base64
import gzip
import pytest
from unittest.mock import patch, MagicMock

from tinfoil.attestation.validate_tdx import (
    verify_tdx_attestation,
    TdxValidationError,
    TdxValidationResult,
)
from tinfoil.attestation.attestation import (
    Document,
    PredicateType,
    Verification,
    Measurement,
    verify_tdx_attestation_v1,
)

# Import test fixtures from test_tdx_verify
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from test_tdx_verify import (
    build_signed_quote_with_keys,
    _generate_self_signed_cert_pem,
)


# =============================================================================
# Test Fixtures
# =============================================================================

def create_test_attestation_doc(raw_quote: bytes, compress: bool = True) -> str:
    """Create a base64-encoded attestation document."""
    if compress:
        compressed = gzip.compress(raw_quote)
        return base64.b64encode(compressed).decode()
    return base64.b64encode(raw_quote).decode()


# =============================================================================
# Unit Tests for verify_tdx_attestation
# =============================================================================

class TestVerifyTdxAttestation:
    """Test verify_tdx_attestation function."""

    def test_invalid_base64(self):
        """Test that invalid base64 raises error."""
        with pytest.raises(TdxValidationError, match="Failed to decode base64"):
            verify_tdx_attestation("not valid base64!!!")

    def test_invalid_gzip(self):
        """Test that invalid gzip raises error."""
        # Valid base64 but not gzip
        doc = base64.b64encode(b"not gzipped").decode()
        with pytest.raises(TdxValidationError, match="Failed to decompress"):
            verify_tdx_attestation(doc, is_compressed=True)

# =============================================================================
# Integration Tests with attestation.py
# =============================================================================

class TestDocumentVerify:
    """Test Document.verify() with TDX format."""

    def test_document_verify_tdx(self):
        """Test that Document.verify() handles TDX format."""
        raw_quote, _, _ = build_signed_quote_with_keys()
        doc = create_test_attestation_doc(raw_quote)

        document = Document(
            format=PredicateType.TDX_GUEST_V1,
            body=doc,
        )

        with patch('tinfoil.attestation.validate_tdx.extract_pck_extensions') as mock_extract:
            from tinfoil.attestation.pck_extensions import PckExtensions, PckCertTCB
            mock_extract.return_value = PckExtensions(
                ppid="00" * 16,
                tcb=PckCertTCB(
                    pce_svn=13,
                    cpu_svn=bytes(16),
                    tcb_components=[0] * 16,
                ),
                pceid="0000",
                fmspc="90c06f000000",
            )

            # Mock collateral fetch to avoid network call
            with patch('tinfoil.attestation.validate_tdx.fetch_collateral') as mock_fetch:
                mock_fetch.side_effect = Exception("Network disabled in test")

                # With skip_collateral default (False), this would fail on network
                # So we patch the entire verify_tdx_attestation to skip collateral
                with patch('tinfoil.attestation.attestation.verify_tdx_attestation') as mock_verify:
                    from tinfoil.attestation.validate_tdx import TdxValidationResult
                    mock_verify.return_value = TdxValidationResult(
                        quote=MagicMock(),
                        pck_chain=MagicMock(),
                        pck_extensions=MagicMock(),
                        collateral=None,
                        tcb_level=None,
                        measurements=["aa" * 48, "bb" * 48, "cc" * 48, "dd" * 48, "00" * 48],
                        tls_key_fp="ff" * 32,
                        hpke_public_key="ee" * 32,
                    )

                    result = document.verify()

                    assert isinstance(result, Verification)
                    assert result.measurement.type == PredicateType.TDX_GUEST_V1
                    assert len(result.measurement.registers) == 5
                    assert result.public_key_fp == "ff" * 32


class TestMeasurementComparison:
    """Test Measurement.equals() with TDX measurements."""

    def test_tdx_same_measurements_equal(self):
        """Test that identical TDX measurements are equal."""
        m1 = Measurement(
            type=PredicateType.TDX_GUEST_V1,
            registers=["aa" * 48, "bb" * 48, "cc" * 48, "dd" * 48, "00" * 48],
        )
        m2 = Measurement(
            type=PredicateType.TDX_GUEST_V1,
            registers=["aa" * 48, "bb" * 48, "cc" * 48, "dd" * 48, "00" * 48],
        )

        # Should not raise
        m1.equals(m2)

    def test_tdx_different_measurements_not_equal(self):
        """Test that different TDX measurements raise error."""
        from tinfoil.attestation.attestation import MeasurementMismatchError

        m1 = Measurement(
            type=PredicateType.TDX_GUEST_V1,
            registers=["aa" * 48, "bb" * 48, "cc" * 48, "dd" * 48, "00" * 48],
        )
        m2 = Measurement(
            type=PredicateType.TDX_GUEST_V1,
            registers=["ff" * 48, "bb" * 48, "cc" * 48, "dd" * 48, "00" * 48],
        )

        with pytest.raises(MeasurementMismatchError):
            m1.equals(m2)

    def test_multiplatform_vs_tdx(self):
        """Test multiplatform measurement comparison with TDX."""
        # Multiplatform: [SNP_measurement, RTMR1, RTMR2]
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=["snp" * 16, "cc" * 48, "dd" * 48],
        )

        # TDX: [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
        tdx = Measurement(
            type=PredicateType.TDX_GUEST_V1,
            registers=["aa" * 48, "bb" * 48, "cc" * 48, "dd" * 48, "00" * 48],
        )

        # RTMR1 and RTMR2 should match
        # multiplatform.registers[1] == tdx.registers[2] (RTMR1)
        # multiplatform.registers[2] == tdx.registers[3] (RTMR2)
        multiplatform.equals(tdx)  # Should not raise


class TestMeasurementStr:
    """Test Measurement.__str__() for TDX."""

    def test_tdx_measurement_str(self):
        """Test string representation of TDX measurement."""
        m = Measurement(
            type=PredicateType.TDX_GUEST_V1,
            registers=["aa" * 48, "bb" * 48, "cc" * 48, "dd" * 48, "00" * 48],
        )

        s = str(m)
        assert "TDX_GUEST_V1" in s or "tdx-guest" in s
        assert "mrtd=" in s
        assert "rtmr0=" in s
        assert "rtmr1=" in s
        assert "rtmr2=" in s
        assert "rtmr3=" in s


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
