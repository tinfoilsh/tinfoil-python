"""
Tests for TDX attestation validation (validate_tdx.py).

Includes:
- Unit tests for policy validation functions (validate_xfam, validate_td_attributes, etc.)
- Integration tests for verify_tdx_attestation
"""

import base64
import gzip
import struct
import pytest
from unittest.mock import patch, MagicMock

from tinfoil.attestation.validate_tdx import (
    verify_tdx_attestation,
    TdxValidationError,
    TdxValidationResult,
    # Policy validation functions
    validate_xfam,
    validate_td_attributes,
    validate_seam_attributes,
    validate_mr_signer_seam,
    validate_tdx_policy,
    validate_mr_seam_whitelist,
    # Options
    PolicyOptions,
    HeaderOptions,
    TdQuoteBodyOptions,
    # Constants
    XFAM_FIXED1,
    XFAM_FIXED0,
    TD_ATTRIBUTES_FIXED0,
    TD_ATTRIBUTES_DEBUG_BIT,
    TD_ATTRIBUTES_SEPT_VE_DIS,
    TD_ATTRIBUTES_PKS,
    TD_ATTRIBUTES_PERFMON,
    ACCEPTED_MR_SEAMS,
    EXPECTED_TD_ATTRIBUTES,
    EXPECTED_XFAM,
    EXPECTED_MINIMUM_TEE_TCB_SVN,
    INTEL_QE_VENDOR_ID,
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
# Unit Tests for Policy Validation Functions
# =============================================================================

class TestValidateXfam:
    """Test XFAM fixed bit validation."""

    def test_valid_xfam_with_fixed1_bits(self):
        """XFAM with required FIXED1 bits set passes."""
        xfam = struct.pack('<Q', XFAM_FIXED1)
        validate_xfam(xfam)  # Should not raise

    def test_valid_xfam_with_additional_allowed_bits(self):
        """XFAM with FIXED1 plus other allowed bits passes."""
        # XFAM_FIXED0 defines which bits are allowed
        xfam = struct.pack('<Q', XFAM_FIXED0)
        validate_xfam(xfam)  # Should not raise

    def test_expected_xfam_value_passes(self):
        """The expected XFAM value from Go passes validation."""
        validate_xfam(EXPECTED_XFAM)  # Should not raise

    def test_missing_fixed1_bits_rejected(self):
        """XFAM missing required FIXED1 bits is rejected."""
        xfam = struct.pack('<Q', 0x0)
        with pytest.raises(TdxValidationError, match="FIXED1.*unset"):
            validate_xfam(xfam)

    def test_unauthorized_bits_rejected(self):
        """XFAM with bits outside FIXED0 mask is rejected."""
        # Set all bits - many are not allowed
        xfam = struct.pack('<Q', 0xFFFFFFFFFFFFFFFF)
        with pytest.raises(TdxValidationError, match="FIXED0.*set"):
            validate_xfam(xfam)

    def test_wrong_size_rejected(self):
        """XFAM with wrong size is rejected."""
        with pytest.raises(TdxValidationError, match="size is"):
            validate_xfam(b'\x00' * 4)  # Too short


class TestValidateTdAttributes:
    """Test TD_ATTRIBUTES fixed bit validation."""

    def test_valid_with_sept_ve_dis(self):
        """TD_ATTRIBUTES with SEPT_VE_DIS bit passes."""
        td_attrs = struct.pack('<Q', TD_ATTRIBUTES_SEPT_VE_DIS)
        validate_td_attributes(td_attrs)  # Should not raise

    def test_valid_with_pks(self):
        """TD_ATTRIBUTES with PKS bit passes."""
        td_attrs = struct.pack('<Q', TD_ATTRIBUTES_PKS)
        validate_td_attributes(td_attrs)  # Should not raise

    def test_valid_with_perfmon(self):
        """TD_ATTRIBUTES with PERFMON bit passes."""
        td_attrs = struct.pack('<Q', TD_ATTRIBUTES_PERFMON)
        validate_td_attributes(td_attrs)  # Should not raise

    def test_valid_with_multiple_allowed_bits(self):
        """TD_ATTRIBUTES with multiple allowed bits passes."""
        value = TD_ATTRIBUTES_SEPT_VE_DIS | TD_ATTRIBUTES_PKS
        td_attrs = struct.pack('<Q', value)
        validate_td_attributes(td_attrs)  # Should not raise

    def test_expected_td_attributes_value_passes(self):
        """The expected TD_ATTRIBUTES value from Go passes validation."""
        validate_td_attributes(EXPECTED_TD_ATTRIBUTES)  # Should not raise

    def test_debug_bit_allowed_by_fixed0(self):
        """DEBUG bit is allowed by FIXED0 (validation happens via exact match)."""
        # DEBUG bit is in FIXED0, so it passes fixed bit validation
        # The actual DEBUG rejection happens via exact byte matching
        td_attrs = struct.pack('<Q', TD_ATTRIBUTES_DEBUG_BIT)
        validate_td_attributes(td_attrs)  # Should not raise (fixed bits allow it)

    def test_unauthorized_bits_rejected(self):
        """TD_ATTRIBUTES with bits outside FIXED0 mask is rejected."""
        # Bit 10 is not in FIXED0
        td_attrs = struct.pack('<Q', 1 << 10)
        with pytest.raises(TdxValidationError, match="FIXED0.*set"):
            validate_td_attributes(td_attrs)

    def test_wrong_size_rejected(self):
        """TD_ATTRIBUTES with wrong size is rejected."""
        with pytest.raises(TdxValidationError, match="size is"):
            validate_td_attributes(b'\x00' * 4)


class TestValidateSeamAttributes:
    """Test SEAMATTRIBUTES validation."""

    def test_zero_accepted(self):
        """Zero SEAMATTRIBUTES passes."""
        validate_seam_attributes(b'\x00' * 8)  # Should not raise

    def test_non_zero_rejected(self):
        """Non-zero SEAMATTRIBUTES is rejected."""
        with pytest.raises(TdxValidationError, match="must be zero"):
            validate_seam_attributes(b'\x01' + b'\x00' * 7)

    def test_all_ones_rejected(self):
        """All-ones SEAMATTRIBUTES is rejected."""
        with pytest.raises(TdxValidationError, match="must be zero"):
            validate_seam_attributes(b'\xff' * 8)

    def test_wrong_size_rejected(self):
        """SEAMATTRIBUTES with wrong size is rejected."""
        with pytest.raises(TdxValidationError, match="size is"):
            validate_seam_attributes(b'\x00' * 4)


class TestValidateMrSignerSeam:
    """Test MRSIGNERSEAM validation."""

    def test_zero_accepted(self):
        """Zero MRSIGNERSEAM passes."""
        validate_mr_signer_seam(b'\x00' * 48)  # Should not raise

    def test_non_zero_rejected(self):
        """Non-zero MRSIGNERSEAM is rejected."""
        with pytest.raises(TdxValidationError, match="must be zero"):
            validate_mr_signer_seam(b'\x01' + b'\x00' * 47)

    def test_all_ones_rejected(self):
        """All-ones MRSIGNERSEAM is rejected."""
        with pytest.raises(TdxValidationError, match="must be zero"):
            validate_mr_signer_seam(b'\xff' * 48)

    def test_wrong_size_rejected(self):
        """MRSIGNERSEAM with wrong size is rejected."""
        with pytest.raises(TdxValidationError, match="size is"):
            validate_mr_signer_seam(b'\x00' * 32)


class TestValidateMrSeamWhitelist:
    """Test MR_SEAM whitelist validation."""

    def test_first_accepted_mr_seam_passes(self):
        """First accepted MR_SEAM value passes."""
        validate_mr_seam_whitelist(ACCEPTED_MR_SEAMS[0])  # Should not raise

    def test_second_accepted_mr_seam_passes(self):
        """Second accepted MR_SEAM value passes."""
        validate_mr_seam_whitelist(ACCEPTED_MR_SEAMS[1])  # Should not raise

    def test_unknown_mr_seam_rejected(self):
        """Unknown MR_SEAM value is rejected."""
        with pytest.raises(TdxValidationError, match="not in accepted list"):
            validate_mr_seam_whitelist(b'\x00' * 48)

    def test_similar_but_different_rejected(self):
        """MR_SEAM that differs by one byte is rejected."""
        # Take first accepted value and change last byte
        modified = ACCEPTED_MR_SEAMS[0][:-1] + b'\xff'
        with pytest.raises(TdxValidationError, match="not in accepted list"):
            validate_mr_seam_whitelist(modified)


class TestPolicyOptions:
    """Test PolicyOptions dataclass."""

    def test_default_options(self):
        """Default options have all fields as None."""
        opts = PolicyOptions()
        assert opts.header.qe_vendor_id is None
        assert opts.header.minimum_qe_svn is None
        assert opts.header.minimum_pce_svn is None
        assert opts.td_quote_body.minimum_tee_tcb_svn is None
        assert opts.td_quote_body.td_attributes is None
        assert opts.td_quote_body.mr_td is None

    def test_custom_header_options(self):
        """Custom header options are set correctly."""
        opts = PolicyOptions(
            header=HeaderOptions(
                qe_vendor_id=INTEL_QE_VENDOR_ID,
                minimum_qe_svn=5,
            ),
        )
        assert opts.header.qe_vendor_id == INTEL_QE_VENDOR_ID
        assert opts.header.minimum_qe_svn == 5

    def test_custom_body_options(self):
        """Custom body options are set correctly."""
        opts = PolicyOptions(
            td_quote_body=TdQuoteBodyOptions(
                td_attributes=EXPECTED_TD_ATTRIBUTES,
                xfam=EXPECTED_XFAM,
                mr_config_id=b'\x00' * 48,
            ),
        )
        assert opts.td_quote_body.td_attributes == EXPECTED_TD_ATTRIBUTES
        assert opts.td_quote_body.xfam == EXPECTED_XFAM
        assert opts.td_quote_body.mr_config_id == b'\x00' * 48


class TestOptionsLengthValidation:
    """Test that option field lengths are validated."""

    def test_invalid_qe_vendor_id_length(self):
        """QE_VENDOR_ID with wrong length is rejected."""
        from tinfoil.attestation.validate_tdx import _check_options_lengths

        opts = PolicyOptions(
            header=HeaderOptions(qe_vendor_id=b'\x00' * 8),  # Should be 16
        )
        with pytest.raises(TdxValidationError, match="qe_vendor_id.*length"):
            _check_options_lengths(opts)

    def test_invalid_mr_td_length(self):
        """MR_TD with wrong length is rejected."""
        from tinfoil.attestation.validate_tdx import _check_options_lengths

        opts = PolicyOptions(
            td_quote_body=TdQuoteBodyOptions(mr_td=b'\x00' * 32),  # Should be 48
        )
        with pytest.raises(TdxValidationError, match="mr_td.*length"):
            _check_options_lengths(opts)

    def test_invalid_rtmrs_count(self):
        """RTMRs with wrong count is rejected."""
        from tinfoil.attestation.validate_tdx import _check_options_lengths

        opts = PolicyOptions(
            td_quote_body=TdQuoteBodyOptions(rtmrs=[b'\x00' * 48] * 3),  # Should be 4
        )
        with pytest.raises(TdxValidationError, match="rtmrs.*entries"):
            _check_options_lengths(opts)

    def test_valid_options_pass(self):
        """Valid options pass length checks."""
        from tinfoil.attestation.validate_tdx import _check_options_lengths

        opts = PolicyOptions(
            header=HeaderOptions(qe_vendor_id=INTEL_QE_VENDOR_ID),
            td_quote_body=TdQuoteBodyOptions(
                minimum_tee_tcb_svn=EXPECTED_MINIMUM_TEE_TCB_SVN,
                td_attributes=EXPECTED_TD_ATTRIBUTES,
                xfam=EXPECTED_XFAM,
                mr_config_id=b'\x00' * 48,
                mr_owner=b'\x00' * 48,
                mr_owner_config=b'\x00' * 48,
            ),
        )
        _check_options_lengths(opts)  # Should not raise


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
