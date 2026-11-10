"""Unit tests for TDX policy validation."""

from __future__ import annotations

import struct

import pytest

from tinfoil._v3.verifier._quote.tdx.lib.abi import INTEL_QE_VENDOR_ID
from tinfoil._v3.verifier._quote.tdx.lib.validate import (
    TD_ATTRIBUTES_DEBUG_BIT,
    TD_ATTRIBUTES_PERFMON,
    TD_ATTRIBUTES_PKS,
    TD_ATTRIBUTES_SEPT_VE_DIS,
    XFAM_FIXED0,
    XFAM_FIXED1,
    HeaderOptions,
    PolicyOptions,
    TdQuoteBodyOptions,
    TdxValidationError,
    validate_mr_signer_seam,
    validate_seam_attributes,
    validate_td_attributes,
    validate_xfam,
)

# Values that a production TDX quote carries, used as the "known good" inputs below.
EXPECTED_TD_ATTRIBUTES = bytes.fromhex("0000001000000000")
EXPECTED_XFAM = bytes.fromhex("e702060000000000")
EXPECTED_MINIMUM_TEE_TCB_SVN = bytes.fromhex("03010200000000000000000000000000")

# Orchestration imports (from attestation_tdx)

# Policy validation imports (from validate_tdx)

# ABI imports

# Import test fixtures from test_tdx_verify


# =============================================================================
# Unit Tests for Policy Validation Functions
# =============================================================================


class TestValidateXfam:
    """Test XFAM fixed bit validation."""

    def test_valid_xfam_with_fixed1_bits(self):
        """XFAM with required FIXED1 bits set passes."""
        xfam = struct.pack("<Q", XFAM_FIXED1)
        validate_xfam(xfam)  # Should not raise

    def test_valid_xfam_with_additional_allowed_bits(self):
        """XFAM with FIXED1 plus other allowed bits passes."""
        # XFAM_FIXED0 defines which bits are allowed
        xfam = struct.pack("<Q", XFAM_FIXED0)
        validate_xfam(xfam)  # Should not raise

    def test_expected_xfam_value_passes(self):
        """The expected XFAM value from Go passes validation."""
        validate_xfam(EXPECTED_XFAM)  # Should not raise

    def test_missing_fixed1_bits_rejected(self):
        """XFAM missing required FIXED1 bits is rejected."""
        xfam = struct.pack("<Q", 0x0)
        with pytest.raises(TdxValidationError, match=r"FIXED1.*unset"):
            validate_xfam(xfam)

    def test_unauthorized_bits_rejected(self):
        """XFAM with bits outside FIXED0 mask is rejected."""
        # Set all bits - many are not allowed
        xfam = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)
        with pytest.raises(TdxValidationError, match=r"FIXED0.*set"):
            validate_xfam(xfam)

    def test_wrong_size_rejected(self):
        """XFAM with wrong size is rejected."""
        with pytest.raises(TdxValidationError, match="size is"):
            validate_xfam(b"\x00" * 4)  # Too short


class TestValidateTdAttributes:
    """Test TD_ATTRIBUTES fixed bit validation."""

    def test_valid_with_sept_ve_dis(self):
        """TD_ATTRIBUTES with SEPT_VE_DIS bit passes."""
        td_attrs = struct.pack("<Q", TD_ATTRIBUTES_SEPT_VE_DIS)
        validate_td_attributes(td_attrs)  # Should not raise

    def test_valid_with_pks(self):
        """TD_ATTRIBUTES with PKS bit passes."""
        td_attrs = struct.pack("<Q", TD_ATTRIBUTES_PKS)
        validate_td_attributes(td_attrs)  # Should not raise

    def test_valid_with_perfmon(self):
        """TD_ATTRIBUTES with PERFMON bit passes."""
        td_attrs = struct.pack("<Q", TD_ATTRIBUTES_PERFMON)
        validate_td_attributes(td_attrs)  # Should not raise

    def test_valid_with_multiple_allowed_bits(self):
        """TD_ATTRIBUTES with multiple allowed bits passes."""
        value = TD_ATTRIBUTES_SEPT_VE_DIS | TD_ATTRIBUTES_PKS
        td_attrs = struct.pack("<Q", value)
        validate_td_attributes(td_attrs)  # Should not raise

    def test_expected_td_attributes_value_passes(self):
        """The expected TD_ATTRIBUTES value from Go passes validation."""
        validate_td_attributes(EXPECTED_TD_ATTRIBUTES)  # Should not raise

    def test_debug_bit_rejected_unconditionally(self):
        """DEBUG bit is rejected unconditionally, even though it's in FIXED0."""
        td_attrs = struct.pack("<Q", TD_ATTRIBUTES_DEBUG_BIT)
        with pytest.raises(TdxValidationError, match="DEBUG bit must not be set"):
            validate_td_attributes(td_attrs)

    def test_unauthorized_bits_rejected(self):
        """TD_ATTRIBUTES with bits outside FIXED0 mask is rejected."""
        # Bit 10 is not in FIXED0
        td_attrs = struct.pack("<Q", 1 << 10)
        with pytest.raises(TdxValidationError, match=r"FIXED0.*set"):
            validate_td_attributes(td_attrs)

    def test_wrong_size_rejected(self):
        """TD_ATTRIBUTES with wrong size is rejected."""
        with pytest.raises(TdxValidationError, match="size is"):
            validate_td_attributes(b"\x00" * 4)


class TestValidateSeamAttributes:
    """Test SEAMATTRIBUTES validation."""

    def test_zero_accepted(self):
        """Zero SEAMATTRIBUTES passes."""
        validate_seam_attributes(b"\x00" * 8)  # Should not raise

    def test_non_zero_rejected(self):
        """Non-zero SEAMATTRIBUTES is rejected."""
        with pytest.raises(TdxValidationError, match="must be zero"):
            validate_seam_attributes(b"\x01" + b"\x00" * 7)

    def test_all_ones_rejected(self):
        """All-ones SEAMATTRIBUTES is rejected."""
        with pytest.raises(TdxValidationError, match="must be zero"):
            validate_seam_attributes(b"\xff" * 8)

    def test_wrong_size_rejected(self):
        """SEAMATTRIBUTES with wrong size is rejected."""
        with pytest.raises(TdxValidationError, match="size is"):
            validate_seam_attributes(b"\x00" * 4)


class TestValidateMrSignerSeam:
    """Test MRSIGNERSEAM validation."""

    def test_zero_accepted(self):
        """Zero MRSIGNERSEAM passes."""
        validate_mr_signer_seam(b"\x00" * 48)  # Should not raise

    def test_non_zero_rejected(self):
        """Non-zero MRSIGNERSEAM is rejected."""
        with pytest.raises(TdxValidationError, match="must be zero"):
            validate_mr_signer_seam(b"\x01" + b"\x00" * 47)

    def test_all_ones_rejected(self):
        """All-ones MRSIGNERSEAM is rejected."""
        with pytest.raises(TdxValidationError, match="must be zero"):
            validate_mr_signer_seam(b"\xff" * 48)

    def test_wrong_size_rejected(self):
        """MRSIGNERSEAM with wrong size is rejected."""
        with pytest.raises(TdxValidationError, match="size is"):
            validate_mr_signer_seam(b"\x00" * 32)


class TestPolicyOptions:
    """Test PolicyOptions dataclass."""

    def test_default_options(self):
        """Default options have all fields as None."""
        opts = PolicyOptions()
        assert opts.header.qe_vendor_id is None
        assert opts.td_quote_body.minimum_tee_tcb_svn is None
        assert opts.td_quote_body.td_attributes is None
        assert opts.td_quote_body.mr_td is None

    def test_custom_header_options(self):
        """Custom header options are set correctly."""
        opts = PolicyOptions(
            header=HeaderOptions(
                qe_vendor_id=INTEL_QE_VENDOR_ID,
            ),
        )
        assert opts.header.qe_vendor_id == INTEL_QE_VENDOR_ID

    def test_custom_body_options(self):
        """Custom body options are set correctly."""
        opts = PolicyOptions(
            td_quote_body=TdQuoteBodyOptions(
                td_attributes=EXPECTED_TD_ATTRIBUTES,
                xfam=EXPECTED_XFAM,
                mr_config_id=b"\x00" * 48,
            ),
        )
        assert opts.td_quote_body.td_attributes == EXPECTED_TD_ATTRIBUTES
        assert opts.td_quote_body.xfam == EXPECTED_XFAM
        assert opts.td_quote_body.mr_config_id == b"\x00" * 48


class TestOptionsLengthValidation:
    """Test that option field lengths are validated."""

    def test_invalid_qe_vendor_id_length(self):
        """QE_VENDOR_ID with wrong length is rejected."""
        from tinfoil._v3.verifier._quote.tdx.lib.validate import _check_options_lengths

        opts = PolicyOptions(
            header=HeaderOptions(qe_vendor_id=b"\x00" * 8),  # Should be 16
        )
        with pytest.raises(TdxValidationError, match=r"qe_vendor_id.*length"):
            _check_options_lengths(opts)

    def test_invalid_mr_td_length(self):
        """MR_TD with wrong length is rejected."""
        from tinfoil._v3.verifier._quote.tdx.lib.validate import _check_options_lengths

        opts = PolicyOptions(
            td_quote_body=TdQuoteBodyOptions(mr_td=b"\x00" * 32),  # Should be 48
        )
        with pytest.raises(TdxValidationError, match=r"mr_td.*length"):
            _check_options_lengths(opts)

    def test_invalid_rtmrs_count(self):
        """RTMRs with wrong count is rejected."""
        from tinfoil._v3.verifier._quote.tdx.lib.validate import _check_options_lengths

        opts = PolicyOptions(
            td_quote_body=TdQuoteBodyOptions(rtmrs=(b"\x00" * 48,) * 3),  # Should be 4
        )
        with pytest.raises(TdxValidationError, match=r"rtmrs.*entries"):
            _check_options_lengths(opts)

    def test_valid_options_pass(self):
        """Valid options pass length checks."""
        from tinfoil._v3.verifier._quote.tdx.lib.validate import _check_options_lengths

        opts = PolicyOptions(
            header=HeaderOptions(qe_vendor_id=INTEL_QE_VENDOR_ID),
            td_quote_body=TdQuoteBodyOptions(
                minimum_tee_tcb_svn=EXPECTED_MINIMUM_TEE_TCB_SVN,
                td_attributes=EXPECTED_TD_ATTRIBUTES,
                xfam=EXPECTED_XFAM,
                mr_config_id=b"\x00" * 48,
                mr_owner=b"\x00" * 48,
                mr_owner_config=b"\x00" * 48,
            ),
        )
        _check_options_lengths(opts)  # Should not raise


# =============================================================================
# Test Fixtures
# =============================================================================


# =============================================================================
# Unit Tests for verify_tdx_attestation
# =============================================================================


# =============================================================================
# Integration Tests with attestation.py
# =============================================================================


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
