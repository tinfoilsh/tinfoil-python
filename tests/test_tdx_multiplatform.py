"""
Unit tests for TDX multiplatform measurement handling.

Covers:
1. Sigstore multiplatform TDX measurement parsing (SNP_TDX_MULTIPLATFORM_v1)
2. RTMR3-zero enforcement in measurement comparison
3. Module-identity matching with real tee_tcb_svn values
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from tinfoil.attestation import (
    Measurement,
    PredicateType,
    MeasurementMismatchError,
    Rtmr3NotZeroError,
    RTMR3_ZERO,
)
from tinfoil.attestation.collateral_tdx import (
    TcbInfo,
    TcbLevel,
    Tcb,
    TcbComponent,
    TcbStatus,
    TdxModuleIdentity,
    get_tdx_module_identity,
    validate_tdx_module_identity,
    CollateralError,
)


# =============================================================================
# Test Data - Realistic TDX Measurements
# =============================================================================

# 48-byte hex strings (96 chars) for TDX measurements
SAMPLE_MRTD = "a1" * 48
SAMPLE_RTMR0 = "b2" * 48
SAMPLE_RTMR1 = "c3" * 48
SAMPLE_RTMR2 = "d4" * 48
SAMPLE_RTMR3_ZEROS = "00" * 48
SAMPLE_RTMR3_NONZERO = "e5" * 48
SAMPLE_SNP_MEASUREMENT = "f6" * 48


# =============================================================================
# Sigstore Multiplatform TDX Measurement Parsing Tests
# =============================================================================

class TestSigstoreMultiplatformParsing:
    """Test parsing of SNP_TDX_MULTIPLATFORM_v1 predicates from Sigstore."""

    def _create_mock_bundle_payload(
        self,
        snp_measurement: str,
        rtmr1: str,
        rtmr2: str,
        digest: str = "abc123",
    ) -> bytes:
        """Create a mock in-toto payload with multiplatform predicate."""
        payload = {
            "predicateType": PredicateType.SNP_TDX_MULTIPLATFORM_v1.value,
            "predicate": {
                "snp_measurement": snp_measurement,
                "tdx_measurement": {
                    "rtmr1": rtmr1,
                    "rtmr2": rtmr2,
                },
            },
            "subject": [{"digest": {"sha256": digest}}],
        }
        return json.dumps(payload).encode()

    def test_parse_multiplatform_extracts_all_registers(self):
        """Test that multiplatform parsing extracts snp_measurement, rtmr1, rtmr2."""
        from tinfoil.sigstore import verify_attestation

        payload = self._create_mock_bundle_payload(
            snp_measurement=SAMPLE_SNP_MEASUREMENT,
            rtmr1=SAMPLE_RTMR1,
            rtmr2=SAMPLE_RTMR2,
            digest="test_digest_abc123",
        )

        with patch('tinfoil.sigstore.Verifier') as mock_verifier_cls:
            mock_verifier = MagicMock()
            mock_verifier_cls.production.return_value = mock_verifier
            mock_verifier.verify_dsse.return_value = (
                'application/vnd.in-toto+json',
                payload,
            )

            with patch('tinfoil.sigstore.Bundle'):
                result = verify_attestation(
                    bundle_json=b'{}',
                    digest="test_digest_abc123",
                    repo="test/repo",
                )

        assert result.type == PredicateType.SNP_TDX_MULTIPLATFORM_v1
        assert len(result.registers) == 3
        assert result.registers[0] == SAMPLE_SNP_MEASUREMENT
        assert result.registers[1] == SAMPLE_RTMR1
        assert result.registers[2] == SAMPLE_RTMR2

    def test_parse_multiplatform_missing_snp_measurement_fails(self):
        """Test that missing snp_measurement raises ValueError."""
        from tinfoil.sigstore import verify_attestation

        payload = {
            "predicateType": PredicateType.SNP_TDX_MULTIPLATFORM_v1.value,
            "predicate": {
                # snp_measurement missing
                "tdx_measurement": {
                    "rtmr1": SAMPLE_RTMR1,
                    "rtmr2": SAMPLE_RTMR2,
                },
            },
            "subject": [{"digest": {"sha256": "test_digest"}}],
        }
        payload_bytes = json.dumps(payload).encode()

        with patch('tinfoil.sigstore.Verifier') as mock_verifier_cls:
            mock_verifier = MagicMock()
            mock_verifier_cls.production.return_value = mock_verifier
            mock_verifier.verify_dsse.return_value = (
                'application/vnd.in-toto+json',
                payload_bytes,
            )

            with patch('tinfoil.sigstore.Bundle'):
                with pytest.raises(ValueError, match="no snp_measurement"):
                    verify_attestation(b'{}', "test_digest", "test/repo")

    def test_parse_multiplatform_missing_tdx_measurement_fails(self):
        """Test that missing tdx_measurement struct raises ValueError."""
        from tinfoil.sigstore import verify_attestation

        payload = {
            "predicateType": PredicateType.SNP_TDX_MULTIPLATFORM_v1.value,
            "predicate": {
                "snp_measurement": SAMPLE_SNP_MEASUREMENT,
                # tdx_measurement missing
            },
            "subject": [{"digest": {"sha256": "test_digest"}}],
        }
        payload_bytes = json.dumps(payload).encode()

        with patch('tinfoil.sigstore.Verifier') as mock_verifier_cls:
            mock_verifier = MagicMock()
            mock_verifier_cls.production.return_value = mock_verifier
            mock_verifier.verify_dsse.return_value = (
                'application/vnd.in-toto+json',
                payload_bytes,
            )

            with patch('tinfoil.sigstore.Bundle'):
                with pytest.raises(ValueError, match="no tdx_measurement"):
                    verify_attestation(b'{}', "test_digest", "test/repo")

    def test_parse_multiplatform_missing_rtmr1_fails(self):
        """Test that missing rtmr1 in tdx_measurement raises ValueError."""
        from tinfoil.sigstore import verify_attestation

        payload = {
            "predicateType": PredicateType.SNP_TDX_MULTIPLATFORM_v1.value,
            "predicate": {
                "snp_measurement": SAMPLE_SNP_MEASUREMENT,
                "tdx_measurement": {
                    # rtmr1 missing
                    "rtmr2": SAMPLE_RTMR2,
                },
            },
            "subject": [{"digest": {"sha256": "test_digest"}}],
        }
        payload_bytes = json.dumps(payload).encode()

        with patch('tinfoil.sigstore.Verifier') as mock_verifier_cls:
            mock_verifier = MagicMock()
            mock_verifier_cls.production.return_value = mock_verifier
            mock_verifier.verify_dsse.return_value = (
                'application/vnd.in-toto+json',
                payload_bytes,
            )

            with patch('tinfoil.sigstore.Bundle'):
                with pytest.raises(ValueError, match="missing rtmr1 or rtmr2"):
                    verify_attestation(b'{}', "test_digest", "test/repo")

    def test_parse_multiplatform_missing_rtmr2_fails(self):
        """Test that missing rtmr2 in tdx_measurement raises ValueError."""
        from tinfoil.sigstore import verify_attestation

        payload = {
            "predicateType": PredicateType.SNP_TDX_MULTIPLATFORM_v1.value,
            "predicate": {
                "snp_measurement": SAMPLE_SNP_MEASUREMENT,
                "tdx_measurement": {
                    "rtmr1": SAMPLE_RTMR1,
                    # rtmr2 missing
                },
            },
            "subject": [{"digest": {"sha256": "test_digest"}}],
        }
        payload_bytes = json.dumps(payload).encode()

        with patch('tinfoil.sigstore.Verifier') as mock_verifier_cls:
            mock_verifier = MagicMock()
            mock_verifier_cls.production.return_value = mock_verifier
            mock_verifier.verify_dsse.return_value = (
                'application/vnd.in-toto+json',
                payload_bytes,
            )

            with patch('tinfoil.sigstore.Bundle'):
                with pytest.raises(ValueError, match="missing rtmr1 or rtmr2"):
                    verify_attestation(b'{}', "test_digest", "test/repo")


# =============================================================================
# RTMR3-Zero Enforcement Tests
# =============================================================================

class TestRtmr3ZeroEnforcement:
    """Test RTMR3-zero enforcement in measurement comparison."""

    def test_rtmr3_zero_constant_is_correct(self):
        """Test that RTMR3_ZERO constant is 96 hex zeros (48 bytes)."""
        assert len(RTMR3_ZERO) == 96
        assert RTMR3_ZERO == "0" * 96

    def test_multiplatform_vs_tdx_with_zero_rtmr3_passes(self):
        """Test comparison passes when TDX RTMR3 is zeros."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        tdx = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=[
                SAMPLE_MRTD,       # MRTD (index 0)
                SAMPLE_RTMR0,      # RTMR0 (index 1)
                SAMPLE_RTMR1,      # RTMR1 (index 2) - must match
                SAMPLE_RTMR2,      # RTMR2 (index 3) - must match
                SAMPLE_RTMR3_ZEROS,  # RTMR3 (index 4) - must be zeros
            ],
        )

        # Should not raise
        multiplatform.equals(tdx)

    def test_multiplatform_vs_tdx_with_nonzero_rtmr3_fails(self):
        """Test comparison fails when TDX RTMR3 is not zeros."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        tdx = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=[
                SAMPLE_MRTD,
                SAMPLE_RTMR0,
                SAMPLE_RTMR1,
                SAMPLE_RTMR2,
                SAMPLE_RTMR3_NONZERO,  # RTMR3 is NOT zeros
            ],
        )

        with pytest.raises(Rtmr3NotZeroError, match="RTMR3 must be zeros"):
            multiplatform.equals(tdx)

    def test_multiplatform_vs_tdx_v1_with_zero_rtmr3_passes(self):
        """Test comparison with TDX_GUEST_V1 passes when RTMR3 is zeros."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        tdx_v1 = Measurement(
            type=PredicateType.TDX_GUEST_V1,
            registers=[
                SAMPLE_MRTD,
                SAMPLE_RTMR0,
                SAMPLE_RTMR1,
                SAMPLE_RTMR2,
                SAMPLE_RTMR3_ZEROS,
            ],
        )

        # Should not raise
        multiplatform.equals(tdx_v1)

    def test_multiplatform_vs_tdx_v1_with_nonzero_rtmr3_fails(self):
        """Test comparison with TDX_GUEST_V1 fails when RTMR3 is not zeros."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        tdx_v1 = Measurement(
            type=PredicateType.TDX_GUEST_V1,
            registers=[
                SAMPLE_MRTD,
                SAMPLE_RTMR0,
                SAMPLE_RTMR1,
                SAMPLE_RTMR2,
                SAMPLE_RTMR3_NONZERO,
            ],
        )

        with pytest.raises(Rtmr3NotZeroError):
            multiplatform.equals(tdx_v1)

    def test_multiplatform_vs_tdx_rtmr1_mismatch_fails(self):
        """Test comparison fails when RTMR1 doesn't match."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        tdx = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=[
                SAMPLE_MRTD,
                SAMPLE_RTMR0,
                "wrong_rtmr1" + "0" * 80,  # Wrong RTMR1
                SAMPLE_RTMR2,
                SAMPLE_RTMR3_ZEROS,
            ],
        )

        with pytest.raises(MeasurementMismatchError):
            multiplatform.equals(tdx)

    def test_multiplatform_vs_tdx_rtmr2_mismatch_fails(self):
        """Test comparison fails when RTMR2 doesn't match."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        tdx = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=[
                SAMPLE_MRTD,
                SAMPLE_RTMR0,
                SAMPLE_RTMR1,
                "wrong_rtmr2" + "0" * 80,  # Wrong RTMR2
                SAMPLE_RTMR3_ZEROS,
            ],
        )

        with pytest.raises(MeasurementMismatchError):
            multiplatform.equals(tdx)

    def test_reverse_comparison_tdx_vs_multiplatform(self):
        """Test reverse comparison (TDX.equals(multiplatform)) also works."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        tdx = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=[
                SAMPLE_MRTD,
                SAMPLE_RTMR0,
                SAMPLE_RTMR1,
                SAMPLE_RTMR2,
                SAMPLE_RTMR3_ZEROS,
            ],
        )

        # Reverse comparison should also work
        tdx.equals(multiplatform)

    def test_reverse_comparison_with_nonzero_rtmr3_fails(self):
        """Test reverse comparison also enforces RTMR3-zero."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        tdx = Measurement(
            type=PredicateType.TDX_GUEST_V2,
            registers=[
                SAMPLE_MRTD,
                SAMPLE_RTMR0,
                SAMPLE_RTMR1,
                SAMPLE_RTMR2,
                SAMPLE_RTMR3_NONZERO,
            ],
        )

        with pytest.raises(Rtmr3NotZeroError):
            tdx.equals(multiplatform)

    def test_multiplatform_vs_snp_compares_snp_measurement(self):
        """Test multiplatform vs SNP compares the SNP measurement register."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        snp = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=[SAMPLE_SNP_MEASUREMENT],
        )

        # Should not raise - SNP measurement matches
        multiplatform.equals(snp)

    def test_multiplatform_vs_snp_mismatch_fails(self):
        """Test multiplatform vs SNP fails when SNP measurement doesn't match."""
        multiplatform = Measurement(
            type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
            registers=[SAMPLE_SNP_MEASUREMENT, SAMPLE_RTMR1, SAMPLE_RTMR2],
        )

        snp = Measurement(
            type=PredicateType.SEV_GUEST_V2,
            registers=["wrong_snp_" + "0" * 86],  # Wrong SNP measurement
        )

        with pytest.raises(MeasurementMismatchError):
            multiplatform.equals(snp)


# =============================================================================
# Module Identity Matching with Real TEE_TCB_SVN Values
# =============================================================================

class TestModuleIdentityMatchingWithRealTeeTcbSvn:
    """Test module-identity matching with realistic tee_tcb_svn byte patterns."""

    def _create_tcb_info_with_modules(
        self,
        module_ids: list[str],
        module_mrsigner: bytes = b"\xaa" * 48,
    ) -> TcbInfo:
        """Create TCB Info with specified module identities."""
        module_identities = []
        for module_id in module_ids:
            module_identities.append(
                TdxModuleIdentity(
                    id=module_id,
                    mrsigner=module_mrsigner,
                    attributes=b"\x00" * 8,
                    attributes_mask=b"\xff" * 8,
                    tcb_levels=[
                        TcbLevel(
                            tcb=Tcb(
                                sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                                pce_svn=0,
                                tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                                isv_svn=3,  # Minimum minor version
                            ),
                            tcb_date="2024-01-01T00:00:00Z",
                            tcb_status=TcbStatus.UP_TO_DATE,
                            advisory_ids=[],
                        ),
                    ],
                )
            )

        return TcbInfo(
            id="TDX",
            version=3,
            issue_date=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(days=30),
            fmspc="00a06f000000",
            pce_id="0000",
            tcb_type=0,
            tcb_evaluation_data_number=17,
            tdx_module=None,
            tdx_module_identities=module_identities,
            tcb_levels=[],
        )

    # --- TEE_TCB_SVN byte layout tests ---
    # TEE_TCB_SVN is 16 bytes where:
    # - Byte 0 (index 0) = minor SVN (used for module TCB level matching)
    # - Byte 1 (index 1) = major SVN (used to derive module ID: TDX_{major:02d})
    # - Bytes 2-15 = other TCB components

    def test_tee_tcb_svn_major_version_3_matches_tdx_03(self):
        """Test TEE_TCB_SVN with major=3 matches TDX_03 module."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_01", "TDX_03", "TDX_05"])

        # TEE_TCB_SVN: minor=5, major=3 (TDX module version 3)
        tee_tcb_svn = bytes([5, 3] + [0] * 14)

        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is not None
        assert result.id == "TDX_03"

    def test_tee_tcb_svn_major_version_1_matches_tdx_01(self):
        """Test TEE_TCB_SVN with major=1 matches TDX_01 module."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_01", "TDX_03"])

        # TEE_TCB_SVN: minor=2, major=1 (TDX module version 1)
        tee_tcb_svn = bytes([2, 1] + [0] * 14)

        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is not None
        assert result.id == "TDX_01"

    def test_tee_tcb_svn_major_version_5_matches_tdx_05(self):
        """Test TEE_TCB_SVN with major=5 matches TDX_05 module."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_03", "TDX_05"])

        # TEE_TCB_SVN: minor=0, major=5 (TDX module version 5)
        tee_tcb_svn = bytes([0, 5] + [0] * 14)

        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is not None
        assert result.id == "TDX_05"

    def test_tee_tcb_svn_unknown_major_version_returns_none(self):
        """Test TEE_TCB_SVN with unknown major version returns None."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_01", "TDX_03"])

        # TEE_TCB_SVN: minor=0, major=99 (no TDX_99 module exists)
        tee_tcb_svn = bytes([0, 99] + [0] * 14)

        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is None

    def test_tee_tcb_svn_major_version_0_matches_tdx_00(self):
        """Test TEE_TCB_SVN with major=0 matches TDX_00 if present."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_00", "TDX_01"])

        # TEE_TCB_SVN: minor=1, major=0 (TDX module version 0)
        tee_tcb_svn = bytes([1, 0] + [0] * 14)

        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is not None
        assert result.id == "TDX_00"

    def test_tee_tcb_svn_too_short_returns_none(self):
        """Test TEE_TCB_SVN with < 2 bytes returns None."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_03"])

        # Only 1 byte - not enough to extract major version
        tee_tcb_svn = bytes([5])

        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is None

    def test_validate_module_identity_with_real_svn_values(self):
        """Test full module identity validation with realistic SVN values."""
        module_mrsigner = b"\xaa" * 48
        tcb_info = self._create_tcb_info_with_modules(
            ["TDX_03"],
            module_mrsigner=module_mrsigner,
        )

        # Realistic TEE_TCB_SVN: minor=5, major=3
        # This should match TDX_03 and pass TCB level check (minor >= 3)
        tee_tcb_svn = bytes([5, 3] + [0] * 14)
        mr_signer_seam = module_mrsigner
        seam_attributes = b"\x00" * 8

        result = validate_tdx_module_identity(
            tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes
        )
        assert result is not None
        assert result.tcb_status == TcbStatus.UP_TO_DATE

    def test_validate_module_identity_minor_svn_too_low_returns_none(self):
        """Test that minor SVN below threshold returns None (no matching level)."""
        module_mrsigner = b"\xaa" * 48

        tcb_info = TcbInfo(
            id="TDX",
            version=3,
            issue_date=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(days=30),
            fmspc="00a06f000000",
            pce_id="0000",
            tcb_type=0,
            tcb_evaluation_data_number=17,
            tdx_module=None,
            tdx_module_identities=[
                TdxModuleIdentity(
                    id="TDX_03",
                    mrsigner=module_mrsigner,
                    attributes=b"\x00" * 8,
                    attributes_mask=b"\xff" * 8,
                    tcb_levels=[
                        TcbLevel(
                            tcb=Tcb(
                                sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                                pce_svn=0,
                                tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                                isv_svn=5,  # Requires minor >= 5
                            ),
                            tcb_date="2024-01-01T00:00:00Z",
                            tcb_status=TcbStatus.UP_TO_DATE,
                            advisory_ids=[],
                        ),
                    ],
                )
            ],
            tcb_levels=[],
        )

        # TEE_TCB_SVN: minor=2, major=3 - minor too low (< 5)
        tee_tcb_svn = bytes([2, 3] + [0] * 14)
        mr_signer_seam = module_mrsigner
        seam_attributes = b"\x00" * 8

        result = validate_tdx_module_identity(
            tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes
        )
        # No matching level found, but not an error
        assert result is None

    def test_validate_module_identity_mrsigner_mismatch_fails(self):
        """Test that MR_SIGNER_SEAM mismatch raises error."""
        expected_mrsigner = b"\xaa" * 48
        tcb_info = self._create_tcb_info_with_modules(
            ["TDX_03"],
            module_mrsigner=expected_mrsigner,
        )

        # TEE_TCB_SVN: minor=5, major=3
        tee_tcb_svn = bytes([5, 3] + [0] * 14)
        mr_signer_seam = b"\xbb" * 48  # Wrong!
        seam_attributes = b"\x00" * 8

        with pytest.raises(CollateralError, match="MR_SIGNER_SEAM does not match"):
            validate_tdx_module_identity(
                tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes
            )

    def test_validate_module_identity_attributes_mismatch_fails(self):
        """Test that SEAM_ATTRIBUTES mismatch under mask raises error."""
        module_mrsigner = b"\xaa" * 48

        tcb_info = TcbInfo(
            id="TDX",
            version=3,
            issue_date=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(days=30),
            fmspc="00a06f000000",
            pce_id="0000",
            tcb_type=0,
            tcb_evaluation_data_number=17,
            tdx_module=None,
            tdx_module_identities=[
                TdxModuleIdentity(
                    id="TDX_03",
                    mrsigner=module_mrsigner,
                    attributes=b"\x01" * 8,  # Expected: all 0x01
                    attributes_mask=b"\xff" * 8,  # Full mask
                    tcb_levels=[
                        TcbLevel(
                            tcb=Tcb(
                                sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                                pce_svn=0,
                                tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                                isv_svn=3,
                            ),
                            tcb_date="2024-01-01T00:00:00Z",
                            tcb_status=TcbStatus.UP_TO_DATE,
                            advisory_ids=[],
                        ),
                    ],
                )
            ],
            tcb_levels=[],
        )

        tee_tcb_svn = bytes([5, 3] + [0] * 14)
        mr_signer_seam = module_mrsigner
        seam_attributes = b"\x00" * 8  # Wrong! Expected 0x01

        with pytest.raises(CollateralError, match="SEAM_ATTRIBUTES do not match"):
            validate_tdx_module_identity(
                tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes
            )

    def test_validate_module_identity_revoked_status_fails(self):
        """Test that REVOKED module TCB status raises error."""
        module_mrsigner = b"\xaa" * 48

        tcb_info = TcbInfo(
            id="TDX",
            version=3,
            issue_date=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(days=30),
            fmspc="00a06f000000",
            pce_id="0000",
            tcb_type=0,
            tcb_evaluation_data_number=17,
            tdx_module=None,
            tdx_module_identities=[
                TdxModuleIdentity(
                    id="TDX_03",
                    mrsigner=module_mrsigner,
                    attributes=b"\x00" * 8,
                    attributes_mask=b"\xff" * 8,
                    tcb_levels=[
                        TcbLevel(
                            tcb=Tcb(
                                sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                                pce_svn=0,
                                tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                                isv_svn=3,
                            ),
                            tcb_date="2024-01-01T00:00:00Z",
                            tcb_status=TcbStatus.REVOKED,  # REVOKED!
                            advisory_ids=[],
                        ),
                    ],
                )
            ],
            tcb_levels=[],
        )

        tee_tcb_svn = bytes([5, 3] + [0] * 14)
        mr_signer_seam = module_mrsigner
        seam_attributes = b"\x00" * 8

        with pytest.raises(CollateralError, match="REVOKED"):
            validate_tdx_module_identity(
                tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes
            )

    def test_real_world_tee_tcb_svn_pattern(self):
        """Test with a realistic TEE_TCB_SVN pattern from production."""
        # Real-world example: TDX module 3.x with minor version 5
        # and non-zero values in other positions
        tcb_info = self._create_tcb_info_with_modules(["TDX_03"])

        # Realistic 16-byte TEE_TCB_SVN:
        # [0]=5 (minor), [1]=3 (major), [2]=0, [3]=0, ...
        # Some positions might have non-zero values for platform TCB
        tee_tcb_svn = bytes([5, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is not None
        assert result.id == "TDX_03"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
