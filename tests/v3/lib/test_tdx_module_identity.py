"""Unit tests for TDX module identity matching against realistic TEE_TCB_SVN values."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tinfoil._v3.verifier._quote.tdx.lib.collateral import (
    CollateralError,
    Tcb,
    TcbComponent,
    TcbInfo,
    TcbLevel,
    TcbStatus,
    TdxModuleIdentity,
    get_tdx_module_identity,
    validate_tdx_module_identity,
)


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
            issue_date=datetime.now(UTC),
            next_update=datetime.now(UTC) + timedelta(days=30),
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

    def test_tee_tcb_svn_unknown_major_version_raises(self):
        """Test TEE_TCB_SVN with unknown major version raises error."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_01", "TDX_03"])

        # TEE_TCB_SVN: minor=0, major=99 (no TDX_99 module exists)
        tee_tcb_svn = bytes([0, 99] + [0] * 14)

        with pytest.raises(CollateralError, match="Unknown TDX module version TDX_99"):
            get_tdx_module_identity(tcb_info, tee_tcb_svn)

    def test_tee_tcb_svn_major_version_0_matches_tdx_00(self):
        """Test TEE_TCB_SVN with major=0 matches TDX_00 if present."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_00", "TDX_01"])

        # TEE_TCB_SVN: minor=1, major=0 (TDX module version 0)
        tee_tcb_svn = bytes([1, 0] + [0] * 14)

        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is not None
        assert result.id == "TDX_00"

    def test_tee_tcb_svn_too_short_raises(self):
        """Test TEE_TCB_SVN with < 2 bytes raises error."""
        tcb_info = self._create_tcb_info_with_modules(["TDX_03"])

        # Only 1 byte - not enough to extract major version
        tee_tcb_svn = bytes([5])

        with pytest.raises(CollateralError, match="TEE_TCB_SVN is too short"):
            get_tdx_module_identity(tcb_info, tee_tcb_svn)

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

        # Should not raise - validation succeeds
        validate_tdx_module_identity(tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes)

    def test_validate_module_identity_minor_svn_too_low_raises_error(self):
        """Test that minor SVN below threshold raises CollateralError."""
        module_mrsigner = b"\xaa" * 48

        tcb_info = TcbInfo(
            id="TDX",
            version=3,
            issue_date=datetime.now(UTC),
            next_update=datetime.now(UTC) + timedelta(days=30),
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

        # No matching level found raises CollateralError
        with pytest.raises(CollateralError, match="Could not find a TDX Module Identity TCB Level"):
            validate_tdx_module_identity(tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes)

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
            validate_tdx_module_identity(tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes)

    def test_validate_module_identity_attributes_mismatch_fails(self):
        """Test that SEAM_ATTRIBUTES mismatch under mask raises error."""
        module_mrsigner = b"\xaa" * 48

        tcb_info = TcbInfo(
            id="TDX",
            version=3,
            issue_date=datetime.now(UTC),
            next_update=datetime.now(UTC) + timedelta(days=30),
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
            validate_tdx_module_identity(tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes)

    def test_validate_module_identity_revoked_status_fails(self):
        """Test that REVOKED module TCB status raises error."""
        module_mrsigner = b"\xaa" * 48

        tcb_info = TcbInfo(
            id="TDX",
            version=3,
            issue_date=datetime.now(UTC),
            next_update=datetime.now(UTC) + timedelta(days=30),
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
            validate_tdx_module_identity(tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes)

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
