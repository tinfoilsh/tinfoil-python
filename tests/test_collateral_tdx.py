"""
Unit tests for TDX collateral fetching and TCB validation.
"""

import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from tinfoil.attestation.collateral_tdx import (
    TcbStatus,
    TcbComponent,
    Tcb,
    TcbLevel,
    TcbInfo,
    TdxTcbInfo,
    EnclaveIdentity,
    QeIdentity,
    TdxCollateral,
    CollateralError,
    parse_tcb_info_response,
    parse_qe_identity_response,
    is_cpu_svn_higher_or_equal,
    is_tdx_tcb_svn_higher_or_equal,
    get_matching_tcb_level,
    validate_tcb_status,
    check_collateral_freshness,
    _parse_datetime,
    _parse_hex_bytes,
)
from tinfoil.attestation.pck_extensions import PckExtensions, PckCertTCB


# =============================================================================
# Sample Data - Based on Real Intel PCS Responses
# =============================================================================

SAMPLE_TCB_INFO_JSON = """
{
  "tcbInfo": {
    "id": "TDX",
    "version": 3,
    "issueDate": "2025-12-17T06:24:56Z",
    "nextUpdate": "2026-01-16T06:24:56Z",
    "fmspc": "90c06f000000",
    "pceId": "0000",
    "tcbType": 0,
    "tcbEvaluationDataNumber": 18,
    "tdxModule": {
      "mrsigner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "attributes": "0000000000000000",
      "attributesMask": "FFFFFFFFFFFFFFFF"
    },
    "tdxModuleIdentities": [
      {
        "id": "TDX_03",
        "mrsigner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "attributes": "0000000000000000",
        "attributesMask": "FFFFFFFFFFFFFFFF",
        "tcbLevels": [
          {
            "tcb": { "isvsvn": 3 },
            "tcbDate": "2024-11-13T00:00:00Z",
            "tcbStatus": "UpToDate"
          }
        ]
      }
    ],
    "tcbLevels": [
      {
        "tcb": {
          "sgxtcbcomponents": [
            {"svn": 3}, {"svn": 3}, {"svn": 2}, {"svn": 2},
            {"svn": 2}, {"svn": 1}, {"svn": 0}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0}
          ],
          "pcesvn": 13,
          "tdxtcbcomponents": [
            {"svn": 5, "category": "TDX Module", "type": "TDX Module"},
            {"svn": 0}, {"svn": 3}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0}
          ]
        },
        "tcbDate": "2024-11-13T00:00:00Z",
        "tcbStatus": "UpToDate"
      },
      {
        "tcb": {
          "sgxtcbcomponents": [
            {"svn": 2}, {"svn": 2}, {"svn": 2}, {"svn": 2},
            {"svn": 2}, {"svn": 1}, {"svn": 0}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0}
          ],
          "pcesvn": 11,
          "tdxtcbcomponents": [
            {"svn": 4}, {"svn": 0}, {"svn": 2}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0},
            {"svn": 0}, {"svn": 0}, {"svn": 0}, {"svn": 0}
          ]
        },
        "tcbDate": "2024-03-13T00:00:00Z",
        "tcbStatus": "OutOfDate"
      }
    ]
  },
  "signature": "abcd1234"
}
"""

SAMPLE_QE_IDENTITY_JSON = """
{
  "enclaveIdentity": {
    "id": "TD_QE",
    "version": 2,
    "issueDate": "2025-12-17T18:48:11Z",
    "nextUpdate": "2026-01-16T18:48:11Z",
    "tcbEvaluationDataNumber": 18,
    "miscselect": "00000000",
    "miscselectMask": "FFFFFFFF",
    "attributes": "11000000000000000000000000000000",
    "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
    "mrsigner": "DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5",
    "isvprodid": 2,
    "tcbLevels": [
      {
        "tcb": { "isvsvn": 4 },
        "tcbDate": "2024-11-13T00:00:00Z",
        "tcbStatus": "UpToDate"
      },
      {
        "tcb": { "isvsvn": 3 },
        "tcbDate": "2024-03-13T00:00:00Z",
        "tcbStatus": "OutOfDate"
      }
    ]
  },
  "signature": "0665a932"
}
"""


# =============================================================================
# Helper Functions
# =============================================================================

def create_sample_pck_extensions() -> PckExtensions:
    """Create sample PCK extensions for testing."""
    return PckExtensions(
        ppid="00" * 16,
        tcb=PckCertTCB(
            pce_svn=13,
            cpu_svn=bytes([3, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            tcb_components=[3, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        pceid="0000",
        fmspc="90c06f000000",
    )


# =============================================================================
# Parsing Tests
# =============================================================================

class TestParseTcbInfoResponse:
    """Test TCB Info parsing."""

    def test_parse_valid_response(self):
        """Test parsing a valid TCB Info response."""
        result = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())

        assert result.tcb_info.id == "TDX"
        assert result.tcb_info.version == 3
        assert result.tcb_info.fmspc == "90c06f000000"
        assert len(result.tcb_info.tcb_levels) == 2
        assert result.signature == "abcd1234"

    def test_parse_tcb_levels(self):
        """Test that TCB levels are parsed correctly."""
        result = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())

        first_level = result.tcb_info.tcb_levels[0]
        assert first_level.tcb_status == TcbStatus.UP_TO_DATE
        assert first_level.tcb.pce_svn == 13
        assert len(first_level.tcb.sgx_tcb_components) == 16
        assert first_level.tcb.sgx_tcb_components[0].svn == 3

    def test_parse_tdx_module_identities(self):
        """Test that TDX module identities are parsed."""
        result = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())

        assert len(result.tcb_info.tdx_module_identities) == 1
        identity = result.tcb_info.tdx_module_identities[0]
        assert identity.id == "TDX_03"

    def test_reject_wrong_id(self):
        """Test that non-TDX ID is rejected."""
        bad_json = SAMPLE_TCB_INFO_JSON.replace('"id": "TDX"', '"id": "SGX"')
        with pytest.raises(CollateralError, match="must be 'TDX'"):
            parse_tcb_info_response(bad_json.encode())

    def test_reject_wrong_version(self):
        """Test that wrong version is rejected."""
        bad_json = SAMPLE_TCB_INFO_JSON.replace('"version": 3', '"version": 2')
        with pytest.raises(CollateralError, match="must be 3"):
            parse_tcb_info_response(bad_json.encode())


class TestParseQeIdentityResponse:
    """Test QE Identity parsing."""

    def test_parse_valid_response(self):
        """Test parsing a valid QE Identity response."""
        result = parse_qe_identity_response(SAMPLE_QE_IDENTITY_JSON.encode())

        assert result.enclave_identity.id == "TD_QE"
        assert result.enclave_identity.version == 2
        assert result.enclave_identity.isv_prod_id == 2
        assert len(result.enclave_identity.tcb_levels) == 2

    def test_parse_mrsigner(self):
        """Test MRSIGNER is parsed correctly."""
        result = parse_qe_identity_response(SAMPLE_QE_IDENTITY_JSON.encode())

        expected = bytes.fromhex(
            "DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5"
        )
        assert result.enclave_identity.mrsigner == expected

    def test_reject_wrong_id(self):
        """Test that non-TD_QE ID is rejected."""
        bad_json = SAMPLE_QE_IDENTITY_JSON.replace('"id": "TD_QE"', '"id": "QE"')
        with pytest.raises(CollateralError, match="must be 'TD_QE'"):
            parse_qe_identity_response(bad_json.encode())


# =============================================================================
# TCB Comparison Tests
# =============================================================================

class TestIsCpuSvnHigherOrEqual:
    """Test CPU SVN comparison."""

    def test_equal_values(self):
        """Test equal SVN values pass."""
        cpu_svn = bytes([3, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        components = [TcbComponent(svn=3), TcbComponent(svn=3), TcbComponent(svn=2),
                      TcbComponent(svn=2), TcbComponent(svn=2), TcbComponent(svn=1),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0)]

        assert is_cpu_svn_higher_or_equal(cpu_svn, components) is True

    def test_higher_values(self):
        """Test higher SVN values pass."""
        cpu_svn = bytes([4, 4, 3, 3, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
        components = [TcbComponent(svn=3), TcbComponent(svn=3), TcbComponent(svn=2),
                      TcbComponent(svn=2), TcbComponent(svn=2), TcbComponent(svn=1),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0)]

        assert is_cpu_svn_higher_or_equal(cpu_svn, components) is True

    def test_lower_first_component(self):
        """Test lower first component fails."""
        cpu_svn = bytes([2, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        components = [TcbComponent(svn=3), TcbComponent(svn=3), TcbComponent(svn=2),
                      TcbComponent(svn=2), TcbComponent(svn=2), TcbComponent(svn=1),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0)]

        assert is_cpu_svn_higher_or_equal(cpu_svn, components) is False

    def test_wrong_length(self):
        """Test wrong length fails."""
        cpu_svn = bytes([3, 3, 2])  # Only 3 bytes
        components = [TcbComponent(svn=3)] * 16

        assert is_cpu_svn_higher_or_equal(cpu_svn, components) is False


class TestIsTdxTcbSvnHigherOrEqual:
    """Test TDX TCB SVN comparison."""

    def test_equal_values(self):
        """Test equal SVN values pass."""
        tee_tcb_svn = bytes([5, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        components = [TcbComponent(svn=5), TcbComponent(svn=0), TcbComponent(svn=3),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0)]

        assert is_tdx_tcb_svn_higher_or_equal(tee_tcb_svn, components) is True

    def test_skip_first_two_when_module_version_set(self):
        """Test that first 2 bytes are skipped when tee_tcb_svn[1] > 0."""
        # tee_tcb_svn[1] = 1, so first 2 bytes should be skipped
        tee_tcb_svn = bytes([0, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        # Components have higher values in first 2 positions, but should be skipped
        components = [TcbComponent(svn=99), TcbComponent(svn=99), TcbComponent(svn=3),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0)]

        assert is_tdx_tcb_svn_higher_or_equal(tee_tcb_svn, components) is True

    def test_lower_value_fails(self):
        """Test lower SVN value fails."""
        tee_tcb_svn = bytes([5, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        components = [TcbComponent(svn=5), TcbComponent(svn=0), TcbComponent(svn=3),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0), TcbComponent(svn=0), TcbComponent(svn=0),
                      TcbComponent(svn=0)]

        assert is_tdx_tcb_svn_higher_or_equal(tee_tcb_svn, components) is False


class TestGetMatchingTcbLevel:
    """Test TCB level matching."""

    def test_find_matching_level(self):
        """Test finding a matching TCB level."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())

        tee_tcb_svn = bytes([5, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        pce_svn = 13
        cpu_svn = bytes([3, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        result = get_matching_tcb_level(
            tcb_info.tcb_info.tcb_levels,
            tee_tcb_svn,
            pce_svn,
            cpu_svn,
        )

        assert result is not None
        assert result.tcb_status == TcbStatus.UP_TO_DATE

    def test_no_matching_level(self):
        """Test no matching level found."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())

        # Very low SVN values - won't match any level
        tee_tcb_svn = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        pce_svn = 1
        cpu_svn = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        result = get_matching_tcb_level(
            tcb_info.tcb_info.tcb_levels,
            tee_tcb_svn,
            pce_svn,
            cpu_svn,
        )

        assert result is None


# =============================================================================
# Validation Tests
# =============================================================================

class TestValidateTcbStatus:
    """Test TCB status validation."""

    def test_up_to_date_passes(self):
        """Test UpToDate status passes."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())
        pck_ext = create_sample_pck_extensions()
        tee_tcb_svn = bytes([5, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        result = validate_tcb_status(
            tcb_info.tcb_info,
            tee_tcb_svn,
            pck_ext,
        )

        assert result.tcb_status == TcbStatus.UP_TO_DATE

    def test_no_matching_level_fails(self):
        """Test that no matching level raises error."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())

        # Create extensions with very low SVN values
        pck_ext = PckExtensions(
            ppid="00" * 16,
            tcb=PckCertTCB(
                pce_svn=1,
                cpu_svn=bytes(16),
                tcb_components=[0] * 16,
            ),
            pceid="0000",
            fmspc="90c06f000000",
        )
        tee_tcb_svn = bytes(16)

        with pytest.raises(CollateralError, match="No matching TCB level"):
            validate_tcb_status(tcb_info.tcb_info, tee_tcb_svn, pck_ext)


class TestCheckCollateralFreshness:
    """Test collateral freshness checking."""

    def test_fresh_collateral_passes(self):
        """Test fresh collateral passes."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())
        qe_identity = parse_qe_identity_response(SAMPLE_QE_IDENTITY_JSON.encode())

        collateral = TdxCollateral(
            tcb_info=tcb_info,
            qe_identity=qe_identity,
            tcb_info_raw=SAMPLE_TCB_INFO_JSON.encode(),
            qe_identity_raw=SAMPLE_QE_IDENTITY_JSON.encode(),
        )

        # Should not raise
        check_collateral_freshness(collateral)

    def test_expired_tcb_info_fails(self):
        """Test expired TCB Info fails."""
        # Modify the sample to have an expired date
        expired_json = SAMPLE_TCB_INFO_JSON.replace(
            '"nextUpdate": "2026-01-16T06:24:56Z"',
            '"nextUpdate": "2020-01-16T06:24:56Z"'
        )
        tcb_info = parse_tcb_info_response(expired_json.encode())
        qe_identity = parse_qe_identity_response(SAMPLE_QE_IDENTITY_JSON.encode())

        collateral = TdxCollateral(
            tcb_info=tcb_info,
            qe_identity=qe_identity,
            tcb_info_raw=expired_json.encode(),
            qe_identity_raw=SAMPLE_QE_IDENTITY_JSON.encode(),
        )

        with pytest.raises(CollateralError, match="TCB Info has expired"):
            check_collateral_freshness(collateral)


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestHelperFunctions:
    """Test helper functions."""

    def test_parse_datetime(self):
        """Test datetime parsing."""
        result = _parse_datetime("2025-12-17T06:24:56Z")
        assert result.year == 2025
        assert result.month == 12
        assert result.day == 17
        assert result.tzinfo is not None

    def test_parse_hex_bytes(self):
        """Test hex string parsing."""
        result = _parse_hex_bytes("aabbccdd")
        assert result == bytes([0xaa, 0xbb, 0xcc, 0xdd])


class TestTcbStatus:
    """Test TcbStatus enum."""

    def test_status_values(self):
        """Test all status values can be created."""
        assert TcbStatus.UP_TO_DATE == "UpToDate"
        assert TcbStatus.OUT_OF_DATE == "OutOfDate"
        assert TcbStatus.REVOKED == "Revoked"
        assert TcbStatus.SW_HARDENING_NEEDED == "SWHardeningNeeded"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
