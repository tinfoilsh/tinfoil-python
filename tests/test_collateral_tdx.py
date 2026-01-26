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
    TdxModuleIdentity,
    EnclaveIdentity,
    QeIdentity,
    TdxCollateral,
    CollateralError,
    parse_tcb_info_response,
    parse_qe_identity_response,
    is_cpu_svn_higher_or_equal,
    is_tdx_tcb_svn_higher_or_equal,
    get_matching_tcb_level,
    get_matching_qe_tcb_level,
    get_tdx_module_identity,
    validate_tcb_status,
    validate_tdx_module_identity,
    validate_qe_identity,
    check_collateral_freshness,
    fetch_tcb_info,
    fetch_qe_identity,
    _parse_datetime,
    _parse_issuer_chain_header,
    _verify_collateral_signature,
    _parse_hex_bytes,
    _get_tcb_info_cache_path,
    _get_qe_identity_cache_path,
    _is_tcb_info_fresh,
    _is_qe_identity_fresh,
    _read_cache,
    _write_cache,
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

# Byte versions for cache testing
SAMPLE_TCB_INFO_RESPONSE = SAMPLE_TCB_INFO_JSON.encode()
SAMPLE_QE_IDENTITY_RESPONSE = SAMPLE_QE_IDENTITY_JSON.encode()

# Stale TCB Info (next_update in the past)
SAMPLE_STALE_TCB_INFO_JSON = """
{
  "tcbInfo": {
    "id": "TDX",
    "version": 3,
    "issueDate": "2024-01-17T06:24:56Z",
    "nextUpdate": "2024-02-16T06:24:56Z",
    "fmspc": "90c06f000000",
    "pceId": "0000",
    "tcbType": 0,
    "tcbEvaluationDataNumber": 18,
    "tdxModuleIdentities": [],
    "tcbLevels": []
  },
  "signature": "stale1234"
}
"""
SAMPLE_STALE_TCB_INFO_RESPONSE = SAMPLE_STALE_TCB_INFO_JSON.encode()


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


class TestGetMatchingQeTcbLevel:
    """Test QE TCB level matching with isvsvn."""

    def test_find_matching_level(self):
        """Test finding a matching QE TCB level by isvsvn."""
        tcb_levels = [
            TcbLevel(
                tcb=Tcb(
                    sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                    pce_svn=0,
                    tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                    isv_svn=8,
                ),
                tcb_date="2024-01-01T00:00:00Z",
                tcb_status=TcbStatus.UP_TO_DATE,
                advisory_ids=[],
            ),
            TcbLevel(
                tcb=Tcb(
                    sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                    pce_svn=0,
                    tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                    isv_svn=6,
                ),
                tcb_date="2023-06-01T00:00:00Z",
                tcb_status=TcbStatus.SW_HARDENING_NEEDED,
                advisory_ids=["INTEL-SA-00001"],
            ),
        ]

        # ISV SVN 8 should match first level (equal)
        result = get_matching_qe_tcb_level(tcb_levels, 8)
        assert result is not None
        assert result.tcb_status == TcbStatus.UP_TO_DATE

        # ISV SVN 10 should also match first level (>= 8)
        result = get_matching_qe_tcb_level(tcb_levels, 10)
        assert result is not None
        assert result.tcb_status == TcbStatus.UP_TO_DATE

        # ISV SVN 7 should match second level (>= 6 but < 8)
        result = get_matching_qe_tcb_level(tcb_levels, 7)
        assert result is not None
        assert result.tcb_status == TcbStatus.SW_HARDENING_NEEDED

    def test_no_matching_level(self):
        """Test no matching QE TCB level when isvsvn too low."""
        tcb_levels = [
            TcbLevel(
                tcb=Tcb(
                    sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                    pce_svn=0,
                    tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                    isv_svn=8,
                ),
                tcb_date="2024-01-01T00:00:00Z",
                tcb_status=TcbStatus.UP_TO_DATE,
                advisory_ids=[],
            ),
        ]

        # ISV SVN 5 is less than 8, so no match
        result = get_matching_qe_tcb_level(tcb_levels, 5)
        assert result is None

    def test_empty_levels(self):
        """Test empty TCB levels list."""
        result = get_matching_qe_tcb_level([], 8)
        assert result is None

    def test_level_without_isv_svn(self):
        """Test TCB level without isv_svn field is skipped."""
        tcb_levels = [
            TcbLevel(
                tcb=Tcb(
                    sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                    pce_svn=0,
                    tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                    isv_svn=None,  # No isv_svn set
                ),
                tcb_date="2024-01-01T00:00:00Z",
                tcb_status=TcbStatus.UP_TO_DATE,
                advisory_ids=[],
            ),
        ]

        result = get_matching_qe_tcb_level(tcb_levels, 8)
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

    def test_fmspc_mismatch_fails(self):
        """Test that FMSPC mismatch raises error."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())

        # Create extensions with different FMSPC
        pck_ext = PckExtensions(
            ppid="00" * 16,
            tcb=PckCertTCB(
                pce_svn=13,
                cpu_svn=bytes([3, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                tcb_components=[3, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            pceid="0000",
            fmspc="aabbcc000000",  # Different FMSPC
        )
        tee_tcb_svn = bytes([5, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        with pytest.raises(CollateralError, match="FMSPC mismatch"):
            validate_tcb_status(tcb_info.tcb_info, tee_tcb_svn, pck_ext)

    def test_pceid_mismatch_fails(self):
        """Test that PCE_ID mismatch raises error."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())

        # Create extensions with different PCE_ID
        pck_ext = PckExtensions(
            ppid="00" * 16,
            tcb=PckCertTCB(
                pce_svn=13,
                cpu_svn=bytes([3, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                tcb_components=[3, 3, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            pceid="1234",  # Different PCE_ID
            fmspc="90c06f000000",
        )
        tee_tcb_svn = bytes([5, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        with pytest.raises(CollateralError, match="PCE_ID mismatch"):
            validate_tcb_status(tcb_info.tcb_info, tee_tcb_svn, pck_ext)


class TestValidateQeIdentity:
    """Test QE identity validation."""

    def _create_qe_identity(self) -> EnclaveIdentity:
        """Create a sample QE Identity for testing."""
        return EnclaveIdentity(
            id="TD_QE",
            version=2,
            issue_date=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(days=30),
            tcb_evaluation_data_number=17,
            miscselect=b"\x00\x00\x00\x00",
            miscselect_mask=b"\xff\xff\xff\xff",
            attributes=b"\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            attributes_mask=b"\xfb\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00",
            mrsigner=b"\xdc" * 32,
            isv_prod_id=1,
            tcb_levels=[
                TcbLevel(
                    tcb=Tcb(
                        sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                        pce_svn=0,
                        tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                        isv_svn=8,
                    ),
                    tcb_date="2024-01-01T00:00:00Z",
                    tcb_status=TcbStatus.UP_TO_DATE,
                    advisory_ids=[],
                ),
            ],
        )

    def test_valid_qe_identity(self):
        """Test validation passes with matching QE identity."""
        qe_identity = self._create_qe_identity()
        result = validate_qe_identity(
            qe_identity=qe_identity,
            qe_report_isv_svn=8,
            qe_report_mrsigner=b"\xdc" * 32,
            qe_report_miscselect=b"\x00\x00\x00\x00",
            qe_report_attributes=b"\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            qe_report_isvprodid=1,
        )
        assert result.tcb_status == TcbStatus.UP_TO_DATE

    def test_mrsigner_mismatch(self):
        """Test validation fails with MRSIGNER mismatch."""
        qe_identity = self._create_qe_identity()
        with pytest.raises(CollateralError, match="MRSIGNER does not match"):
            validate_qe_identity(
                qe_identity=qe_identity,
                qe_report_isv_svn=8,
                qe_report_mrsigner=b"\xaa" * 32,  # Wrong MRSIGNER
                qe_report_miscselect=b"\x00\x00\x00\x00",
                qe_report_attributes=b"\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                qe_report_isvprodid=1,
            )

    def test_miscselect_mismatch(self):
        """Test validation fails with MISCSELECT mismatch under mask."""
        qe_identity = self._create_qe_identity()
        with pytest.raises(CollateralError, match="MISCSELECT does not match"):
            validate_qe_identity(
                qe_identity=qe_identity,
                qe_report_isv_svn=8,
                qe_report_mrsigner=b"\xdc" * 32,
                qe_report_miscselect=b"\x01\x00\x00\x00",  # Wrong MISCSELECT
                qe_report_attributes=b"\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                qe_report_isvprodid=1,
            )

    def test_attributes_mismatch(self):
        """Test validation fails with Attributes mismatch under mask."""
        qe_identity = self._create_qe_identity()
        with pytest.raises(CollateralError, match="Attributes do not match"):
            validate_qe_identity(
                qe_identity=qe_identity,
                qe_report_isv_svn=8,
                qe_report_mrsigner=b"\xdc" * 32,
                qe_report_miscselect=b"\x00\x00\x00\x00",
                qe_report_attributes=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # Wrong
                qe_report_isvprodid=1,
            )

    def test_isvprodid_mismatch(self):
        """Test validation fails with ISV ProdID mismatch."""
        qe_identity = self._create_qe_identity()
        with pytest.raises(CollateralError, match="ISV ProdID does not match"):
            validate_qe_identity(
                qe_identity=qe_identity,
                qe_report_isv_svn=8,
                qe_report_mrsigner=b"\xdc" * 32,
                qe_report_miscselect=b"\x00\x00\x00\x00",
                qe_report_attributes=b"\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                qe_report_isvprodid=2,  # Wrong ISV ProdID
            )

    def test_isv_svn_too_low(self):
        """Test validation fails when ISV SVN is too low."""
        qe_identity = self._create_qe_identity()
        with pytest.raises(CollateralError, match="No matching QE TCB level"):
            validate_qe_identity(
                qe_identity=qe_identity,
                qe_report_isv_svn=5,  # Below required 8
                qe_report_mrsigner=b"\xdc" * 32,
                qe_report_miscselect=b"\x00\x00\x00\x00",
                qe_report_attributes=b"\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                qe_report_isvprodid=1,
            )


class TestTdxModuleIdentity:
    """Test TDX module identity validation."""

    def _create_tcb_info_with_module_identities(self) -> TcbInfo:
        """Create TCB Info with module identities for testing."""
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
            tdx_module_identities=[
                TdxModuleIdentity(
                    id="TDX_03",
                    mrsigner=b"\xaa" * 48,
                    attributes=b"\x00\x00\x00\x00\x00\x00\x00\x00",
                    attributes_mask=b"\xff\xff\xff\xff\xff\xff\xff\xff",
                    tcb_levels=[
                        TcbLevel(
                            tcb=Tcb(
                                sgx_tcb_components=[TcbComponent(svn=0)] * 16,
                                pce_svn=0,
                                tdx_tcb_components=[TcbComponent(svn=0)] * 16,
                                isv_svn=3,  # Minor version 3
                            ),
                            tcb_date="2024-01-01T00:00:00Z",
                            tcb_status=TcbStatus.UP_TO_DATE,
                            advisory_ids=[],
                        ),
                    ],
                ),
            ],
            tcb_levels=[],
        )

    def test_get_module_identity(self):
        """Test finding module identity by TEE_TCB_SVN."""
        tcb_info = self._create_tcb_info_with_module_identities()

        # Version 3.x should match TDX_03
        tee_tcb_svn = bytes([3, 3] + [0] * 14)
        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is not None
        assert result.id == "TDX_03"

    def test_get_module_identity_not_found(self):
        """Test no matching module identity for unknown version."""
        tcb_info = self._create_tcb_info_with_module_identities()

        # Version 5.x should not match any
        tee_tcb_svn = bytes([5, 0] + [0] * 14)
        result = get_tdx_module_identity(tcb_info, tee_tcb_svn)
        assert result is None

    def test_validate_module_identity_success(self):
        """Test successful module identity validation."""
        tcb_info = self._create_tcb_info_with_module_identities()

        tee_tcb_svn = bytes([3, 3] + [0] * 14)
        mr_signer_seam = b"\xaa" * 48
        seam_attributes = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        result = validate_tdx_module_identity(
            tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes
        )
        assert result is not None
        assert result.tcb_status == TcbStatus.UP_TO_DATE

    def test_validate_module_identity_mrsigner_mismatch(self):
        """Test module identity validation fails with MR_SIGNER_SEAM mismatch."""
        tcb_info = self._create_tcb_info_with_module_identities()

        tee_tcb_svn = bytes([3, 3] + [0] * 14)
        mr_signer_seam = b"\xbb" * 48  # Wrong MR_SIGNER_SEAM
        seam_attributes = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        with pytest.raises(CollateralError, match="MR_SIGNER_SEAM does not match"):
            validate_tdx_module_identity(
                tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes
            )

    def test_validate_module_identity_no_match_returns_none(self):
        """Test validation returns None when no matching module identity."""
        tcb_info = self._create_tcb_info_with_module_identities()

        # Version 5.x doesn't exist in module identities
        tee_tcb_svn = bytes([5, 0] + [0] * 14)
        mr_signer_seam = b"\xaa" * 48
        seam_attributes = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        result = validate_tdx_module_identity(
            tcb_info, tee_tcb_svn, mr_signer_seam, seam_attributes
        )
        assert result is None


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

    def test_tcb_evaluation_data_number_threshold_passes(self):
        """Test collateral passes when tcbEvaluationDataNumber meets threshold."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())
        qe_identity = parse_qe_identity_response(SAMPLE_QE_IDENTITY_JSON.encode())

        collateral = TdxCollateral(
            tcb_info=tcb_info,
            qe_identity=qe_identity,
            tcb_info_raw=SAMPLE_TCB_INFO_JSON.encode(),
            qe_identity_raw=SAMPLE_QE_IDENTITY_JSON.encode(),
        )

        # Sample data has tcbEvaluationDataNumber=18, threshold of 18 should pass
        check_collateral_freshness(collateral, min_tcb_evaluation_data_number=18)

        # Lower threshold should also pass
        check_collateral_freshness(collateral, min_tcb_evaluation_data_number=10)

    def test_tcb_info_evaluation_data_number_below_threshold(self):
        """Test failure when TCB Info tcbEvaluationDataNumber is below threshold."""
        tcb_info = parse_tcb_info_response(SAMPLE_TCB_INFO_JSON.encode())
        qe_identity = parse_qe_identity_response(SAMPLE_QE_IDENTITY_JSON.encode())

        collateral = TdxCollateral(
            tcb_info=tcb_info,
            qe_identity=qe_identity,
            tcb_info_raw=SAMPLE_TCB_INFO_JSON.encode(),
            qe_identity_raw=SAMPLE_QE_IDENTITY_JSON.encode(),
        )

        # Sample data has tcbEvaluationDataNumber=18, threshold of 19 should fail
        with pytest.raises(CollateralError, match="TCB Info tcbEvaluationDataNumber .* is below"):
            check_collateral_freshness(collateral, min_tcb_evaluation_data_number=19)

    def test_qe_identity_evaluation_data_number_below_threshold(self):
        """Test failure when QE Identity tcbEvaluationDataNumber is below threshold."""
        # Create TCB Info with high tcbEvaluationDataNumber
        high_eval_tcb_json = SAMPLE_TCB_INFO_JSON.replace(
            '"tcbEvaluationDataNumber": 18',
            '"tcbEvaluationDataNumber": 25'
        )
        tcb_info = parse_tcb_info_response(high_eval_tcb_json.encode())
        # QE Identity still has tcbEvaluationDataNumber=18
        qe_identity = parse_qe_identity_response(SAMPLE_QE_IDENTITY_JSON.encode())

        collateral = TdxCollateral(
            tcb_info=tcb_info,
            qe_identity=qe_identity,
            tcb_info_raw=high_eval_tcb_json.encode(),
            qe_identity_raw=SAMPLE_QE_IDENTITY_JSON.encode(),
        )

        # TCB Info has 25, QE Identity has 18, threshold of 20 should fail on QE Identity
        with pytest.raises(CollateralError, match="QE Identity tcbEvaluationDataNumber .* is below"):
            check_collateral_freshness(collateral, min_tcb_evaluation_data_number=20)


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


# =============================================================================
# Caching Tests
# =============================================================================

class TestCacheHelpers:
    """Test cache helper functions."""

    def test_tcb_info_cache_path(self):
        """Test TCB Info cache path generation."""
        path = _get_tcb_info_cache_path("00A06D080000")
        assert "tdx_tcb_info_00a06d080000.bin" in path
        # Should be lowercase
        path2 = _get_tcb_info_cache_path("00a06d080000")
        assert path == path2

    def test_qe_identity_cache_path(self):
        """Test QE Identity cache path generation."""
        path = _get_qe_identity_cache_path()
        assert "tdx_qe_identity.bin" in path

    def test_is_tcb_info_fresh(self):
        """Test TCB Info freshness check."""
        # Fresh: next_update is in the future
        fresh_tcb_info = TdxTcbInfo(
            tcb_info=TcbInfo(
                id="TDX",
                version=3,
                issue_date=datetime.now(timezone.utc) - timedelta(days=1),
                next_update=datetime.now(timezone.utc) + timedelta(days=29),
                fmspc="00A06D080000",
                pce_id="0000",
                tcb_type=0,
                tcb_evaluation_data_number=1,
                tdx_module=None,
                tdx_module_identities=[],
                tcb_levels=[],
            ),
            signature="",
        )
        assert _is_tcb_info_fresh(fresh_tcb_info) is True

        # Stale: next_update is in the past
        stale_tcb_info = TdxTcbInfo(
            tcb_info=TcbInfo(
                id="TDX",
                version=3,
                issue_date=datetime.now(timezone.utc) - timedelta(days=31),
                next_update=datetime.now(timezone.utc) - timedelta(days=1),
                fmspc="00A06D080000",
                pce_id="0000",
                tcb_type=0,
                tcb_evaluation_data_number=1,
                tdx_module=None,
                tdx_module_identities=[],
                tcb_levels=[],
            ),
            signature="",
        )
        assert _is_tcb_info_fresh(stale_tcb_info) is False

    def test_is_qe_identity_fresh(self):
        """Test QE Identity freshness check."""
        # Fresh
        fresh_qe = QeIdentity(
            enclave_identity=EnclaveIdentity(
                id="TD_QE",
                version=2,
                issue_date=datetime.now(timezone.utc) - timedelta(days=1),
                next_update=datetime.now(timezone.utc) + timedelta(days=29),
                tcb_evaluation_data_number=1,
                miscselect=b"\x00" * 4,
                miscselect_mask=b"\xff" * 4,
                attributes=b"\x00" * 16,
                attributes_mask=b"\xff" * 16,
                mrsigner=b"\xaa" * 32,
                isv_prod_id=1,
                tcb_levels=[],
            ),
            signature="",
        )
        assert _is_qe_identity_fresh(fresh_qe) is True

        # Stale
        stale_qe = QeIdentity(
            enclave_identity=EnclaveIdentity(
                id="TD_QE",
                version=2,
                issue_date=datetime.now(timezone.utc) - timedelta(days=31),
                next_update=datetime.now(timezone.utc) - timedelta(days=1),
                tcb_evaluation_data_number=1,
                miscselect=b"\x00" * 4,
                miscselect_mask=b"\xff" * 4,
                attributes=b"\x00" * 16,
                attributes_mask=b"\xff" * 16,
                mrsigner=b"\xaa" * 32,
                isv_prod_id=1,
                tcb_levels=[],
            ),
            signature="",
        )
        assert _is_qe_identity_fresh(stale_qe) is False


class TestIssuerChainParsing:
    """Test issuer chain header parsing."""

    def test_parse_issuer_chain_missing_certs(self):
        """Test that parsing fails with too few certificates."""
        # Single certificate is not enough (need signing + root at minimum)
        single_cert_pem = """-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----"""
        with pytest.raises(CollateralError, match="at least 2 certificates"):
            _parse_issuer_chain_header(single_cert_pem)

    def test_parse_issuer_chain_invalid_pem(self):
        """Test that parsing fails with invalid PEM data."""
        with pytest.raises(CollateralError, match="Failed to parse"):
            _parse_issuer_chain_header("not-valid-pem-data")


class TestCollateralSignatureVerification:
    """Test collateral signature verification."""

    def test_verify_signature_missing_key(self):
        """Test that verification fails when JSON key is missing."""
        json_data = b'{"other": "data"}'
        with pytest.raises(CollateralError, match="does not contain"):
            _verify_collateral_signature(
                json_bytes=json_data,
                json_key="tcbInfo",
                signature_hex="00" * 64,
                signing_cert=MagicMock(),
                data_name="Test",
            )

    def test_verify_signature_invalid_hex(self):
        """Test that verification fails with invalid signature hex."""
        json_data = b'{"tcbInfo": {}}'
        with pytest.raises(CollateralError, match="not valid hex"):
            _verify_collateral_signature(
                json_bytes=json_data,
                json_key="tcbInfo",
                signature_hex="not-hex",
                signing_cert=MagicMock(),
                data_name="Test",
            )

    def test_verify_signature_wrong_length(self):
        """Test that verification fails with wrong signature length."""
        json_data = b'{"tcbInfo": {}}'
        with pytest.raises(CollateralError, match="expected 64"):
            _verify_collateral_signature(
                json_bytes=json_data,
                json_key="tcbInfo",
                signature_hex="00" * 32,  # 32 bytes instead of 64
                signing_cert=MagicMock(),
                data_name="Test",
            )


class TestFetchTcbInfoWithCache:
    """Test fetch_tcb_info caching behavior."""

    def test_cache_miss_fetches_from_network(self, tmp_path):
        """Test that cache miss triggers network fetch."""
        with patch('tinfoil.attestation.collateral_tdx._TDX_CACHE_DIR', str(tmp_path)):
            with patch('tinfoil.attestation.collateral_tdx.requests.get') as mock_get:
                with patch('tinfoil.attestation.collateral_tdx.verify_tcb_info_signature'):
                    mock_response = MagicMock()
                    mock_response.content = SAMPLE_TCB_INFO_RESPONSE
                    mock_response.raise_for_status = MagicMock()
                    mock_response.headers = {"TCB-Info-Issuer-Chain": "dummy"}
                    mock_get.return_value = mock_response

                    # Also mock _parse_issuer_chain_header since we have dummy header
                    with patch('tinfoil.attestation.collateral_tdx._parse_issuer_chain_header') as mock_parse:
                        mock_parse.return_value = []

                        tcb_info, raw = fetch_tcb_info("00A06D080000")

                        mock_get.assert_called_once()
                        assert tcb_info.tcb_info.id == "TDX"

    def test_cache_hit_skips_network(self, tmp_path):
        """Test that fresh cache hit skips network fetch."""
        with patch('tinfoil.attestation.collateral_tdx._TDX_CACHE_DIR', str(tmp_path)):
            # Write fresh cache (signature was verified on original fetch)
            cache_path = tmp_path / "tdx_tcb_info_00a06d080000.bin"
            cache_path.write_bytes(SAMPLE_TCB_INFO_RESPONSE)

            with patch('tinfoil.attestation.collateral_tdx.requests.get') as mock_get:
                tcb_info, raw = fetch_tcb_info("00A06D080000")

                # Should not call network
                mock_get.assert_not_called()
                assert tcb_info.tcb_info.id == "TDX"

    def test_stale_cache_fetches_fresh(self, tmp_path):
        """Test that stale cache triggers fresh fetch."""
        with patch('tinfoil.attestation.collateral_tdx._TDX_CACHE_DIR', str(tmp_path)):
            # Write stale cache (expired next_update)
            cache_path = tmp_path / "tdx_tcb_info_00a06d080000.bin"
            cache_path.write_bytes(SAMPLE_STALE_TCB_INFO_RESPONSE)

            with patch('tinfoil.attestation.collateral_tdx.requests.get') as mock_get:
                with patch('tinfoil.attestation.collateral_tdx.verify_tcb_info_signature'):
                    mock_response = MagicMock()
                    mock_response.content = SAMPLE_TCB_INFO_RESPONSE
                    mock_response.raise_for_status = MagicMock()
                    mock_response.headers = {"TCB-Info-Issuer-Chain": "dummy"}
                    mock_get.return_value = mock_response

                    with patch('tinfoil.attestation.collateral_tdx._parse_issuer_chain_header') as mock_parse:
                        mock_parse.return_value = []

                        tcb_info, raw = fetch_tcb_info("00A06D080000")

                        # Should call network because cache is stale
                        mock_get.assert_called_once()


class TestFetchQeIdentityWithCache:
    """Test fetch_qe_identity caching behavior."""

    def test_cache_miss_fetches_from_network(self, tmp_path):
        """Test that cache miss triggers network fetch."""
        with patch('tinfoil.attestation.collateral_tdx._TDX_CACHE_DIR', str(tmp_path)):
            with patch('tinfoil.attestation.collateral_tdx.requests.get') as mock_get:
                with patch('tinfoil.attestation.collateral_tdx.verify_qe_identity_signature'):
                    mock_response = MagicMock()
                    mock_response.content = SAMPLE_QE_IDENTITY_RESPONSE
                    mock_response.raise_for_status = MagicMock()
                    mock_response.headers = {"SGX-Enclave-Identity-Issuer-Chain": "dummy"}
                    mock_get.return_value = mock_response

                    with patch('tinfoil.attestation.collateral_tdx._parse_issuer_chain_header') as mock_parse:
                        mock_parse.return_value = []

                        qe_identity, raw = fetch_qe_identity()

                        mock_get.assert_called_once()
                        assert qe_identity.enclave_identity.id == "TD_QE"

    def test_cache_hit_skips_network(self, tmp_path):
        """Test that fresh cache hit skips network fetch."""
        with patch('tinfoil.attestation.collateral_tdx._TDX_CACHE_DIR', str(tmp_path)):
            # Write fresh cache (signature was verified on original fetch)
            cache_path = tmp_path / "tdx_qe_identity.bin"
            cache_path.write_bytes(SAMPLE_QE_IDENTITY_RESPONSE)

            with patch('tinfoil.attestation.collateral_tdx.requests.get') as mock_get:
                qe_identity, raw = fetch_qe_identity()

                # Should not call network
                mock_get.assert_not_called()
                assert qe_identity.enclave_identity.id == "TD_QE"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
