"""
Intel TDX Collateral Fetching and TCB Validation.

This module handles fetching and validating collateral from Intel's
Provisioning Certification Service (PCS) for TDX attestation:

- TCB Info: Contains TCB levels and status for the platform
- QE Identity: Contains Quoting Enclave identity information

Intel PCS API:
    Base URL: https://api.trustedservices.intel.com/tdx/certification/v4
    TCB Info: /tcb?fmspc={fmspc}
    QE Identity: /qe/identity
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
import json

import requests

from .pck_extensions import PckExtensions


# Intel PCS API base URLs
INTEL_PCS_TDX_BASE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4"
INTEL_PCS_SGX_BASE_URL = "https://api.trustedservices.intel.com/sgx/certification/v4"


class CollateralError(Exception):
    """Raised when collateral fetching or validation fails."""
    pass


class TcbStatus(str, Enum):
    """TCB status values from Intel PCS."""
    UP_TO_DATE = "UpToDate"
    SW_HARDENING_NEEDED = "SWHardeningNeeded"
    CONFIGURATION_NEEDED = "ConfigurationNeeded"
    CONFIGURATION_AND_SW_HARDENING_NEEDED = "ConfigurationAndSWHardeningNeeded"
    OUT_OF_DATE = "OutOfDate"
    OUT_OF_DATE_CONFIGURATION_NEEDED = "OutOfDateConfigurationNeeded"
    REVOKED = "Revoked"


# =============================================================================
# TCB Info Data Structures
# =============================================================================

@dataclass
class TcbComponent:
    """A single TCB component with SVN and metadata."""
    svn: int
    category: str = ""
    type: str = ""


@dataclass
class Tcb:
    """TCB level data containing SVN components."""
    sgx_tcb_components: List[TcbComponent]  # 16 SGX components
    pce_svn: int
    tdx_tcb_components: List[TcbComponent]  # 16 TDX components


@dataclass
class TcbLevel:
    """A TCB level with status and advisory IDs."""
    tcb: Tcb
    tcb_date: str
    tcb_status: TcbStatus
    advisory_ids: List[str]


@dataclass
class TdxModule:
    """TDX module identity information."""
    mrsigner: bytes  # 48 bytes
    attributes: bytes
    attributes_mask: bytes


@dataclass
class TdxModuleIdentity:
    """TDX module identity with associated TCB levels."""
    id: str  # e.g., "TDX_01", "TDX_03"
    mrsigner: bytes
    attributes: bytes
    attributes_mask: bytes
    tcb_levels: List[TcbLevel]


@dataclass
class TcbInfo:
    """TCB Info structure from Intel PCS."""
    id: str  # Must be "TDX"
    version: int  # Must be 3
    issue_date: datetime
    next_update: datetime
    fmspc: str
    pce_id: str
    tcb_type: int
    tcb_evaluation_data_number: int
    tdx_module: Optional[TdxModule]
    tdx_module_identities: List[TdxModuleIdentity]
    tcb_levels: List[TcbLevel]


@dataclass
class TdxTcbInfo:
    """Top-level TCB Info response with signature."""
    tcb_info: TcbInfo
    signature: str


# =============================================================================
# QE Identity Data Structures
# =============================================================================

@dataclass
class EnclaveIdentity:
    """Quoting Enclave identity information."""
    id: str  # Must be "TD_QE"
    version: int  # Must be 2
    issue_date: datetime
    next_update: datetime
    tcb_evaluation_data_number: int
    miscselect: bytes  # 4 bytes
    miscselect_mask: bytes  # 4 bytes
    attributes: bytes  # 16 bytes
    attributes_mask: bytes  # 16 bytes
    mrsigner: bytes  # 32 bytes
    isv_prod_id: int
    tcb_levels: List[TcbLevel]


@dataclass
class QeIdentity:
    """Top-level QE Identity response with signature."""
    enclave_identity: EnclaveIdentity
    signature: str


# =============================================================================
# Collateral Container
# =============================================================================

@dataclass
class TdxCollateral:
    """Container for all TDX collateral data."""
    tcb_info: TdxTcbInfo
    qe_identity: QeIdentity
    tcb_info_raw: bytes  # Raw JSON for signature verification
    qe_identity_raw: bytes  # Raw JSON for signature verification


# =============================================================================
# Parsing Functions
# =============================================================================

def _parse_hex_bytes(hex_str: str) -> bytes:
    """Parse hex string to bytes."""
    return bytes.fromhex(hex_str)


def _parse_datetime(dt_str: str) -> datetime:
    """Parse ISO datetime string to datetime object."""
    # Handle format: "2025-12-17T06:24:56Z"
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def _parse_tcb_component(data: dict) -> TcbComponent:
    """Parse a TCB component from JSON."""
    return TcbComponent(
        svn=data.get("svn", 0),
        category=data.get("category", ""),
        type=data.get("type", ""),
    )


def _parse_tcb(data: dict) -> Tcb:
    """Parse TCB from JSON."""
    sgx_components = [
        _parse_tcb_component(c) for c in data.get("sgxtcbcomponents", [])
    ]
    tdx_components = [
        _parse_tcb_component(c) for c in data.get("tdxtcbcomponents", [])
    ]

    # Pad to 16 components if needed
    while len(sgx_components) < 16:
        sgx_components.append(TcbComponent(svn=0))
    while len(tdx_components) < 16:
        tdx_components.append(TcbComponent(svn=0))

    return Tcb(
        sgx_tcb_components=sgx_components[:16],
        pce_svn=data.get("pcesvn", 0),
        tdx_tcb_components=tdx_components[:16],
    )


def _parse_tcb_level(data: dict) -> TcbLevel:
    """Parse a TCB level from JSON."""
    tcb_data = data.get("tcb", {})

    # Handle simple TCB (just isvsvn) vs full TCB
    if "sgxtcbcomponents" in tcb_data:
        tcb = _parse_tcb(tcb_data)
    else:
        # Simple TCB with just isvsvn
        tcb = Tcb(
            sgx_tcb_components=[TcbComponent(svn=0)] * 16,
            pce_svn=0,
            tdx_tcb_components=[TcbComponent(svn=0)] * 16,
        )

    return TcbLevel(
        tcb=tcb,
        tcb_date=data.get("tcbDate", ""),
        tcb_status=TcbStatus(data.get("tcbStatus", "UpToDate")),
        advisory_ids=data.get("advisoryIDs", []),
    )


def _parse_tdx_module(data: dict) -> TdxModule:
    """Parse TDX module from JSON."""
    return TdxModule(
        mrsigner=_parse_hex_bytes(data.get("mrsigner", "00" * 48)),
        attributes=_parse_hex_bytes(data.get("attributes", "")),
        attributes_mask=_parse_hex_bytes(data.get("attributesMask", "")),
    )


def _parse_tdx_module_identity(data: dict) -> TdxModuleIdentity:
    """Parse TDX module identity from JSON."""
    return TdxModuleIdentity(
        id=data.get("id", ""),
        mrsigner=_parse_hex_bytes(data.get("mrsigner", "00" * 48)),
        attributes=_parse_hex_bytes(data.get("attributes", "")),
        attributes_mask=_parse_hex_bytes(data.get("attributesMask", "")),
        tcb_levels=[_parse_tcb_level(l) for l in data.get("tcbLevels", [])],
    )


def _parse_tcb_info(data: dict) -> TcbInfo:
    """Parse TCB Info from JSON."""
    tdx_module = None
    if "tdxModule" in data:
        tdx_module = _parse_tdx_module(data["tdxModule"])

    return TcbInfo(
        id=data.get("id", ""),
        version=data.get("version", 0),
        issue_date=_parse_datetime(data.get("issueDate", "1970-01-01T00:00:00Z")),
        next_update=_parse_datetime(data.get("nextUpdate", "1970-01-01T00:00:00Z")),
        fmspc=data.get("fmspc", ""),
        pce_id=data.get("pceId", ""),
        tcb_type=data.get("tcbType", 0),
        tcb_evaluation_data_number=data.get("tcbEvaluationDataNumber", 0),
        tdx_module=tdx_module,
        tdx_module_identities=[
            _parse_tdx_module_identity(m) for m in data.get("tdxModuleIdentities", [])
        ],
        tcb_levels=[_parse_tcb_level(l) for l in data.get("tcbLevels", [])],
    )


def _parse_enclave_identity(data: dict) -> EnclaveIdentity:
    """Parse Enclave Identity from JSON."""
    return EnclaveIdentity(
        id=data.get("id", ""),
        version=data.get("version", 0),
        issue_date=_parse_datetime(data.get("issueDate", "1970-01-01T00:00:00Z")),
        next_update=_parse_datetime(data.get("nextUpdate", "1970-01-01T00:00:00Z")),
        tcb_evaluation_data_number=data.get("tcbEvaluationDataNumber", 0),
        miscselect=_parse_hex_bytes(data.get("miscselect", "00000000")),
        miscselect_mask=_parse_hex_bytes(data.get("miscselectMask", "00000000")),
        attributes=_parse_hex_bytes(data.get("attributes", "00" * 16)),
        attributes_mask=_parse_hex_bytes(data.get("attributesMask", "00" * 16)),
        mrsigner=_parse_hex_bytes(data.get("mrsigner", "00" * 32)),
        isv_prod_id=data.get("isvprodid", 0),
        tcb_levels=[_parse_tcb_level(l) for l in data.get("tcbLevels", [])],
    )


def parse_tcb_info_response(response_bytes: bytes) -> TdxTcbInfo:
    """
    Parse TCB Info response from Intel PCS.

    Args:
        response_bytes: Raw JSON response bytes

    Returns:
        Parsed TdxTcbInfo

    Raises:
        CollateralError: If parsing fails
    """
    try:
        data = json.loads(response_bytes)
    except json.JSONDecodeError as e:
        raise CollateralError(f"Failed to parse TCB Info JSON: {e}")

    tcb_info = _parse_tcb_info(data.get("tcbInfo", {}))

    # Validate required fields
    if tcb_info.id != "TDX":
        raise CollateralError(f"TCB Info ID must be 'TDX', got '{tcb_info.id}'")
    if tcb_info.version != 3:
        raise CollateralError(f"TCB Info version must be 3, got {tcb_info.version}")

    return TdxTcbInfo(
        tcb_info=tcb_info,
        signature=data.get("signature", ""),
    )


def parse_qe_identity_response(response_bytes: bytes) -> QeIdentity:
    """
    Parse QE Identity response from Intel PCS.

    Args:
        response_bytes: Raw JSON response bytes

    Returns:
        Parsed QeIdentity

    Raises:
        CollateralError: If parsing fails
    """
    try:
        data = json.loads(response_bytes)
    except json.JSONDecodeError as e:
        raise CollateralError(f"Failed to parse QE Identity JSON: {e}")

    enclave_identity = _parse_enclave_identity(data.get("enclaveIdentity", {}))

    # Validate required fields
    if enclave_identity.id != "TD_QE":
        raise CollateralError(
            f"QE Identity ID must be 'TD_QE', got '{enclave_identity.id}'"
        )
    if enclave_identity.version != 2:
        raise CollateralError(
            f"QE Identity version must be 2, got {enclave_identity.version}"
        )

    return QeIdentity(
        enclave_identity=enclave_identity,
        signature=data.get("signature", ""),
    )


# =============================================================================
# Collateral Fetching
# =============================================================================

def fetch_tcb_info(fmspc: str, timeout: float = 30.0) -> tuple[TdxTcbInfo, bytes]:
    """
    Fetch TCB Info from Intel PCS.

    Args:
        fmspc: FMSPC value from PCK certificate (6 bytes hex)
        timeout: Request timeout in seconds

    Returns:
        Tuple of (parsed TdxTcbInfo, raw response bytes)

    Raises:
        CollateralError: If fetching or parsing fails
    """
    url = f"{INTEL_PCS_TDX_BASE_URL}/tcb?fmspc={fmspc}"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as e:
        raise CollateralError(f"Failed to fetch TCB Info from Intel PCS: {e}")

    raw_bytes = response.content
    tcb_info = parse_tcb_info_response(raw_bytes)

    return tcb_info, raw_bytes


def fetch_qe_identity(timeout: float = 30.0) -> tuple[QeIdentity, bytes]:
    """
    Fetch QE Identity from Intel PCS.

    Args:
        timeout: Request timeout in seconds

    Returns:
        Tuple of (parsed QeIdentity, raw response bytes)

    Raises:
        CollateralError: If fetching or parsing fails
    """
    url = f"{INTEL_PCS_TDX_BASE_URL}/qe/identity"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as e:
        raise CollateralError(f"Failed to fetch QE Identity from Intel PCS: {e}")

    raw_bytes = response.content
    qe_identity = parse_qe_identity_response(raw_bytes)

    return qe_identity, raw_bytes


def fetch_collateral(pck_extensions: PckExtensions, timeout: float = 30.0) -> TdxCollateral:
    """
    Fetch all required collateral from Intel PCS.

    Args:
        pck_extensions: PCK certificate extensions containing FMSPC
        timeout: Request timeout in seconds

    Returns:
        TdxCollateral containing all fetched data

    Raises:
        CollateralError: If fetching fails
    """
    tcb_info, tcb_info_raw = fetch_tcb_info(pck_extensions.fmspc, timeout)
    qe_identity, qe_identity_raw = fetch_qe_identity(timeout)

    return TdxCollateral(
        tcb_info=tcb_info,
        qe_identity=qe_identity,
        tcb_info_raw=tcb_info_raw,
        qe_identity_raw=qe_identity_raw,
    )


# =============================================================================
# TCB Level Matching and Validation
# =============================================================================

def is_cpu_svn_higher_or_equal(
    pck_cert_cpu_svn: bytes,
    sgx_tcb_components: List[TcbComponent],
) -> bool:
    """
    Check if PCK certificate CPU SVN is >= TCB level SGX components.

    Args:
        pck_cert_cpu_svn: CPU SVN from PCK certificate (16 bytes)
        sgx_tcb_components: SGX TCB components from TCB level

    Returns:
        True if all components are >=
    """
    if len(pck_cert_cpu_svn) != len(sgx_tcb_components):
        return False

    for i, component in enumerate(sgx_tcb_components):
        if pck_cert_cpu_svn[i] < component.svn:
            return False

    return True


def is_tdx_tcb_svn_higher_or_equal(
    tee_tcb_svn: bytes,
    tdx_tcb_components: List[TcbComponent],
) -> bool:
    """
    Check if TEE TCB SVN is >= TCB level TDX components.

    Args:
        tee_tcb_svn: TEE TCB SVN from quote body (16 bytes)
        tdx_tcb_components: TDX TCB components from TCB level

    Returns:
        True if all relevant components are >=
    """
    if len(tee_tcb_svn) != len(tdx_tcb_components):
        return False

    # If teeTcbSvn[1] > 0, skip first 2 bytes (module-specific behavior)
    start = 0
    if len(tee_tcb_svn) > 1 and tee_tcb_svn[1] > 0:
        start = 2

    for i in range(start, len(tee_tcb_svn)):
        if tee_tcb_svn[i] < tdx_tcb_components[i].svn:
            return False

    return True


def get_matching_tcb_level(
    tcb_levels: List[TcbLevel],
    tee_tcb_svn: bytes,
    pck_cert_pce_svn: int,
    pck_cert_cpu_svn: bytes,
) -> Optional[TcbLevel]:
    """
    Find the matching TCB level for the given SVN values.

    TCB levels are ordered from newest to oldest. Returns the first
    level where all three checks pass.

    Args:
        tcb_levels: List of TCB levels from TCB Info
        tee_tcb_svn: TEE TCB SVN from quote body
        pck_cert_pce_svn: PCE SVN from PCK certificate
        pck_cert_cpu_svn: CPU SVN from PCK certificate

    Returns:
        Matching TcbLevel or None if no match found
    """
    for level in tcb_levels:
        if (is_cpu_svn_higher_or_equal(pck_cert_cpu_svn, level.tcb.sgx_tcb_components) and
            pck_cert_pce_svn >= level.tcb.pce_svn and
            is_tdx_tcb_svn_higher_or_equal(tee_tcb_svn, level.tcb.tdx_tcb_components)):
            return level

    return None


def get_matching_qe_tcb_level(
    tcb_levels: List[TcbLevel],
    isv_svn: int,
) -> Optional[TcbLevel]:
    """
    Find the matching TCB level for the QE ISV SVN.

    Args:
        tcb_levels: List of TCB levels from QE Identity
        isv_svn: ISV SVN from QE report

    Returns:
        Matching TcbLevel or None if no match found
    """
    for level in tcb_levels:
        # QE TCB levels use isvsvn in the tcb structure
        # The level matches if report's ISV SVN >= level's ISV SVN
        if level.tcb.sgx_tcb_components and level.tcb.sgx_tcb_components[0].svn <= isv_svn:
            return level

    # Fallback: check if there's a simple isvsvn match
    return tcb_levels[0] if tcb_levels else None


def validate_tcb_status(
    tcb_info: TcbInfo,
    tee_tcb_svn: bytes,
    pck_extensions: PckExtensions,
) -> TcbLevel:
    """
    Validate TCB status against Intel's published levels.

    Args:
        tcb_info: Parsed TCB Info from Intel PCS
        tee_tcb_svn: TEE TCB SVN from quote body
        pck_extensions: PCK certificate extensions

    Returns:
        Matching TcbLevel

    Raises:
        CollateralError: If TCB status is not acceptable
    """
    matching_level = get_matching_tcb_level(
        tcb_levels=tcb_info.tcb_levels,
        tee_tcb_svn=tee_tcb_svn,
        pck_cert_pce_svn=pck_extensions.tcb.pce_svn,
        pck_cert_cpu_svn=pck_extensions.tcb.cpu_svn,
    )

    if matching_level is None:
        raise CollateralError(
            "No matching TCB level found for the quote's SVN values"
        )

    # Check status
    if matching_level.tcb_status == TcbStatus.REVOKED:
        raise CollateralError("TCB status is REVOKED - platform is not trusted")

    if matching_level.tcb_status == TcbStatus.OUT_OF_DATE:
        raise CollateralError("TCB status is OUT_OF_DATE - platform needs update")

    if matching_level.tcb_status != TcbStatus.UP_TO_DATE:
        # Log warning for non-UpToDate but acceptable statuses
        pass

    return matching_level


def validate_qe_identity(
    qe_identity: EnclaveIdentity,
    qe_report_isv_svn: int,
    qe_report_mrsigner: bytes,
) -> TcbLevel:
    """
    Validate QE identity against Intel's published identity.

    Args:
        qe_identity: Parsed QE Identity from Intel PCS
        qe_report_isv_svn: ISV SVN from QE report
        qe_report_mrsigner: MRSIGNER from QE report

    Returns:
        Matching TcbLevel

    Raises:
        CollateralError: If QE identity validation fails
    """
    # Verify MRSIGNER matches
    if qe_report_mrsigner != qe_identity.mrsigner:
        raise CollateralError(
            f"QE report MRSIGNER does not match expected value. "
            f"Got {qe_report_mrsigner.hex()}, expected {qe_identity.mrsigner.hex()}"
        )

    # Find matching TCB level
    matching_level = get_matching_qe_tcb_level(
        tcb_levels=qe_identity.tcb_levels,
        isv_svn=qe_report_isv_svn,
    )

    if matching_level is None:
        raise CollateralError(
            f"No matching QE TCB level found for ISV SVN {qe_report_isv_svn}"
        )

    # Check status
    if matching_level.tcb_status == TcbStatus.REVOKED:
        raise CollateralError("QE TCB status is REVOKED")

    if matching_level.tcb_status == TcbStatus.OUT_OF_DATE:
        raise CollateralError("QE TCB status is OUT_OF_DATE")

    return matching_level


def check_collateral_freshness(collateral: TdxCollateral) -> None:
    """
    Check that collateral is not expired.

    Args:
        collateral: TDX collateral to check

    Raises:
        CollateralError: If collateral is expired
    """
    now = datetime.now(timezone.utc)

    tcb_next_update = collateral.tcb_info.tcb_info.next_update
    if now > tcb_next_update:
        raise CollateralError(
            f"TCB Info has expired (next update was {tcb_next_update})"
        )

    qe_next_update = collateral.qe_identity.enclave_identity.next_update
    if now > qe_next_update:
        raise CollateralError(
            f"QE Identity has expired (next update was {qe_next_update})"
        )
