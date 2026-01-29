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

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
import stat
from typing import List, Optional, Tuple
from urllib.parse import unquote

from cryptography import x509
from cryptography.x509 import verification
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import platformdirs
import requests

from .intel_root_ca import get_intel_root_ca
from .pck_extensions import PckExtensions


# Intel PCS API base URLs
INTEL_PCS_TDX_BASE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4"
INTEL_PCS_SGX_BASE_URL = "https://api.trustedservices.intel.com/sgx/certification/v4"

# Cache directory for TDX collateral
_TDX_CACHE_DIR = platformdirs.user_cache_dir("tinfoil", "tinfoil")


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
# CRL Data Structures
# =============================================================================

@dataclass
class PckCrl:
    """
    PCK Certificate Revocation List from Intel PCS.

    Contains the parsed CRL and metadata for caching.
    """
    crl: x509.CertificateRevocationList
    ca_type: str  # "platform" or "processor"
    next_update: datetime


@dataclass
class RootCrl:
    """
    Intel SGX Root CA Certificate Revocation List.

    Used to check if intermediate CA certificates have been revoked.
    """
    crl: x509.CertificateRevocationList
    next_update: datetime


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
    isv_svn: Optional[int] = None  # ISV SVN for QE Identity TCB levels


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
    pck_crl: Optional[PckCrl] = None  # PCK CRL for revocation checking
    root_crl: Optional[RootCrl] = None  # Root CA CRL for intermediate revocation checking


# =============================================================================
# Collateral Cache Helpers
# =============================================================================

# Cache directory permissions (owner-only)
_CACHE_DIR_MODE = stat.S_IRWXU  # 0700
_CACHE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0600


@dataclass
class CacheEntry:
    """
    Cache entry containing body and issuer chain for signature verification.

    This allows re-verification of signatures on cache hits, not just on fetch.
    """
    body: bytes  # Raw response body (JSON for TCB/QE, DER for CRLs)
    issuer_chain_pem: Optional[str] = None  # PEM-encoded issuer cert chain


def _ensure_cache_dir() -> bool:
    """
    Ensure cache directory exists with secure permissions (0700).

    Returns:
        True if directory exists/was created, False on failure
    """
    try:
        if not os.path.exists(_TDX_CACHE_DIR):
            os.makedirs(_TDX_CACHE_DIR, mode=_CACHE_DIR_MODE)
        else:
            # Tighten permissions if directory already exists
            os.chmod(_TDX_CACHE_DIR, _CACHE_DIR_MODE)
        return True
    except OSError:
        return False


def _get_tcb_info_cache_path(fmspc: str) -> str:
    """Get cache file path for TCB Info (keyed by FMSPC)."""
    return os.path.join(_TDX_CACHE_DIR, f"tdx_tcb_info_{fmspc.lower()}.json")


def _get_qe_identity_cache_path() -> str:
    """Get cache file path for QE Identity (global, not FMSPC-specific)."""
    return os.path.join(_TDX_CACHE_DIR, "tdx_qe_identity.json")


def _read_cache(cache_path: str) -> Optional[CacheEntry]:
    """
    Read cached collateral from disk.

    Returns:
        CacheEntry with body and optional issuer chain, or None on failure
    """
    if not os.path.isfile(cache_path):
        return None
    try:
        with open(cache_path, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))
        return CacheEntry(
            body=base64.b64decode(data["body"]),
            issuer_chain_pem=data.get("issuer_chain_pem"),
        )
    except (OSError, json.JSONDecodeError, KeyError, ValueError):
        return None


def _write_cache(cache_path: str, entry: CacheEntry) -> None:
    """
    Write collateral to disk cache atomically with secure permissions.

    Uses write-to-temp + rename pattern to prevent partial writes.
    Sets file permissions to 0600 (owner read/write only).
    """
    if not _ensure_cache_dir():
        return

    data = {
        "body": base64.b64encode(entry.body).decode("ascii"),
    }
    if entry.issuer_chain_pem is not None:
        data["issuer_chain_pem"] = entry.issuer_chain_pem

    tmp_path = cache_path + ".tmp"
    try:
        # Write to temp file
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _CACHE_FILE_MODE)
        try:
            os.write(fd, json.dumps(data).encode("utf-8"))
        finally:
            os.close(fd)
        # Atomic rename
        os.replace(tmp_path, cache_path)
    except OSError:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _is_tcb_info_fresh(tcb_info: TdxTcbInfo) -> bool:
    """Check if TCB Info is still fresh (not expired)."""
    now = datetime.now(timezone.utc)
    return now < tcb_info.tcb_info.next_update


def _is_qe_identity_fresh(qe_identity: QeIdentity) -> bool:
    """Check if QE Identity is still fresh (not expired)."""
    now = datetime.now(timezone.utc)
    return now < qe_identity.enclave_identity.next_update


def _get_crl_cache_path(ca_type: str) -> str:
    """Get cache file path for PCK CRL (keyed by CA type)."""
    return os.path.join(_TDX_CACHE_DIR, f"tdx_pck_crl_{ca_type.lower()}.json")


def _get_root_crl_cache_path() -> str:
    """Get cache file path for Intel SGX Root CA CRL."""
    return os.path.join(_TDX_CACHE_DIR, "intel_sgx_root_ca_crl.json")


def _is_crl_fresh(crl: x509.CertificateRevocationList) -> bool:
    """Check if CRL is still fresh (not expired)."""
    now = datetime.now(timezone.utc)
    next_update = crl.next_update_utc
    if next_update is None:
        return False
    return now < next_update


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

    # Capture isvsvn if present (used by QE Identity TCB levels)
    isv_svn = data.get("isvsvn")

    return Tcb(
        sgx_tcb_components=sgx_components[:16],
        pce_svn=data.get("pcesvn", 0),
        tdx_tcb_components=tdx_components[:16],
        isv_svn=isv_svn,
    )


def _parse_tcb_level(data: dict) -> TcbLevel:
    """Parse a TCB level from JSON."""
    tcb_data = data.get("tcb", {})

    # Handle simple TCB (just isvsvn) vs full TCB
    if "sgxtcbcomponents" in tcb_data:
        tcb = _parse_tcb(tcb_data)
    else:
        # Simple TCB with just isvsvn (used by QE Identity)
        # Capture the isvsvn value for QE TCB level matching
        isv_svn = tcb_data.get("isvsvn")
        tcb = Tcb(
            sgx_tcb_components=[TcbComponent(svn=0)] * 16,
            pce_svn=0,
            tdx_tcb_components=[TcbComponent(svn=0)] * 16,
            isv_svn=isv_svn,
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
# Collateral Signature Verification
# =============================================================================

def _parse_issuer_chain_header(header_value: str) -> List[x509.Certificate]:
    """
    Parse the issuer certificate chain from a PCS response header.

    Intel PCS returns the chain as URL-encoded concatenated PEM certificates
    in the TCB-Info-Issuer-Chain or SGX-Enclave-Identity-Issuer-Chain header.

    Args:
        header_value: URL-encoded PEM certificate chain

    Returns:
        List of parsed certificates (signing cert first, root last)

    Raises:
        CollateralError: If parsing fails
    """
    # URL-decode the header value
    pem_data = unquote(header_value).encode('utf-8')

    certs = []
    remaining = pem_data

    while remaining:
        # Strip leading whitespace
        remaining = remaining.lstrip()
        if not remaining:
            break

        try:
            cert = x509.load_pem_x509_certificate(remaining)
            certs.append(cert)

            # Find end of this certificate and move to next
            end_marker = b'-----END CERTIFICATE-----'
            end_pos = remaining.find(end_marker)
            if end_pos == -1:
                break
            remaining = remaining[end_pos + len(end_marker):]
        except Exception as e:
            if certs:
                # If we got some certs, remaining might just be whitespace
                if not remaining.strip():
                    break
            raise CollateralError(f"Failed to parse issuer chain certificate: {e}")

    if len(certs) < 2:
        raise CollateralError(
            f"Issuer chain should contain at least 2 certificates, got {len(certs)}"
        )

    return certs


def _verify_issuer_chain(certs: List[x509.Certificate], chain_name: str) -> None:
    """
    Verify the issuer certificate chain against Intel SGX Root CA.

    Args:
        certs: Certificate chain (signing cert first, root last)
        chain_name: Human-readable name for error messages

    Raises:
        CollateralError: If chain verification fails
    """
    intel_root = get_intel_root_ca()

    # Verify root certificate matches Intel SGX Root CA
    chain_root = certs[-1]
    intel_root_pubkey = intel_root.public_bytes(serialization.Encoding.DER)
    chain_root_pubkey = chain_root.public_bytes(serialization.Encoding.DER)

    if chain_root_pubkey != intel_root_pubkey:
        raise CollateralError(
            f"{chain_name} root certificate does not match Intel SGX Root CA"
        )

    # Verify certificate chain (validity + signatures) using cryptography library
    store = verification.Store([intel_root])
    builder = verification.PolicyBuilder().store(store)
    verifier = builder.build_client_verifier()

    # Chain is [leaf, intermediate(s)..., root] - verify leaf against intermediates
    leaf = certs[0]
    intermediates = certs[1:-1]  # Everything between leaf and root

    try:
        verifier.verify(leaf, intermediates)
    except verification.VerificationError as e:
        raise CollateralError(f"{chain_name} certificate chain verification failed: {e}")


def _verify_collateral_signature(
    json_bytes: bytes,
    json_key: str,
    signature_hex: str,
    signing_cert: x509.Certificate,
    data_name: str,
) -> None:
    """
    Verify the signature over collateral JSON data.

    Intel PCS signs the raw JSON string of the inner object (tcbInfo or
    enclaveIdentity), not the outer wrapper. The signature is ECDSA P-256
    over SHA256 of the raw JSON bytes.

    Args:
        json_bytes: Raw response bytes (full JSON)
        json_key: Key name to extract for signing ("tcbInfo" or "enclaveIdentity")
        signature_hex: Hex-encoded signature from response
        signing_cert: Signing certificate (leaf of issuer chain)
        data_name: Human-readable name for error messages

    Raises:
        CollateralError: If signature verification fails
    """
    # Extract the raw JSON string for the signed object
    # We need to find the exact bytes of the inner JSON object as it appears
    # in the response (including whitespace), since the signature is over
    # the exact byte representation.
    #
    # The format is: {"tcbInfo":{...},"signature":"..."}
    # We need to extract the exact "{...}" for tcbInfo
    try:
        json_str = json_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise CollateralError(f"Failed to decode {data_name} JSON: {e}")

    # Find the start of the inner object
    key_pattern = f'"{json_key}":'
    key_pos = json_str.find(key_pattern)
    if key_pos == -1:
        raise CollateralError(f"{data_name} JSON does not contain '{json_key}' key")

    # Find the start of the object value (skip whitespace after colon)
    obj_start = key_pos + len(key_pattern)
    while obj_start < len(json_str) and json_str[obj_start] in ' \t\n\r':
        obj_start += 1

    if obj_start >= len(json_str) or json_str[obj_start] != '{':
        raise CollateralError(f"{data_name} '{json_key}' is not an object")

    # Find matching closing brace (handle nested objects)
    depth = 0
    obj_end = obj_start
    in_string = False
    escape_next = False

    for i in range(obj_start, len(json_str)):
        char = json_str[i]

        if escape_next:
            escape_next = False
            continue

        if char == '\\' and in_string:
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                obj_end = i + 1
                break

    if depth != 0:
        raise CollateralError(f"{data_name} JSON has mismatched braces")

    # Extract the signed data (exact bytes as they appear in the response)
    signed_json = json_str[obj_start:obj_end].encode('utf-8')

    # Parse signature (hex-encoded raw R||S format, 64 bytes = 128 hex chars)
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError as e:
        raise CollateralError(f"{data_name} signature is not valid hex: {e}")

    if len(sig_bytes) != 64:
        raise CollateralError(
            f"{data_name} signature is {len(sig_bytes)} bytes, expected 64"
        )

    # Convert R||S to DER format
    r = int.from_bytes(sig_bytes[0:32], byteorder='big')
    s = int.from_bytes(sig_bytes[32:64], byteorder='big')
    signature_der = encode_dss_signature(r, s)

    # Verify ECDSA signature
    try:
        public_key = signing_cert.public_key()
        public_key.verify(signature_der, signed_json, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise CollateralError(
            f"{data_name} signature verification failed: signature does not match content"
        )


def verify_tcb_info_signature(
    response_bytes: bytes,
    tcb_info: TdxTcbInfo,
    issuer_chain: List[x509.Certificate],
) -> None:
    """
    Verify TCB Info signature against the issuer certificate chain.

    Args:
        response_bytes: Raw TCB Info response bytes
        tcb_info: Parsed TCB Info
        issuer_chain: Issuer certificate chain from response header

    Raises:
        CollateralError: If verification fails
    """
    # Verify the issuer chain
    _verify_issuer_chain(issuer_chain, "TCB Info issuer chain")

    # Verify signature over tcbInfo JSON
    _verify_collateral_signature(
        json_bytes=response_bytes,
        json_key="tcbInfo",
        signature_hex=tcb_info.signature,
        signing_cert=issuer_chain[0],
        data_name="TCB Info",
    )


def verify_qe_identity_signature(
    response_bytes: bytes,
    qe_identity: QeIdentity,
    issuer_chain: List[x509.Certificate],
) -> None:
    """
    Verify QE Identity signature against the issuer certificate chain.

    Args:
        response_bytes: Raw QE Identity response bytes
        qe_identity: Parsed QE Identity
        issuer_chain: Issuer certificate chain from response header

    Raises:
        CollateralError: If verification fails
    """
    # Verify the issuer chain
    _verify_issuer_chain(issuer_chain, "QE Identity issuer chain")

    # Verify signature over enclaveIdentity JSON
    _verify_collateral_signature(
        json_bytes=response_bytes,
        json_key="enclaveIdentity",
        signature_hex=qe_identity.signature,
        signing_cert=issuer_chain[0],
        data_name="QE Identity",
    )


# =============================================================================
# Collateral Fetching
# =============================================================================

def _certs_to_pem(certs: List[x509.Certificate]) -> str:
    """Convert list of certificates to concatenated PEM string."""
    pem_parts = []
    for cert in certs:
        pem_parts.append(cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    return "".join(pem_parts)


def _pem_to_certs(pem_data: str) -> List[x509.Certificate]:
    """Parse concatenated PEM string to list of certificates."""
    certs = []
    remaining = pem_data.encode("utf-8")

    while remaining:
        remaining = remaining.lstrip()
        if not remaining:
            break

        try:
            cert = x509.load_pem_x509_certificate(remaining)
            certs.append(cert)

            end_marker = b'-----END CERTIFICATE-----'
            end_pos = remaining.find(end_marker)
            if end_pos == -1:
                break
            remaining = remaining[end_pos + len(end_marker):]
        except Exception:
            if not remaining.strip():
                break
            raise

    return certs


def fetch_tcb_info(fmspc: str, timeout: float = 30.0) -> Tuple[TdxTcbInfo, bytes]:
    """
    Fetch TCB Info from Intel PCS, with caching.

    Cached TCB Info is stored on disk and reused until the next_update
    timestamp expires. Signature is re-verified on every cache hit.

    Args:
        fmspc: FMSPC value from PCK certificate (6 bytes hex)
        timeout: Request timeout in seconds

    Returns:
        Tuple of (parsed TdxTcbInfo, raw response bytes)

    Raises:
        CollateralError: If fetching, parsing, or signature verification fails
    """
    cache_path = _get_tcb_info_cache_path(fmspc)

    # Try cache first
    cached_entry = _read_cache(cache_path)
    if cached_entry is not None and cached_entry.issuer_chain_pem is not None:
        try:
            cached_tcb_info = parse_tcb_info_response(cached_entry.body)
            if _is_tcb_info_fresh(cached_tcb_info):
                # Re-verify signature on cache hit
                issuer_chain = _pem_to_certs(cached_entry.issuer_chain_pem)
                verify_tcb_info_signature(
                    cached_entry.body, cached_tcb_info, issuer_chain
                )
                return cached_tcb_info, cached_entry.body
        except (CollateralError, Exception):
            # Cache corrupted, parse failed, or signature invalid - fetch fresh
            pass

    # Cache miss or stale - fetch from Intel PCS
    url = f"{INTEL_PCS_TDX_BASE_URL}/tcb?fmspc={fmspc}"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as e:
        raise CollateralError(f"Failed to fetch TCB Info from Intel PCS: {e}")

    raw_bytes = response.content
    tcb_info = parse_tcb_info_response(raw_bytes)

    # Extract and verify issuer certificate chain from response header
    issuer_chain_header = response.headers.get("TCB-Info-Issuer-Chain")
    if not issuer_chain_header:
        raise CollateralError(
            "TCB Info response missing TCB-Info-Issuer-Chain header"
        )

    issuer_chain = _parse_issuer_chain_header(issuer_chain_header)
    verify_tcb_info_signature(raw_bytes, tcb_info, issuer_chain)

    # Write to cache with issuer chain for re-verification
    cache_entry = CacheEntry(
        body=raw_bytes,
        issuer_chain_pem=_certs_to_pem(issuer_chain),
    )
    _write_cache(cache_path, cache_entry)

    return tcb_info, raw_bytes


def fetch_qe_identity(timeout: float = 30.0) -> Tuple[QeIdentity, bytes]:
    """
    Fetch QE Identity from Intel PCS, with caching.

    Cached QE Identity is stored on disk and reused until the next_update
    timestamp expires. Signature is re-verified on every cache hit.

    Note: QE Identity is global (not FMSPC-specific) so there's only one
    cache file shared across all platforms.

    Args:
        timeout: Request timeout in seconds

    Returns:
        Tuple of (parsed QeIdentity, raw response bytes)

    Raises:
        CollateralError: If fetching, parsing, or signature verification fails
    """
    cache_path = _get_qe_identity_cache_path()

    # Try cache first
    cached_entry = _read_cache(cache_path)
    if cached_entry is not None and cached_entry.issuer_chain_pem is not None:
        try:
            cached_qe_identity = parse_qe_identity_response(cached_entry.body)
            if _is_qe_identity_fresh(cached_qe_identity):
                # Re-verify signature on cache hit
                issuer_chain = _pem_to_certs(cached_entry.issuer_chain_pem)
                verify_qe_identity_signature(
                    cached_entry.body, cached_qe_identity, issuer_chain
                )
                return cached_qe_identity, cached_entry.body
        except (CollateralError, Exception):
            # Cache corrupted, parse failed, or signature invalid - fetch fresh
            pass

    # Cache miss or stale - fetch from Intel PCS
    url = f"{INTEL_PCS_TDX_BASE_URL}/qe/identity"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as e:
        raise CollateralError(f"Failed to fetch QE Identity from Intel PCS: {e}")

    raw_bytes = response.content
    qe_identity = parse_qe_identity_response(raw_bytes)

    # Extract and verify issuer certificate chain from response header
    issuer_chain_header = response.headers.get("SGX-Enclave-Identity-Issuer-Chain")
    if not issuer_chain_header:
        raise CollateralError(
            "QE Identity response missing SGX-Enclave-Identity-Issuer-Chain header"
        )

    issuer_chain = _parse_issuer_chain_header(issuer_chain_header)
    verify_qe_identity_signature(raw_bytes, qe_identity, issuer_chain)

    # Write to cache with issuer chain for re-verification
    cache_entry = CacheEntry(
        body=raw_bytes,
        issuer_chain_pem=_certs_to_pem(issuer_chain),
    )
    _write_cache(cache_path, cache_entry)

    return qe_identity, raw_bytes


def _verify_crl_signature(
    crl: x509.CertificateRevocationList,
    issuer_chain: List[x509.Certificate],
    ca_type: str,
) -> None:
    """
    Verify the CRL signature against the issuer certificate chain.

    Args:
        crl: Parsed CRL
        issuer_chain: Issuer certificate chain from response header
        ca_type: CA type for error messages

    Raises:
        CollateralError: If verification fails
    """
    # Verify the issuer chain first
    _verify_issuer_chain(issuer_chain, f"PCK CRL ({ca_type}) issuer chain")

    # Verify CRL signature using the signing cert (first in chain)
    signing_cert = issuer_chain[0]
    try:
        signing_cert.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            ec.ECDSA(crl.signature_hash_algorithm),
        )
    except InvalidSignature:
        raise CollateralError(
            f"PCK CRL ({ca_type}) signature verification failed"
        )


def fetch_pck_crl(ca_type: str, timeout: float = 30.0) -> PckCrl:
    """
    Fetch PCK CRL from Intel PCS, with caching.

    The CRL is fetched from the SGX certification API (shared with TDX).
    Cached CRL is stored on disk and reused until next_update expires.
    Signature is re-verified on every cache hit.

    Args:
        ca_type: CA type - "platform" or "processor"
        timeout: Request timeout in seconds

    Returns:
        Parsed PckCrl

    Raises:
        CollateralError: If fetching, parsing, or signature verification fails
    """
    if ca_type not in ("platform", "processor"):
        raise CollateralError(f"Invalid CA type: {ca_type}. Must be 'platform' or 'processor'")

    cache_path = _get_crl_cache_path(ca_type)

    # Try cache first
    cached_entry = _read_cache(cache_path)
    if cached_entry is not None and cached_entry.issuer_chain_pem is not None:
        try:
            cached_crl = x509.load_der_x509_crl(cached_entry.body)
            if _is_crl_fresh(cached_crl):
                # Re-verify signature on cache hit
                issuer_chain = _pem_to_certs(cached_entry.issuer_chain_pem)
                _verify_crl_signature(cached_crl, issuer_chain, ca_type)
                next_update = cached_crl.next_update_utc
                if next_update is None:
                    raise CollateralError(f"PCK CRL ({ca_type}) is missing next_update field")
                return PckCrl(crl=cached_crl, ca_type=ca_type, next_update=next_update)
        except Exception:
            # Cache corrupted, parse failed, or signature invalid - fetch fresh
            pass

    # Cache miss or stale - fetch from Intel PCS
    # CRL endpoint is under the SGX API (not TDX-specific)
    url = f"{INTEL_PCS_SGX_BASE_URL}/pckcrl?ca={ca_type}"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as e:
        raise CollateralError(f"Failed to fetch PCK CRL ({ca_type}) from Intel PCS: {e}")

    raw_bytes = response.content

    # Parse the DER-encoded CRL
    try:
        crl = x509.load_der_x509_crl(raw_bytes)
    except Exception as e:
        raise CollateralError(f"Failed to parse PCK CRL ({ca_type}): {e}")

    # Extract and verify issuer certificate chain from response header
    issuer_chain_header = response.headers.get("SGX-PCK-CRL-Issuer-Chain")
    if not issuer_chain_header:
        raise CollateralError(
            f"PCK CRL ({ca_type}) response missing SGX-PCK-CRL-Issuer-Chain header"
        )

    issuer_chain = _parse_issuer_chain_header(issuer_chain_header)
    _verify_crl_signature(crl, issuer_chain, ca_type)

    # Write to cache with issuer chain for re-verification
    cache_entry = CacheEntry(
        body=raw_bytes,
        issuer_chain_pem=_certs_to_pem(issuer_chain),
    )
    _write_cache(cache_path, cache_entry)

    next_update = crl.next_update_utc
    if next_update is None:
        raise CollateralError(f"PCK CRL ({ca_type}) is missing next_update field")

    return PckCrl(crl=crl, ca_type=ca_type, next_update=next_update)


# Intel SGX Root CA CRL URL (from the certificate's CRL Distribution Point)
INTEL_SGX_ROOT_CA_CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"


def _verify_root_crl_signature(crl: x509.CertificateRevocationList) -> None:
    """
    Verify the Root CA CRL signature against Intel SGX Root CA.

    Args:
        crl: Parsed CRL

    Raises:
        CollateralError: If signature verification fails
    """
    intel_root = get_intel_root_ca()
    hash_algo = crl.signature_hash_algorithm
    if hash_algo is None:
        raise CollateralError("Intel SGX Root CA CRL has no signature hash algorithm")
    try:
        intel_root.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            ec.ECDSA(hash_algo),
        )
    except InvalidSignature:
        raise CollateralError("Intel SGX Root CA CRL signature verification failed")


def fetch_root_ca_crl(timeout: float = 30.0) -> RootCrl:
    """
    Fetch Intel SGX Root CA CRL, with caching.

    This CRL lists revoked intermediate CA certificates (Platform CA, Processor CA).
    Used to verify that the PCK certificate chain's intermediate CA is not revoked.
    Signature is re-verified on every cache hit.

    Args:
        timeout: Request timeout in seconds

    Returns:
        Parsed RootCrl

    Raises:
        CollateralError: If fetching, parsing, or signature verification fails
    """
    cache_path = _get_root_crl_cache_path()

    # Try cache first
    cached_entry = _read_cache(cache_path)
    if cached_entry is not None:
        try:
            cached_crl = x509.load_der_x509_crl(cached_entry.body)
            if _is_crl_fresh(cached_crl):
                # Re-verify signature on cache hit
                _verify_root_crl_signature(cached_crl)
                next_update = cached_crl.next_update_utc
                if next_update is None:
                    raise CollateralError("Intel SGX Root CA CRL is missing next_update field")
                return RootCrl(crl=cached_crl, next_update=next_update)
        except (CollateralError, Exception):
            # Cache corrupted, parse failed, or signature invalid - fetch fresh
            pass

    # Cache miss or stale - fetch from Intel
    try:
        response = requests.get(INTEL_SGX_ROOT_CA_CRL_URL, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as e:
        raise CollateralError(f"Failed to fetch Intel SGX Root CA CRL: {e}")

    raw_bytes = response.content

    # Parse the DER-encoded CRL
    try:
        crl = x509.load_der_x509_crl(raw_bytes)
    except Exception as e:
        raise CollateralError(f"Failed to parse Intel SGX Root CA CRL: {e}")

    # Verify CRL is signed by the Intel SGX Root CA
    _verify_root_crl_signature(crl)

    # Write to cache (no issuer chain needed - verified against embedded root)
    cache_entry = CacheEntry(body=raw_bytes)
    _write_cache(cache_path, cache_entry)

    next_update = crl.next_update_utc
    if next_update is None:
        raise CollateralError("Intel SGX Root CA CRL is missing next_update field")

    return RootCrl(crl=crl, next_update=next_update)


def _determine_pck_ca_type(pck_cert: x509.Certificate) -> str:
    """
    Determine which CA issued the PCK certificate.

    The PCK certificate issuer CN indicates the CA type:
    - "Intel SGX PCK Platform CA" -> "platform"
    - "Intel SGX PCK Processor CA" -> "processor"

    Args:
        pck_cert: PCK certificate from the quote

    Returns:
        CA type string ("platform" or "processor")

    Raises:
        CollateralError: If CA type cannot be determined
    """
    try:
        issuer = pck_cert.issuer
        for attr in issuer:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                cn = attr.value
                if "Platform" in cn:
                    return "platform"
                elif "Processor" in cn:
                    return "processor"
        raise CollateralError(
            f"Could not determine PCK CA type from issuer: {issuer}"
        )
    except Exception as e:
        raise CollateralError(f"Failed to determine PCK CA type: {e}")


def fetch_collateral(
    pck_extensions: PckExtensions,
    pck_cert: x509.Certificate,
    timeout: float = 30.0,
) -> TdxCollateral:
    """
    Fetch all required collateral from Intel PCS.

    Args:
        pck_extensions: PCK certificate extensions containing FMSPC
        pck_cert: PCK certificate (needed for CRL fetching)
        timeout: Request timeout in seconds

    Returns:
        TdxCollateral containing all fetched data

    Raises:
        CollateralError: If fetching fails
    """
    tcb_info, tcb_info_raw = fetch_tcb_info(pck_extensions.fmspc, timeout)
    qe_identity, qe_identity_raw = fetch_qe_identity(timeout)

    # Fetch CRLs for revocation checking
    ca_type = _determine_pck_ca_type(pck_cert)
    pck_crl = fetch_pck_crl(ca_type, timeout)
    root_crl = fetch_root_ca_crl(timeout)

    return TdxCollateral(
        tcb_info=tcb_info,
        qe_identity=qe_identity,
        tcb_info_raw=tcb_info_raw,
        qe_identity_raw=qe_identity_raw,
        pck_crl=pck_crl,
        root_crl=root_crl,
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

    TCB levels are ordered from newest to oldest. Returns the first
    level where the report's ISV SVN >= the level's ISV SVN.

    Args:
        tcb_levels: List of TCB levels from QE Identity
        isv_svn: ISV SVN from QE report

    Returns:
        Matching TcbLevel or None if no match found
    """
    for level in tcb_levels:
        # QE TCB levels use isvsvn in the tcb structure
        # The level matches if report's ISV SVN >= level's ISV SVN
        if level.tcb.isv_svn is not None and isv_svn >= level.tcb.isv_svn:
            return level

    return None


def validate_tcb_status(
    tcb_info: TcbInfo,
    tee_tcb_svn: bytes,
    pck_extensions: PckExtensions,
    strict_mode: bool = False,
) -> TcbLevel:
    """
    Validate TCB status against Intel's published levels.

    Performs the following checks:
    1. Cross-validates FMSPC and PCE_ID between PCK cert and TCB Info
    2. Finds matching TCB level for platform SVN values
    3. Checks TCB status (REVOKED and OUT_OF_DATE always rejected)

    Args:
        tcb_info: Parsed TCB Info from Intel PCS
        tee_tcb_svn: TEE TCB SVN from quote body
        pck_extensions: PCK certificate extensions
        strict_mode: If True, reject SW_HARDENING_NEEDED and CONFIGURATION_NEEDED

    Returns:
        Matching TcbLevel

    Raises:
        CollateralError: If TCB status is not acceptable
    """
    # Cross-check FMSPC between PCK certificate and TCB Info
    pck_fmspc = pck_extensions.fmspc.lower()
    tcb_fmspc = tcb_info.fmspc.lower()
    if pck_fmspc != tcb_fmspc:
        raise CollateralError(
            f"FMSPC mismatch: PCK certificate has {pck_fmspc}, "
            f"TCB Info has {tcb_fmspc}"
        )

    # Cross-check PCE_ID between PCK certificate and TCB Info
    pck_pceid = pck_extensions.pceid.lower()
    tcb_pceid = tcb_info.pce_id.lower()
    if pck_pceid != tcb_pceid:
        raise CollateralError(
            f"PCE_ID mismatch: PCK certificate has {pck_pceid}, "
            f"TCB Info has {tcb_pceid}"
        )

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

    # Check status - always reject REVOKED and OUT_OF_DATE
    if matching_level.tcb_status == TcbStatus.REVOKED:
        raise CollateralError("TCB status is REVOKED - platform is not trusted")

    if matching_level.tcb_status == TcbStatus.OUT_OF_DATE:
        raise CollateralError("TCB status is OUT_OF_DATE - platform needs update")

    if matching_level.tcb_status == TcbStatus.OUT_OF_DATE_CONFIGURATION_NEEDED:
        raise CollateralError(
            "TCB status is OUT_OF_DATE_CONFIGURATION_NEEDED - platform needs update"
        )

    # In strict mode, also reject statuses that indicate security advisories
    if strict_mode:
        if matching_level.tcb_status == TcbStatus.SW_HARDENING_NEEDED:
            advisories = ", ".join(matching_level.advisory_ids) or "none listed"
            raise CollateralError(
                f"TCB status is SW_HARDENING_NEEDED (strict mode). "
                f"Advisories: {advisories}"
            )

        if matching_level.tcb_status == TcbStatus.CONFIGURATION_NEEDED:
            advisories = ", ".join(matching_level.advisory_ids) or "none listed"
            raise CollateralError(
                f"TCB status is CONFIGURATION_NEEDED (strict mode). "
                f"Advisories: {advisories}"
            )

        if matching_level.tcb_status == TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED:
            advisories = ", ".join(matching_level.advisory_ids) or "none listed"
            raise CollateralError(
                f"TCB status is CONFIGURATION_AND_SW_HARDENING_NEEDED (strict mode). "
                f"Advisories: {advisories}"
            )

    return matching_level


def get_tdx_module_identity(
    tcb_info: TcbInfo,
    tee_tcb_svn: bytes,
) -> Optional[TdxModuleIdentity]:
    """
    Find the matching TDX module identity based on TEE_TCB_SVN.

    The module ID is derived from TEE_TCB_SVN[0] (major version):
    - TEE_TCB_SVN[1] = 0x03 -> Module ID = "TDX_03"
    - TEE_TCB_SVN[1] = 0x01 -> Module ID = "TDX_01"

    Args:
        tcb_info: Parsed TCB Info from Intel PCS
        tee_tcb_svn: TEE TCB SVN from quote body (16 bytes)

    Returns:
        Matching TdxModuleIdentity or None if no match found
    """
    if len(tee_tcb_svn) < 2:
        return None

    # Extract major version and form module ID
    # TEE_TCB_SVN[0] = minor SVN, TEE_TCB_SVN[1] = major SVN
    major_version = tee_tcb_svn[1]
    module_id = f"TDX_{major_version:02d}"

    # Find matching module identity
    for module_identity in tcb_info.tdx_module_identities:
        if module_identity.id == module_id:
            return module_identity

    return None


def validate_tdx_module_identity(
    tcb_info: TcbInfo,
    tee_tcb_svn: bytes,
    mr_signer_seam: bytes,
    seam_attributes: bytes,
) -> Optional[TcbLevel]:
    """
    Validate TDX module identity against Intel's published identities.

    This validates:
    - MR_SIGNER_SEAM matches the expected module signer
    - SEAM_ATTRIBUTES match under the attribute mask
    - Module-specific TCB level matches the minor version (TEE_TCB_SVN[0])

    Args:
        tcb_info: Parsed TCB Info from Intel PCS
        tee_tcb_svn: TEE TCB SVN from quote body (16 bytes)
        mr_signer_seam: MR_SIGNER_SEAM from quote body (48 bytes)
        seam_attributes: SEAM_ATTRIBUTES from quote body (8 bytes)

    Returns:
        Matching module-specific TcbLevel if found

    Raises:
        CollateralError: If module identity validation fails
    """
    module_identity = get_tdx_module_identity(tcb_info, tee_tcb_svn)

    # If no matching module identity found, this could be an older TDX version
    # without module identities in TCB Info - skip module validation
    if module_identity is None:
        return None

    # Verify MR_SIGNER_SEAM matches
    if mr_signer_seam != module_identity.mrsigner:
        raise CollateralError(
            f"TDX module MR_SIGNER_SEAM does not match expected value. "
            f"Got {mr_signer_seam.hex()}, expected {module_identity.mrsigner.hex()}"
        )

    # Verify SEAM_ATTRIBUTES match under mask
    # Pad seam_attributes to match mask length if needed
    mask = module_identity.attributes_mask
    attrs = seam_attributes

    # Handle length mismatch by padding with zeros
    if len(attrs) < len(mask):
        attrs = attrs + b'\x00' * (len(mask) - len(attrs))
    if len(mask) < len(attrs):
        mask = mask + b'\x00' * (len(attrs) - len(mask))

    report_attrs_masked = bytes(a & b for a, b in zip(attrs, mask))
    expected_attrs_masked = bytes(
        a & b for a, b in zip(module_identity.attributes, mask)
    )
    if report_attrs_masked != expected_attrs_masked:
        raise CollateralError(
            f"TDX module SEAM_ATTRIBUTES do not match expected value under mask. "
            f"Got {seam_attributes.hex()}, expected {module_identity.attributes.hex()} "
            f"(mask {module_identity.attributes_mask.hex()})"
        )

    # Find matching module-specific TCB level
    # TEE_TCB_SVN[0] = minor SVN, TEE_TCB_SVN[1] = major SVN
    # The minor version is used for module TCB matching
    minor_version = tee_tcb_svn[0]

    for level in module_identity.tcb_levels:
        # Module TCB levels should have isv_svn (minor version) set
        if level.tcb.isv_svn is not None and minor_version >= level.tcb.isv_svn:
            # Check status
            if level.tcb_status == TcbStatus.REVOKED:
                raise CollateralError(
                    f"TDX module TCB status is REVOKED for version "
                    f"{tee_tcb_svn[1]}.{minor_version}"
                )
            return level

    # If no matching level, that's not necessarily an error - the platform
    # TCB level matching is the primary check
    return None


def validate_qe_identity(
    qe_identity: EnclaveIdentity,
    qe_report_isv_svn: int,
    qe_report_mrsigner: bytes,
    qe_report_miscselect: bytes,
    qe_report_attributes: bytes,
    qe_report_isvprodid: int,
) -> TcbLevel:
    """
    Validate QE identity against Intel's published identity.

    This performs comprehensive validation of the Quoting Enclave:
    - MRSIGNER must match exactly
    - MISCSELECT must match under mask
    - Attributes must match under mask
    - ISV ProdID must match exactly
    - ISV SVN must meet minimum threshold for a TCB level

    Args:
        qe_identity: Parsed QE Identity from Intel PCS
        qe_report_isv_svn: ISV SVN from QE report
        qe_report_mrsigner: MRSIGNER from QE report (32 bytes)
        qe_report_miscselect: MISCSELECT from QE report (4 bytes)
        qe_report_attributes: Attributes from QE report (16 bytes)
        qe_report_isvprodid: ISV ProdID from QE report

    Returns:
        Matching TcbLevel

    Raises:
        CollateralError: If QE identity validation fails
    """
    # Verify MRSIGNER matches exactly
    if qe_report_mrsigner != qe_identity.mrsigner:
        raise CollateralError(
            f"QE report MRSIGNER does not match expected value. "
            f"Got {qe_report_mrsigner.hex()}, expected {qe_identity.mrsigner.hex()}"
        )

    # Verify MISCSELECT matches under mask
    # (qe_report_miscselect & mask) == (qe_identity.miscselect & mask)
    report_miscselect_masked = bytes(
        a & b for a, b in zip(qe_report_miscselect, qe_identity.miscselect_mask)
    )
    expected_miscselect_masked = bytes(
        a & b for a, b in zip(qe_identity.miscselect, qe_identity.miscselect_mask)
    )
    if report_miscselect_masked != expected_miscselect_masked:
        raise CollateralError(
            f"QE report MISCSELECT does not match expected value under mask. "
            f"Got {qe_report_miscselect.hex()}, expected {qe_identity.miscselect.hex()} "
            f"(mask {qe_identity.miscselect_mask.hex()})"
        )

    # Verify Attributes match under mask
    # (qe_report_attributes & mask) == (qe_identity.attributes & mask)
    report_attributes_masked = bytes(
        a & b for a, b in zip(qe_report_attributes, qe_identity.attributes_mask)
    )
    expected_attributes_masked = bytes(
        a & b for a, b in zip(qe_identity.attributes, qe_identity.attributes_mask)
    )
    if report_attributes_masked != expected_attributes_masked:
        raise CollateralError(
            f"QE report Attributes do not match expected value under mask. "
            f"Got {qe_report_attributes.hex()}, expected {qe_identity.attributes.hex()} "
            f"(mask {qe_identity.attributes_mask.hex()})"
        )

    # Verify ISV ProdID matches exactly
    if qe_report_isvprodid != qe_identity.isv_prod_id:
        raise CollateralError(
            f"QE report ISV ProdID does not match expected value. "
            f"Got {qe_report_isvprodid}, expected {qe_identity.isv_prod_id}"
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


def check_collateral_freshness(
    collateral: TdxCollateral,
    min_tcb_evaluation_data_number: Optional[int] = None,
) -> None:
    """
    Check that collateral is not expired and meets freshness requirements.

    This performs the following checks:
    1. TCB Info has not expired (now < next_update)
    2. QE Identity has not expired (now < next_update)
    3. If min_tcb_evaluation_data_number is set, both TCB Info and QE Identity
       must have tcbEvaluationDataNumber >= the threshold

    The tcbEvaluationDataNumber is a monotonically increasing number that
    Intel updates when new TCB recovery events occur. Relying parties can
    specify a minimum threshold to ensure they don't accept collateral that
    was issued before critical security updates.

    Args:
        collateral: TDX collateral to check
        min_tcb_evaluation_data_number: Optional minimum tcbEvaluationDataNumber
            threshold. If set, collateral with a lower number is rejected.

    Raises:
        CollateralError: If collateral is expired or too old
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

    # Check tcbEvaluationDataNumber threshold if specified
    if min_tcb_evaluation_data_number is not None:
        tcb_eval_num = collateral.tcb_info.tcb_info.tcb_evaluation_data_number
        if tcb_eval_num < min_tcb_evaluation_data_number:
            raise CollateralError(
                f"TCB Info tcbEvaluationDataNumber ({tcb_eval_num}) is below "
                f"minimum required ({min_tcb_evaluation_data_number}). "
                f"Collateral may be outdated."
            )

        qe_eval_num = collateral.qe_identity.enclave_identity.tcb_evaluation_data_number
        if qe_eval_num < min_tcb_evaluation_data_number:
            raise CollateralError(
                f"QE Identity tcbEvaluationDataNumber ({qe_eval_num}) is below "
                f"minimum required ({min_tcb_evaluation_data_number}). "
                f"Collateral may be outdated."
            )


def validate_certificate_revocation(
    collateral: TdxCollateral,
    pck_cert: x509.Certificate,
    intermediate_cert: Optional[x509.Certificate] = None,
) -> None:
    """
    Validate that the PCK certificate and intermediate CA have not been revoked.

    Checks:
    1. PCK (leaf) certificate against the PCK CRL from Intel PCS
    2. Intermediate CA certificate against the Intel SGX Root CA CRL

    Args:
        collateral: TDX collateral containing the PCK CRL and Root CRL
        pck_cert: PCK certificate to check
        intermediate_cert: Intermediate CA certificate to check (optional)

    Raises:
        CollateralError: If any certificate is revoked or CRL check fails

    TODO: Use cryptography.x509.verification integrated CRL checking when available.
          As of cryptography 46.0.3, PolicyBuilder doesn't support CRL stores.
          Track: https://github.com/pyca/cryptography/issues
    """
    if collateral.pck_crl is None:
        raise CollateralError(
            "Cannot check certificate revocation: PCK CRL not available in collateral"
        )

    # --- Check PCK (leaf) certificate against PCK CRL ---
    pck_crl = collateral.pck_crl.crl

    # Check PCK CRL freshness
    now = datetime.now(timezone.utc)
    pck_crl_next_update = pck_crl.next_update_utc
    if pck_crl_next_update is not None and now > pck_crl_next_update:
        raise CollateralError(
            f"PCK CRL has expired (next update was {pck_crl_next_update})"
        )

    # Check if PCK certificate is revoked
    pck_serial = pck_cert.serial_number
    revoked_pck = pck_crl.get_revoked_certificate_by_serial_number(pck_serial)

    if revoked_pck is not None:
        revocation_date = revoked_pck.revocation_date_utc
        raise CollateralError(
            f"PCK certificate has been revoked. "
            f"Serial: {pck_serial:x}, Revocation date: {revocation_date}"
        )

    # --- Check intermediate CA certificate against Root CA CRL ---
    if intermediate_cert is not None:
        if collateral.root_crl is None:
            raise CollateralError(
                "Cannot check intermediate CA revocation: Root CRL not available in collateral"
            )

        root_crl = collateral.root_crl.crl

        # Check Root CRL freshness
        root_crl_next_update = root_crl.next_update_utc
        if root_crl_next_update is not None and now > root_crl_next_update:
            raise CollateralError(
                f"Intel SGX Root CA CRL has expired (next update was {root_crl_next_update})"
            )

        # Check if intermediate CA certificate is revoked
        intermediate_serial = intermediate_cert.serial_number
        revoked_intermediate = root_crl.get_revoked_certificate_by_serial_number(intermediate_serial)

        if revoked_intermediate is not None:
            revocation_date = revoked_intermediate.revocation_date_utc
            raise CollateralError(
                f"Intermediate CA certificate has been revoked. "
                f"Serial: {intermediate_serial:x}, Revocation date: {revocation_date}"
            )
