"""Intel PCS collateral for TDX: parsing of TCB Info, QE Identity and CRL responses, their signatures, and the
TCB appraisal of a quote against them.

Collateral arrives as bytes (and the issuer-chain response headers) that the
caller captured; nothing here is fetched. The appraisal functions compare a
parsed quote and PCK certificate against the parsed collateral.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import unquote

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from tinfoil._v3.verifier._quote.tdx.lib.abi import QuoteV4
from tinfoil._v3.verifier._quote.tdx.lib.chain import (
    CertificateChainError,
    PCKCertificateChain,
    get_intel_root_ca,
    parse_pem_chain,
    verify_intel_chain,
)
from tinfoil._v3.verifier._quote.tdx.lib.pck import PckExtensionError, PckExtensions, extract_pck_extensions

# Intel PCS API base URLs
INTEL_PCS_TDX_BASE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4"
INTEL_PCS_SGX_BASE_URL = "https://api.trustedservices.intel.com/sgx/certification/v4"


class CollateralError(Exception):
    """Raised when collateral fetching or validation fails."""


class TcbStatus(StrEnum):
    """TCB status values from Intel PCS."""

    UP_TO_DATE = "UpToDate"
    SW_HARDENING_NEEDED = "SWHardeningNeeded"
    CONFIGURATION_NEEDED = "ConfigurationNeeded"
    CONFIGURATION_AND_SW_HARDENING_NEEDED = "ConfigurationAndSWHardeningNeeded"
    OUT_OF_DATE = "OutOfDate"
    OUT_OF_DATE_CONFIGURATION_NEEDED = "OutOfDateConfigurationNeeded"
    REVOKED = "Revoked"


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


@dataclass
class TcbComponent:
    """A single TCB component with SVN and metadata."""

    svn: int
    category: str = ""
    type: str = ""


@dataclass
class Tcb:
    """TCB level data containing SVN components."""

    sgx_tcb_components: list[TcbComponent]  # 16 SGX components
    pce_svn: int
    tdx_tcb_components: list[TcbComponent]  # 16 TDX components
    isv_svn: int | None = None  # ISV SVN for QE Identity TCB levels


@dataclass
class TcbLevel:
    """A TCB level with status and advisory IDs."""

    tcb: Tcb
    tcb_date: str
    tcb_status: TcbStatus
    advisory_ids: list[str]


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
    tcb_levels: list[TcbLevel]


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
    tdx_module: TdxModule | None
    tdx_module_identities: list[TdxModuleIdentity]
    tcb_levels: list[TcbLevel]


@dataclass
class TdxTcbInfo:
    """Top-level TCB Info response with signature."""

    tcb_info: TcbInfo
    signature: str


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
    tcb_levels: list[TcbLevel]


@dataclass
class QeIdentity:
    """Top-level QE Identity response with signature."""

    enclave_identity: EnclaveIdentity
    signature: str


@dataclass
class TdxCollateral:
    """Container for all TDX collateral data."""

    tcb_info: TdxTcbInfo
    qe_identity: QeIdentity
    tcb_info_raw: bytes  # Raw JSON for signature verification
    qe_identity_raw: bytes  # Raw JSON for signature verification
    pck_crl: PckCrl | None = None  # PCK CRL for revocation checking
    root_crl: RootCrl | None = None  # Root CA CRL for intermediate revocation checking
    tcb_info_issuer_chain: list[x509.Certificate] | None = None  # TCB Info signing chain for CRL checking
    qe_identity_issuer_chain: list[x509.Certificate] | None = None  # QE Identity signing chain for CRL checking


# Minimum required tcbEvaluationDataNumber.
# This prevents accepting collateral issued before critical security updates.
# See: https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html
#
# This value should ideally be set dynamically using:
#   from tinfoil.attestation.collateral_tdx import calculate_min_tcb_evaluation_data_number
#   min_num = calculate_min_tcb_evaluation_data_number()
#
# That function queries Intel PCS and returns the lowest tcbEvaluationDataNumber
# whose TCB recovery event date is within the last year.
DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER = 19


TDX_MRSIGNER_SIZE = 48  # TDX module MRSIGNER: 48 bytes


QE_MRSIGNER_SIZE = 32  # QE enclave MRSIGNER: 32 bytes


QE_ATTRIBUTES_SIZE = 16  # QE enclave attributes: 16 bytes


MISCSELECT_SIZE = 4  # MISCSELECT field: 4 bytes


TCB_COMPONENT_COUNT = 16  # Number of TCB SVN components


ECDSA_P256_COMPONENT_SIZE = 32  # 32 bytes per R or S component


ECDSA_SIGNATURE_SIZE = 64  # R || S (32 + 32 bytes)


def _parse_hex_bytes(hex_str: str) -> bytes:
    """Parse hex string to bytes."""
    return bytes.fromhex(hex_str)


def _parse_datetime(dt_str: str) -> datetime:
    """Parse ISO datetime string to datetime object."""
    # Handle format: "2025-12-17T06:24:56Z"
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def _parse_tcb_component(data: dict[str, Any]) -> TcbComponent:
    """Parse a TCB component from JSON."""
    return TcbComponent(
        svn=data.get("svn", 0),
        category=data.get("category", ""),
        type=data.get("type", ""),
    )


def _parse_tcb(data: dict[str, Any]) -> Tcb:
    """Parse TCB from JSON."""
    sgx_components = [_parse_tcb_component(c) for c in data.get("sgxtcbcomponents", [])]
    tdx_components = [_parse_tcb_component(c) for c in data.get("tdxtcbcomponents", [])]

    # Pad to 16 components if needed
    while len(sgx_components) < TCB_COMPONENT_COUNT:
        sgx_components.append(TcbComponent(svn=0))
    while len(tdx_components) < TCB_COMPONENT_COUNT:
        tdx_components.append(TcbComponent(svn=0))

    # Capture isvsvn if present (used by QE Identity TCB levels)
    isv_svn = data.get("isvsvn")

    return Tcb(
        sgx_tcb_components=sgx_components[:TCB_COMPONENT_COUNT],
        pce_svn=data.get("pcesvn", 0),
        tdx_tcb_components=tdx_components[:TCB_COMPONENT_COUNT],
        isv_svn=isv_svn,
    )


def _parse_tcb_level(data: dict[str, Any]) -> TcbLevel:
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


def _parse_tdx_module(data: dict[str, Any]) -> TdxModule:
    """Parse TDX module from JSON."""
    return TdxModule(
        mrsigner=_parse_hex_bytes(data.get("mrsigner", "00" * TDX_MRSIGNER_SIZE)),
        attributes=_parse_hex_bytes(data.get("attributes", "")),
        attributes_mask=_parse_hex_bytes(data.get("attributesMask", "")),
    )


def _parse_tdx_module_identity(data: dict[str, Any]) -> TdxModuleIdentity:
    """Parse TDX module identity from JSON."""
    return TdxModuleIdentity(
        id=data.get("id", ""),
        mrsigner=_parse_hex_bytes(data.get("mrsigner", "00" * TDX_MRSIGNER_SIZE)),
        attributes=_parse_hex_bytes(data.get("attributes", "")),
        attributes_mask=_parse_hex_bytes(data.get("attributesMask", "")),
        tcb_levels=[_parse_tcb_level(level) for level in data.get("tcbLevels", [])],
    )


def _parse_tcb_info(data: dict[str, Any]) -> TcbInfo:
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
        tdx_module_identities=[_parse_tdx_module_identity(m) for m in data.get("tdxModuleIdentities", [])],
        tcb_levels=[_parse_tcb_level(level) for level in data.get("tcbLevels", [])],
    )


def _parse_enclave_identity(data: dict[str, Any]) -> EnclaveIdentity:
    """Parse Enclave Identity from JSON."""
    return EnclaveIdentity(
        id=data.get("id", ""),
        version=data.get("version", 0),
        issue_date=_parse_datetime(data.get("issueDate", "1970-01-01T00:00:00Z")),
        next_update=_parse_datetime(data.get("nextUpdate", "1970-01-01T00:00:00Z")),
        tcb_evaluation_data_number=data.get("tcbEvaluationDataNumber", 0),
        miscselect=_parse_hex_bytes(data.get("miscselect", "00" * MISCSELECT_SIZE)),
        miscselect_mask=_parse_hex_bytes(data.get("miscselectMask", "00" * MISCSELECT_SIZE)),
        attributes=_parse_hex_bytes(data.get("attributes", "00" * QE_ATTRIBUTES_SIZE)),
        attributes_mask=_parse_hex_bytes(data.get("attributesMask", "00" * QE_ATTRIBUTES_SIZE)),
        mrsigner=_parse_hex_bytes(data.get("mrsigner", "00" * QE_MRSIGNER_SIZE)),
        isv_prod_id=data.get("isvprodid", 0),
        tcb_levels=[_parse_tcb_level(level) for level in data.get("tcbLevels", [])],
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
        raise CollateralError(f"Failed to parse TCB Info JSON: {e}") from e

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
        raise CollateralError(f"Failed to parse QE Identity JSON: {e}") from e

    enclave_identity = _parse_enclave_identity(data.get("enclaveIdentity", {}))

    # Validate required fields
    if enclave_identity.id != "TD_QE":
        raise CollateralError(f"QE Identity ID must be 'TD_QE', got '{enclave_identity.id}'")
    if enclave_identity.version != 2:
        raise CollateralError(f"QE Identity version must be 2, got {enclave_identity.version}")

    return QeIdentity(
        enclave_identity=enclave_identity,
        signature=data.get("signature", ""),
    )


def _parse_issuer_chain_header(header_value: str) -> list[x509.Certificate]:
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
    pem_data = unquote(header_value).encode("utf-8")

    try:
        certs = parse_pem_chain(pem_data)
    except CertificateChainError as e:
        raise CollateralError(f"Failed to parse issuer chain certificate: {e}") from e

    if len(certs) < 2:
        raise CollateralError(f"Issuer chain should contain at least 2 certificates, got {len(certs)}")

    return certs


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
        json_str = json_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CollateralError(f"Failed to decode {data_name} JSON: {e}") from e

    # Find the start of the inner object.
    # Only match at the top-level (must be preceded by '{' or ',' ignoring whitespace).
    key_pattern = f'"{json_key}":'
    key_pos = json_str.find(key_pattern)
    if key_pos == -1:
        raise CollateralError(f"{data_name} JSON does not contain '{json_key}' key")

    # Verify the match is at the top level (preceded by '{' or ',' outside strings)
    prefix = json_str[:key_pos].rstrip()
    if not prefix or prefix[-1] not in ("{", ","):
        raise CollateralError(f"{data_name} JSON key '{json_key}' found in unexpected position")

    # Find the start of the object value (skip whitespace after colon)
    obj_start = key_pos + len(key_pattern)
    while obj_start < len(json_str) and json_str[obj_start] in " \t\n\r":
        obj_start += 1

    if obj_start >= len(json_str) or json_str[obj_start] != "{":
        raise CollateralError(f"{data_name} '{json_key}' is not an object")

    # Use the stdlib JSON decoder to find the extent of the nested object.
    # raw_decode parses from the given index and returns the end position,
    # correctly handling string escaping, nesting, and all JSON edge cases.
    try:
        decoder = json.JSONDecoder()
        _, obj_end = decoder.raw_decode(json_str, obj_start)
    except json.JSONDecodeError as e:
        raise CollateralError(f"{data_name} JSON has malformed '{json_key}' object: {e}") from e

    # Extract the signed data (exact bytes as they appear in the response)
    signed_json = json_str[obj_start:obj_end].encode("utf-8")

    # Parse signature (hex-encoded raw R||S format, 64 bytes = 128 hex chars)
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError as e:
        raise CollateralError(f"{data_name} signature is not valid hex: {e}") from e

    if len(sig_bytes) != ECDSA_SIGNATURE_SIZE:
        raise CollateralError(f"{data_name} signature is {len(sig_bytes)} bytes, expected {ECDSA_SIGNATURE_SIZE}")

    # Convert R||S to DER format
    r = int.from_bytes(sig_bytes[0:ECDSA_P256_COMPONENT_SIZE], byteorder="big")
    s = int.from_bytes(sig_bytes[ECDSA_P256_COMPONENT_SIZE:ECDSA_SIGNATURE_SIZE], byteorder="big")
    signature_der = encode_dss_signature(r, s)

    # Verify ECDSA signature
    try:
        public_key = signing_cert.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise CollateralError(f"{data_name} signing certificate does not carry an EC public key")
        public_key.verify(signature_der, signed_json, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise CollateralError(f"{data_name} signature verification failed: signature does not match content") from None


def verify_tcb_info_signature(
    response_bytes: bytes,
    tcb_info: TdxTcbInfo,
    issuer_chain: list[x509.Certificate],
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
    try:
        verify_intel_chain(issuer_chain, "TCB Info issuer chain")
    except CertificateChainError as e:
        raise CollateralError(str(e)) from e

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
    issuer_chain: list[x509.Certificate],
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
    try:
        verify_intel_chain(issuer_chain, "QE Identity issuer chain")
    except CertificateChainError as e:
        raise CollateralError(str(e)) from e

    # Verify signature over enclaveIdentity JSON
    _verify_collateral_signature(
        json_bytes=response_bytes,
        json_key="enclaveIdentity",
        signature_hex=qe_identity.signature,
        signing_cert=issuer_chain[0],
        data_name="QE Identity",
    )


# =============================================================================
# Collateral Loading
# =============================================================================


def load_tcb_info(body: bytes, issuer_chain_header: str) -> tuple[TdxTcbInfo, bytes, list[x509.Certificate]]:
    """
    Parse and verify a captured TCB Info response.

    Args:
        body: Raw TCB Info response bytes
        issuer_chain_header: The TCB-Info-Issuer-Chain response header

    Returns:
        Tuple of (parsed TdxTcbInfo, raw response bytes, issuer certificate chain)

    Raises:
        CollateralError: If parsing or signature verification fails
    """
    tcb_info = parse_tcb_info_response(body)

    if not issuer_chain_header:
        raise CollateralError("TCB Info response missing TCB-Info-Issuer-Chain header")

    issuer_chain = _parse_issuer_chain_header(issuer_chain_header)
    verify_tcb_info_signature(body, tcb_info, issuer_chain)

    return tcb_info, body, issuer_chain


def load_qe_identity(body: bytes, issuer_chain_header: str) -> tuple[QeIdentity, bytes, list[x509.Certificate]]:
    """
    Parse and verify a captured QE Identity response.

    Args:
        body: Raw QE Identity response bytes
        issuer_chain_header: The SGX-Enclave-Identity-Issuer-Chain response header

    Returns:
        Tuple of (parsed QeIdentity, raw response bytes, issuer certificate chain)

    Raises:
        CollateralError: If parsing or signature verification fails
    """
    qe_identity = parse_qe_identity_response(body)

    if not issuer_chain_header:
        raise CollateralError("QE Identity response missing SGX-Enclave-Identity-Issuer-Chain header")

    issuer_chain = _parse_issuer_chain_header(issuer_chain_header)
    verify_qe_identity_signature(body, qe_identity, issuer_chain)

    return qe_identity, body, issuer_chain


def load_pck_crl(ca_type: str, body: bytes, issuer_chain_header: str) -> PckCrl:
    """
    Parse and verify a captured PCK CRL response (PEM).

    Args:
        ca_type: CA type - "platform" or "processor"
        body: Raw PCK CRL response bytes
        issuer_chain_header: The SGX-PCK-CRL-Issuer-Chain response header

    Returns:
        Parsed PckCrl

    Raises:
        CollateralError: If parsing or signature verification fails
    """
    if ca_type not in ("platform", "processor"):
        raise CollateralError(f"Invalid CA type: {ca_type}. Must be 'platform' or 'processor'")

    # Parse the PEM-encoded CRL
    try:
        crl = x509.load_pem_x509_crl(body)
    except ValueError as e:
        raise CollateralError(f"Failed to parse PCK CRL ({ca_type}): {e}") from e

    if not issuer_chain_header:
        raise CollateralError(f"PCK CRL ({ca_type}) response missing SGX-PCK-CRL-Issuer-Chain header")

    issuer_chain = _parse_issuer_chain_header(issuer_chain_header)
    _verify_crl_signature(crl, issuer_chain, ca_type)

    next_update = crl.next_update_utc
    if next_update is None:
        raise CollateralError(f"PCK CRL ({ca_type}) is missing next_update field")

    return PckCrl(crl=crl, ca_type=ca_type, next_update=next_update)


def load_root_ca_crl(body: bytes) -> RootCrl:
    """
    Parse and verify a captured Intel SGX Root CA CRL (DER).

    This CRL lists revoked intermediate CA certificates (Platform CA, Processor CA).

    Args:
        body: Raw DER CRL bytes

    Returns:
        Parsed RootCrl

    Raises:
        CollateralError: If parsing or signature verification fails
    """
    # Parse the DER-encoded CRL
    try:
        crl = x509.load_der_x509_crl(body)
    except Exception as e:
        raise CollateralError(f"Failed to parse Intel SGX Root CA CRL: {e}") from e

    # Verify CRL is signed by the Intel SGX Root CA
    _verify_root_crl_signature(crl)

    next_update = crl.next_update_utc
    if next_update is None:
        raise CollateralError("Intel SGX Root CA CRL is missing next_update field")

    return RootCrl(crl=crl, next_update=next_update)


def _verify_crl_signature(
    crl: x509.CertificateRevocationList,
    issuer_chain: list[x509.Certificate],
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
    try:
        verify_intel_chain(issuer_chain, f"PCK CRL ({ca_type}) issuer chain")
    except CertificateChainError as e:
        raise CollateralError(str(e)) from e

    # Verify CRL signature using the signing cert (first in chain)
    signing_cert = issuer_chain[0]
    hash_algo = crl.signature_hash_algorithm
    if hash_algo is None:
        raise CollateralError(f"PCK CRL ({ca_type}) has no signature hash algorithm")
    signing_key = signing_cert.public_key()
    if not isinstance(signing_key, ec.EllipticCurvePublicKey):
        raise CollateralError(f"PCK CRL ({ca_type}) signing certificate does not carry an EC public key")
    try:
        signing_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            ec.ECDSA(hash_algo),
        )
    except InvalidSignature:
        raise CollateralError(f"PCK CRL ({ca_type}) signature verification failed") from None


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
    root_key = intel_root.public_key()
    if not isinstance(root_key, ec.EllipticCurvePublicKey):
        raise CollateralError("Intel SGX Root CA does not carry an EC public key")
    try:
        root_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            ec.ECDSA(hash_algo),
        )
    except InvalidSignature:
        raise CollateralError("Intel SGX Root CA CRL signature verification failed") from None


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
        raise CollateralError(f"Could not determine PCK CA type from issuer: {issuer}")
    except Exception as e:
        raise CollateralError(f"Failed to determine PCK CA type: {e}") from e


def is_cpu_svn_higher_or_equal(
    pck_cert_cpu_svn: bytes,
    sgx_tcb_components: list[TcbComponent],
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

    return all(pck_cert_cpu_svn[i] >= component.svn for i, component in enumerate(sgx_tcb_components))


def is_tdx_tcb_svn_higher_or_equal(
    tee_tcb_svn: bytes,
    tdx_tcb_components: list[TcbComponent],
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

    return all(tee_tcb_svn[i] >= tdx_tcb_components[i].svn for i in range(start, len(tee_tcb_svn)))


def get_matching_tcb_level(
    tcb_levels: list[TcbLevel],
    tee_tcb_svn: bytes,
    pck_cert_pce_svn: int,
    pck_cert_cpu_svn: bytes,
) -> TcbLevel | None:
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
        if (
            is_cpu_svn_higher_or_equal(pck_cert_cpu_svn, level.tcb.sgx_tcb_components)
            and pck_cert_pce_svn >= level.tcb.pce_svn
            and is_tdx_tcb_svn_higher_or_equal(tee_tcb_svn, level.tcb.tdx_tcb_components)
        ):
            return level

    return None


def get_matching_qe_tcb_level(
    tcb_levels: list[TcbLevel],
    isv_svn: int,
) -> TcbLevel | None:
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
        raise CollateralError(f"FMSPC mismatch: PCK certificate has {pck_fmspc}, TCB Info has {tcb_fmspc}")

    # Cross-check PCE_ID between PCK certificate and TCB Info
    pck_pceid = pck_extensions.pceid.lower()
    tcb_pceid = tcb_info.pce_id.lower()
    if pck_pceid != tcb_pceid:
        raise CollateralError(f"PCE_ID mismatch: PCK certificate has {pck_pceid}, TCB Info has {tcb_pceid}")

    matching_level = get_matching_tcb_level(
        tcb_levels=tcb_info.tcb_levels,
        tee_tcb_svn=tee_tcb_svn,
        pck_cert_pce_svn=pck_extensions.tcb.pce_svn,
        pck_cert_cpu_svn=pck_extensions.tcb.cpu_svn,
    )

    if matching_level is None:
        raise CollateralError("No matching TCB level found for the quote's SVN values")

    # Check status - always reject REVOKED and OUT_OF_DATE
    if matching_level.tcb_status == TcbStatus.REVOKED:
        raise CollateralError("TCB status is REVOKED - platform is not trusted")

    if matching_level.tcb_status == TcbStatus.OUT_OF_DATE:
        raise CollateralError("TCB status is OUT_OF_DATE - platform needs update")

    if matching_level.tcb_status == TcbStatus.OUT_OF_DATE_CONFIGURATION_NEEDED:
        raise CollateralError("TCB status is OUT_OF_DATE_CONFIGURATION_NEEDED - platform needs update")

    # In strict mode, also reject statuses that indicate security advisories
    if strict_mode:
        if matching_level.tcb_status == TcbStatus.SW_HARDENING_NEEDED:
            advisories = ", ".join(matching_level.advisory_ids) or "none listed"
            raise CollateralError(f"TCB status is SW_HARDENING_NEEDED (strict mode). Advisories: {advisories}")

        if matching_level.tcb_status == TcbStatus.CONFIGURATION_NEEDED:
            advisories = ", ".join(matching_level.advisory_ids) or "none listed"
            raise CollateralError(f"TCB status is CONFIGURATION_NEEDED (strict mode). Advisories: {advisories}")

        if matching_level.tcb_status == TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED:
            advisories = ", ".join(matching_level.advisory_ids) or "none listed"
            raise CollateralError(
                f"TCB status is CONFIGURATION_AND_SW_HARDENING_NEEDED (strict mode). Advisories: {advisories}"
            )

    return matching_level


def get_tdx_module_identity(
    tcb_info: TcbInfo,
    tee_tcb_svn: bytes,
) -> TdxModuleIdentity:
    """
    Find the matching TDX module identity based on TEE_TCB_SVN.

    The module ID is derived from TEE_TCB_SVN[1] (major version):
    - TEE_TCB_SVN[1] = 0x03 -> Module ID = "TDX_03"
    - TEE_TCB_SVN[1] = 0x01 -> Module ID = "TDX_01"

    Args:
        tcb_info: Parsed TCB Info from Intel PCS
        tee_tcb_svn: TEE TCB SVN from quote body (16 bytes)

    Returns:
        Matching TdxModuleIdentity

    Raises:
        CollateralError: If no module identities in TCB Info, tee_tcb_svn is
            malformed, or module version is unknown
    """
    if not tcb_info.tdx_module_identities:
        raise CollateralError("TCB Info has no TDX module identities")

    if len(tee_tcb_svn) < 2:
        raise CollateralError(f"TEE_TCB_SVN is too short ({len(tee_tcb_svn)} bytes, expected >= 2)")

    # Extract major version and form module ID
    # TEE_TCB_SVN[0] = minor SVN, TEE_TCB_SVN[1] = major SVN
    major_version = tee_tcb_svn[1]
    module_id = f"TDX_{major_version:02d}"

    # Find matching module identity
    for module_identity in tcb_info.tdx_module_identities:
        if module_identity.id == module_id:
            return module_identity

    known_ids = [m.id for m in tcb_info.tdx_module_identities]
    raise CollateralError(f"Unknown TDX module version {module_id}. Known module identities: {known_ids}")


def validate_tdx_module_identity(
    tcb_info: TcbInfo,
    tee_tcb_svn: bytes,
    mr_signer_seam: bytes,
    seam_attributes: bytes,
) -> None:
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

    Raises:
        CollateralError: If module identity validation fails
    """
    module_identity = get_tdx_module_identity(tcb_info, tee_tcb_svn)

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
        attrs = attrs + b"\x00" * (len(mask) - len(attrs))
    if len(mask) < len(attrs):
        mask = mask + b"\x00" * (len(attrs) - len(mask))

    report_attrs_masked = bytes(a & b for a, b in zip(attrs, mask, strict=False))
    expected_attrs_masked = bytes(a & b for a, b in zip(module_identity.attributes, mask, strict=False))
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
            # Check status - reject insecure statuses consistently with
            # validate_tcb_status and validate_qe_identity
            if level.tcb_status == TcbStatus.REVOKED:
                raise CollateralError(f"TDX module TCB status is REVOKED for version {tee_tcb_svn[1]}.{minor_version}")
            if level.tcb_status == TcbStatus.OUT_OF_DATE:
                raise CollateralError(
                    f"TDX module TCB status is OUT_OF_DATE for version {tee_tcb_svn[1]}.{minor_version}"
                )
            if level.tcb_status == TcbStatus.OUT_OF_DATE_CONFIGURATION_NEEDED:
                raise CollateralError(
                    f"TDX module TCB status is OUT_OF_DATE_CONFIGURATION_NEEDED "
                    f"for version {tee_tcb_svn[1]}.{minor_version}"
                )
            return

    # No matching TCB level found - this is an error (matches Go behavior)
    raise CollateralError(
        f"Could not find a TDX Module Identity TCB Level matching the TDX Module's ISVSVN ({minor_version})"
    )


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
        a & b for a, b in zip(qe_report_miscselect, qe_identity.miscselect_mask, strict=False)
    )
    expected_miscselect_masked = bytes(
        a & b for a, b in zip(qe_identity.miscselect, qe_identity.miscselect_mask, strict=False)
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
        a & b for a, b in zip(qe_report_attributes, qe_identity.attributes_mask, strict=False)
    )
    expected_attributes_masked = bytes(
        a & b for a, b in zip(qe_identity.attributes, qe_identity.attributes_mask, strict=False)
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
        raise CollateralError(f"No matching QE TCB level found for ISV SVN {qe_report_isv_svn}")

    # Check status
    if matching_level.tcb_status == TcbStatus.REVOKED:
        raise CollateralError("QE TCB status is REVOKED")

    if matching_level.tcb_status == TcbStatus.OUT_OF_DATE:
        raise CollateralError("QE TCB status is OUT_OF_DATE")

    if matching_level.tcb_status == TcbStatus.OUT_OF_DATE_CONFIGURATION_NEEDED:
        raise CollateralError("QE TCB status is OUT_OF_DATE_CONFIGURATION_NEEDED")

    return matching_level


def check_collateral_freshness(
    collateral: TdxCollateral,
    min_tcb_evaluation_data_number: int,
) -> None:
    """
    Check that collateral is not expired and meets freshness requirements.

    This performs the following checks:
    1. TCB Info has not expired (now < next_update)
    2. QE Identity has not expired (now < next_update)
    3. Both TCB Info and QE Identity must have tcbEvaluationDataNumber >= threshold

    The tcbEvaluationDataNumber is a monotonically increasing number that
    Intel updates when new TCB recovery (TCB-R) events occur. The minimum
    threshold ensures we don't accept collateral issued before critical
    security updates.

    See: https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html

    Args:
        collateral: TDX collateral to check
        min_tcb_evaluation_data_number: Minimum tcbEvaluationDataNumber threshold.
            Collateral with a lower number is rejected.

    Raises:
        CollateralError: If collateral is expired or too old
    """
    now = datetime.now(UTC)

    tcb_next_update = collateral.tcb_info.tcb_info.next_update
    if now > tcb_next_update:
        raise CollateralError(f"TCB Info has expired (next update was {tcb_next_update})")

    qe_next_update = collateral.qe_identity.enclave_identity.next_update
    if now > qe_next_update:
        raise CollateralError(f"QE Identity has expired (next update was {qe_next_update})")

    # Check tcbEvaluationDataNumber threshold
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
    intermediate_cert: x509.Certificate | None = None,
) -> None:
    """
    Validate that certificates in the attestation chain have not been revoked.

    Per Intel DCAP spec Section 2.3, checks:
    1. PCK (leaf) certificate against the PCK CRL from Intel PCS
    2. Intermediate CA certificate against the Intel SGX Root CA CRL
    3. TCB Info signing certificate against the Intel SGX Root CA CRL
    4. QE Identity signing certificate against the Intel SGX Root CA CRL

    Args:
        collateral: TDX collateral containing CRLs and issuer chains
        pck_cert: PCK certificate to check
        intermediate_cert: Intermediate CA certificate to check (optional)

    Raises:
        CollateralError: If any certificate is revoked or CRL check fails

    TODO: Use cryptography.x509.verification integrated CRL checking when available.
          As of cryptography 46.0.3, PolicyBuilder doesn't support CRL stores.
          Track: https://github.com/pyca/cryptography/issues
    """
    if collateral.pck_crl is None:
        raise CollateralError("Cannot check certificate revocation: PCK CRL not available in collateral")

    # --- Check PCK (leaf) certificate against PCK CRL ---
    pck_crl = collateral.pck_crl.crl

    # Check PCK CRL freshness
    now = datetime.now(UTC)
    pck_crl_next_update = pck_crl.next_update_utc
    if pck_crl_next_update is not None and now > pck_crl_next_update:
        raise CollateralError(f"PCK CRL has expired (next update was {pck_crl_next_update})")

    # Check if PCK certificate is revoked
    pck_serial = pck_cert.serial_number
    revoked_pck = pck_crl.get_revoked_certificate_by_serial_number(pck_serial)

    if revoked_pck is not None:
        revocation_date = revoked_pck.revocation_date_utc
        raise CollateralError(
            f"PCK certificate has been revoked. Serial: {pck_serial:x}, Revocation date: {revocation_date}"
        )

    # --- Check certificates against Root CA CRL ---
    # The Root CRL lists revoked intermediate CAs (Platform CA, Processor CA,
    # TCB Signing CA, etc.) issued by Intel SGX Root CA.
    if collateral.root_crl is not None:
        root_crl = collateral.root_crl.crl

        # Check Root CRL freshness (once, shared across all checks below)
        root_crl_next_update = root_crl.next_update_utc
        if root_crl_next_update is not None and now > root_crl_next_update:
            raise CollateralError(f"Intel SGX Root CA CRL has expired (next update was {root_crl_next_update})")

        # Check intermediate CA certificate (from PCK cert chain)
        if intermediate_cert is not None:
            _check_cert_against_crl(root_crl, intermediate_cert, "Intermediate CA")

        # Check TCB Info signing certificate (per DCAP spec Section 2.3:
        # "Check if verification collaterals are on the CRL")
        if collateral.tcb_info_issuer_chain:
            _check_cert_against_crl(root_crl, collateral.tcb_info_issuer_chain[0], "TCB Info signing")

        # Check QE Identity signing certificate
        if collateral.qe_identity_issuer_chain:
            _check_cert_against_crl(root_crl, collateral.qe_identity_issuer_chain[0], "QE Identity signing")

    elif intermediate_cert is not None or collateral.tcb_info_issuer_chain or collateral.qe_identity_issuer_chain:
        raise CollateralError("Cannot check certificate revocation: Root CRL not available in collateral")


def _check_cert_against_crl(
    crl: x509.CertificateRevocationList,
    cert: x509.Certificate,
    cert_name: str,
) -> None:
    """
    Check if a certificate has been revoked according to a CRL.

    Args:
        crl: Certificate Revocation List to check against
        cert: Certificate to check
        cert_name: Human-readable name for error messages

    Raises:
        CollateralError: If the certificate has been revoked
    """
    serial = cert.serial_number
    revoked = crl.get_revoked_certificate_by_serial_number(serial)
    if revoked is not None:
        revocation_date = revoked.revocation_date_utc
        raise CollateralError(
            f"{cert_name} certificate has been revoked. Serial: {serial:x}, Revocation date: {revocation_date}"
        )


@dataclass
class CollateralValidationResult:
    """
    Result of collateral validation.

    Attributes:
        collateral: The fetched TDX collateral
        tcb_level: The matching TCB level for the platform
        pck_extensions: Extracted PCK certificate extensions
    """

    collateral: TdxCollateral
    tcb_level: TcbLevel
    pck_extensions: PckExtensions


def validate_collateral(
    quote: QuoteV4,
    pck_chain: PCKCertificateChain,
    collateral: TdxCollateral,
    min_tcb_evaluation_data_number: int = DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER,
) -> CollateralValidationResult:
    """
    Validate all collateral for a TDX quote.

    This function orchestrates the complete collateral validation flow:
    1. Extract PCK extensions (FMSPC, TCB components)
    2. Check collateral freshness
    3. Validate certificate revocation
    4. Validate TCB status
    5. Validate TDX module identity
    6. Validate QE identity

    Args:
        quote: Parsed TDX QuoteV4
        pck_chain: Extracted PCK certificate chain
        collateral: The loaded collateral (TCB Info, QE Identity, CRLs)
        min_tcb_evaluation_data_number: Minimum required tcbEvaluationDataNumber

    Returns:
        CollateralValidationResult with validated collateral and TCB level

    Raises:
        CollateralError: If any collateral validation step fails
    """

    # Step 1: Extract PCK extensions
    try:
        pck_extensions = extract_pck_extensions(pck_chain.pck_cert)
    except PckExtensionError as e:
        raise CollateralError(f"Failed to extract PCK extensions: {e}") from e

    # Step 2: Check collateral freshness
    check_collateral_freshness(collateral, min_tcb_evaluation_data_number)

    # Step 3: Validate certificate revocation
    validate_certificate_revocation(collateral, pck_chain.pck_cert, pck_chain.intermediate_cert)

    # Step 4: Validate TCB status
    tcb_level = validate_tcb_status(
        collateral.tcb_info.tcb_info,
        quote.td_quote_body.tee_tcb_svn,
        pck_extensions,
    )

    # Step 5: Validate TDX module identity
    validate_tdx_module_identity(
        collateral.tcb_info.tcb_info,
        quote.td_quote_body.tee_tcb_svn,
        quote.td_quote_body.mr_signer_seam,
        quote.td_quote_body.seam_attributes,
    )

    # Step 6: Validate QE identity
    qe_report = quote.signed_data.certification_data.qe_report_data
    if qe_report is None:
        raise CollateralError("Quote missing QE report certification data")
    qe_parsed = qe_report.qe_report_parsed
    miscselect_bytes = qe_parsed.misc_select.to_bytes(4, byteorder="little")
    validate_qe_identity(
        collateral.qe_identity.enclave_identity,
        qe_parsed.isv_svn,
        qe_parsed.mr_signer,
        miscselect_bytes,
        qe_parsed.attributes,
        qe_parsed.isv_prod_id,
    )

    return CollateralValidationResult(
        collateral=collateral,
        tcb_level=tcb_level,
        pck_extensions=pck_extensions,
    )
