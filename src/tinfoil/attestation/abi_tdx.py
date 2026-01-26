"""
TDX Quote parsing structures and constants.

This module provides data structures and parsing logic for Intel TDX attestation
quotes in the QuoteV4 format. Based on go-tdx-guest/abi/abi.go.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import List

# =============================================================================
# Constants
# =============================================================================

# Quote structure sizes
QUOTE_MIN_SIZE = 0x3FC  # 1020 bytes minimum
HEADER_SIZE = 0x30  # 48 bytes
TD_QUOTE_BODY_SIZE = 0x248  # 584 bytes
QE_REPORT_SIZE = 0x180  # 384 bytes

# Quote versions
QUOTE_VERSION_V4 = 4
QUOTE_VERSION_V5 = 5

# TEE type for TDX
TEE_TDX = 0x00000081

# Attestation key type (ECDSA-256-with-P-256 curve)
ATTESTATION_KEY_TYPE_ECDSA_P256 = 2

# Certification data types
CERT_DATA_TYPE_PCK_CERT_CHAIN = 5
CERT_DATA_TYPE_QE_REPORT = 6

# Field sizes
TEE_TCB_SVN_SIZE = 0x10  # 16 bytes
MR_SEAM_SIZE = 0x30  # 48 bytes
MR_SIGNER_SEAM_SIZE = 0x30  # 48 bytes
SEAM_ATTRIBUTES_SIZE = 0x08  # 8 bytes
TD_ATTRIBUTES_SIZE = 0x08  # 8 bytes
XFAM_SIZE = 0x08  # 8 bytes
MR_TD_SIZE = 0x30  # 48 bytes
MR_CONFIG_ID_SIZE = 0x30  # 48 bytes
MR_OWNER_SIZE = 0x30  # 48 bytes
MR_OWNER_CONFIG_SIZE = 0x30  # 48 bytes
RTMR_SIZE = 0x30  # 48 bytes
RTMR_COUNT = 4
REPORT_DATA_SIZE = 0x40  # 64 bytes
QE_VENDOR_ID_SIZE = 0x10  # 16 bytes
USER_DATA_SIZE = 0x14  # 20 bytes
SIGNATURE_SIZE = 0x40  # 64 bytes
ATTESTATION_KEY_SIZE = 0x40  # 64 bytes

# Intel QE Vendor ID: 939a7233-f79c-4ca9-940a-0db3957f0607
INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")

# =============================================================================
# Header offsets (relative to quote start)
# =============================================================================

HEADER_VERSION_START = 0x00
HEADER_VERSION_END = 0x02
HEADER_AK_TYPE_START = 0x02
HEADER_AK_TYPE_END = 0x04
HEADER_TEE_TYPE_START = 0x04
HEADER_TEE_TYPE_END = 0x08
HEADER_PCE_SVN_START = 0x08
HEADER_PCE_SVN_END = 0x0A
HEADER_QE_SVN_START = 0x0A
HEADER_QE_SVN_END = 0x0C
HEADER_QE_VENDOR_ID_START = 0x0C
HEADER_QE_VENDOR_ID_END = 0x1C
HEADER_USER_DATA_START = 0x1C
HEADER_USER_DATA_END = 0x30

# =============================================================================
# TdQuoteBody offsets (relative to body start at 0x30)
# =============================================================================

TD_TEE_TCB_SVN_START = 0x00
TD_TEE_TCB_SVN_END = 0x10
TD_MR_SEAM_START = 0x10
TD_MR_SEAM_END = 0x40
TD_MR_SIGNER_SEAM_START = 0x40
TD_MR_SIGNER_SEAM_END = 0x70
TD_SEAM_ATTRIBUTES_START = 0x70
TD_SEAM_ATTRIBUTES_END = 0x78
TD_ATTRIBUTES_START = 0x78
TD_ATTRIBUTES_END = 0x80
TD_XFAM_START = 0x80
TD_XFAM_END = 0x88
TD_MR_TD_START = 0x88
TD_MR_TD_END = 0xB8
TD_MR_CONFIG_ID_START = 0xB8
TD_MR_CONFIG_ID_END = 0xE8
TD_MR_OWNER_START = 0xE8
TD_MR_OWNER_END = 0x118
TD_MR_OWNER_CONFIG_START = 0x118
TD_MR_OWNER_CONFIG_END = 0x148
TD_RTMRS_START = 0x148
TD_RTMRS_END = 0x208
TD_REPORT_DATA_START = 0x208
TD_REPORT_DATA_END = 0x248

# =============================================================================
# Quote-level offsets
# =============================================================================

QUOTE_HEADER_START = 0x00
QUOTE_HEADER_END = 0x30
QUOTE_BODY_START = 0x30
QUOTE_BODY_END = 0x278
QUOTE_SIGNED_DATA_SIZE_START = 0x278
QUOTE_SIGNED_DATA_SIZE_END = 0x27C
QUOTE_SIGNED_DATA_START = 0x27C

# =============================================================================
# SignedData offsets (relative to signed data start)
# =============================================================================

SIGNED_DATA_SIGNATURE_START = 0x00
SIGNED_DATA_SIGNATURE_END = 0x40
SIGNED_DATA_AK_START = 0x40
SIGNED_DATA_AK_END = 0x80
SIGNED_DATA_CERT_DATA_START = 0x80

# =============================================================================
# QE Report offsets (within certification data)
# =============================================================================

QE_CPU_SVN_START = 0x00
QE_CPU_SVN_END = 0x10
QE_MISC_SELECT_START = 0x10
QE_MISC_SELECT_END = 0x14
QE_ATTRIBUTES_START = 0x30
QE_ATTRIBUTES_END = 0x40
QE_MR_ENCLAVE_START = 0x40
QE_MR_ENCLAVE_END = 0x60
QE_MR_SIGNER_START = 0x80
QE_MR_SIGNER_END = 0xA0
QE_ISV_PROD_ID_START = 0x100
QE_ISV_PROD_ID_END = 0x102
QE_ISV_SVN_START = 0x102
QE_ISV_SVN_END = 0x104
QE_REPORT_DATA_START = 0x140
QE_REPORT_DATA_END = 0x180


# =============================================================================
# Enums
# =============================================================================

class CertificationDataType(IntEnum):
    """Type of certification data embedded in the quote."""
    PCK_CERT_CHAIN = 5  # PCK certificate chain in PEM format
    QE_REPORT_CERTIFICATION_DATA = 6  # QE report with nested certification


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class TdxHeader:
    """
    TDX Quote header (48 bytes).

    Contains quote metadata including version, attestation key type,
    TEE type, and QE/PCE SVN values.
    """
    version: int  # 2 bytes - must be 4 for QuoteV4
    attestation_key_type: int  # 2 bytes - must be 2 (ECDSA-P256)
    tee_type: int  # 4 bytes - must be 0x81 (TDX)
    pce_svn: int  # 2 bytes - PCE Security Version Number
    qe_svn: int  # 2 bytes - QE Security Version Number
    qe_vendor_id: bytes  # 16 bytes - Intel: 939a7233-f79c-4ca9-940a-0db3957f0607
    user_data: bytes  # 20 bytes - Custom data from QE

    def __str__(self) -> str:
        return (
            f"TdxHeader(version={self.version}, "
            f"ak_type={self.attestation_key_type}, "
            f"tee_type=0x{self.tee_type:x}, "
            f"pce_svn={self.pce_svn}, "
            f"qe_svn={self.qe_svn}, "
            f"qe_vendor_id={self.qe_vendor_id.hex()})"
        )


@dataclass
class TdQuoteBody:
    """
    TD Quote Body (584 bytes).

    Contains the TD's measurements and report data. This is the core
    attestation data signed by the QE.
    """
    tee_tcb_svn: bytes  # 16 bytes - TEE TCB Security Version Number
    mr_seam: bytes  # 48 bytes - Measurement of SEAM module
    mr_signer_seam: bytes  # 48 bytes - Signer of SEAM module (zeros for Intel SEAM)
    seam_attributes: bytes  # 8 bytes - SEAM attributes
    td_attributes: bytes  # 8 bytes - TD attributes
    xfam: bytes  # 8 bytes - Extended feature mask
    mr_td: bytes  # 48 bytes - Measurement of TD (MRTD)
    mr_config_id: bytes  # 48 bytes - Config ID
    mr_owner: bytes  # 48 bytes - Owner measurement
    mr_owner_config: bytes  # 48 bytes - Owner config measurement
    rtmrs: List[bytes]  # 4 x 48 bytes - Runtime measurement registers
    report_data: bytes  # 64 bytes - Custom data (TLS key FP + HPKE key)

    def __str__(self) -> str:
        return (
            f"TdQuoteBody(\n"
            f"  mr_td={self.mr_td.hex()},\n"
            f"  rtmr0={self.rtmrs[0].hex()},\n"
            f"  rtmr1={self.rtmrs[1].hex()},\n"
            f"  rtmr2={self.rtmrs[2].hex()},\n"
            f"  rtmr3={self.rtmrs[3].hex()},\n"
            f"  mr_seam={self.mr_seam.hex()},\n"
            f"  report_data={self.report_data.hex()}\n"
            f")"
        )

    def get_measurements(self) -> List[bytes]:
        """Return the 5 TDX measurements: [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]."""
        return [self.mr_td] + self.rtmrs


@dataclass
class QeReport:
    """
    Quoting Enclave Report (384 bytes).

    SGX enclave report from the Quoting Enclave, used to verify
    the attestation key is bound to a legitimate QE.
    """
    cpu_svn: bytes  # 16 bytes
    misc_select: int  # 4 bytes
    attributes: bytes  # 16 bytes
    mr_enclave: bytes  # 32 bytes - QE enclave measurement
    mr_signer: bytes  # 32 bytes - QE signer measurement
    isv_prod_id: int  # 2 bytes - Product ID
    isv_svn: int  # 2 bytes - Security Version Number
    report_data: bytes  # 64 bytes - Contains hash of attestation key

    def __str__(self) -> str:
        return (
            f"QeReport(mr_enclave={self.mr_enclave.hex()}, "
            f"mr_signer={self.mr_signer.hex()}, "
            f"isv_prod_id={self.isv_prod_id}, "
            f"isv_svn={self.isv_svn})"
        )


@dataclass
class QeReportCertificationData:
    """
    QE Report Certification Data.

    Contains the QE report, its signature, authentication data,
    and the nested PCK certificate chain.
    """
    qe_report: bytes  # 384 bytes - Raw QE report
    qe_report_parsed: QeReport  # Parsed QE report
    qe_report_signature: bytes  # 64 bytes - ECDSA signature over QE report
    qe_auth_data: bytes  # Variable - Authentication data
    pck_cert_chain_data: "PckCertChainData"  # Nested PCK certificate chain


@dataclass
class PckCertChainData:
    """
    PCK Certificate Chain Data.

    Contains the certification data type and the actual certificate
    chain in PEM format.
    """
    cert_type: int  # 2 bytes - Should be 5 (PCK cert chain)
    cert_data_size: int  # 4 bytes
    cert_data: bytes  # Variable - PEM certificate chain


@dataclass
class CertificationData:
    """
    Certification Data from the quote.

    Can be either a direct PCK cert chain (type 5) or QE report
    certification data (type 6) which contains nested cert chain.
    """
    cert_type: int  # 2 bytes - Type of certification data
    cert_data_size: int  # 4 bytes - Size of certification data
    # One of these will be populated based on cert_type:
    pck_cert_chain: PckCertChainData | None = None
    qe_report_data: QeReportCertificationData | None = None


@dataclass
class SignedData:
    """
    Signed Data section of the quote.

    Contains the quote signature, attestation public key, and
    certification data (certificate chain).
    """
    signature: bytes  # 64 bytes - ECDSA signature (R || S)
    attestation_key: bytes  # 64 bytes - Raw ECDSA P-256 public key
    certification_data: CertificationData

    def __str__(self) -> str:
        return (
            f"SignedData(signature={self.signature[:8].hex()}..., "
            f"attestation_key={self.attestation_key[:8].hex()}..., "
            f"cert_type={self.certification_data.cert_type})"
        )


@dataclass
class QuoteV4:
    """
    TDX Quote Version 4.

    The complete TDX attestation quote containing header, TD quote body,
    and signed data with certification chain.
    """
    header: TdxHeader
    td_quote_body: TdQuoteBody
    signed_data_size: int
    signed_data: SignedData
    extra_bytes: bytes = b""  # Any trailing bytes after signed data

    def __str__(self) -> str:
        return (
            f"QuoteV4(\n"
            f"  header={self.header},\n"
            f"  td_quote_body={self.td_quote_body},\n"
            f"  signed_data_size={self.signed_data_size},\n"
            f"  signed_data={self.signed_data}\n"
            f")"
        )

    def get_measurements(self) -> List[bytes]:
        """Return the 5 TDX measurements: [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]."""
        return self.td_quote_body.get_measurements()

    def get_report_data(self) -> bytes:
        """Return the 64-byte report data containing TLS key FP and HPKE key."""
        return self.td_quote_body.report_data


# =============================================================================
# Parsing Functions
# =============================================================================

import struct


class TdxQuoteParseError(Exception):
    """Raised when TDX quote parsing fails."""
    pass


def _parse_header(data: bytes) -> TdxHeader:
    """
    Parse the 48-byte TDX quote header.

    Args:
        data: 48 bytes of header data

    Returns:
        Parsed TdxHeader

    Raises:
        TdxQuoteParseError: If header is malformed
    """
    if len(data) < HEADER_SIZE:
        raise TdxQuoteParseError(
            f"Header too short: {len(data)} bytes, expected {HEADER_SIZE}"
        )

    version = struct.unpack_from("<H", data, HEADER_VERSION_START)[0]
    attestation_key_type = struct.unpack_from("<H", data, HEADER_AK_TYPE_START)[0]
    tee_type = struct.unpack_from("<I", data, HEADER_TEE_TYPE_START)[0]
    pce_svn = struct.unpack_from("<H", data, HEADER_PCE_SVN_START)[0]
    qe_svn = struct.unpack_from("<H", data, HEADER_QE_SVN_START)[0]
    qe_vendor_id = data[HEADER_QE_VENDOR_ID_START:HEADER_QE_VENDOR_ID_END]
    user_data = data[HEADER_USER_DATA_START:HEADER_USER_DATA_END]

    return TdxHeader(
        version=version,
        attestation_key_type=attestation_key_type,
        tee_type=tee_type,
        pce_svn=pce_svn,
        qe_svn=qe_svn,
        qe_vendor_id=qe_vendor_id,
        user_data=user_data,
    )


def _parse_td_quote_body(data: bytes) -> TdQuoteBody:
    """
    Parse the 584-byte TD quote body.

    Args:
        data: 584 bytes of TD quote body data

    Returns:
        Parsed TdQuoteBody

    Raises:
        TdxQuoteParseError: If body is malformed
    """
    if len(data) < TD_QUOTE_BODY_SIZE:
        raise TdxQuoteParseError(
            f"TD quote body too short: {len(data)} bytes, expected {TD_QUOTE_BODY_SIZE}"
        )

    # Parse RTMRs (4 x 48 bytes)
    rtmrs = []
    for i in range(RTMR_COUNT):
        start = TD_RTMRS_START + (i * RTMR_SIZE)
        end = start + RTMR_SIZE
        rtmrs.append(data[start:end])

    return TdQuoteBody(
        tee_tcb_svn=data[TD_TEE_TCB_SVN_START:TD_TEE_TCB_SVN_END],
        mr_seam=data[TD_MR_SEAM_START:TD_MR_SEAM_END],
        mr_signer_seam=data[TD_MR_SIGNER_SEAM_START:TD_MR_SIGNER_SEAM_END],
        seam_attributes=data[TD_SEAM_ATTRIBUTES_START:TD_SEAM_ATTRIBUTES_END],
        td_attributes=data[TD_ATTRIBUTES_START:TD_ATTRIBUTES_END],
        xfam=data[TD_XFAM_START:TD_XFAM_END],
        mr_td=data[TD_MR_TD_START:TD_MR_TD_END],
        mr_config_id=data[TD_MR_CONFIG_ID_START:TD_MR_CONFIG_ID_END],
        mr_owner=data[TD_MR_OWNER_START:TD_MR_OWNER_END],
        mr_owner_config=data[TD_MR_OWNER_CONFIG_START:TD_MR_OWNER_CONFIG_END],
        rtmrs=rtmrs,
        report_data=data[TD_REPORT_DATA_START:TD_REPORT_DATA_END],
    )


def _parse_qe_report(data: bytes) -> QeReport:
    """
    Parse the 384-byte QE report.

    Args:
        data: 384 bytes of QE report data

    Returns:
        Parsed QeReport

    Raises:
        TdxQuoteParseError: If report is malformed
    """
    if len(data) < QE_REPORT_SIZE:
        raise TdxQuoteParseError(
            f"QE report too short: {len(data)} bytes, expected {QE_REPORT_SIZE}"
        )

    return QeReport(
        cpu_svn=data[QE_CPU_SVN_START:QE_CPU_SVN_END],
        misc_select=struct.unpack_from("<I", data, QE_MISC_SELECT_START)[0],
        attributes=data[QE_ATTRIBUTES_START:QE_ATTRIBUTES_END],
        mr_enclave=data[QE_MR_ENCLAVE_START:QE_MR_ENCLAVE_END],
        mr_signer=data[QE_MR_SIGNER_START:QE_MR_SIGNER_END],
        isv_prod_id=struct.unpack_from("<H", data, QE_ISV_PROD_ID_START)[0],
        isv_svn=struct.unpack_from("<H", data, QE_ISV_SVN_START)[0],
        report_data=data[QE_REPORT_DATA_START:QE_REPORT_DATA_END],
    )


def _parse_pck_cert_chain_data(data: bytes) -> tuple[PckCertChainData, int]:
    """
    Parse PCK certificate chain data.

    Args:
        data: Raw bytes starting at PCK cert chain data

    Returns:
        Tuple of (PckCertChainData, bytes_consumed)

    Raises:
        TdxQuoteParseError: If data is malformed
    """
    if len(data) < 6:  # 2 bytes type + 4 bytes size
        raise TdxQuoteParseError("PCK cert chain data too short for header")

    cert_type = struct.unpack_from("<H", data, 0)[0]
    cert_data_size = struct.unpack_from("<I", data, 2)[0]

    if cert_type != CERT_DATA_TYPE_PCK_CERT_CHAIN:
        raise TdxQuoteParseError(
            f"Expected PCK cert chain type {CERT_DATA_TYPE_PCK_CERT_CHAIN}, got {cert_type}"
        )

    header_size = 6
    if len(data) < header_size + cert_data_size:
        raise TdxQuoteParseError(
            f"PCK cert chain data truncated: have {len(data)} bytes, "
            f"need {header_size + cert_data_size}"
        )

    cert_data = data[header_size:header_size + cert_data_size]
    bytes_consumed = header_size + cert_data_size

    return PckCertChainData(
        cert_type=cert_type,
        cert_data_size=cert_data_size,
        cert_data=cert_data,
    ), bytes_consumed


def _parse_qe_report_certification_data(data: bytes) -> tuple[QeReportCertificationData, int]:
    """
    Parse QE report certification data (type 6).

    Structure:
        - QE Report: 384 bytes
        - QE Report Signature: 64 bytes
        - QE Auth Data Size: 2 bytes
        - QE Auth Data: variable
        - PCK Cert Chain Data: variable (nested type 5)

    Args:
        data: Raw bytes starting at QE report certification data

    Returns:
        Tuple of (QeReportCertificationData, bytes_consumed)

    Raises:
        TdxQuoteParseError: If data is malformed
    """
    offset = 0

    # QE Report (384 bytes)
    if len(data) < offset + QE_REPORT_SIZE:
        raise TdxQuoteParseError("Data too short for QE report")
    qe_report_raw = data[offset:offset + QE_REPORT_SIZE]
    qe_report_parsed = _parse_qe_report(qe_report_raw)
    offset += QE_REPORT_SIZE

    # QE Report Signature (64 bytes)
    if len(data) < offset + SIGNATURE_SIZE:
        raise TdxQuoteParseError("Data too short for QE report signature")
    qe_report_signature = data[offset:offset + SIGNATURE_SIZE]
    offset += SIGNATURE_SIZE

    # QE Auth Data Size (2 bytes) + Auth Data
    if len(data) < offset + 2:
        raise TdxQuoteParseError("Data too short for QE auth data size")
    qe_auth_data_size = struct.unpack_from("<H", data, offset)[0]
    offset += 2

    if len(data) < offset + qe_auth_data_size:
        raise TdxQuoteParseError("Data too short for QE auth data")
    qe_auth_data = data[offset:offset + qe_auth_data_size]
    offset += qe_auth_data_size

    # Nested PCK Cert Chain Data
    pck_cert_chain_data, pck_bytes = _parse_pck_cert_chain_data(data[offset:])
    offset += pck_bytes

    return QeReportCertificationData(
        qe_report=qe_report_raw,
        qe_report_parsed=qe_report_parsed,
        qe_report_signature=qe_report_signature,
        qe_auth_data=qe_auth_data,
        pck_cert_chain_data=pck_cert_chain_data,
    ), offset


def _parse_certification_data(data: bytes) -> tuple[CertificationData, int]:
    """
    Parse certification data from signed data section.

    Can be either:
        - Type 5: Direct PCK cert chain
        - Type 6: QE report certification data (contains nested type 5)

    Args:
        data: Raw bytes starting at certification data

    Returns:
        Tuple of (CertificationData, bytes_consumed)

    Raises:
        TdxQuoteParseError: If data is malformed or unsupported type
    """
    if len(data) < 6:  # 2 bytes type + 4 bytes size
        raise TdxQuoteParseError("Certification data too short for header")

    cert_type = struct.unpack_from("<H", data, 0)[0]
    cert_data_size = struct.unpack_from("<I", data, 2)[0]
    header_size = 6

    if len(data) < header_size + cert_data_size:
        raise TdxQuoteParseError(
            f"Certification data truncated: have {len(data)} bytes, "
            f"need {header_size + cert_data_size}"
        )

    cert_data_raw = data[header_size:header_size + cert_data_size]

    if cert_type == CERT_DATA_TYPE_PCK_CERT_CHAIN:
        # Type 5: Direct PCK cert chain
        pck_data = PckCertChainData(
            cert_type=cert_type,
            cert_data_size=cert_data_size,
            cert_data=cert_data_raw,
        )
        return CertificationData(
            cert_type=cert_type,
            cert_data_size=cert_data_size,
            pck_cert_chain=pck_data,
            qe_report_data=None,
        ), header_size + cert_data_size

    elif cert_type == CERT_DATA_TYPE_QE_REPORT:
        # Type 6: QE report certification data
        qe_report_data, _ = _parse_qe_report_certification_data(cert_data_raw)
        return CertificationData(
            cert_type=cert_type,
            cert_data_size=cert_data_size,
            pck_cert_chain=None,
            qe_report_data=qe_report_data,
        ), header_size + cert_data_size

    else:
        raise TdxQuoteParseError(f"Unsupported certification data type: {cert_type}")


def _parse_signed_data(data: bytes) -> SignedData:
    """
    Parse the signed data section of the quote.

    Structure:
        - Signature: 64 bytes (ECDSA R || S)
        - Attestation Key: 64 bytes (raw P-256 public key)
        - Certification Data: variable

    Args:
        data: Raw bytes of signed data section

    Returns:
        Parsed SignedData

    Raises:
        TdxQuoteParseError: If data is malformed
    """
    min_size = SIGNATURE_SIZE + ATTESTATION_KEY_SIZE + 6  # + cert header
    if len(data) < min_size:
        raise TdxQuoteParseError(
            f"Signed data too short: {len(data)} bytes, minimum {min_size}"
        )

    signature = data[SIGNED_DATA_SIGNATURE_START:SIGNED_DATA_SIGNATURE_END]
    attestation_key = data[SIGNED_DATA_AK_START:SIGNED_DATA_AK_END]

    certification_data, _ = _parse_certification_data(data[SIGNED_DATA_CERT_DATA_START:])

    return SignedData(
        signature=signature,
        attestation_key=attestation_key,
        certification_data=certification_data,
    )


def _validate_header(header: TdxHeader) -> None:
    """
    Validate TDX quote header fields.

    Args:
        header: Parsed header to validate

    Raises:
        TdxQuoteParseError: If validation fails
    """
    if header.version == QUOTE_VERSION_V5:
        raise TdxQuoteParseError(
            "TDX QuoteV5 is not supported. Only QuoteV4 is implemented."
        )

    if header.version != QUOTE_VERSION_V4:
        raise TdxQuoteParseError(
            f"Unsupported quote version: {header.version}. Expected {QUOTE_VERSION_V4}."
        )

    if header.attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA_P256:
        raise TdxQuoteParseError(
            f"Unsupported attestation key type: {header.attestation_key_type}. "
            f"Expected {ATTESTATION_KEY_TYPE_ECDSA_P256} (ECDSA-P256)."
        )

    if header.tee_type != TEE_TDX:
        raise TdxQuoteParseError(
            f"Invalid TEE type: 0x{header.tee_type:x}. Expected 0x{TEE_TDX:x} (TDX)."
        )


def parse_quote(data: bytes) -> QuoteV4:
    """
    Parse a TDX attestation quote from raw bytes.

    This is the main entry point for TDX quote parsing. It handles QuoteV4
    format and explicitly rejects QuoteV5.

    Args:
        data: Raw quote bytes (typically from base64-decoded, gzip-decompressed
              attestation document)

    Returns:
        Parsed QuoteV4 structure

    Raises:
        TdxQuoteParseError: If parsing fails or quote format is unsupported

    Example:
        >>> raw_quote = base64.b64decode(attestation_doc)
        >>> decompressed = gzip.decompress(raw_quote)
        >>> quote = parse_quote(decompressed)
        >>> measurements = quote.get_measurements()
    """
    if len(data) < QUOTE_MIN_SIZE:
        raise TdxQuoteParseError(
            f"Quote too short: {len(data)} bytes, minimum {QUOTE_MIN_SIZE}"
        )

    # Parse header first to check version
    header = _parse_header(data[QUOTE_HEADER_START:QUOTE_HEADER_END])
    _validate_header(header)

    # Parse TD quote body
    td_quote_body = _parse_td_quote_body(data[QUOTE_BODY_START:QUOTE_BODY_END])

    # Get signed data size and parse signed data
    signed_data_size = struct.unpack_from(
        "<I", data, QUOTE_SIGNED_DATA_SIZE_START
    )[0]

    signed_data_end = QUOTE_SIGNED_DATA_START + signed_data_size
    if len(data) < signed_data_end:
        raise TdxQuoteParseError(
            f"Quote truncated: signed data size is {signed_data_size}, "
            f"but only {len(data) - QUOTE_SIGNED_DATA_START} bytes available"
        )

    signed_data = _parse_signed_data(
        data[QUOTE_SIGNED_DATA_START:signed_data_end]
    )

    # Capture any extra bytes after signed data
    extra_bytes = data[signed_data_end:] if len(data) > signed_data_end else b""

    return QuoteV4(
        header=header,
        td_quote_body=td_quote_body,
        signed_data_size=signed_data_size,
        signed_data=signed_data,
        extra_bytes=extra_bytes,
    )
