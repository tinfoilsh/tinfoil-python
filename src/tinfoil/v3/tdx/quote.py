"""Intel TDX quote v4 ABI parsing, a 1:1 port of go-tdx-guest/abi (the subset
QuoteToProto/CheckQuoteV4 exercise for quote v4). Every condition mirrors the
library's errors. All errors are ValueError; the authenticate wrapper assigns
the rejection layer."""

from __future__ import annotations

from dataclasses import dataclass

# Sizes and offsets (abi.go constants).
QUOTE_MIN_SIZE = 0x3FC
QUOTE_VERSION = 4
ATTESTATION_KEY_TYPE = 2  # ECDSA-256-with-P-256 curve
TEE_TDX = 0x00000081

_QUOTE_HEADER_END = 0x30
_QUOTE_BODY_END = 0x278
_QUOTE_SIGNED_DATA_SIZE_END = 0x27C
_QE_REPORT_SIZE = 0x180
_SIGNATURE_SIZE = 0x40
_QE_REPORT_CERTIFICATION_DATA_TYPE = 0x6
_PCK_REPORT_CERTIFICATION_DATA_TYPE = 0x5
_RTMRS_COUNT = 4
RTMR_SIZE = 0x30


@dataclass
class Header:
    version: int
    attestation_key_type: int
    tee_type: int
    qe_svn: bytes  # reserved bytes 10-12 in quote v4
    pce_svn: bytes  # reserved bytes 8-10 in quote v4
    qe_vendor_id: bytes
    user_data: bytes


@dataclass
class TDQuoteBody:
    tee_tcb_svn: bytes
    mr_seam: bytes
    mr_signer_seam: bytes
    seam_attributes: bytes
    td_attributes: bytes
    xfam: bytes
    mr_td: bytes
    mr_config_id: bytes
    mr_owner: bytes
    mr_owner_config: bytes
    rtmrs: list[bytes]
    report_data: bytes


@dataclass
class EnclaveReport:
    cpu_svn: bytes
    misc_select: int
    attributes: bytes
    mr_enclave: bytes
    mr_signer: bytes
    isv_prod_id: int
    isv_svn: int
    report_data: bytes


@dataclass
class QeAuthData:
    parsed_data_size: int
    data: bytes


@dataclass
class PCKCertificateChainData:
    certificate_data_type: int
    size: int
    pck_cert_chain: bytes


@dataclass
class QEReportCertificationData:
    qe_report: EnclaveReport
    qe_report_raw: bytes  # exact 384 signed bytes (EnclaveReportToAbiBytes)
    qe_report_signature: bytes
    qe_auth_data: QeAuthData
    pck_certificate_chain_data: PCKCertificateChainData


@dataclass
class CertificationData:
    certificate_data_type: int
    size: int
    qe_report_certification_data: QEReportCertificationData


@dataclass
class Ecdsa256BitQuoteV4AuthData:
    signature: bytes
    ecdsa_attestation_key: bytes
    certification_data: CertificationData


@dataclass
class QuoteV4:
    header: Header
    td_quote_body: TDQuoteBody
    signed_data_size: int
    signed_data: Ecdsa256BitQuoteV4AuthData
    extra_bytes: bytes
    header_and_body: bytes  # exact signed region raw[0:0x278]


def _slice(b: bytes, start: int, end: int, what: str) -> bytes:
    if end > len(b) or start > end:
        raise ValueError(f"{what}: quote data is truncated")
    return b[start:end]


def _u16le(b: bytes, off: int, what: str) -> int:
    s = _slice(b, off, off + 2, what)
    return s[0] | (s[1] << 8)


def _u32le(b: bytes, off: int, what: str) -> int:
    s = _slice(b, off, off + 4, what)
    return s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24)


def _header_to_proto(data: bytes) -> Header:
    header = Header(
        version=_u16le(data, 0x00, "header version"),
        attestation_key_type=_u16le(data, 0x02, "attestation key type"),
        tee_type=_u32le(data, 0x04, "tee type"),
        pce_svn=data[0x08:0x0A],
        qe_svn=data[0x0A:0x0C],
        qe_vendor_id=data[0x0C:0x1C],
        user_data=data[0x1C:0x30],
    )
    _check_header(header)
    return header


def _check_header(header: Header) -> None:
    if header.version != QUOTE_VERSION:
        raise ValueError(f"parsing header failed: version {header.version} not supported")
    if header.attestation_key_type != ATTESTATION_KEY_TYPE:
        raise ValueError("parsing header failed: attestation key type not supported")
    if header.tee_type != TEE_TDX:
        raise ValueError("parsing header failed: TEE type is not TDX")


def _td_quote_body_to_proto(data: bytes) -> TDQuoteBody:
    rtmrs = [
        data[0x148 + i * RTMR_SIZE : 0x148 + (i + 1) * RTMR_SIZE]
        for i in range(_RTMRS_COUNT)
    ]
    return TDQuoteBody(
        tee_tcb_svn=data[0x00:0x10],
        mr_seam=data[0x10:0x40],
        mr_signer_seam=data[0x40:0x70],
        seam_attributes=data[0x70:0x78],
        td_attributes=data[0x78:0x80],
        xfam=data[0x80:0x88],
        mr_td=data[0x88:0xB8],
        mr_config_id=data[0xB8:0xE8],
        mr_owner=data[0xE8:0x118],
        mr_owner_config=data[0x118:0x148],
        rtmrs=rtmrs,
        report_data=data[0x208:0x248],
    )


def _enclave_report_to_proto(data: bytes) -> EnclaveReport:
    return EnclaveReport(
        cpu_svn=data[0x00:0x10],
        misc_select=_u32le(data, 0x10, "QE report miscSelect"),
        attributes=data[0x30:0x40],
        mr_enclave=data[0x40:0x60],
        mr_signer=data[0x80:0xA0],
        isv_prod_id=_u16le(data, 0x100, "QE report isvProdId"),
        isv_svn=_u16le(data, 0x102, "QE report isvSvn"),
        report_data=data[0x140:0x180],
    )


def _qe_auth_data_to_proto(data: bytes) -> tuple[QeAuthData, int]:
    parsed_data_size = _u16le(data, 0x00, "QE AuthData size")
    auth_data_end = 0x02 + parsed_data_size
    return (
        QeAuthData(
            parsed_data_size=parsed_data_size,
            data=_slice(data, 0x02, auth_data_end, "QE AuthData"),
        ),
        auth_data_end,
    )


def _pck_certificate_chain_to_proto(data: bytes) -> PCKCertificateChainData:
    chain = PCKCertificateChainData(
        certificate_data_type=_u16le(data, 0x00, "PCK chain data type"),
        size=_u32le(data, 0x02, "PCK chain size"),
        pck_cert_chain=data[0x06:],
    )
    if chain.certificate_data_type != _PCK_REPORT_CERTIFICATION_DATA_TYPE:
        raise ValueError(
            "parsing PCK certification chain failed: PCK certificate chain data "
            f"type invalid, got {chain.certificate_data_type}, expected "
            f"{_PCK_REPORT_CERTIFICATION_DATA_TYPE}"
        )
    if chain.size != len(chain.pck_cert_chain):
        raise ValueError(
            "parsing PCK certification chain failed: PCK certificate chain size "
            f"is {len(chain.pck_cert_chain)}. Expected size {chain.size}"
        )
    return chain


def _qe_report_certification_data_to_proto(data: bytes) -> QEReportCertificationData:
    qe_report_raw = _slice(data, 0x00, _QE_REPORT_SIZE, "QE report")
    qe_report = _enclave_report_to_proto(qe_report_raw)
    qe_report_signature = _slice(
        data, _QE_REPORT_SIZE, _QE_REPORT_SIZE + _SIGNATURE_SIZE, "QE report signature"
    )
    auth_data, auth_data_end = _qe_auth_data_to_proto(data[0x1C0:])
    pck_certificate_chain_data = _pck_certificate_chain_to_proto(
        data[0x1C0 + auth_data_end :]
    )
    return QEReportCertificationData(
        qe_report=qe_report,
        qe_report_raw=qe_report_raw,
        qe_report_signature=qe_report_signature,
        qe_auth_data=auth_data,
        pck_certificate_chain_data=pck_certificate_chain_data,
    )


def _certification_data_to_proto(data: bytes) -> CertificationData:
    certificate_data_type = _u16le(data, 0x00, "certification data type")
    size = _u32le(data, 0x02, "certification data size")
    raw_certificate_data = data[0x06:]
    if len(raw_certificate_data) != size:
        raise ValueError(
            f"size of certificate data is 0x{len(raw_certificate_data):x}. "
            f"Expected size 0x{size:x}"
        )
    if certificate_data_type != _QE_REPORT_CERTIFICATION_DATA_TYPE:
        raise ValueError(
            "parsing certification data failed: certification data type invalid, "
            f"got {certificate_data_type}, expected {_QE_REPORT_CERTIFICATION_DATA_TYPE}"
        )
    return CertificationData(
        certificate_data_type=certificate_data_type,
        size=size,
        qe_report_certification_data=_qe_report_certification_data_to_proto(
            raw_certificate_data
        ),
    )


def _signed_data_to_proto(data: bytes) -> Ecdsa256BitQuoteV4AuthData:
    return Ecdsa256BitQuoteV4AuthData(
        signature=_slice(data, 0x00, 0x40, "quote signature"),
        ecdsa_attestation_key=_slice(data, 0x40, 0x80, "attestation key"),
        certification_data=_certification_data_to_proto(data[0x80:]),
    )


def quote_to_proto_v4(b: bytes) -> QuoteV4:
    """Parse the Intel ABI little-endian quote v4 byte layout (abi.QuoteToProto
    restricted to v4 — Go's wrapper rejects any other version, which
    determineQuoteFormat surfaces as an unsupported format)."""
    if len(b) < 2:
        raise ValueError(
            "unable to determine quote format since bytes length is less than 2 bytes"
        )
    version = b[0] | (b[1] << 8)
    if version != QUOTE_VERSION:
        raise ValueError("quote format not supported")
    if len(b) < QUOTE_MIN_SIZE:
        raise ValueError(
            f"raw quote size is 0x{len(b):x}, a TDX quote should have size a "
            f"minimum size of 0x{QUOTE_MIN_SIZE:x}"
        )
    header = _header_to_proto(b[:_QUOTE_HEADER_END])
    td_quote_body = _td_quote_body_to_proto(b[_QUOTE_HEADER_END:_QUOTE_BODY_END])
    signed_data_size = _u32le(b, _QUOTE_BODY_END, "signed data size")
    additional_data = b[_QUOTE_SIGNED_DATA_SIZE_END:]
    if len(additional_data) < signed_data_size:
        raise ValueError(
            f"size of signed data is 0x{len(additional_data):x}. Expected minimum "
            f"size of 0x{signed_data_size:x}"
        )
    signed_data = _signed_data_to_proto(additional_data[:signed_data_size])
    extra_bytes = additional_data[signed_data_size:]
    return QuoteV4(
        header=header,
        td_quote_body=td_quote_body,
        signed_data_size=signed_data_size,
        signed_data=signed_data,
        extra_bytes=extra_bytes,
        header_and_body=b[:_QUOTE_BODY_END],
    )
