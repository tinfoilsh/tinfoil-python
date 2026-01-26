"""
Unit tests for TDX quote parsing (abi_tdx.py).
"""

import pytest
import struct

from tinfoil.attestation.abi_tdx import (
    # Constants
    QUOTE_MIN_SIZE,
    QUOTE_VERSION_V4,
    QUOTE_VERSION_V5,
    TEE_TDX,
    ATTESTATION_KEY_TYPE_ECDSA_P256,
    INTEL_QE_VENDOR_ID,
    HEADER_SIZE,
    TD_QUOTE_BODY_SIZE,
    CERT_DATA_TYPE_PCK_CERT_CHAIN,
    CERT_DATA_TYPE_QE_REPORT,
    QE_REPORT_SIZE,
    # Dataclasses
    TdxHeader,
    TdQuoteBody,
    QeReport,
    SignedData,
    QuoteV4,
    CertificationData,
    PckCertChainData,
    QeReportCertificationData,
    # Parsing functions
    parse_quote,
    TdxQuoteParseError,
    _parse_header,
    _parse_td_quote_body,
    _parse_qe_report,
)


# =============================================================================
# Test Fixtures - Synthetic Quote Generation
# =============================================================================

def build_header(
    version: int = QUOTE_VERSION_V4,
    attestation_key_type: int = ATTESTATION_KEY_TYPE_ECDSA_P256,
    tee_type: int = TEE_TDX,
    reserved: bytes = b'\x00\x00\x00\x00',
    qe_vendor_id: bytes = INTEL_QE_VENDOR_ID,
    user_data: bytes = b'\x00' * 20,
) -> bytes:
    """Build a synthetic TDX quote header (48 bytes).

    Note: Bytes 8-11 are reserved. Some older specs labeled these as
    QE_SVN/PCE_SVN, but they are always zero in actual quotes. The real
    SVN values come from PCK certificate extensions and QE Report.
    """
    header = b''
    header += struct.pack('<H', version)
    header += struct.pack('<H', attestation_key_type)
    header += struct.pack('<I', tee_type)
    header += reserved[:4].ljust(4, b'\x00')
    header += qe_vendor_id[:16].ljust(16, b'\x00')
    header += user_data[:20].ljust(20, b'\x00')
    assert len(header) == HEADER_SIZE
    return header


def build_td_quote_body(
    tee_tcb_svn: bytes = b'\x03' + b'\x00' * 15,
    mr_seam: bytes = b'\xaa' * 48,
    mr_signer_seam: bytes = b'\x00' * 48,
    seam_attributes: bytes = b'\x00' * 8,
    td_attributes: bytes = b'\x00\x00\x00\x10\x00\x00\x00\x00',
    xfam: bytes = b'\xe7\x02\x06\x00\x00\x00\x00\x00',
    mr_td: bytes = b'\x11' * 48,
    mr_config_id: bytes = b'\x00' * 48,
    mr_owner: bytes = b'\x00' * 48,
    mr_owner_config: bytes = b'\x00' * 48,
    rtmr0: bytes = b'\x22' * 48,
    rtmr1: bytes = b'\x33' * 48,
    rtmr2: bytes = b'\x44' * 48,
    rtmr3: bytes = b'\x00' * 48,
    report_data: bytes = b'\xab' * 32 + b'\xcd' * 32,
) -> bytes:
    """Build a synthetic TD quote body (584 bytes)."""
    body = b''
    body += tee_tcb_svn[:16].ljust(16, b'\x00')
    body += mr_seam[:48].ljust(48, b'\x00')
    body += mr_signer_seam[:48].ljust(48, b'\x00')
    body += seam_attributes[:8].ljust(8, b'\x00')
    body += td_attributes[:8].ljust(8, b'\x00')
    body += xfam[:8].ljust(8, b'\x00')
    body += mr_td[:48].ljust(48, b'\x00')
    body += mr_config_id[:48].ljust(48, b'\x00')
    body += mr_owner[:48].ljust(48, b'\x00')
    body += mr_owner_config[:48].ljust(48, b'\x00')
    body += rtmr0[:48].ljust(48, b'\x00')
    body += rtmr1[:48].ljust(48, b'\x00')
    body += rtmr2[:48].ljust(48, b'\x00')
    body += rtmr3[:48].ljust(48, b'\x00')
    body += report_data[:64].ljust(64, b'\x00')
    assert len(body) == TD_QUOTE_BODY_SIZE
    return body


def build_qe_report(
    cpu_svn: bytes = b'\x00' * 16,
    misc_select: int = 0,
    attributes: bytes = b'\x00' * 16,
    mr_enclave: bytes = b'\xee' * 32,
    mr_signer: bytes = b'\xff' * 32,
    isv_prod_id: int = 1,
    isv_svn: int = 2,
    report_data: bytes = b'\x00' * 64,
) -> bytes:
    """Build a synthetic QE report (384 bytes)."""
    report = b''
    report += cpu_svn[:16].ljust(16, b'\x00')  # 0x00-0x10
    report += struct.pack('<I', misc_select)   # 0x10-0x14
    report += b'\x00' * 28                      # 0x14-0x30 reserved
    report += attributes[:16].ljust(16, b'\x00')  # 0x30-0x40
    report += mr_enclave[:32].ljust(32, b'\x00')  # 0x40-0x60
    report += b'\x00' * 32                      # 0x60-0x80 reserved
    report += mr_signer[:32].ljust(32, b'\x00')   # 0x80-0xA0
    report += b'\x00' * 96                      # 0xA0-0x100 reserved
    report += struct.pack('<H', isv_prod_id)   # 0x100-0x102
    report += struct.pack('<H', isv_svn)       # 0x102-0x104
    report += b'\x00' * 60                      # 0x104-0x140 reserved
    report += report_data[:64].ljust(64, b'\x00')  # 0x140-0x180
    assert len(report) == QE_REPORT_SIZE
    return report


def build_pck_cert_chain(cert_pem: bytes = b'-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----') -> bytes:
    """Build PCK cert chain data (type 5)."""
    return struct.pack('<H', CERT_DATA_TYPE_PCK_CERT_CHAIN) + struct.pack('<I', len(cert_pem)) + cert_pem


def build_signed_data(
    signature: bytes = b'\x55' * 64,
    attestation_key: bytes = b'\x66' * 64,
    qe_report: bytes | None = None,
    qe_report_signature: bytes = b'\x77' * 64,
    qe_auth_data: bytes = b'\x88' * 32,
    cert_pem: bytes = b'-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
) -> bytes:
    """Build signed data with type 6 (QE report certification data)."""
    if qe_report is None:
        qe_report = build_qe_report()

    # QE report certification data content
    qe_cert_content = qe_report + qe_report_signature + struct.pack('<H', len(qe_auth_data)) + qe_auth_data + build_pck_cert_chain(cert_pem)

    # Outer certification data (type 6)
    cert_data = struct.pack('<H', CERT_DATA_TYPE_QE_REPORT) + struct.pack('<I', len(qe_cert_content)) + qe_cert_content

    return signature + attestation_key + cert_data


def build_quote(
    header: bytes | None = None,
    body: bytes | None = None,
    signed_data: bytes | None = None,
) -> bytes:
    """Build a complete synthetic TDX quote."""
    if header is None:
        header = build_header()
    if body is None:
        body = build_td_quote_body()
    if signed_data is None:
        signed_data = build_signed_data()

    return header + body + struct.pack('<I', len(signed_data)) + signed_data


# =============================================================================
# Header Parsing Tests
# =============================================================================

class TestParseHeader:
    """Test TDX header parsing."""

    def test_parse_valid_header(self):
        """Test parsing a valid TDX header."""
        header_bytes = build_header()
        header = _parse_header(header_bytes)

        assert header.version == QUOTE_VERSION_V4
        assert header.attestation_key_type == ATTESTATION_KEY_TYPE_ECDSA_P256
        assert header.tee_type == TEE_TDX
        assert header.reserved == b'\x00\x00\x00\x00'
        assert header.qe_vendor_id == INTEL_QE_VENDOR_ID

    def test_parse_header_custom_values(self):
        """Test parsing header with custom values."""
        custom_vendor = b'\x01\x02\x03\x04' + b'\x00' * 12
        custom_user_data = b'custom_data_here' + b'\x00' * 4
        custom_reserved = b'\xab\xcd\xef\x12'

        header_bytes = build_header(
            reserved=custom_reserved,
            qe_vendor_id=custom_vendor,
            user_data=custom_user_data,
        )
        header = _parse_header(header_bytes)

        assert header.reserved == custom_reserved
        assert header.qe_vendor_id == custom_vendor
        assert header.user_data == custom_user_data

    def test_parse_header_too_short(self):
        """Test that short header raises error."""
        short_header = b'\x00' * (HEADER_SIZE - 1)

        with pytest.raises(TdxQuoteParseError, match="Header too short"):
            _parse_header(short_header)

    def test_header_str_representation(self):
        """Test TdxHeader string representation."""
        header = _parse_header(build_header())
        str_repr = str(header)

        assert "version=4" in str_repr
        assert "tee_type=0x81" in str_repr


# =============================================================================
# TD Quote Body Parsing Tests
# =============================================================================

class TestParseTdQuoteBody:
    """Test TD quote body parsing."""

    def test_parse_valid_body(self):
        """Test parsing a valid TD quote body."""
        body_bytes = build_td_quote_body()
        body = _parse_td_quote_body(body_bytes)

        assert body.mr_td == b'\x11' * 48
        assert body.rtmrs[0] == b'\x22' * 48  # RTMR0
        assert body.rtmrs[1] == b'\x33' * 48  # RTMR1
        assert body.rtmrs[2] == b'\x44' * 48  # RTMR2
        assert body.rtmrs[3] == b'\x00' * 48  # RTMR3
        assert body.mr_seam == b'\xaa' * 48
        assert len(body.report_data) == 64

    def test_parse_body_custom_measurements(self):
        """Test parsing body with custom measurements."""
        custom_mr_td = bytes.fromhex('a1' * 48)
        custom_rtmr1 = bytes.fromhex('b2' * 48)
        custom_rtmr2 = bytes.fromhex('c3' * 48)

        body_bytes = build_td_quote_body(
            mr_td=custom_mr_td,
            rtmr1=custom_rtmr1,
            rtmr2=custom_rtmr2,
        )
        body = _parse_td_quote_body(body_bytes)

        assert body.mr_td == custom_mr_td
        assert body.rtmrs[1] == custom_rtmr1
        assert body.rtmrs[2] == custom_rtmr2

    def test_parse_body_too_short(self):
        """Test that short body raises error."""
        short_body = b'\x00' * (TD_QUOTE_BODY_SIZE - 1)

        with pytest.raises(TdxQuoteParseError, match="TD quote body too short"):
            _parse_td_quote_body(short_body)

    def test_get_measurements(self):
        """Test get_measurements returns correct order."""
        body_bytes = build_td_quote_body()
        body = _parse_td_quote_body(body_bytes)

        measurements = body.get_measurements()

        assert len(measurements) == 5
        assert measurements[0] == body.mr_td      # MRTD
        assert measurements[1] == body.rtmrs[0]   # RTMR0
        assert measurements[2] == body.rtmrs[1]   # RTMR1
        assert measurements[3] == body.rtmrs[2]   # RTMR2
        assert measurements[4] == body.rtmrs[3]   # RTMR3

    def test_body_str_representation(self):
        """Test TdQuoteBody string representation."""
        body = _parse_td_quote_body(build_td_quote_body())
        str_repr = str(body)

        assert "mr_td=" in str_repr
        assert "rtmr0=" in str_repr
        assert "rtmr1=" in str_repr


# =============================================================================
# QE Report Parsing Tests
# =============================================================================

class TestParseQeReport:
    """Test QE report parsing."""

    def test_parse_valid_qe_report(self):
        """Test parsing a valid QE report."""
        report_bytes = build_qe_report()
        report = _parse_qe_report(report_bytes)

        assert report.mr_enclave == b'\xee' * 32
        assert report.mr_signer == b'\xff' * 32
        assert report.isv_prod_id == 1
        assert report.isv_svn == 2
        assert len(report.report_data) == 64

    def test_parse_qe_report_custom_values(self):
        """Test parsing QE report with custom values."""
        custom_enclave = bytes.fromhex('ab' * 32)
        custom_signer = bytes.fromhex('cd' * 32)

        report_bytes = build_qe_report(
            mr_enclave=custom_enclave,
            mr_signer=custom_signer,
            isv_prod_id=100,
            isv_svn=50,
        )
        report = _parse_qe_report(report_bytes)

        assert report.mr_enclave == custom_enclave
        assert report.mr_signer == custom_signer
        assert report.isv_prod_id == 100
        assert report.isv_svn == 50

    def test_parse_qe_report_too_short(self):
        """Test that short QE report raises error."""
        short_report = b'\x00' * (QE_REPORT_SIZE - 1)

        with pytest.raises(TdxQuoteParseError, match="QE report too short"):
            _parse_qe_report(short_report)


# =============================================================================
# Full Quote Parsing Tests
# =============================================================================

class TestParseQuote:
    """Test complete quote parsing."""

    def test_parse_valid_quote(self):
        """Test parsing a valid quote with type 6 certification data."""
        quote_bytes = build_quote()
        quote = parse_quote(quote_bytes)

        assert isinstance(quote, QuoteV4)
        assert quote.header.version == QUOTE_VERSION_V4
        assert quote.header.tee_type == TEE_TDX
        assert len(quote.get_measurements()) == 5
        assert quote.signed_data.certification_data.cert_type == CERT_DATA_TYPE_QE_REPORT

    def test_parse_quote_extracts_measurements(self):
        """Test that measurements are correctly extracted."""
        mr_td = bytes.fromhex('11' * 48)
        rtmr0 = bytes.fromhex('22' * 48)
        rtmr1 = bytes.fromhex('33' * 48)
        rtmr2 = bytes.fromhex('44' * 48)
        rtmr3 = bytes.fromhex('00' * 48)

        body = build_td_quote_body(
            mr_td=mr_td,
            rtmr0=rtmr0,
            rtmr1=rtmr1,
            rtmr2=rtmr2,
            rtmr3=rtmr3,
        )
        quote_bytes = build_quote(body=body)
        quote = parse_quote(quote_bytes)

        measurements = quote.get_measurements()
        assert measurements[0] == mr_td
        assert measurements[1] == rtmr0
        assert measurements[2] == rtmr1
        assert measurements[3] == rtmr2
        assert measurements[4] == rtmr3

    def test_parse_quote_extracts_report_data(self):
        """Test that report data is correctly extracted."""
        report_data = b'\xde\xad' * 32
        body = build_td_quote_body(report_data=report_data)
        quote_bytes = build_quote(body=body)
        quote = parse_quote(quote_bytes)

        assert quote.get_report_data() == report_data

    def test_parse_quote_too_short(self):
        """Test that short quote raises error."""
        short_quote = b'\x00' * (QUOTE_MIN_SIZE - 1)

        with pytest.raises(TdxQuoteParseError, match="Quote too short"):
            parse_quote(short_quote)

    def test_parse_quote_extra_bytes(self):
        """Test that extra bytes after signed data are captured."""
        quote_bytes = build_quote() + b'\xde\xad\xbe\xef'
        quote = parse_quote(quote_bytes)

        assert quote.extra_bytes == b'\xde\xad\xbe\xef'


# =============================================================================
# Version Validation Tests
# =============================================================================

class TestVersionValidation:
    """Test quote version validation."""

    def test_reject_v5_quote(self):
        """Test that V5 quotes are rejected with clear error."""
        header = build_header(version=QUOTE_VERSION_V5)
        quote_bytes = build_quote(header=header)

        with pytest.raises(TdxQuoteParseError, match="QuoteV5 is not supported"):
            parse_quote(quote_bytes)

    def test_reject_unknown_version(self):
        """Test that unknown versions are rejected."""
        header = build_header(version=99)
        quote_bytes = build_quote(header=header)

        with pytest.raises(TdxQuoteParseError, match="Unsupported quote version"):
            parse_quote(quote_bytes)

    def test_reject_wrong_tee_type(self):
        """Test that non-TDX TEE types are rejected."""
        header = build_header(tee_type=0x00)  # SGX, not TDX
        quote_bytes = build_quote(header=header)

        with pytest.raises(TdxQuoteParseError, match="Invalid TEE type"):
            parse_quote(quote_bytes)

    def test_reject_wrong_attestation_key_type(self):
        """Test that unsupported attestation key types are rejected."""
        header = build_header(attestation_key_type=99)
        quote_bytes = build_quote(header=header)

        with pytest.raises(TdxQuoteParseError, match="Unsupported attestation key type"):
            parse_quote(quote_bytes)


# =============================================================================
# Certification Data Tests
# =============================================================================

class TestCertificationData:
    """Test certification data parsing."""

    def test_parse_qe_report_cert_data(self):
        """Test parsing type 6 (QE report certification data)."""
        quote_bytes = build_quote()
        quote = parse_quote(quote_bytes)

        cert_data = quote.signed_data.certification_data
        assert cert_data.cert_type == CERT_DATA_TYPE_QE_REPORT
        assert cert_data.qe_report_data is not None
        assert cert_data.qe_report_data.qe_report_parsed is not None

    def test_nested_pck_chain(self):
        """Test that certification data contains nested PCK cert chain."""
        cert_pem = b'-----BEGIN CERTIFICATE-----\nNested\n-----END CERTIFICATE-----'
        signed_data = build_signed_data(cert_pem=cert_pem)
        quote_bytes = build_quote(signed_data=signed_data)
        quote = parse_quote(quote_bytes)

        qe_data = quote.signed_data.certification_data.qe_report_data
        assert qe_data.pck_cert_chain_data is not None
        assert qe_data.pck_cert_chain_data.cert_data == cert_pem

    def test_qe_report_fields(self):
        """Test that QE report fields are correctly extracted."""
        mr_enclave = bytes.fromhex('ab' * 32)
        mr_signer = bytes.fromhex('cd' * 32)
        qe_report = build_qe_report(mr_enclave=mr_enclave, mr_signer=mr_signer, isv_prod_id=42)
        signed_data = build_signed_data(qe_report=qe_report)
        quote_bytes = build_quote(signed_data=signed_data)
        quote = parse_quote(quote_bytes)

        qe = quote.signed_data.certification_data.qe_report_data.qe_report_parsed
        assert qe.mr_enclave == mr_enclave
        assert qe.mr_signer == mr_signer
        assert qe.isv_prod_id == 42


# =============================================================================
# Signed Data Tests
# =============================================================================

class TestSignedData:
    """Test signed data parsing."""

    def test_extract_signature(self):
        """Test signature extraction."""
        signature = bytes.fromhex('ab' * 64)
        signed_data = build_signed_data(signature=signature)
        quote_bytes = build_quote(signed_data=signed_data)
        quote = parse_quote(quote_bytes)

        assert quote.signed_data.signature == signature

    def test_extract_attestation_key(self):
        """Test attestation key extraction."""
        attestation_key = bytes.fromhex('cd' * 64)
        signed_data = build_signed_data(attestation_key=attestation_key)
        quote_bytes = build_quote(signed_data=signed_data)
        quote = parse_quote(quote_bytes)

        assert quote.signed_data.attestation_key == attestation_key

    def test_signed_data_str_representation(self):
        """Test SignedData string representation."""
        quote = parse_quote(build_quote())
        str_repr = str(quote.signed_data)

        assert "signature=" in str_repr
        assert "attestation_key=" in str_repr


# =============================================================================
# Constants Tests
# =============================================================================

class TestConstants:
    """Test that constants have expected values."""

    def test_intel_qe_vendor_id(self):
        """Test Intel QE vendor ID constant."""
        # 939a7233-f79c-4ca9-940a-0db3957f0607
        expected = bytes.fromhex('939a7233f79c4ca9940a0db3957f0607')
        assert INTEL_QE_VENDOR_ID == expected

    def test_tee_tdx_constant(self):
        """Test TEE TDX constant."""
        assert TEE_TDX == 0x81

    def test_size_constants(self):
        """Test size constants are correct."""
        assert HEADER_SIZE == 48
        assert TD_QUOTE_BODY_SIZE == 584
        assert QE_REPORT_SIZE == 384


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
