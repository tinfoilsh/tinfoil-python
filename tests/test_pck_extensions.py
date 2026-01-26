"""
Unit tests for PCK certificate extension parsing.
"""

import pytest

from tinfoil.attestation.pck_extensions import (
    PckExtensions,
    PckCertTCB,
    PckExtensionError,
    OID_SGX_EXTENSION,
    OID_FMSPC,
    OID_PCEID,
    OID_PPID,
    OID_TCB,
    FMSPC_SIZE,
    PCEID_SIZE,
    PPID_SIZE,
    TCB_COMPONENTS_COUNT,
    _decode_oid,
    _parse_asn1_length,
    _parse_asn1_sequence,
    _extract_octet_string,
)


# =============================================================================
# Test OID Constants
# =============================================================================

class TestOidConstants:
    """Test Intel SGX OID constants."""

    def test_sgx_extension_oid(self):
        """Test SGX extension OID value."""
        assert OID_SGX_EXTENSION.dotted_string == "1.2.840.113741.1.13.1"

    def test_fmspc_oid(self):
        """Test FMSPC OID value."""
        assert OID_FMSPC.dotted_string == "1.2.840.113741.1.13.1.4"

    def test_pceid_oid(self):
        """Test PCEID OID value."""
        assert OID_PCEID.dotted_string == "1.2.840.113741.1.13.1.3"

    def test_ppid_oid(self):
        """Test PPID OID value."""
        assert OID_PPID.dotted_string == "1.2.840.113741.1.13.1.1"

    def test_tcb_oid(self):
        """Test TCB OID value."""
        assert OID_TCB.dotted_string == "1.2.840.113741.1.13.1.2"


# =============================================================================
# Test Size Constants
# =============================================================================

class TestSizeConstants:
    """Test size constants."""

    def test_fmspc_size(self):
        """Test FMSPC is 6 bytes."""
        assert FMSPC_SIZE == 6

    def test_pceid_size(self):
        """Test PCEID is 2 bytes."""
        assert PCEID_SIZE == 2

    def test_ppid_size(self):
        """Test PPID is 16 bytes."""
        assert PPID_SIZE == 16

    def test_tcb_components_count(self):
        """Test TCB has 16 components."""
        assert TCB_COMPONENTS_COUNT == 16


# =============================================================================
# Test ASN.1 Helper Functions
# =============================================================================

class TestDecodeOid:
    """Test OID decoding from bytes."""

    def test_decode_simple_oid(self):
        """Test decoding a simple OID."""
        # OID 2.5.4.3 (commonName) encoded as bytes
        oid_bytes = bytes([0x55, 0x04, 0x03])
        result = _decode_oid(oid_bytes)
        assert result == "2.5.4.3"

    def test_decode_long_oid(self):
        """Test decoding OID with multi-byte components."""
        # OID 1.2.840.113741 requires multi-byte encoding for 840 and 113741
        # First byte: 1*40 + 2 = 42 = 0x2a
        # 840 = 0x348 -> encoded as 0x86, 0x48
        # 113741 = 0x1BC4D -> encoded as 0x86, 0xF8, 0x4D
        oid_bytes = bytes([0x2a, 0x86, 0x48, 0x86, 0xF8, 0x4D])
        result = _decode_oid(oid_bytes)
        assert result == "1.2.840.113741"


class TestParseAsn1Length:
    """Test ASN.1 length field parsing."""

    def test_short_form_length(self):
        """Test short form length (< 128)."""
        data = bytes([0x10, 0xFF, 0xFF])  # length = 16
        length, pos = _parse_asn1_length(data, 0)
        assert length == 16
        assert pos == 1

    def test_long_form_length_one_byte(self):
        """Test long form length with one length byte."""
        data = bytes([0x81, 0x80, 0xFF])  # length = 128
        length, pos = _parse_asn1_length(data, 0)
        assert length == 128
        assert pos == 2

    def test_long_form_length_two_bytes(self):
        """Test long form length with two length bytes."""
        data = bytes([0x82, 0x01, 0x00, 0xFF])  # length = 256
        length, pos = _parse_asn1_length(data, 0)
        assert length == 256
        assert pos == 3


class TestExtractOctetString:
    """Test OCTET STRING extraction."""

    def test_extract_octet_string_with_tag(self):
        """Test extracting OCTET STRING with ASN.1 tag."""
        # OCTET STRING tag (0x04), length 6, then 6 bytes of data
        value = bytes([0x04, 0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        result = _extract_octet_string(value, "TEST", 6)
        assert result == "aabbccddeeff"

    def test_extract_octet_string_wrong_size(self):
        """Test that wrong size raises error."""
        value = bytes([0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD])
        with pytest.raises(PckExtensionError, match="wrong size"):
            _extract_octet_string(value, "TEST", 6)


# =============================================================================
# Test Data Classes
# =============================================================================

class TestPckCertTCB:
    """Test PckCertTCB dataclass."""

    def test_create_tcb(self):
        """Test creating PckCertTCB."""
        tcb = PckCertTCB(
            pce_svn=13,
            cpu_svn=bytes(16),
            tcb_components=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        assert tcb.pce_svn == 13
        assert len(tcb.cpu_svn) == 16
        assert len(tcb.tcb_components) == 16

    def test_tcb_str(self):
        """Test string representation."""
        tcb = PckCertTCB(
            pce_svn=13,
            cpu_svn=bytes([0xAB] * 16),
            tcb_components=[0] * 16,
        )
        s = str(tcb)
        assert "pce_svn=13" in s
        assert "abab" in s.lower()


class TestPckExtensions:
    """Test PckExtensions dataclass."""

    def test_create_extensions(self):
        """Test creating PckExtensions."""
        tcb = PckCertTCB(
            pce_svn=13,
            cpu_svn=bytes(16),
            tcb_components=[0] * 16,
        )
        ext = PckExtensions(
            ppid="00112233445566778899aabbccddeeff",
            tcb=tcb,
            pceid="0000",
            fmspc="00606a000000",
        )
        assert ext.fmspc == "00606a000000"
        assert ext.pceid == "0000"
        assert len(ext.ppid) == 32  # 16 bytes hex

    def test_extensions_str(self):
        """Test string representation."""
        tcb = PckCertTCB(
            pce_svn=13,
            cpu_svn=bytes(16),
            tcb_components=[0] * 16,
        )
        ext = PckExtensions(
            ppid="00112233445566778899aabbccddeeff",
            tcb=tcb,
            pceid="0000",
            fmspc="00606a000000",
        )
        s = str(ext)
        assert "fmspc=00606a000000" in s
        assert "pceid=0000" in s


# =============================================================================
# Test ASN.1 Sequence Parsing
# =============================================================================

class TestParseAsn1Sequence:
    """Test ASN.1 SEQUENCE parsing."""

    def test_parse_simple_sequence(self):
        """Test parsing a simple SEQUENCE with one OID-value pair."""
        # SEQUENCE { OID(2.5.4.3), OCTET STRING "test" }
        data = bytes([
            0x30, 0x0B,  # SEQUENCE, length 11
            0x30, 0x09,  # Inner SEQUENCE, length 9
            0x06, 0x03, 0x55, 0x04, 0x03,  # OID 2.5.4.3
            0x04, 0x02, 0xAA, 0xBB,  # OCTET STRING
        ])
        result = _parse_asn1_sequence(data)
        assert len(result) == 1
        oid_bytes, value = result[0]
        assert _decode_oid(oid_bytes) == "2.5.4.3"

    def test_parse_empty_sequence(self):
        """Test parsing an empty SEQUENCE."""
        data = bytes([0x30, 0x00])  # Empty SEQUENCE
        result = _parse_asn1_sequence(data)
        assert len(result) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
