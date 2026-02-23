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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
