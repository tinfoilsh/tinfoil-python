"""
PCK Certificate Extension Parsing for Intel TDX attestation.

This module extracts Intel SGX-specific extensions from PCK (Provisioning
Certification Key) certificates. These extensions contain critical information
for TCB (Trusted Computing Base) validation:

- FMSPC: Firmware/Microcode Security Patch Cluster (6 bytes)
- PCEID: PCE ID (2 bytes)
- TCB: TCB components including PCE SVN and CPU SVN

Intel SGX Extension OID hierarchy:
    1.2.840.113741.1.13.1       - SGX Extension (parent)
    1.2.840.113741.1.13.1.1     - PPID
    1.2.840.113741.1.13.1.2     - TCB
    1.2.840.113741.1.13.1.2.1-16 - TCB Components
    1.2.840.113741.1.13.1.2.17  - PCE SVN
    1.2.840.113741.1.13.1.2.18  - CPU SVN
    1.2.840.113741.1.13.1.3     - PCEID
    1.2.840.113741.1.13.1.4     - FMSPC
"""

from contextlib import contextmanager
from dataclasses import dataclass

from cryptography import x509
from pyasn1.codec.der import decoder as der_decoder

# Intel SGX OID base
_INTEL_SGX_OID_BASE = "1.2.840.113741.1.13.1"

# Intel SGX Extension OIDs
OID_SGX_EXTENSION = x509.ObjectIdentifier(_INTEL_SGX_OID_BASE)
OID_PPID = x509.ObjectIdentifier(f"{_INTEL_SGX_OID_BASE}.1")
OID_TCB = x509.ObjectIdentifier(f"{_INTEL_SGX_OID_BASE}.2")
OID_PCEID = x509.ObjectIdentifier(f"{_INTEL_SGX_OID_BASE}.3")
OID_FMSPC = x509.ObjectIdentifier(f"{_INTEL_SGX_OID_BASE}.4")

# TCB sub-OIDs
OID_PCE_SVN = x509.ObjectIdentifier(f"{_INTEL_SGX_OID_BASE}.2.17")
OID_CPU_SVN = x509.ObjectIdentifier(f"{_INTEL_SGX_OID_BASE}.2.18")

# TCB component OID → index mapping (1-indexed OID to 0-indexed array position)
_TCB_COMPONENT_OID_INDEX = {
    f"{_INTEL_SGX_OID_BASE}.2.{i}": i - 1 for i in range(1, 17)
}

# Size constants (match go-tdx-guest/pcs/pcs.go)
PCK_CERT_EXTENSION_COUNT = 6
SGX_EXTENSION_MIN_SIZE = 4
TCB_EXTENSION_SIZE = 18  # 16 components + PCE SVN + CPU SVN
PPID_SIZE = 16
CPU_SVN_SIZE = 16
FMSPC_SIZE = 6
PCEID_SIZE = 2
TCB_COMPONENTS_COUNT = 16


class PckExtensionError(Exception):
    """Raised when PCK certificate extension parsing fails."""
    pass


@contextmanager
def _asn1_errors(label: str):
    """Wrap unexpected ASN.1 exceptions as PckExtensionError."""
    try:
        yield
    except PckExtensionError:
        raise
    except Exception as e:
        raise PckExtensionError(f"Unexpected ASN.1 structure in {label}: {e}") from e


@dataclass
class PckCertTCB:
    """
    TCB (Trusted Computing Base) information from PCK certificate.

    Attributes:
        pce_svn: PCE Security Version Number
        cpu_svn: CPU SVN as raw bytes (16 bytes)
        tcb_components: Individual TCB component SVNs (16 values)
    """
    pce_svn: int
    cpu_svn: bytes  # 16 bytes
    tcb_components: list[int]  # 16 components

    def __str__(self) -> str:
        return (
            f"PckCertTCB(pce_svn={self.pce_svn}, "
            f"cpu_svn={self.cpu_svn.hex()}, "
            f"components={self.tcb_components})"
        )


@dataclass
class PckExtensions:
    """
    Intel SGX extensions extracted from a PCK certificate.

    Attributes:
        ppid: Platform/Product ID as hex string (16 bytes)
        tcb: TCB information
        pceid: PCE ID as hex string (2 bytes)
        fmspc: Firmware/Microcode FMSPC as hex string (6 bytes)
    """
    ppid: str  # 16 bytes hex
    tcb: PckCertTCB
    pceid: str  # 2 bytes hex
    fmspc: str  # 6 bytes hex

    def __str__(self) -> str:
        return (
            f"PckExtensions(fmspc={self.fmspc}, pceid={self.pceid}, "
            f"ppid={self.ppid[:8]}...)"
        )


def extract_pck_extensions(cert: x509.Certificate) -> PckExtensions:
    """
    Extract Intel SGX extensions from a PCK certificate.

    Args:
        cert: PCK leaf certificate from the quote

    Returns:
        PckExtensions containing FMSPC, PCEID, PPID, and TCB info

    Raises:
        PckExtensionError: If required extensions are missing or malformed
    """
    if len(cert.extensions) != PCK_CERT_EXTENSION_COUNT:
        raise PckExtensionError(
            f"PCK certificate has {len(cert.extensions)} extensions, "
            f"expected {PCK_CERT_EXTENSION_COUNT}"
        )

    sgx_ext = None
    for ext in cert.extensions:
        if ext.oid == OID_SGX_EXTENSION:
            sgx_ext = ext
            break

    if sgx_ext is None:
        raise PckExtensionError(
            "PCK certificate does not contain Intel SGX extension "
            f"(OID {OID_SGX_EXTENSION.dotted_string})"
        )

    return _parse_sgx_extension(sgx_ext.value.value)


def _der_decode(data: bytes, label: str = "value"):
    """Decode DER data using pyasn1, wrapping errors as PckExtensionError.

    Checks for leftover bytes after decoding (matches Go's asn1.Unmarshal behavior).
    """
    try:
        result, remainder = der_decoder.decode(data)
    except Exception as e:
        raise PckExtensionError(f"Failed to decode ASN.1 {label}: {e}") from e
    if remainder:
        raise PckExtensionError(
            f"Unexpected leftover bytes after decoding {label}: {len(remainder)} bytes"
        )
    return result


def _octet_hex(component, name: str, expected_size: int) -> str:
    """Extract bytes from a decoded ASN.1 value, validate size, return hex."""
    raw = bytes(component)
    if len(raw) != expected_size:
        raise PckExtensionError(
            f"{name} has wrong size: expected {expected_size}, got {len(raw)}"
        )
    return raw.hex()


def _parse_sgx_extension(raw_value: bytes) -> PckExtensions:
    """Parse the SGX extension: a SEQUENCE OF SEQUENCE(OID, value)."""
    outer_seq = _der_decode(raw_value, "SGX extension")

    if len(outer_seq) < SGX_EXTENSION_MIN_SIZE:
        raise PckExtensionError(
            f"SGX extension has {len(outer_seq)} elements, "
            f"expected at least {SGX_EXTENSION_MIN_SIZE}"
        )

    ppid = None
    tcb = None
    pceid = None
    fmspc = None

    with _asn1_errors("SGX extension"):
        for item in outer_seq:
            if len(item) < 2:
                raise PckExtensionError(
                    f"Malformed SGX extension item: expected at least 2 fields, got {len(item)}"
                )
            oid_str = str(item[0])

            if oid_str == OID_PPID.dotted_string:
                ppid = _octet_hex(item[1], "PPID", PPID_SIZE)
            elif oid_str == OID_TCB.dotted_string:
                tcb = _parse_tcb(item[1])
            elif oid_str == OID_PCEID.dotted_string:
                pceid = _octet_hex(item[1], "PCEID", PCEID_SIZE)
            elif oid_str == OID_FMSPC.dotted_string:
                fmspc = _octet_hex(item[1], "FMSPC", FMSPC_SIZE)

    if fmspc is None:
        raise PckExtensionError("FMSPC not found in PCK certificate")
    if pceid is None:
        raise PckExtensionError("PCEID not found in PCK certificate")
    if ppid is None:
        raise PckExtensionError("PPID not found in PCK certificate")
    if tcb is None:
        raise PckExtensionError("TCB not found in PCK certificate")

    return PckExtensions(ppid=ppid, tcb=tcb, pceid=pceid, fmspc=fmspc)


def _parse_tcb(value_component) -> PckCertTCB:
    """
    Parse the TCB extension: a SEQUENCE of (OID, value) pairs for
    16 TCB components, PCE SVN, and CPU SVN.

    value_component is already a decoded pyasn1 Sequence from the parent decode.
    """
    tcb_seq = value_component

    if len(tcb_seq) != TCB_EXTENSION_SIZE:
        raise PckExtensionError(
            f"TCB extension has {len(tcb_seq)} elements, "
            f"expected {TCB_EXTENSION_SIZE}"
        )

    tcb_components = [0] * TCB_COMPONENTS_COUNT
    pce_svn = 0
    cpu_svn = bytes(CPU_SVN_SIZE)

    with _asn1_errors("TCB extension"):
        for item in tcb_seq:
            if len(item) < 2:
                raise PckExtensionError(
                    f"Malformed TCB extension item: expected at least 2 fields, got {len(item)}"
                )
            oid_str = str(item[0])

            if oid_str == OID_PCE_SVN.dotted_string:
                val = int(item[1])
                if val < 0 or val > 0xFFFF:
                    raise PckExtensionError(
                        f"PCE SVN value {val} out of uint16 range"
                    )
                pce_svn = val
            elif oid_str == OID_CPU_SVN.dotted_string:
                raw = bytes(item[1])
                if len(raw) != CPU_SVN_SIZE:
                    raise PckExtensionError(
                        f"CPU SVN has wrong size: expected {CPU_SVN_SIZE}, got {len(raw)}"
                    )
                cpu_svn = raw
            elif (idx := _TCB_COMPONENT_OID_INDEX.get(oid_str)) is not None:
                val = int(item[1])
                if val < 0 or val > 0xFF:
                    raise PckExtensionError(
                        f"TCB component {idx + 1} value {val} out of byte range"
                    )
                tcb_components[idx] = val

    return PckCertTCB(pce_svn=pce_svn, cpu_svn=cpu_svn, tcb_components=tcb_components)
