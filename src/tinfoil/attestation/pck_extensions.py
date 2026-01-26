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

from dataclasses import dataclass
from typing import List

from cryptography import x509

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

# TCB component OIDs (1-16)
def _tcb_component_oid(index: int) -> str:
    """Get the OID for TCB component at index (1-16)."""
    return f"{_INTEL_SGX_OID_BASE}.2.{index}"

# Size constants
PPID_SIZE = 16
CPU_SVN_SIZE = 16
FMSPC_SIZE = 6
PCEID_SIZE = 2
TCB_COMPONENTS_COUNT = 16


class PckExtensionError(Exception):
    """Raised when PCK certificate extension parsing fails."""
    pass


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
    tcb_components: List[int]  # 16 components

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

    The PCK certificate contains extensions with FMSPC, PCEID, and TCB
    information that are required for TCB validation against Intel's
    collateral service.

    Args:
        cert: PCK leaf certificate from the quote

    Returns:
        PckExtensions containing FMSPC, PCEID, PPID, and TCB info

    Raises:
        PckExtensionError: If required extensions are missing or malformed
    """
    # Find the SGX extension
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

    # Parse the SGX extension value (ASN.1 SEQUENCE)
    return _parse_sgx_extension(sgx_ext.value.value)


def _parse_sgx_extension(raw_value: bytes) -> PckExtensions:
    """
    Parse the SGX extension ASN.1 structure.

    The structure is a SEQUENCE of SEQUENCE items, each containing:
    - OID identifying the extension type
    - Value (OCTET STRING or nested SEQUENCE for TCB)
    """
    try:
        parsed = _parse_asn1_sequence(raw_value)
    except Exception as e:
        raise PckExtensionError(f"Failed to parse SGX extension ASN.1: {e}")

    ppid = None
    tcb = None
    pceid = None
    fmspc = None

    for item in parsed:
        if len(item) < 2:
            continue

        oid_bytes, value = item[0], item[1]
        oid_str = _decode_oid(oid_bytes)

        if oid_str == OID_PPID.dotted_string:
            ppid = _extract_octet_string(value, "PPID", PPID_SIZE)
        elif oid_str == OID_TCB.dotted_string:
            tcb = _parse_tcb_extension(value)
        elif oid_str == OID_PCEID.dotted_string:
            pceid = _extract_octet_string(value, "PCEID", PCEID_SIZE)
        elif oid_str == OID_FMSPC.dotted_string:
            fmspc = _extract_octet_string(value, "FMSPC", FMSPC_SIZE)

    # Validate required fields
    if fmspc is None:
        raise PckExtensionError("FMSPC extension not found in PCK certificate")
    if pceid is None:
        raise PckExtensionError("PCEID extension not found in PCK certificate")
    if ppid is None:
        raise PckExtensionError("PPID extension not found in PCK certificate")
    if tcb is None:
        raise PckExtensionError("TCB extension not found in PCK certificate")

    return PckExtensions(
        ppid=ppid,
        tcb=tcb,
        pceid=pceid,
        fmspc=fmspc,
    )


def _parse_asn1_sequence(data: bytes) -> List:
    """
    Parse ASN.1 SEQUENCE structure manually.

    This is a simplified parser that handles the specific structure
    of Intel SGX extensions.
    """
    result = []
    pos = 0

    # Skip outer SEQUENCE tag and length
    if data[pos] != 0x30:  # SEQUENCE tag
        raise PckExtensionError(f"Expected SEQUENCE tag, got {data[pos]:02x}")
    pos += 1
    length, pos = _parse_asn1_length(data, pos)

    end = pos + length

    while pos < end:
        # Each item should be a SEQUENCE
        if data[pos] != 0x30:
            break
        pos += 1
        item_length, pos = _parse_asn1_length(data, pos)
        item_end = pos + item_length

        # Parse OID
        if data[pos] != 0x06:  # OID tag
            pos = item_end
            continue
        pos += 1
        oid_length, pos = _parse_asn1_length(data, pos)
        oid_bytes = data[pos:pos + oid_length]
        pos += oid_length

        # Parse value (remaining bytes in this item)
        value_bytes = data[pos:item_end]
        result.append((oid_bytes, value_bytes))

        pos = item_end

    return result


def _parse_asn1_length(data: bytes, pos: int) -> tuple:
    """Parse ASN.1 length field and return (length, new_position)."""
    if data[pos] < 0x80:
        return data[pos], pos + 1

    num_bytes = data[pos] & 0x7f
    length = 0
    pos += 1
    for _ in range(num_bytes):
        length = (length << 8) | data[pos]
        pos += 1
    return length, pos


def _decode_oid(oid_bytes: bytes) -> str:
    """Decode ASN.1 OID bytes to dotted string format."""
    if len(oid_bytes) < 1:
        return ""

    # First byte encodes first two components
    components = [oid_bytes[0] // 40, oid_bytes[0] % 40]

    # Remaining bytes use variable-length encoding
    value = 0
    for byte in oid_bytes[1:]:
        value = (value << 7) | (byte & 0x7f)
        if byte < 0x80:  # Last byte of this component
            components.append(value)
            value = 0

    return ".".join(str(c) for c in components)


def _extract_octet_string(value: bytes, name: str, expected_size: int) -> str:
    """
    Extract and validate an OCTET STRING extension value.

    Returns hex-encoded string.
    """
    # Skip OCTET STRING tag and length if present
    if len(value) >= 2 and value[0] == 0x04:  # OCTET STRING tag
        _, pos = _parse_asn1_length(value, 1)
        value = value[pos:]

    if len(value) != expected_size:
        raise PckExtensionError(
            f"{name} extension has wrong size: expected {expected_size}, got {len(value)}"
        )

    return value.hex()


def _parse_tcb_extension(value: bytes) -> PckCertTCB:
    """
    Parse the TCB extension SEQUENCE.

    The TCB extension value is wrapped in an OCTET STRING containing:
    - 16 TCB component values (OID 1.2.840.113741.1.13.1.2.1 through .16)
    - PCE SVN (OID 1.2.840.113741.1.13.1.2.17)
    - CPU SVN (OID 1.2.840.113741.1.13.1.2.18)
    """
    tcb_components = [0] * TCB_COMPONENTS_COUNT
    pce_svn = 0
    cpu_svn = bytes(CPU_SVN_SIZE)

    # Unwrap OCTET STRING if present (the TCB value is wrapped in OCTET STRING)
    if len(value) >= 2 and value[0] == 0x04:  # OCTET STRING tag
        _, pos = _parse_asn1_length(value, 1)
        value = value[pos:]

    # Parse outer SEQUENCE
    if len(value) == 0 or value[0] != 0x30:
        raise PckExtensionError("TCB extension is not a SEQUENCE")

    pos = 1
    length, pos = _parse_asn1_length(value, pos)
    end = pos + length

    while pos < end:
        if value[pos] != 0x30:
            break
        pos += 1
        item_length, pos = _parse_asn1_length(value, pos)
        item_end = pos + item_length

        # Parse OID
        if value[pos] != 0x06:
            pos = item_end
            continue
        pos += 1
        oid_length, pos = _parse_asn1_length(value, pos)
        oid_bytes = value[pos:pos + oid_length]
        oid_str = _decode_oid(oid_bytes)
        pos += oid_length

        # Parse value (remaining bytes)
        val_bytes = value[pos:item_end]

        # Check which TCB field this is
        if oid_str == OID_PCE_SVN.dotted_string:
            pce_svn = _parse_integer(val_bytes)
        elif oid_str == OID_CPU_SVN.dotted_string:
            cpu_svn = _parse_octet_string(val_bytes)
        else:
            # Check if it's a TCB component (indices 1-16)
            for i in range(1, TCB_COMPONENTS_COUNT + 1):
                if oid_str == _tcb_component_oid(i):
                    tcb_components[i - 1] = _parse_integer(val_bytes)
                    break

        pos = item_end

    return PckCertTCB(
        pce_svn=pce_svn,
        cpu_svn=cpu_svn,
        tcb_components=tcb_components,
    )


def _parse_integer(data: bytes) -> int:
    """Parse ASN.1 INTEGER value."""
    if len(data) < 2:
        return 0
    if data[0] != 0x02:  # INTEGER tag
        return 0

    length = data[1]
    if length > len(data) - 2:
        return 0

    value = 0
    for byte in data[2:2 + length]:
        value = (value << 8) | byte
    return value


def _parse_octet_string(data: bytes) -> bytes:
    """Parse ASN.1 OCTET STRING value."""
    if len(data) < 2:
        return bytes()
    if data[0] != 0x04:  # OCTET STRING tag
        return data

    _, pos = _parse_asn1_length(data, 1)
    return data[pos:]
