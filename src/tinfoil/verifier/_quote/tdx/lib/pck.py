"""The Intel SGX extension of a PCK certificate: PPID, TCB components, PCE id and FMSPC.

The extension (OID 1.2.840.113741.1.13.1) is a SEQUENCE of attribute pairs,
each a SEQUENCE of an OID and a value:

    1.2.840.113741.1.13.1.1        PPID, 16-byte OCTET STRING
    1.2.840.113741.1.13.1.2        TCB, a SEQUENCE of attribute pairs naming each of the 18 below once
    1.2.840.113741.1.13.1.2.1-16   TCB components 1-16, INTEGER 0-255
    1.2.840.113741.1.13.1.2.17     PCE SVN, INTEGER 0-65535
    1.2.840.113741.1.13.1.2.18     CPU SVN, 16-byte OCTET STRING
    1.2.840.113741.1.13.1.3        PCE id, 2-byte OCTET STRING
    1.2.840.113741.1.13.1.4        FMSPC, 6-byte OCTET STRING

Values that are absent keep their zero value rather than failing here: a
missing FMSPC selects no TCB Info, a missing PPID is no identity and a
missing TCB matches no TCB level, so each surfaces where it is used. A TCB
attribute that is present must name each of its 18 attributes exactly once,
so that no component or SVN is ever read as zero by default. Attribute
pairs with other OIDs are ignored.
"""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil.verifier._x509 import der
from tinfoil.verifier._x509.certificate import Certificate, X509Error, extensions

_INTEL_SGX_OID_BASE = "1.2.840.113741.1.13.1"

OID_SGX_EXTENSION = _INTEL_SGX_OID_BASE
OID_PPID = f"{_INTEL_SGX_OID_BASE}.1"
OID_TCB = f"{_INTEL_SGX_OID_BASE}.2"
OID_PCEID = f"{_INTEL_SGX_OID_BASE}.3"
OID_FMSPC = f"{_INTEL_SGX_OID_BASE}.4"
OID_PCE_SVN = f"{_INTEL_SGX_OID_BASE}.2.17"
OID_CPU_SVN = f"{_INTEL_SGX_OID_BASE}.2.18"

# Component OID (1-indexed) to its position in the component array.
_TCB_COMPONENT_OID_INDEX = {f"{_INTEL_SGX_OID_BASE}.2.{i}": i - 1 for i in range(1, 17)}
_TCB_ATTRIBUTE_OIDS = frozenset(_TCB_COMPONENT_OID_INDEX) | {OID_PCE_SVN, OID_CPU_SVN}
"""The 18 attributes that a TCB attribute must name exactly once."""

PCK_CERT_EXTENSION_COUNT = 6
SGX_EXTENSION_MIN_SIZE = 4
TCB_EXTENSION_SIZE = 18
PPID_SIZE = 16
CPU_SVN_SIZE = 16
FMSPC_SIZE = 6
PCEID_SIZE = 2
TCB_COMPONENTS_COUNT = 16


class PckExtensionError(ValueError):
    """A PCK certificate whose SGX extension is missing or malformed."""


@dataclass(frozen=True, slots=True)
class PckCertTCB:
    """The TCB attribute of a PCK certificate.

    ``cpu_svn_components`` holds the 16 component SVNs once the TCB attribute
    was seen, and is empty when the certificate carries no TCB attribute, so
    that it can never equal a 16-entry TCB level by default.
    """

    pce_svn: int = 0
    cpu_svn: bytes = b""
    cpu_svn_components: bytes = b""


@dataclass(frozen=True, slots=True)
class PckExtensions:
    """The SGX extension values of a PCK certificate, hex values as lowercase strings."""

    ppid: str = ""
    tcb: PckCertTCB = PckCertTCB()
    pceid: str = ""
    fmspc: str = ""


def extract_pck_extensions(cert: Certificate) -> PckExtensions:
    """Read the SGX extension of a PCK certificate.

    The certificate must carry exactly six extensions, one of them the SGX
    extension, whose value must be a SEQUENCE of at least four attribute
    pairs.
    """
    try:
        exts = extensions(cert)
    except X509Error as err:
        raise PckExtensionError(f"PCK certificate extensions: {err}") from err
    if len(exts) != PCK_CERT_EXTENSION_COUNT:
        raise PckExtensionError(
            f"PCK certificate extensions length found {len(exts)}. Expected {PCK_CERT_EXTENSION_COUNT}"
        )
    sgx = next((ext for ext in exts if ext.oid == OID_SGX_EXTENSION), None)
    if sgx is None:
        raise PckExtensionError(f"could not find SGX extension {OID_SGX_EXTENSION} in the PCK certificate")
    try:
        return _parse_sgx_extension(sgx.value)
    except der.DerError as err:
        raise PckExtensionError(f"could not parse SGX extension present in the PCK certificate: {err}") from err


def _parse_sgx_extension(value: bytes) -> PckExtensions:
    top = der.decode(value)
    der.validate_tree(top)
    items = der.expect_sequence(top, "SGX extension")
    if len(items) < SGX_EXTENSION_MIN_SIZE:
        raise PckExtensionError(
            f"SGX Extension has length {len(items)}. It should have a minimum length of {SGX_EXTENSION_MIN_SIZE}"
        )
    ppid = pceid = fmspc = ""
    tcb = PckCertTCB()
    for item in items:
        oid, _ = _attribute(item, "SGX extension")
        if oid == OID_PPID:
            ppid = _octet_string_attribute(item, "PPID", PPID_SIZE).hex()
        elif oid == OID_TCB:
            tcb = _parse_tcb(item)
        elif oid == OID_PCEID:
            pceid = _octet_string_attribute(item, "PCEID", PCEID_SIZE).hex()
        elif oid == OID_FMSPC:
            fmspc = _octet_string_attribute(item, "FMSPC", FMSPC_SIZE).hex()
    return PckExtensions(ppid=ppid, tcb=tcb, pceid=pceid, fmspc=fmspc)


def _attribute(item: der.Element, what: str) -> tuple[str, der.Element]:
    """An attribute pair: a SEQUENCE whose first element is an OID and whose second is the value.

    Elements after the value are tolerated, as in a structure that gained
    fields over time.
    """
    parts = der.expect_sequence(item, f"{what} attribute")
    if len(parts) < 2:
        raise PckExtensionError(f"{what} attribute must hold an OID and a value")
    return der.object_identifier(parts[0]), parts[1]


def _octet_string_attribute(item: der.Element, name: str, size: int) -> bytes:
    """The value of an OCTET STRING attribute of exactly ``size`` bytes.

    The pair is read as an extension record: the OID, an optional BOOLEAN,
    then the OCTET STRING. A value of another length is accepted when it is
    itself a DER OCTET STRING of the right size.
    """
    parts = der.expect_sequence(item, f"{name} attribute")
    index = 1
    if len(parts) > 1 and der.is_universal(parts[1], der.TAG_BOOLEAN):
        der.boolean(parts[1])
        index = 2
    if len(parts) <= index:
        raise PckExtensionError(f"{name} attribute has no value")
    if not der.is_universal(parts[index], der.TAG_OCTET_STRING):
        raise PckExtensionError(f"{name} attribute value is not an OCTET STRING")
    value = der.octet_string(parts[index])
    if len(value) == size:
        return value
    try:
        inner = der.decode(value)
    except der.DerError as err:
        raise PckExtensionError(f"could not parse {name} extension as an octet string: {err}") from err
    if not der.is_universal(inner, der.TAG_OCTET_STRING):
        raise PckExtensionError(f"could not parse {name} extension as an octet string")
    octet = der.octet_string(inner)
    if len(octet) != size:
        raise PckExtensionError(f"{name} extension's value size is {len(octet)}, expected {size}")
    return octet


def _parse_tcb(item: der.Element) -> PckCertTCB:
    """The TCB attribute: a two-element SEQUENCE whose second element lists attribute pairs that name each of the
    16 components, the PCE SVN and the CPU SVN exactly once; pairs with other OIDs are ignored."""
    parts = der.expect_sequence(item, "TCB extension")
    if len(parts) != 2:
        raise PckExtensionError(f"TCB extension when unmarshaled is of size {len(parts)}, expected 2")
    entries = der.expect_sequence(parts[1], "TCB components")
    components = bytearray(TCB_COMPONENTS_COUNT)
    pce_svn = 0
    cpu_svn = b""
    seen: set[str] = set()
    for entry in entries:
        oid, value = _attribute(entry, "TCB component")
        if oid in _TCB_ATTRIBUTE_OIDS:
            if oid in seen:
                raise PckExtensionError(f"TCB extension names {oid} more than once")
            seen.add(oid)
        index = _TCB_COMPONENT_OID_INDEX.get(oid)
        if index is not None:
            components[index] = _small_integer(value, f"sgxTcbComponent{index + 1}", 0xFF)
        elif oid == OID_PCE_SVN:
            pce_svn = _small_integer(value, "PCESvn", 0xFFFF)
        elif oid == OID_CPU_SVN:
            if not der.is_universal(value, der.TAG_OCTET_STRING):
                raise PckExtensionError("CPUSVN component in TCB extension is not an OCTET STRING")
            cpu_svn = der.octet_string(value)
            if len(cpu_svn) != CPU_SVN_SIZE:
                raise PckExtensionError(
                    f"CPUSVN component in TCB extension is of size {len(cpu_svn)}, expected {CPU_SVN_SIZE}"
                )
    if len(seen) != TCB_EXTENSION_SIZE:
        missing = min(_TCB_ATTRIBUTE_OIDS - seen, key=lambda dotted: int(dotted.rsplit(".", 1)[1]))
        raise PckExtensionError(
            f"TCB extension names {len(seen)} of its {TCB_EXTENSION_SIZE} attributes, {missing} is missing"
        )
    return PckCertTCB(pce_svn=pce_svn, cpu_svn=cpu_svn, cpu_svn_components=bytes(components))


def _small_integer(value: der.Element, field: str, maximum: int) -> int:
    if not der.is_universal(value, der.TAG_INTEGER):
        raise PckExtensionError(f"{field} extension is not an INTEGER")
    number = der.integer(value)
    if number < 0 or number > maximum:
        raise PckExtensionError(f"int value for field {field} is out of range: {number}")
    return number
