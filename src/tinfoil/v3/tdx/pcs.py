"""Intel PCS values and parsers, a 1:1 port of go-tdx-guest/pcs plus the
lenient JSON decoding go-tdx-guest performs on PCS response bodies with
encoding/json (case-exact keys as emitted by Intel, unknown members ignored,
typed members validated). All errors are ValueError; the authenticate wrapper
assigns the rejection layer."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..bytesutil import decode_hex
from .der import (
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TLV,
    ZERO_TIME,
    Certificate,
    decode_oid,
    decode_uint,
    read_tlv,
    tlv_children,
    tlv_content,
)

_PPID_SIZE = 16
_CPU_SVN_SIZE = 16
_PCE_ID_SIZE = 2
_FMSPC_SIZE = 6
_TCB_COMPONENT_SIZE = 16
_TCB_EXTENSION_SIZE = 18
_PCK_CERT_EXTENSION_SIZE = 6
_SGX_EXTENSION_MIN_SIZE = 4

_PCS_SGX_BASE_URL = "https://api.trustedservices.intel.com/sgx/certification/v4"
_PCS_TDX_BASE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4"

OID_SGX_EXTENSION = "1.2.840.113741.1.13.1"
_OID_PPID = "1.2.840.113741.1.13.1.1"
_OID_TCB = "1.2.840.113741.1.13.1.2"
_OID_PCEID = "1.2.840.113741.1.13.1.3"
_OID_FMSPC = "1.2.840.113741.1.13.1.4"
_OID_PCE_SVN = "1.2.840.113741.1.13.1.2.17"
_OID_CPU_SVN = "1.2.840.113741.1.13.1.2.18"


def pck_crl_url(ca: str) -> str:
    return f"{_PCS_SGX_BASE_URL}/pckcrl?ca={ca}&encoding=der"


def tcb_info_url(fmspc: str) -> str:
    return f"{_PCS_TDX_BASE_URL}/tcb?fmspc={fmspc}"


def qe_identity_url() -> str:
    return f"{_PCS_TDX_BASE_URL}/qe/identity"


# --- PCK certificate SGX extension (pcs.PckCertificateExtensions) -------------


@dataclass
class PckCertTCB:
    pce_svn: int = 0
    cpu_svn: bytes = b""
    cpu_svn_components: bytes = bytes(_TCB_COMPONENT_SIZE)


@dataclass
class PckExtensions:
    ppid: str = ""
    tcb: PckCertTCB = field(default_factory=PckCertTCB)
    pceid: str = ""
    fmspc: str = ""


def _entry_oid_and_value(b: bytes, entry: TLV, what: str) -> tuple[str, TLV]:
    if entry.cls != 0 or entry.tag != TAG_SEQUENCE:
        raise ValueError(f"could not parse {what} in the PCK certificate")
    parts = tlv_children(b, entry)
    if len(parts) != 2 or parts[0].cls != 0 or parts[0].tag != TAG_OID:
        raise ValueError(f"could not parse {what} in the PCK certificate")
    return decode_oid(tlv_content(b, parts[0])), parts[1]


def _octet_string_value(b: bytes, v: TLV, field_name: str, size: int) -> str:
    if v.cls != 0 or v.tag != TAG_OCTET_STRING:
        raise ValueError(f"could not parse {field_name} extension as an octet string")
    val = tlv_content(b, v)
    if len(val) != size:
        raise ValueError(
            f"{field_name} extension's value size is {len(val)}, expected {size}"
        )
    return val.hex()


def _extract_tcb_extension(b: bytes, value: TLV) -> PckCertTCB:
    if value.cls != 0 or value.tag != TAG_SEQUENCE:
        raise ValueError(
            "could not parse TCB extension present inside the SGX extension in "
            "PCK certificate"
        )
    tcb_extension = tlv_children(b, value)
    if len(tcb_extension) != _TCB_EXTENSION_SIZE:
        raise ValueError(
            f"TCB extension is of size {len(tcb_extension)}, expected "
            f"{_TCB_EXTENSION_SIZE}"
        )
    components = bytearray(_TCB_COMPONENT_SIZE)
    tcb = PckCertTCB()
    for ext in tcb_extension:
        oid, v = _entry_oid_and_value(b, ext, "TCB component inside the TCB extension")
        for i in range(_TCB_COMPONENT_SIZE):
            if oid == f"{_OID_TCB}.{i + 1}":
                if v.tag != TAG_INTEGER or v.cls != 0:
                    raise ValueError(f"sgxTcbComponent{i + 1} extension is not an INTEGER")
                val = decode_uint(tlv_content(b, v), f"sgxTcbComponent{i + 1}")
                if val > 255:
                    raise ValueError(
                        f"int value for field sgxTcbComponent{i + 1} isn't a byte: {val}"
                    )
                components[i] = val
                break
        if oid == _OID_PCE_SVN:
            if v.tag != TAG_INTEGER or v.cls != 0:
                raise ValueError("PCESvn extension is not an INTEGER")
            val = decode_uint(tlv_content(b, v), "PCESvn")
            if val > 65535:
                raise ValueError(f"int value for field PCESvn isn't a uint16: {val}")
            tcb.pce_svn = val
        if oid == _OID_CPU_SVN:
            if v.tag != TAG_OCTET_STRING or v.cls != 0:
                raise ValueError("CPUSVN component in TCB extension is not an octet string")
            val_bytes = tlv_content(b, v)
            if len(val_bytes) != _CPU_SVN_SIZE:
                raise ValueError(
                    f"CPUSVN component in TCB extension is of size {len(val_bytes)}, "
                    f"expected {_CPU_SVN_SIZE}"
                )
            tcb.cpu_svn = val_bytes
    tcb.cpu_svn_components = bytes(components)
    return tcb


def pck_certificate_extensions(cert: Certificate) -> PckExtensions:
    """Extract the SGX x509v3 extension fields required for verification,
    enforcing the exact extension count the library pins."""
    exts = list(cert.obj.extensions)
    if len(exts) != _PCK_CERT_EXTENSION_SIZE:
        raise ValueError(
            f"PCK certificate extensions length found {len(exts)}. Expected "
            f"{_PCK_CERT_EXTENSION_SIZE}"
        )
    sgx_value: Optional[bytes] = None
    for ext in exts:
        if ext.oid.dotted_string == OID_SGX_EXTENSION:
            sgx_value = ext.value.value  # UnrecognizedExtension raw bytes
            break
    if sgx_value is None:
        raise ValueError("could not find SGX extension present in the PCK certificate")
    outer = read_tlv(sgx_value, 0)
    if outer.cls != 0 or outer.tag != TAG_SEQUENCE or outer.end != len(sgx_value):
        raise ValueError("could not parse SGX extension present in the PCK certificate")
    entries = tlv_children(sgx_value, outer)
    if len(entries) < _SGX_EXTENSION_MIN_SIZE:
        raise ValueError(
            f"SGX Extension has length {len(entries)}. It should have a minimum "
            f"length of {_SGX_EXTENSION_MIN_SIZE}"
        )
    out = PckExtensions()
    for entry in entries:
        oid, value = _entry_oid_and_value(sgx_value, entry, "SGX extension's")
        if oid == _OID_PPID:
            out.ppid = _octet_string_value(sgx_value, value, "PPID", _PPID_SIZE)
        elif oid == _OID_TCB:
            out.tcb = _extract_tcb_extension(sgx_value, value)
        elif oid == _OID_PCEID:
            out.pceid = _octet_string_value(sgx_value, value, "PCEID", _PCE_ID_SIZE)
        elif oid == _OID_FMSPC:
            out.fmspc = _octet_string_value(sgx_value, value, "FMSPC", _FMSPC_SIZE)
    return out


# --- PCS response body types (pcs.TdxTcbInfo / pcs.QeIdentity) -----------------

TCB_COMPONENT_STATUS_UP_TO_DATE = "UpToDate"

_VALID_TCB_STATUSES = {
    "UpToDate",
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
    "OutOfDate",
    "OutOfDateConfigurationNeeded",
    "Revoked",
}

_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1


@dataclass
class TcbComponent:
    svn: int
    category: str
    type: str


@dataclass
class Tcb:
    sgx_tcbcomponents: list[TcbComponent]
    pcesvn: int
    tdx_tcbcomponents: list[TcbComponent]
    isvsvn: int


@dataclass
class TcbLevel:
    tcb: Tcb
    tcb_date: str
    tcb_status: str


@dataclass
class TdxModule:
    mrsigner: bytes
    attributes: bytes
    attributes_mask: bytes


@dataclass
class TdxModuleIdentity:
    id: str
    mrsigner: bytes
    attributes: bytes
    attributes_mask: bytes
    tcb_levels: list[TcbLevel]


@dataclass
class TcbInfo:
    id: str
    version: int
    issue_date: datetime
    next_update: datetime
    fmspc: str
    pce_id: str
    tcb_type: int
    tcb_evaluation_data_number: int
    tdx_module: TdxModule
    tdx_module_identities: list[TdxModuleIdentity]
    tcb_levels: list[TcbLevel]


@dataclass
class TdxTcbInfo:
    tcb_info: TcbInfo
    signature: str


@dataclass
class EnclaveIdentity:
    id: str
    version: int
    issue_date: datetime
    next_update: datetime
    tcb_evaluation_data_number: int
    miscselect: bytes
    miscselect_mask: bytes
    attributes: bytes
    attributes_mask: bytes
    mrsigner: bytes
    isv_prod_id: int
    tcb_levels: list[TcbLevel]


@dataclass
class QeIdentity:
    enclave_identity: EnclaveIdentity
    signature: str


# Typed member readers mirroring encoding/json unmarshal failures: a present
# member of the wrong JSON type is an error, an absent member is the zero
# value. Unknown members are ignored (encoding/json default).


def _json_str(obj: dict, key: str) -> str:
    v = obj.get(key)
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValueError(f"cannot unmarshal {key}: not a string")
    return v


def _json_int(obj: dict, key: str, lo: int, hi: int) -> int:
    v = obj.get(key)
    if v is None:
        return 0
    if isinstance(v, bool) or not isinstance(v, int) or v < lo or v > hi:
        raise ValueError(f"cannot unmarshal {key}: not an integer in range")
    return v


# _json_time mirrors time.Time unmarshalling: RFC 3339 required.
_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def _json_time(obj: dict, key: str) -> datetime:
    v = obj.get(key)
    if v is None:
        return ZERO_TIME
    if not isinstance(v, str):
        raise ValueError(f"cannot unmarshal {key}: not an RFC 3339 time")
    m = _RFC3339_RE.fullmatch(v)
    if m is None:
        raise ValueError(f"cannot unmarshal {key}: not an RFC 3339 time")
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7)
    # Fractional seconds truncated to microseconds, no float arithmetic.
    micro = int((frac[1:] + "000000")[:6]) if frac else 0
    offset = m.group(8)
    if offset == "Z":
        tz = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6])))
    try:
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    except ValueError:
        raise ValueError(f"cannot unmarshal {key}: invalid time") from None


def _json_hex_bytes(obj: dict, key: str) -> bytes:
    """Mirror pcs.HexBytes: a hex string (either case) or error."""
    v = obj.get(key)
    if v is None:
        return b""
    if not isinstance(v, str):
        raise ValueError(f"cannot unmarshal {key}: not a string")
    try:
        return decode_hex(v)
    except ValueError:
        raise ValueError(f"cannot unmarshal {key}: not hex") from None


def _json_obj(v: Any, what: str) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ValueError(f"cannot unmarshal {what}: not an object")
    return v


def _json_arr(obj: dict, key: str) -> list:
    v = obj.get(key)
    if v is None:
        return []
    if not isinstance(v, list):
        raise ValueError(f"cannot unmarshal {key}: not an array")
    return v


def _parse_tcb_components(obj: dict, key: str) -> list[TcbComponent]:
    out = []
    for e in _json_arr(obj, key):
        c = _json_obj(e, key)
        out.append(
            TcbComponent(
                svn=_json_int(c, "svn", 0, 255),
                category=_json_str(c, "category"),
                type=_json_str(c, "type"),
            )
        )
    return out


def _parse_tcb_levels(obj: dict) -> list[TcbLevel]:
    out = []
    for e in _json_arr(obj, "tcbLevels"):
        level = _json_obj(e, "tcbLevels")
        t = _json_obj(level.get("tcb"), "tcb")
        status = level.get("tcbStatus")
        tcb_status = ""
        if status is not None:
            if not isinstance(status, str) or status not in _VALID_TCB_STATUSES:
                raise ValueError(f"unexpected tcb status found: {json.dumps(status)}")
            tcb_status = status
        out.append(
            TcbLevel(
                tcb=Tcb(
                    sgx_tcbcomponents=_parse_tcb_components(t, "sgxtcbcomponents"),
                    pcesvn=_json_int(t, "pcesvn", 0, 65535),
                    tdx_tcbcomponents=_parse_tcb_components(t, "tdxtcbcomponents"),
                    isvsvn=_json_int(t, "isvsvn", 0, 4294967295),
                ),
                tcb_date=_json_str(level, "tcbDate"),
                tcb_status=tcb_status,
            )
        )
    return out


def _parse_tdx_module(v: Any) -> TdxModule:
    m = _json_obj(v, "tdxModule")
    return TdxModule(
        mrsigner=_json_hex_bytes(m, "mrsigner"),
        attributes=_json_hex_bytes(m, "attributes"),
        attributes_mask=_json_hex_bytes(m, "attributesMask"),
    )


def _reject_constant(name: str) -> Any:
    # Go's encoding/json rejects bare NaN/Infinity literals.
    raise ValueError(f"invalid JSON literal {name}")


def _loads(body: bytes) -> Any:
    # Decode leniently like Go, which coerces invalid UTF-8 inside strings.
    return json.loads(body.decode("utf-8", errors="replace"), parse_constant=_reject_constant)


def parse_tdx_tcb_info(body: bytes) -> TdxTcbInfo:
    """Decode a TCB Info response body (Go: json.Unmarshal into pcs.TdxTcbInfo)."""
    try:
        root = _loads(body)
    except ValueError as e:
        raise ValueError(f"unable to unmarshal tcbInfo response: {e}") from None
    outer = _json_obj(root, "tcbInfo response")
    info = _json_obj(outer.get("tcbInfo"), "tcbInfo")
    identities = []
    for e in _json_arr(info, "tdxModuleIdentities"):
        m = _json_obj(e, "tdxModuleIdentities")
        identities.append(
            TdxModuleIdentity(
                id=_json_str(m, "id"),
                mrsigner=_json_hex_bytes(m, "mrsigner"),
                attributes=_json_hex_bytes(m, "attributes"),
                attributes_mask=_json_hex_bytes(m, "attributesMask"),
                tcb_levels=_parse_tcb_levels(m),
            )
        )
    return TdxTcbInfo(
        tcb_info=TcbInfo(
            id=_json_str(info, "id"),
            version=_json_int(info, "version", 0, 255),
            issue_date=_json_time(info, "issueDate"),
            next_update=_json_time(info, "nextUpdate"),
            fmspc=_json_str(info, "fmspc"),
            pce_id=_json_str(info, "pceId"),
            tcb_type=_json_int(info, "tcbType", 0, 255),
            tcb_evaluation_data_number=_json_int(
                info, "tcbEvaluationDataNumber", _INT64_MIN, _INT64_MAX
            ),
            tdx_module=_parse_tdx_module(info.get("tdxModule")),
            tdx_module_identities=identities,
            tcb_levels=_parse_tcb_levels(info),
        ),
        signature=_json_str(outer, "signature"),
    )


def parse_qe_identity(body: bytes) -> QeIdentity:
    """Decode a QE Identity response body (Go: json.Unmarshal into pcs.QeIdentity)."""
    try:
        root = _loads(body)
    except ValueError as e:
        raise ValueError(f"unable to unmarshal QeIdentity response: {e}") from None
    outer = _json_obj(root, "QeIdentity response")
    ident = _json_obj(outer.get("enclaveIdentity"), "enclaveIdentity")
    return QeIdentity(
        enclave_identity=EnclaveIdentity(
            id=_json_str(ident, "id"),
            version=_json_int(ident, "version", 0, 255),
            issue_date=_json_time(ident, "issueDate"),
            next_update=_json_time(ident, "nextUpdate"),
            tcb_evaluation_data_number=_json_int(
                ident, "tcbEvaluationDataNumber", _INT64_MIN, _INT64_MAX
            ),
            miscselect=_json_hex_bytes(ident, "miscselect"),
            miscselect_mask=_json_hex_bytes(ident, "miscselectMask"),
            attributes=_json_hex_bytes(ident, "attributes"),
            attributes_mask=_json_hex_bytes(ident, "attributesMask"),
            mrsigner=_json_hex_bytes(ident, "mrsigner"),
            isv_prod_id=_json_int(ident, "isvprodid", 0, 65535),
            tcb_levels=_parse_tcb_levels(ident),
        ),
        signature=_json_str(outer, "signature"),
    )


_WS = b" \t\r\n"


def raw_top_level_member(body: bytes, name: str) -> Optional[bytes]:
    """The exact raw JSON bytes of a top-level object member (Go:
    bodyToRawMessage via map[string]json.RawMessage — last duplicate wins).
    None when the member is absent. Scans bytes so the signed region is exact.
    Raises ValueError on malformed JSON structure."""
    err = ValueError(f"could not convert {json.dumps(name)} body to raw message")
    pos = 0
    n = len(body)

    def skip_ws() -> None:
        nonlocal pos
        while pos < n and body[pos] in _WS:
            pos += 1

    def skip_string() -> bytes:
        nonlocal pos
        start = pos
        pos += 1  # opening quote
        while pos < n:
            c = body[pos]
            if c == 0x5C:  # backslash
                pos += 2
            elif c == 0x22:  # closing quote
                pos += 1
                return body[start:pos]
            else:
                pos += 1
        raise ValueError("unexpected end of string literal")

    def skip_value() -> None:
        nonlocal pos
        skip_ws()
        if pos >= n:
            raise ValueError("unexpected end of JSON value")
        c = body[pos]
        if c == 0x22:
            skip_string()
            return
        if c in (0x7B, 0x5B):  # { or [
            depth = 0
            while pos < n:
                d = body[pos]
                if d == 0x22:
                    skip_string()
                    continue
                if d in (0x7B, 0x5B):
                    depth += 1
                if d in (0x7D, 0x5D):  # } or ]
                    depth -= 1
                    if depth == 0:
                        pos += 1
                        return
                pos += 1
            raise ValueError("unexpected end of JSON value")
        while pos < n and body[pos] not in b",}] \t\r\n":
            pos += 1

    skip_ws()
    if pos >= n or body[pos] != 0x7B:
        raise err
    pos += 1
    found: Optional[bytes] = None
    skip_ws()
    if pos < n and body[pos] == 0x7D:
        return found
    while True:
        skip_ws()
        if pos >= n or body[pos] != 0x22:
            raise err
        key_token = skip_string()
        key = json.loads(key_token.decode("utf-8", errors="replace"))
        skip_ws()
        if pos >= n or body[pos] != 0x3A:  # colon
            raise err
        pos += 1
        skip_ws()
        value_start = pos
        skip_value()
        if key == name:
            found = body[value_start:pos]
        skip_ws()
        if pos < n and body[pos] == 0x7D:
            return found
        if pos >= n or body[pos] != 0x2C:  # comma
            raise err
        pos += 1
