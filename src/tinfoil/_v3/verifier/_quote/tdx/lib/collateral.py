"""Intel PCS collateral for TDX: parsing of TCB Info, QE Identity and issuer-chain responses, verification of their
signatures, and the appraisal of a quote against them.

Every function works on bytes and parsed values that the caller supplies;
nothing here is fetched. The JSON bodies are decoded strictly (a duplicate
member name at any depth rejects) and read the way a typed decoder would:
a member that is absent or null keeps its zero value, a member of the
wrong type is an error, members that are not read are ignored, and
member names match exactly. Checks that depend on an absent member fail
where the value is used, with one exception: the TCB members that the
appraisal compares a quote against (a platform level's component lists
and PCE SVN, an enclave level's ISV SVN) must be present, because their
zero values would be reached by every quote.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from urllib.parse import unquote_to_bytes

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._quote.tdx.lib.abi import QeReport, TdQuoteBody
from tinfoil._v3.verifier._quote.tdx.lib.chain import (
    OID_EKU_SERVER_AUTH,
    ROOT_CERT_PHRASE,
    TdxVerificationError,
    pem_certificates,
    signature_to_der,
    validate_certificate,
    validate_crl,
)
from tinfoil._v3.verifier._quote.tdx.lib.pck import PckExtensions
from tinfoil._v3.verifier._x509.certificate import Certificate, X509Error, verify_chain
from tinfoil._v3.verifier._x509.crl import RevocationList

TCB_INFO_ID = "TDX"
TCB_INFO_VERSION = 3
QE_IDENTITY_ID = "TD_QE"
QE_IDENTITY_VERSION = 2
TCB_SIGNING_PHRASE = "Intel SGX TCB Signing"
TDX_MODULE_ID_PREFIX = "TDX_"
MISCSELECT_SIZE = 4
TDX_MODULE_VERSION_BYTES = 2
"""The leading TEE TCB SVN bytes that name the TDX module: its ISV SVN, then its major version."""

# The members of a level's ``tcb`` that the appraisal compares against the
# quote, by the kind of level that carries it.
_PLATFORM_TCB_MEMBERS = ("sgxtcbcomponents", "pcesvn", "tdxtcbcomponents")
_ENCLAVE_TCB_MEMBERS = ("isvsvn",)

_HEX = re.compile(r"[0-9a-fA-F]*")
_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})")
_QUERY_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_JSON_WHITESPACE = " \t\n\r"


class CollateralError(ValueError):
    """Collateral that does not parse, is not signed by Intel, or does not vouch for the quote."""


class TcbStatus(StrEnum):
    """The status of a TCB level."""

    UP_TO_DATE = "UpToDate"
    SW_HARDENING_NEEDED = "SWHardeningNeeded"
    CONFIGURATION_NEEDED = "ConfigurationNeeded"
    CONFIGURATION_AND_SW_HARDENING_NEEDED = "ConfigurationAndSWHardeningNeeded"
    OUT_OF_DATE = "OutOfDate"
    OUT_OF_DATE_CONFIGURATION_NEEDED = "OutOfDateConfigurationNeeded"
    REVOKED = "Revoked"


# --- records ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TcbComponent:
    svn: int = 0
    category: str = ""
    type: str = ""


@dataclass(frozen=True, slots=True)
class Tcb:
    sgx_tcb_components: tuple[TcbComponent, ...] = ()
    pce_svn: int = 0
    tdx_tcb_components: tuple[TcbComponent, ...] = ()
    isv_svn: int = 0


@dataclass(frozen=True, slots=True)
class TcbLevel:
    tcb: Tcb = Tcb()
    tcb_date: str = ""
    tcb_status: TcbStatus | None = None
    """None when the level names no status; only ``UP_TO_DATE`` is ever accepted."""
    advisory_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TdxModule:
    mrsigner: bytes = b""
    attributes: bytes = b""
    attributes_mask: bytes = b""


@dataclass(frozen=True, slots=True)
class TdxModuleIdentity:
    id: str = ""
    mrsigner: bytes = b""
    attributes: bytes = b""
    attributes_mask: bytes = b""
    tcb_levels: tuple[TcbLevel, ...] = ()


@dataclass(frozen=True, slots=True)
class TcbInfo:
    id: str = ""
    version: int = 0
    issue_date: datetime | None = None
    next_update: datetime | None = None
    fmspc: str = ""
    pce_id: str = ""
    tcb_type: int = 0
    tcb_evaluation_data_number: int | None = None
    tdx_module: TdxModule = TdxModule()
    tdx_module_identities: tuple[TdxModuleIdentity, ...] = ()
    tcb_levels: tuple[TcbLevel, ...] = ()


@dataclass(frozen=True, slots=True)
class TdxTcbInfo:
    """A TCB Info response: the signed object and its signature as published."""

    tcb_info: TcbInfo
    signature: str = ""


@dataclass(frozen=True, slots=True)
class EnclaveIdentity:
    id: str = ""
    version: int = 0
    issue_date: datetime | None = None
    next_update: datetime | None = None
    tcb_evaluation_data_number: int | None = None
    miscselect: bytes = b""
    miscselect_mask: bytes = b""
    attributes: bytes = b""
    attributes_mask: bytes = b""
    mrsigner: bytes = b""
    isv_prod_id: int = 0
    tcb_levels: tuple[TcbLevel, ...] = ()


@dataclass(frozen=True, slots=True)
class QeIdentity:
    """A QE Identity response: the signed object and its signature as published."""

    enclave_identity: EnclaveIdentity
    signature: str = ""


@dataclass(frozen=True, slots=True)
class PckCrl:
    """A PCK CRL with the issuer chain that its response carried."""

    crl: RevocationList
    ca_type: str
    issuer_intermediate: Certificate
    issuer_root: Certificate


@dataclass(frozen=True, slots=True)
class RootCrl:
    """The Intel SGX Root CA CRL."""

    crl: RevocationList


@dataclass(frozen=True, slots=True)
class TdxCollateral:
    """Everything that the appraisal of one quote reads: the two signed responses with their issuer chains and
    signed bodies, and the two CRLs."""

    tcb_info: TdxTcbInfo
    tcb_info_body: bytes
    """The exact bytes of the ``tcbInfo`` member, which the signature covers."""
    tcb_info_issuer_intermediate: Certificate
    tcb_info_issuer_root: Certificate
    qe_identity: QeIdentity
    enclave_identity_body: bytes
    """The exact bytes of the ``enclaveIdentity`` member."""
    qe_identity_issuer_intermediate: Certificate
    qe_identity_issuer_root: Certificate
    pck_crl: PckCrl
    root_crl: RootCrl


# --- JSON reading --------------------------------------------------------------


def _present(obj: _json.JsonObject, key: str) -> _json.JsonValue:
    """The member's value, or None when it is absent or null."""
    return obj.get(key)


def _required(obj: _json.JsonObject, key: str, what: str) -> _json.JsonValue:
    """The member's value; absent or null is an error."""
    value = _present(obj, key)
    if value is None:
        raise CollateralError(f"{what} has no '{key}'")
    return value


def _string(obj: _json.JsonObject, key: str, what: str) -> str:
    value = _present(obj, key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise CollateralError(f"{what} '{key}' is not a string")
    return value


def _unsigned(obj: _json.JsonObject, key: str, what: str, bits: int) -> int:
    value = _present(obj, key)
    if value is None:
        return 0
    if not isinstance(value, _json.JsonNumber):
        raise CollateralError(f"{what} '{key}' is not a number")
    try:
        return value.to_int(bits=bits, signed=False)
    except _json.JsonError as err:
        raise CollateralError(f"{what} '{key}': {err}") from err


def _optional_unsigned(obj: _json.JsonObject, key: str, what: str, bits: int) -> int | None:
    """Like ``_unsigned``, but an absent or null member is None rather than zero, so that a check which needs the
    member can tell that it was never published."""
    if _present(obj, key) is None:
        return None
    return _unsigned(obj, key, what, bits)


def _time(obj: _json.JsonObject, key: str, what: str) -> datetime | None:
    value = _present(obj, key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise CollateralError(f"{what} '{key}' is not a timestamp string")
    try:
        return parse_rfc3339(value)
    except ValueError as err:
        raise CollateralError(f"{what} '{key}': {err}") from err


def _hex(obj: _json.JsonObject, key: str, what: str) -> bytes:
    """A hex-encoded member. Absent is empty; null is an error, as for a typed hex decoder."""
    if key not in obj:
        return b""
    value = obj[key]
    if not isinstance(value, str):
        raise CollateralError(f"{what} '{key}' is not a hex string")
    try:
        return decode_hex(value)
    except ValueError as err:
        raise CollateralError(f"{what} '{key}': {err}") from err


def _status(obj: _json.JsonObject, key: str, what: str) -> TcbStatus | None:
    """A TCB status member. Absent is None; null or an unknown status is an error."""
    if key not in obj:
        return None
    value = obj[key]
    if not isinstance(value, str):
        raise CollateralError(f"{what} '{key}' is not a status string")
    try:
        return TcbStatus(value)
    except ValueError:
        raise CollateralError(f"unexpected tcb status found: {value!r}") from None


def _array(obj: _json.JsonObject, key: str, what: str) -> tuple[_json.JsonValue, ...]:
    value = _present(obj, key)
    if value is None:
        return ()
    if not isinstance(value, tuple):
        raise CollateralError(f"{what} '{key}' is not an array")
    return value


def _object(value: _json.JsonValue, what: str) -> _json.JsonObject:
    if value is None:
        return _json.JsonObject()
    if not isinstance(value, _json.JsonObject):
        raise CollateralError(f"{what} is not a JSON object")
    return value


def _strings(obj: _json.JsonObject, key: str, what: str) -> tuple[str, ...]:
    out: list[str] = []
    for item in _array(obj, key, what):
        if item is None:
            out.append("")
        elif isinstance(item, str):
            out.append(item)
        else:
            raise CollateralError(f"{what} '{key}' is not an array of strings")
    return tuple(out)


def decode_hex(value: str) -> bytes:
    """Decode hex in either case; an odd length or a non-hex character is an error."""
    if not _HEX.fullmatch(value):
        raise ValueError("invalid hex byte")
    if len(value) % 2:
        raise ValueError("odd length hex string")
    return bytes.fromhex(value)


def parse_rfc3339(value: str) -> datetime:
    """An RFC 3339 timestamp with a zone designator; fractional seconds beyond microseconds are truncated."""
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise ValueError(f"not an RFC 3339 timestamp: {value!r}")
    fraction = match[7]
    microsecond = int(fraction[1:7].ljust(6, "0")) if fraction else 0
    try:
        parsed = datetime(
            int(match[1]), int(match[2]), int(match[3]), int(match[4]), int(match[5]), int(match[6]), microsecond
        )
    except ValueError as err:
        raise ValueError(f"not a valid calendar time: {value!r}") from err
    zone = match[8]
    if zone == "Z":
        return parsed.replace(tzinfo=UTC)
    hours, minutes = int(zone[1:3]), int(zone[4:6])
    if hours > 23 or minutes > 59:
        raise ValueError(f"timezone offset out of range: {value!r}")
    offset = timedelta(hours=hours, minutes=minutes)
    return parsed.replace(tzinfo=timezone(-offset if zone[0] == "-" else offset))


# --- response parsing ----------------------------------------------------------


def _parse_tcb_component(value: _json.JsonValue) -> TcbComponent:
    data = _object(value, "TCB component")
    return TcbComponent(
        svn=_unsigned(data, "svn", "TCB component", 8),
        category=_string(data, "category", "TCB component"),
        type=_string(data, "type", "TCB component"),
    )


def _parse_tcb(value: _json.JsonValue, required: tuple[str, ...]) -> Tcb:
    """A level's ``tcb`` object; the ``required`` members, which the appraisal compares, must be present."""
    data = _object(value, "TCB")
    for key in required:
        _required(data, key, "TCB")
    return Tcb(
        sgx_tcb_components=tuple(_parse_tcb_component(c) for c in _array(data, "sgxtcbcomponents", "TCB")),
        pce_svn=_unsigned(data, "pcesvn", "TCB", 16),
        tdx_tcb_components=tuple(_parse_tcb_component(c) for c in _array(data, "tdxtcbcomponents", "TCB")),
        isv_svn=_unsigned(data, "isvsvn", "TCB", 32),
    )


def _parse_tcb_level(value: _json.JsonValue, required_tcb_members: tuple[str, ...]) -> TcbLevel:
    """A TCB level whose ``tcb`` carries at least ``required_tcb_members``."""
    data = _object(value, "TCB level")
    return TcbLevel(
        tcb=_parse_tcb(_required(data, "tcb", "TCB level"), required_tcb_members),
        tcb_date=_string(data, "tcbDate", "TCB level"),
        tcb_status=_status(data, "tcbStatus", "TCB level"),
        advisory_ids=_strings(data, "advisoryIDs", "TCB level"),
    )


def _parse_platform_tcb_levels(obj: _json.JsonObject, what: str) -> tuple[TcbLevel, ...]:
    """The ``tcbLevels`` of a TCB Info: each level's ``tcb`` carries the component lists and PCE SVN."""
    return tuple(_parse_tcb_level(level, _PLATFORM_TCB_MEMBERS) for level in _array(obj, "tcbLevels", what))


def _parse_enclave_tcb_levels(obj: _json.JsonObject, what: str) -> tuple[TcbLevel, ...]:
    """The ``tcbLevels`` of a QE Identity or TDX module identity: each level's ``tcb`` carries the ISV SVN."""
    return tuple(_parse_tcb_level(level, _ENCLAVE_TCB_MEMBERS) for level in _array(obj, "tcbLevels", what))


def _parse_tdx_module(value: _json.JsonValue) -> TdxModule:
    data = _object(value, "tdxModule")
    return TdxModule(
        mrsigner=_hex(data, "mrsigner", "tdxModule"),
        attributes=_hex(data, "attributes", "tdxModule"),
        attributes_mask=_hex(data, "attributesMask", "tdxModule"),
    )


def _parse_tdx_module_identity(value: _json.JsonValue) -> TdxModuleIdentity:
    data = _object(value, "TDX module identity")
    return TdxModuleIdentity(
        id=_string(data, "id", "TDX module identity"),
        mrsigner=_hex(data, "mrsigner", "TDX module identity"),
        attributes=_hex(data, "attributes", "TDX module identity"),
        attributes_mask=_hex(data, "attributesMask", "TDX module identity"),
        tcb_levels=_parse_enclave_tcb_levels(data, "TDX module identity"),
    )


def _parse_tcb_info(value: _json.JsonValue) -> TcbInfo:
    data = _object(value, "tcbInfo")
    return TcbInfo(
        id=_string(data, "id", "TCB Info"),
        version=_unsigned(data, "version", "TCB Info", 8),
        issue_date=_time(data, "issueDate", "TCB Info"),
        next_update=_time(data, "nextUpdate", "TCB Info"),
        fmspc=_string(data, "fmspc", "TCB Info"),
        pce_id=_string(data, "pceId", "TCB Info"),
        tcb_type=_unsigned(data, "tcbType", "TCB Info", 8),
        tcb_evaluation_data_number=_optional_unsigned(data, "tcbEvaluationDataNumber", "TCB Info", 64),
        tdx_module=_parse_tdx_module(_present(data, "tdxModule")),
        tdx_module_identities=tuple(
            _parse_tdx_module_identity(m) for m in _array(data, "tdxModuleIdentities", "TCB Info")
        ),
        tcb_levels=_parse_platform_tcb_levels(data, "TCB Info"),
    )


def _parse_enclave_identity(value: _json.JsonValue) -> EnclaveIdentity:
    data = _object(value, "enclaveIdentity")
    return EnclaveIdentity(
        id=_string(data, "id", "QE Identity"),
        version=_unsigned(data, "version", "QE Identity", 8),
        issue_date=_time(data, "issueDate", "QE Identity"),
        next_update=_time(data, "nextUpdate", "QE Identity"),
        tcb_evaluation_data_number=_optional_unsigned(data, "tcbEvaluationDataNumber", "QE Identity", 64),
        miscselect=_hex(data, "miscselect", "QE Identity"),
        miscselect_mask=_hex(data, "miscselectMask", "QE Identity"),
        attributes=_hex(data, "attributes", "QE Identity"),
        attributes_mask=_hex(data, "attributesMask", "QE Identity"),
        mrsigner=_hex(data, "mrsigner", "QE Identity"),
        isv_prod_id=_unsigned(data, "isvprodid", "QE Identity", 16),
        tcb_levels=_parse_enclave_tcb_levels(data, "QE Identity"),
    )


def _parse_response(body: bytes, what: str) -> _json.JsonObject:
    """Strictly decode a response body: invalid JSON, a non-object body and a duplicate member name at any depth
    reject."""
    try:
        value = _json.strict_parse(body)
    except _json.JsonError as err:
        raise CollateralError(f"unable to unmarshal {what} response: {err}") from err
    if not isinstance(value, _json.JsonObject):
        raise CollateralError(f"{what} response is not a JSON object")
    return value


def parse_tcb_info_response(body: bytes) -> TdxTcbInfo:
    """Decode a TCB Info response. The id, version and levels are checked at verification, not here."""
    data = _parse_response(body, "tcbInfo")
    return TdxTcbInfo(
        tcb_info=_parse_tcb_info(_present(data, "tcbInfo")), signature=_string(data, "signature", "TCB Info response")
    )


def parse_qe_identity_response(body: bytes) -> QeIdentity:
    """Decode a QE Identity response. The id, version and levels are checked at verification, not here."""
    data = _parse_response(body, "QeIdentity")
    return QeIdentity(
        enclave_identity=_parse_enclave_identity(_present(data, "enclaveIdentity")),
        signature=_string(data, "signature", "QE Identity response"),
    )


def top_level_member(body: bytes, key: str) -> bytes:
    """The exact bytes of the value of ``key`` in the top-level object of ``body``: what the response signature
    covers.

    The top-level object is walked member by member, so a member of the
    same name nested inside another value is never mistaken for the
    top-level one, and the span is exactly the value's own bytes. The value
    must be an object; a repeated top-level name is an error.
    """
    if not body:
        raise CollateralError(f"{key!r} is empty")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as err:
        raise CollateralError(f"could not convert {key!r} body to raw message: {err}") from err
    try:
        return _top_level_member_text(text, key).encode("utf-8")
    except ValueError as err:
        raise CollateralError(f"{key!r} body: {err}") from err


def _top_level_member_text(text: str, key: str) -> str:
    decoder = json.JSONDecoder()
    pos = _skip_whitespace(text, 0)
    if pos >= len(text) or text[pos] != "{":
        raise ValueError("body is not a JSON object")
    pos += 1
    found: str | None = None
    while True:
        pos = _skip_whitespace(text, pos)
        if pos >= len(text):
            raise ValueError("unterminated top-level object")
        if text[pos] == "}":
            break
        try:
            name, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError as err:
            raise ValueError(f"malformed member name: {err}") from err
        if not isinstance(name, str):
            raise ValueError("member name is not a string")
        pos = _skip_whitespace(text, pos)
        if pos >= len(text) or text[pos] != ":":
            raise ValueError(f"member {name!r} has no value")
        value_start = _skip_whitespace(text, pos + 1)
        try:
            _, value_end = decoder.raw_decode(text, value_start)
        except json.JSONDecodeError as err:
            raise ValueError(f"malformed value of member {name!r}: {err}") from err
        if name == key:
            if found is not None:
                raise ValueError(f"duplicate top-level member {key!r}")
            if text[value_start] != "{":
                raise ValueError(f"{key!r} is not an object")
            found = text[value_start:value_end]
        pos = _skip_whitespace(text, value_end)
        if pos >= len(text):
            raise ValueError("unterminated top-level object")
        if text[pos] == ",":
            pos += 1
        elif text[pos] != "}":
            raise ValueError(f"unexpected character after member {name!r}")
    if found is None:
        raise ValueError(f"{key!r} field is missing in the response received")
    return found


def _skip_whitespace(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in _JSON_WHITESPACE:
        pos += 1
    return pos


def parse_issuer_chain_header(value: str, phrase: str) -> tuple[Certificate, Certificate]:
    """The signing certificate and the root from a URL-encoded issuer-chain header: exactly two PEM certificates.

    ``+`` decodes to a space and ``%XX`` to a byte; a ``%`` not followed by
    two hex digits is an error.
    """
    if value == "":
        raise CollateralError(f"issuer chain certificates missing in {phrase!r}")
    if _QUERY_ESCAPE.search(value):
        raise CollateralError(f"unable to decode issuer chain in {phrase!r}: invalid URL escape")
    data = unquote_to_bytes(value.replace("+", " "))
    try:
        signing, root = pem_certificates(data, 2, phrase)
    except TdxVerificationError as err:
        raise CollateralError(str(err)) from err
    return signing, root


# --- response verification ----------------------------------------------------------


def verify_response(
    signing_phrase: str,
    root: Certificate,
    signing: Certificate,
    raw_body: bytes,
    signature_hex: str,
    root_crl: RevocationList,
    trusted_roots: Sequence[Certificate],
    now: datetime,
) -> None:
    """Verify one signed PCS response.

    The issuer chain's root is self-consistent and named as the Intel root;
    the signing certificate is named ``signing_phrase``, issued by that
    root, and chains to a trusted root at ``now``; the hex signature is a
    64-byte ECDSA P-256 signature over ``raw_body``; the root CRL is the
    issuer root's and does not list the signing certificate.
    """
    try:
        validate_certificate(root, root, ROOT_CERT_PHRASE)
    except TdxVerificationError as err:
        raise CollateralError(f"unable to validate root certificate in the issuer chain: {err}") from err
    try:
        validate_certificate(signing, root, signing_phrase)
    except TdxVerificationError as err:
        raise CollateralError(f"unable to validate signing certificate in the issuer chain: {err}") from err
    try:
        verify_chain(signing, [], trusted_roots, now, extended_key_usage=OID_EKU_SERVER_AUTH)
    except X509Error as err:
        raise CollateralError(f"unable to verify signing certificate: {err}") from err
    try:
        signature = decode_hex(signature_hex)
    except ValueError as err:
        raise CollateralError(f"unable to decode signature string in the response: {err}") from err
    try:
        signature_der = signature_to_der(signature)
    except TdxVerificationError as err:
        raise CollateralError(f"unable to convert signature to DER format: {err}") from err
    key = signing.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise CollateralError("signing certificate public key is not of type ecdsa public key")
    try:
        key.verify(signature_der, raw_body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise CollateralError("could not verify response body using the signing certificate") from None
    try:
        verified = validate_crl(root_crl, root, now)
    except TdxVerificationError as err:
        raise CollateralError(
            f"root CA CRL verification failed using root certificate in the issuer's chain: {err}"
        ) from err
    if signing.serial_number in verified.crl.revoked_serials:
        raise CollateralError("signing certificate was revoked")


def verify_tcb_info(collateral: TdxCollateral, trusted_roots: Sequence[Certificate], now: datetime) -> None:
    """The TCB Info is for TDX, version 3, lists at least one level, and its response verifies."""
    tcb_info = collateral.tcb_info.tcb_info
    if tcb_info.id != TCB_INFO_ID:
        raise CollateralError(f"tcbInfo ID {tcb_info.id!r} does not match with expected ID {TCB_INFO_ID!r}")
    if tcb_info.version != TCB_INFO_VERSION:
        raise CollateralError(f"tcbInfo version {tcb_info.version} does not match with expected version 3")
    if not tcb_info.tcb_levels:
        raise CollateralError("tcbInfo contains empty TcbLevels")
    try:
        verify_response(
            TCB_SIGNING_PHRASE,
            collateral.tcb_info_issuer_root,
            collateral.tcb_info_issuer_intermediate,
            collateral.tcb_info_body,
            collateral.tcb_info.signature,
            collateral.root_crl.crl,
            trusted_roots,
            now,
        )
    except CollateralError as err:
        raise CollateralError(f"tcbInfo response verification failed: {err}") from err


def verify_qe_identity(collateral: TdxCollateral, trusted_roots: Sequence[Certificate], now: datetime) -> None:
    """The QE Identity is for the TD QE, version 2, lists at least one level, and its response verifies."""
    identity = collateral.qe_identity.enclave_identity
    if identity.id != QE_IDENTITY_ID:
        raise CollateralError(f"QeIdentity ID {identity.id!r} does not match with expected ID {QE_IDENTITY_ID!r}")
    if identity.version != QE_IDENTITY_VERSION:
        raise CollateralError(f"QeIdentity version {identity.version} does not match with expected version 2")
    if not identity.tcb_levels:
        raise CollateralError("QeIdentity contains empty TcbLevels")
    try:
        verify_response(
            TCB_SIGNING_PHRASE,
            collateral.qe_identity_issuer_root,
            collateral.qe_identity_issuer_intermediate,
            collateral.enclave_identity_body,
            collateral.qe_identity.signature,
            collateral.root_crl.crl,
            trusted_roots,
            now,
        )
    except CollateralError as err:
        raise CollateralError(f"QeIdentity response verification failed: {err}") from err


def check_collateral_expiration(collateral: TdxCollateral, now: datetime) -> None:
    """Nothing in the collateral is past its end at ``now``: the two responses' next updates, every issuer
    certificate's notAfter, and the two CRLs' next updates."""
    tcb_next = collateral.tcb_info.tcb_info.next_update
    if tcb_next is None or now > tcb_next:
        raise CollateralError("tcbInfo has expired")
    qe_next = collateral.qe_identity.enclave_identity.next_update
    if qe_next is None or now > qe_next:
        raise CollateralError("QeIdentity has expired")
    if now > collateral.tcb_info_issuer_intermediate.not_valid_after_utc:
        raise CollateralError("tcbInfo signing certificate has expired")
    if now > collateral.tcb_info_issuer_root.not_valid_after_utc:
        raise CollateralError("tcbInfo root certificate has expired")
    if now > collateral.qe_identity_issuer_root.not_valid_after_utc:
        raise CollateralError("QeIdentity root certificate has expired")
    if now > collateral.qe_identity_issuer_intermediate.not_valid_after_utc:
        raise CollateralError("QeIdentity signing certificate has expired")
    if now > collateral.root_crl.crl.next_update:
        raise CollateralError("root CA CRL has expired")
    if now > collateral.pck_crl.crl.next_update:
        raise CollateralError("PCK CRL has expired")
    if now > collateral.pck_crl.issuer_intermediate.not_valid_after_utc:
        raise CollateralError("PCK CRL signing certificate has expired")
    if now > collateral.pck_crl.issuer_root.not_valid_after_utc:
        raise CollateralError("PCK CRL root certificate has expired")


# --- appraisal ---------------------------------------------------------------------


def apply_mask(mask: bytes, value: bytes) -> bytes:
    """``value`` masked by ``mask``, over the length of ``mask``."""
    return bytes(m & v for m, v in zip(mask, value, strict=False))


def is_cpu_svn_higher_or_equal(cpu_svn_components: bytes, sgx_tcb_components: Sequence[TcbComponent]) -> bool:
    """Every PCK TCB component is at least the level's; the two must have the same length."""
    if len(cpu_svn_components) != len(sgx_tcb_components):
        return False
    return all(cpu_svn_components[i] >= component.svn for i, component in enumerate(sgx_tcb_components))


def is_tdx_tcb_svn_higher_or_equal(tee_tcb_svn: bytes, tdx_tcb_components: Sequence[TcbComponent]) -> bool:
    """Every TEE TCB SVN component is at least the level's, skipping the first two when the second (the TDX module
    major version) is non-zero, since those are then appraised through the module identity."""
    if len(tee_tcb_svn) != len(tdx_tcb_components):
        return False
    start = 2 if tee_tcb_svn[1] > 0 else 0
    return all(tee_tcb_svn[i] >= tdx_tcb_components[i].svn for i in range(start, len(tee_tcb_svn)))


def get_matching_tcb_level(
    tcb_levels: Sequence[TcbLevel], tee_tcb_svn: bytes, pck_cert_pce_svn: int, pck_cert_cpu_svn_components: bytes
) -> TcbLevel:
    """The first level, in published order, that the PCK TCB, PCE SVN and TEE TCB SVN all reach."""
    for level in tcb_levels:
        if (
            is_cpu_svn_higher_or_equal(pck_cert_cpu_svn_components, level.tcb.sgx_tcb_components)
            and pck_cert_pce_svn >= level.tcb.pce_svn
            and is_tdx_tcb_svn_higher_or_equal(tee_tcb_svn, level.tcb.tdx_tcb_components)
        ):
            return level
    raise CollateralError("no matching TCB level found")


def get_matching_tdx_module_tcb_level(identities: Sequence[TdxModuleIdentity], tee_tcb_svn: bytes) -> TcbLevel:
    """The first level of the module identity ``TDX_<major>`` (the second TEE TCB SVN byte, hex) that the module's
    ISV SVN (the first byte) reaches. A TEE TCB SVN too short to carry both bytes is an error, never a lookup of
    a module id derived from a missing byte."""
    if len(tee_tcb_svn) < TDX_MODULE_VERSION_BYTES:
        raise CollateralError(
            f"TEE TCB SVN of {len(tee_tcb_svn)} bytes is too short to name a TDX module version "
            f"(expected at least {TDX_MODULE_VERSION_BYTES})"
        )
    major = tee_tcb_svn[1:2]
    module_id = TDX_MODULE_ID_PREFIX + major.hex()
    isv_svn = tee_tcb_svn[0]
    for identity in identities:
        if identity.id == module_id:
            for level in identity.tcb_levels:
                if isv_svn >= level.tcb.isv_svn:
                    return level
            raise CollateralError(
                f"could not find a TDX Module Identity TCB Level matching the TDX Module's ISVSVN ({isv_svn})"
            )
    raise CollateralError(
        f"could not find a TDX Module Identity ({module_id!r}) matching the given TEE TDX version ({major.hex()!r})"
    )


def check_tcb_info_tcb_status(tcb_info: TcbInfo, body: TdQuoteBody, pck_extensions: PckExtensions) -> TcbLevel:
    """The platform's TCB level, and when the TDX module version is set its module level too, must be up to date."""
    level = get_matching_tcb_level(
        tcb_info.tcb_levels, body.tee_tcb_svn, pck_extensions.tcb.pce_svn, pck_extensions.tcb.cpu_svn_components
    )
    if body.tee_tcb_svn[1] > 0:
        module_level = get_matching_tdx_module_tcb_level(tcb_info.tdx_module_identities, body.tee_tcb_svn)
        if module_level.tcb_status != TcbStatus.UP_TO_DATE:
            raise CollateralError(f"TDX Module TCB Status is not 'UpToDate', found {_status_text(module_level)}")
    if level.tcb_status != TcbStatus.UP_TO_DATE:
        raise CollateralError(f"TCB Status is not 'UpToDate', found {_status_text(level)}")
    return level


def _status_text(level: TcbLevel) -> str:
    return repr(level.tcb_status.value if level.tcb_status is not None else "")


def verify_td_quote_body(body: TdQuoteBody, tcb_info: TcbInfo, pck_extensions: PckExtensions) -> TcbLevel:
    """Appraise the TD quote body against the TCB Info.

    The PCK certificate's FMSPC and PCE id equal the TCB Info's, the
    quote's MRSIGNERSEAM equals the TDX module signer, the SEAM attributes
    under the module's mask equal the module's attributes, and the TCB
    status is up to date. Returns the matched platform TCB level.
    """
    if pck_extensions.fmspc != tcb_info.fmspc:
        raise CollateralError(
            f"FMSPC from PCK Certificate({pck_extensions.fmspc!r}) is not equal to FMSPC value from Intel PCS's "
            f"reported TDX TCB info({tcb_info.fmspc!r})"
        )
    if pck_extensions.pceid != tcb_info.pce_id:
        raise CollateralError(
            f"PCEID from PCK Certificate({pck_extensions.pceid!r}) is not equal to PCEID from Intel PCS's reported "
            f"TDX TCB info({tcb_info.pce_id!r})"
        )
    module = tcb_info.tdx_module
    if module.mrsigner != body.mr_signer_seam:
        raise CollateralError(
            f"MRSIGNERSEAM value from TD Quote Body({body.mr_signer_seam.hex()!r}) is not equal to TdxModule.Mrsigner "
            f"field in Intel PCS's reported TDX TCB info({module.mrsigner.hex()!r})"
        )
    if len(module.attributes_mask) != len(body.seam_attributes):
        raise CollateralError(
            f"size of SeamAttributes from TD Quote Body({len(body.seam_attributes)}) is not equal to size of "
            f"TdxModule.AttributesMask in Intel PCS's reported TDX TCB info({len(module.attributes_mask)})"
        )
    masked = apply_mask(module.attributes_mask, body.seam_attributes)
    if module.attributes != masked:
        raise CollateralError(
            f"AttributesMask value({masked.hex()!r}) is not equal to TdxModule.Attributes field in Intel PCS's "
            f"reported TDX TCB info({module.attributes.hex()!r})"
        )
    try:
        return check_tcb_info_tcb_status(tcb_info, body, pck_extensions)
    except CollateralError as err:
        raise CollateralError(f"TDX TCB info reported by Intel PCS failed TCB status check: {err}") from err


def check_qe_tcb_status(tcb_levels: Sequence[TcbLevel], isv_svn: int) -> None:
    """The first level whose ISV SVN the QE reaches must be up to date; no such level is out of date."""
    for level in tcb_levels:
        if level.tcb.isv_svn <= isv_svn:
            if level.tcb_status != TcbStatus.UP_TO_DATE:
                raise CollateralError(f"TCB Status is not 'UpToDate', found {_status_text(level)}")
            return
    raise CollateralError("unable to find latest status of TCB, it is now OutOfDate")


def verify_qe_report(report: QeReport, identity: EnclaveIdentity) -> None:
    """Appraise the QE report against the QE Identity: MISCSELECT and attributes under their masks, MRSIGNER, the
    ISV product id, and an up-to-date TCB level for the ISV SVN."""
    if len(identity.miscselect_mask) != MISCSELECT_SIZE:
        raise CollateralError(
            f"MISCSELECTMask field size({len(identity.miscselect_mask)}) in Intel PCS's reported QE Identity is not "
            f"equal to expected size({MISCSELECT_SIZE})"
        )
    if len(identity.miscselect) != MISCSELECT_SIZE:
        raise CollateralError(
            f"MISCSELECT field size({len(identity.miscselect)}) in Intel PCS's reported QE Identity is not equal to "
            f"expected size({MISCSELECT_SIZE})"
        )
    mask = int.from_bytes(identity.miscselect_mask, "little")
    expected = int.from_bytes(identity.miscselect, "little")
    masked_miscselect = report.misc_select & mask
    if masked_miscselect != expected:
        raise CollateralError(
            f"MISCSELECT value({expected}) from Intel PCS's reported QE Identity is not equal to MISCSELECTMask "
            f"value({masked_miscselect})"
        )
    if len(identity.attributes_mask) != len(report.attributes):
        raise CollateralError(
            f"size of AttributesMask value({len(identity.attributes_mask)}) in Intel PCS's reported QE Identity is "
            f"not equal to size of SeamAttributes value({len(report.attributes)}) in QE Report"
        )
    masked_attributes = apply_mask(identity.attributes_mask, report.attributes)
    if identity.attributes != masked_attributes:
        raise CollateralError(
            f"AttributesMask value({masked_attributes.hex()!r}) is not equal to Attributes value"
            f"({identity.attributes.hex()!r}) in Intel PCS's reported QE Identity"
        )
    if identity.mrsigner != report.mr_signer:
        raise CollateralError(
            f"MRSIGNER value({report.mr_signer.hex()!r}) in QE Report is not equal to MRSIGNER value"
            f"({identity.mrsigner.hex()!r}) in Intel PCS's reported QE Identity"
        )
    if report.isv_prod_id != identity.isv_prod_id:
        raise CollateralError(
            f"ISV PRODID value({report.isv_prod_id}) in QE Report is not equal to ISV PRODID value"
            f"({identity.isv_prod_id}) in Intel PCS's reported QE Identity"
        )
    try:
        check_qe_tcb_status(identity.tcb_levels, report.isv_svn)
    except CollateralError as err:
        raise CollateralError(f"QE Identity reported by Intel PCS failed TCB status check: {err}") from err
