"""A strict DER tokenizer for the structures that the verifier reads itself.

Only the subset that appears in certificates, CRLs, timestamp tokens and
vendor extensions is supported. Every accessor rejects an encoding that
DER forbids, so that one byte string has exactly one accepted encoding:
definite minimal lengths, minimal two's-complement integers, ``00``/``FF``
booleans, zero unused bits, times with a trailing ``Z`` and no fractional
seconds in UTCTime.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import UTC, datetime

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3

TAG_BOOLEAN = 1
TAG_INTEGER = 2
TAG_BIT_STRING = 3
TAG_OCTET_STRING = 4
TAG_NULL = 5
TAG_OBJECT_IDENTIFIER = 6
TAG_ENUMERATED = 10
TAG_UTF8_STRING = 12
TAG_SEQUENCE = 16
TAG_SET = 17
TAG_PRINTABLE_STRING = 19
TAG_IA5_STRING = 22
TAG_UTC_TIME = 23
TAG_GENERALIZED_TIME = 24

MAX_DEPTH = 32
"""The deepest nesting that ``children`` and every recursive walker built on it follow; deeper structures are
rejected."""

_MAX_LENGTH_OCTETS = 4
_UTC_TIME = re.compile(rb"\A(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z\Z")
_GENERALIZED_TIME = re.compile(rb"\A(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z\Z")
_PEM_BOUNDARY = re.compile(r"\A-----(BEGIN|END) ([^-]+)-----\Z")


class DerError(ValueError):
    """An encoding that is not the one DER prescribes, or a structure of the wrong shape."""


@dataclass(frozen=True, slots=True)
class Element:
    """One TLV element."""

    tag_class: int
    constructed: bool
    tag: int
    content: bytes
    """The bytes between the length and the end of the element."""
    raw: bytes
    """The whole element: identifier, length and content."""


def decode(data: bytes) -> Element:
    """Decode exactly one element from ``data``.

    Rejects trailing bytes, indefinite lengths, non-minimal lengths,
    high-tag-number forms above 30 and lengths that overrun the input.
    """
    if not data:
        raise DerError("empty input")
    element, end = decode_at(data, 0)
    if end != len(data):
        raise DerError("trailing bytes after the element")
    return element


def decode_prefix(data: bytes) -> tuple[Element, bytes]:
    """Decode the element at the start of ``data`` and return it with the bytes that follow."""
    element, end = decode_at(data, 0)
    return element, data[end:]


def decode_at(data: bytes, offset: int) -> tuple[Element, int]:
    """Decode the element that starts at ``offset`` in ``data`` and return it with the offset just past it.

    Only the element's own bytes are copied, never the bytes that follow
    it, so a walk over a long list of siblings stays linear in the size of
    the list.
    """
    if offset < 0:
        raise DerError("negative element offset")
    if len(data) - offset < 2:
        raise DerError("truncated element header")
    identifier = data[offset]
    tag = identifier & 0x1F
    if tag == 0x1F:
        raise DerError("long-form tag numbers are not supported")
    first = data[offset + 1]
    header = offset + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError("indefinite length is not DER")
    else:
        count = first & 0x7F
        if count > _MAX_LENGTH_OCTETS:
            raise DerError("length octets exceed the supported range")
        if len(data) < header + count:
            raise DerError("truncated length")
        octets = data[header : header + count]
        length = int.from_bytes(octets, "big")
        # Minimal form: no leading zero octet, and the long form only when
        # the value does not fit the short form.
        if octets[0] == 0 or length < 0x80:
            raise DerError("length is not in minimal form")
        header += count
    end = header + length
    if end > len(data):
        raise DerError("element extends past the end of its container")
    constructed = bool(identifier & 0x20)
    tag_class = identifier >> 6
    if tag_class == CLASS_UNIVERSAL:
        if tag in (TAG_SEQUENCE, TAG_SET):
            if not constructed:
                raise DerError("SEQUENCE and SET must be constructed")
        elif constructed:
            raise DerError("constructed encoding of a primitive type")
    element = Element(
        tag_class=tag_class, constructed=constructed, tag=tag, content=data[header:end], raw=data[offset:end]
    )
    return element, end


def children(element: Element) -> tuple[Element, ...]:
    """The elements inside a constructed element, in order, consuming its content exactly."""
    if not element.constructed:
        raise DerError("primitive element has no children")
    out: list[Element] = []
    content = element.content
    offset = 0
    while offset < len(content):
        child, offset = decode_at(content, offset)
        out.append(child)
    return tuple(out)


def validate_tree(element: Element, *, depth: int = 0) -> None:
    """Walk the whole element, checking every nested encoding.

    Each constructed element's children must fill its content exactly and
    every universal primitive must carry a DER-valid value: minimal
    integers, ``00``/``FF`` booleans, zero-padded bit strings, empty NULLs,
    minimal object identifiers and ``Z``-terminated times (a GeneralizedTime
    fraction in DER form passes here; whether a structure admits one is for
    ``time`` to decide). Nesting beyond MAX_DEPTH is rejected.
    """
    if depth > MAX_DEPTH:
        raise DerError(f"nesting deeper than {MAX_DEPTH}")
    if element.constructed:
        for child in children(element):
            validate_tree(child, depth=depth + 1)
        return
    if element.tag_class != CLASS_UNIVERSAL:
        # An implicitly tagged primitive is typed by its schema alone.
        return
    if element.tag == TAG_BOOLEAN:
        boolean(element)
    elif element.tag in (TAG_INTEGER, TAG_ENUMERATED):
        _check_integer(element.content)
    elif element.tag == TAG_BIT_STRING:
        _check_bit_string(element.content)
    elif element.tag == TAG_NULL:
        if element.content:
            raise DerError("NULL must be empty")
    elif element.tag == TAG_OBJECT_IDENTIFIER:
        object_identifier(element)
    elif element.tag in (TAG_UTC_TIME, TAG_GENERALIZED_TIME):
        time(element, fractional_seconds=True)


def is_universal(element: Element, tag: int) -> bool:
    """Whether the element is a universal, primitive-or-constructed element with ``tag``."""
    return element.tag_class == CLASS_UNIVERSAL and element.tag == tag


def is_context(element: Element, tag: int) -> bool:
    """Whether the element is context-specific with ``tag``."""
    return element.tag_class == CLASS_CONTEXT and element.tag == tag


def expect_sequence(element: Element, what: str) -> tuple[Element, ...]:
    """The children of a universal SEQUENCE; ``what`` names the structure in the error."""
    if not is_universal(element, TAG_SEQUENCE):
        raise DerError(f"{what} must be a SEQUENCE")
    return children(element)


def _expect_primitive(element: Element, tag: int, name: str) -> bytes:
    if not is_universal(element, tag) or element.constructed:
        raise DerError(f"expected {name}")
    return element.content


def _check_integer(content: bytes) -> None:
    if not content:
        raise DerError("INTEGER has no content")
    if len(content) >= 2:
        redundant_zero = content[0] == 0x00 and not content[1] & 0x80
        redundant_ones = content[0] == 0xFF and content[1] & 0x80
        if redundant_zero or redundant_ones:
            raise DerError("INTEGER is not minimally encoded")


def integer(element: Element) -> int:
    """Decode an INTEGER, rejecting an empty content and non-minimal two's-complement encodings."""
    content = _expect_primitive(element, TAG_INTEGER, "INTEGER")
    _check_integer(content)
    return int.from_bytes(content, "big", signed=True)


def boolean(element: Element) -> bool:
    """Decode a BOOLEAN, accepting only ``00`` and ``FF``."""
    content = _expect_primitive(element, TAG_BOOLEAN, "BOOLEAN")
    if content not in (b"\x00", b"\xff"):
        raise DerError("BOOLEAN must be a single 0x00 or 0xFF byte")
    return content == b"\xff"


def _check_bit_string(content: bytes) -> int:
    """Check the unused-bits octet and padding of a BIT STRING and return the unused-bits count."""
    if not content:
        raise DerError("BIT STRING has no unused-bits octet")
    unused = content[0]
    if unused > 7:
        raise DerError("BIT STRING unused-bits count exceeds 7")
    if len(content) == 1 and unused:
        raise DerError("empty BIT STRING with unused bits")
    if unused and content[-1] & ((1 << unused) - 1):
        raise DerError("BIT STRING unused bits must be zero")
    return unused


def bit_string(element: Element) -> bytes:
    """Decode a BIT STRING with zero unused bits and return its bytes."""
    content = _expect_primitive(element, TAG_BIT_STRING, "BIT STRING")
    if _check_bit_string(content):
        raise DerError("BIT STRING must have no unused bits here")
    return content[1:]


def named_bits(element: Element) -> tuple[bool, ...]:
    """Decode a BIT STRING as a named bit list, bit 0 first.

    The unused bits must be zero. Trailing zero bits that DER would trim
    are accepted, because production CA certificates carry them.
    """
    content = _expect_primitive(element, TAG_BIT_STRING, "BIT STRING")
    unused = _check_bit_string(content)
    body = content[1:]
    bits: list[bool] = []
    for index, octet in enumerate(body):
        last_octet = index == len(body) - 1
        for shift in range(7, (unused if last_octet else 0) - 1, -1):
            bits.append(bool(octet >> shift & 1))
    return tuple(bits)


def octet_string(element: Element) -> bytes:
    """The content of a primitive OCTET STRING."""
    return _expect_primitive(element, TAG_OCTET_STRING, "OCTET STRING")


def object_identifier(element: Element) -> str:
    """Decode an OBJECT IDENTIFIER to dotted-decimal, rejecting non-minimal subidentifiers."""
    content = _expect_primitive(element, TAG_OBJECT_IDENTIFIER, "OBJECT IDENTIFIER")
    if not content:
        raise DerError("OBJECT IDENTIFIER has no content")
    if content[-1] & 0x80:
        raise DerError("OBJECT IDENTIFIER is truncated")
    arcs: list[int] = []
    value = 0
    start = True
    for octet in content:
        if start and octet == 0x80:
            raise DerError("OBJECT IDENTIFIER sub-identifier is not minimally encoded")
        value = (value << 7) | (octet & 0x7F)
        start = not octet & 0x80
        if start:
            arcs.append(value)
            value = 0
    first = arcs[0]
    lead = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(arc) for arc in [*lead, *arcs[1:]])


def ia5_string(element: Element) -> str:
    """Decode an IA5String, rejecting bytes above 0x7F."""
    content = _expect_primitive(element, TAG_IA5_STRING, "IA5String")
    if any(octet > 0x7F for octet in content):
        raise DerError("IA5String contains a byte above 0x7F")
    return content.decode("ascii")


def utf8_string(element: Element) -> str:
    """Decode a UTF8String, rejecting invalid UTF-8."""
    content = _expect_primitive(element, TAG_UTF8_STRING, "UTF8String")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as err:
        raise DerError("UTF8String is not valid UTF-8") from err


def time(element: Element, *, fractional_seconds: bool = False) -> datetime:
    """Decode a UTCTime or GeneralizedTime to an aware UTC datetime.

    Both forms must end in ``Z`` and carry seconds. UTCTime years map
    50-99 to 1950-1999 and 00-49 to 2000-2049. GeneralizedTime accepts a
    fraction only when ``fractional_seconds`` is set (RFC 3161 genTime),
    with no trailing zeros and at most nine digits; digits beyond six are
    truncated to the microsecond.
    """
    if element.tag_class != CLASS_UNIVERSAL or element.constructed:
        raise DerError("expected UTCTime or GeneralizedTime")
    fraction = b""
    if element.tag == TAG_UTC_TIME:
        match = _UTC_TIME.match(element.content)
        if match is None:
            raise DerError("UTCTime must be YYMMDDHHMMSSZ")
        year = int(match[1])
        year += 1900 if year >= 50 else 2000
    elif element.tag == TAG_GENERALIZED_TIME:
        match = _GENERALIZED_TIME.match(element.content)
        if match is None:
            raise DerError("GeneralizedTime must be YYYYMMDDHHMMSS[.fff]Z")
        year = int(match[1])
        fraction = match[7] or b""
        if fraction:
            if not fractional_seconds:
                raise DerError("time must be whole seconds")
            if fraction.endswith(b"0"):
                raise DerError("fractional seconds must omit trailing zeros")
    else:
        raise DerError("expected UTCTime or GeneralizedTime")
    microsecond = int(fraction[:6].ljust(6, b"0")) if fraction else 0
    try:
        return datetime(
            year, int(match[2]), int(match[3]), int(match[4]), int(match[5]), int(match[6]), microsecond, tzinfo=UTC
        )
    except ValueError as err:
        raise DerError("time is not a valid calendar date") from err


def pem_blocks(pem: str, label: str) -> tuple[bytes, ...]:
    """Decode every PEM block with ``label`` (for example ``CERTIFICATE``) in order.

    A block with another label, an empty block, malformed base64 or
    non-whitespace text outside the blocks is an error.
    """
    out: list[bytes] = []
    body: list[str] | None = None
    for raw_line in pem.splitlines():
        line = raw_line.strip()
        boundary = _PEM_BOUNDARY.match(line)
        if body is None:
            if not line:
                continue
            if boundary is None:
                raise DerError("text outside PEM blocks")
            if boundary[1] != "BEGIN" or boundary[2] != label:
                raise DerError(f"PEM block is not a {label}")
            body = []
        elif boundary is not None:
            if boundary[1] != "END" or boundary[2] != label:
                raise DerError(f"unexpected boundary inside {label} block")
            text = "".join(body)
            if not text:
                raise DerError(f"empty {label} block")
            out.append(_base64(text))
            body = None
        elif line:
            body.append(line)
    if body is not None:
        raise DerError(f"unterminated {label} block")
    return tuple(out)


def _base64(text: str) -> bytes:
    """Standard base64 with padding; the round trip rejects padding bits that are not zero."""
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as err:
        raise DerError("PEM body is not valid base64") from err
    if base64.b64encode(decoded).decode("ascii") != text:
        raise DerError("PEM body is not canonical base64")
    return decoded


def ecdsa_signature_to_raw(der: bytes, coordinate_bytes: int) -> bytes:
    """Convert a DER ECDSA-Sig-Value to the fixed-width ``r || s`` encoding of ``2 * coordinate_bytes`` bytes."""
    parts = expect_sequence(decode(der), "ECDSA signature")
    if len(parts) != 2:
        raise DerError("ECDSA signature must hold exactly r and s")
    out = bytearray(2 * coordinate_bytes)
    for index, part in enumerate(parts):
        value = integer(part)
        if value <= 0:
            raise DerError("ECDSA signature component is not positive")
        magnitude = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if len(magnitude) > coordinate_bytes:
            raise DerError("ECDSA signature component exceeds the coordinate size")
        end = (index + 1) * coordinate_bytes
        out[end - len(magnitude) : end] = magnitude
    return bytes(out)


def raw_signature_to_der(raw: bytes, coordinate_bytes: int) -> bytes:
    """Convert a fixed-width ``r || s`` ECDSA signature to a DER ECDSA-Sig-Value."""
    if len(raw) != 2 * coordinate_bytes:
        raise DerError(f"raw ECDSA signature must be {2 * coordinate_bytes} bytes")
    body = b"".join(
        _encode_integer(int.from_bytes(raw[i : i + coordinate_bytes], "big")) for i in (0, coordinate_bytes)
    )
    return bytes([0x30]) + encode_length(len(body)) + body


def encode_length(length: int) -> bytes:
    """The DER length octets for ``length``."""
    if length < 0x80:
        return bytes([length])
    octets = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def _encode_integer(value: int) -> bytes:
    magnitude = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if magnitude[0] & 0x80:
        magnitude = b"\x00" + magnitude
    return bytes([TAG_INTEGER]) + encode_length(len(magnitude)) + magnitude
