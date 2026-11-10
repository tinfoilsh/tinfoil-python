"""A strict DER tokenizer for the structures that the verifier reads itself.

Only the subset that appears in certificates, CRLs, timestamp tokens and
vendor extensions is supported. Every accessor rejects an encoding that
DER forbids, so that one byte string has exactly one accepted encoding:
definite minimal lengths, minimal two's-complement integers, ``00``/``FF``
booleans, zero unused bits, times with a trailing ``Z`` and no fractional
seconds in UTCTime.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

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
TAG_UTF8_STRING = 12
TAG_SEQUENCE = 16
TAG_SET = 17
TAG_PRINTABLE_STRING = 19
TAG_IA5_STRING = 22
TAG_UTC_TIME = 23
TAG_GENERALIZED_TIME = 24

MAX_DEPTH = 32
"""The deepest nesting that ``children`` follows; deeper structures are rejected."""


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
    raise NotImplementedError


def decode_prefix(data: bytes) -> tuple[Element, bytes]:
    """Decode the element at the start of ``data`` and return it with the bytes that follow."""
    raise NotImplementedError


def children(element: Element) -> tuple[Element, ...]:
    """The elements inside a constructed element, in order, consuming its content exactly."""
    raise NotImplementedError


def is_universal(element: Element, tag: int) -> bool:
    """Whether the element is a universal, primitive-or-constructed element with ``tag``."""
    raise NotImplementedError


def is_context(element: Element, tag: int) -> bool:
    """Whether the element is context-specific with ``tag``."""
    raise NotImplementedError


def expect_sequence(element: Element, what: str) -> tuple[Element, ...]:
    """The children of a universal SEQUENCE; ``what`` names the structure in the error."""
    raise NotImplementedError


def integer(element: Element) -> int:
    """Decode an INTEGER, rejecting an empty content and non-minimal two's-complement encodings."""
    raise NotImplementedError


def boolean(element: Element) -> bool:
    """Decode a BOOLEAN, accepting only ``00`` and ``FF``."""
    raise NotImplementedError


def bit_string(element: Element) -> bytes:
    """Decode a BIT STRING with zero unused bits and return its bytes."""
    raise NotImplementedError


def octet_string(element: Element) -> bytes:
    """The content of a primitive OCTET STRING."""
    raise NotImplementedError


def object_identifier(element: Element) -> str:
    """Decode an OBJECT IDENTIFIER to dotted-decimal, rejecting non-minimal subidentifiers."""
    raise NotImplementedError


def ia5_string(element: Element) -> str:
    """Decode an IA5String, rejecting bytes above 0x7F."""
    raise NotImplementedError


def utf8_string(element: Element) -> str:
    """Decode a UTF8String, rejecting invalid UTF-8."""
    raise NotImplementedError


def time(element: Element, *, fractional_seconds: bool = False) -> datetime:
    """Decode a UTCTime or GeneralizedTime to an aware UTC datetime.

    Both forms must end in ``Z`` and carry seconds. UTCTime years map
    50-99 to 1950-1999 and 00-49 to 2000-2049. GeneralizedTime accepts a
    fraction only when ``fractional_seconds`` is set (RFC 3161 genTime),
    with no trailing zeros and at most nine digits; digits beyond six are
    truncated to the microsecond.
    """
    raise NotImplementedError


def pem_blocks(pem: str, label: str) -> tuple[bytes, ...]:
    """Decode every PEM block with ``label`` (for example ``CERTIFICATE``) in order.

    A block with another label, an empty block, malformed base64 or
    non-whitespace text outside the blocks is an error.
    """
    raise NotImplementedError


def ecdsa_signature_to_raw(der: bytes, coordinate_bytes: int) -> bytes:
    """Convert a DER ECDSA-Sig-Value to the fixed-width ``r || s`` encoding of ``2 * coordinate_bytes`` bytes."""
    raise NotImplementedError


def raw_signature_to_der(raw: bytes, coordinate_bytes: int) -> bytes:
    """Convert a fixed-width ``r || s`` ECDSA signature to a DER ECDSA-Sig-Value."""
    raise NotImplementedError
