"""Byte-level primitives shared by the v3 verifier: strict lowercase-hex and
canonical-base64 decoding, mirroring Go's encoding/hex and encoding/base64
semantics. All errors are ValueError; the calling module assigns the
rejection layer."""

import base64
import binascii
import re

_LOWER_HEX_RE = re.compile(r"^[0-9a-f]*$")
_ANY_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

# Standard base64 with mandatory padding; matches Go's accepted token shape.
_BASE64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)


def is_lower_hex(value: str) -> bool:
    return _LOWER_HEX_RE.fullmatch(value) is not None


def decode_hex(value: str) -> bytes:
    """Mirror Go hex.DecodeString: either case, even length required, no
    whitespace (bytes.fromhex alone would skip spaces)."""
    if _ANY_HEX_RE.fullmatch(value) is None or len(value) % 2 != 0:
        raise ValueError("invalid hex string")
    return bytes.fromhex(value)


def decode_lower_hex(name: str, value: str, want_len: int) -> bytes:
    """Decode a required lowercase hex field of an exact byte length."""
    if not is_lower_hex(value):
        raise ValueError(f"{name} is not lowercase hex")
    if len(value) % 2 != 0:
        raise ValueError(f"{name} is not hex: odd length hex string")
    b = bytes.fromhex(value)
    if len(b) != want_len:
        raise ValueError(f"{name} must be {want_len} bytes, got {len(b)}")
    return b


def decode_base64(value: str) -> bytes:
    """Mirror Go base64.StdEncoding.DecodeString: standard alphabet, padding
    required, \\r and \\n skipped, non-canonical padding bits tolerated."""
    stripped = value.replace("\r", "").replace("\n", "")
    if _BASE64_RE.fullmatch(stripped) is None:
        raise ValueError("invalid base64 string")
    try:
        return binascii.a2b_base64(stripped.encode("ascii"))
    except (binascii.Error, ValueError) as e:  # pragma: no cover - regex gates
        raise ValueError(f"invalid base64 string: {e}") from None


def decode_canonical_base64(name: str, value: str) -> bytes:
    """Decode a required standard-base64 field and reject non-canonical
    encodings: the round-trip comparison guarantees exactly one accepted
    encoding per byte string."""
    if _BASE64_RE.fullmatch(value) is None:
        raise ValueError(f"decoding {name}: illegal base64 data")
    b = binascii.a2b_base64(value.encode("ascii"))
    if base64.b64encode(b).decode("ascii") != value:
        raise ValueError(f"{name} is not canonical base64")
    return b
