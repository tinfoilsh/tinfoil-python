"""The attestation document's binary field encodings, accepting exactly one encoding per byte string."""

from __future__ import annotations

import base64
import binascii
import re

_LOWER_HEX = re.compile(r"[0-9a-f]*")


class EncodingError(ValueError):
    """A field that is not in its one accepted encoding."""


def is_lower_hex(value: str) -> bool:
    """Whether ``value`` contains only lowercase hex digits. Length parity is not checked."""
    return _LOWER_HEX.fullmatch(value) is not None


def decode_lower_hex(name: str, value: str, want_len: int) -> bytes:
    """Decode a required lowercase hex field of an exact byte length."""
    if not is_lower_hex(value):
        raise EncodingError(f"{name} is not lowercase hex")
    if len(value) % 2:
        raise EncodingError(f"{name} is not hex: odd length hex string")
    decoded = bytes.fromhex(value)
    if len(decoded) != want_len:
        raise EncodingError(f"{name} must be {want_len} bytes, got {len(decoded)}")
    return decoded


def decode_base64(name: str, value: str) -> bytes:
    """Decode a required standard-base64 field, rejecting every non-canonical encoding.

    Decoding skips line breaks and accepts non-zero padding bits; the round
    trip through the encoder is what guarantees one accepted encoding per
    byte string.
    """
    try:
        decoded = base64.b64decode(value.replace("\r", "").replace("\n", ""), validate=True)
    except (binascii.Error, ValueError) as err:
        raise EncodingError(f"decoding {name}: {err}") from err
    if base64.b64encode(decoded).decode("ascii") != value:
        raise EncodingError(f"{name} is not canonical base64")
    return decoded
