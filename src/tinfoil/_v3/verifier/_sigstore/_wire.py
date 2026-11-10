"""Decoding rules shared by the trusted-root and bundle decoders.

Both documents are protobuf messages in their JSON form. ``sigstore_models``
validates the shape; the helpers here supply the stricter value rules:
member names in their JSON form only, 64-bit integers as decimal strings,
RFC 3339 times with a zone, and the key type names that the verifier
accepts.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import ValidationError

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._x509.certificate import PublicKey

_RFC3339 = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})\Z")
_DECIMAL = re.compile(r"\A(?:0|[1-9][0-9]*)\Z")
_MAX_INT64 = (1 << 63) - 1

KEY_DETAILS_P256 = "PKIX_ECDSA_P256_SHA_256"
KEY_DETAILS_P384 = "PKIX_ECDSA_P384_SHA_384"
KEY_DETAILS_ED25519 = "PKIX_ED25519"


class WireError(ValueError):
    """A wire value outside the accepted form."""


def check_member_names(value: _json.JsonValue) -> None:
    """Reject any object member name that contains an underscore, at every depth.

    Protobuf JSON decoders accept each field under its original name as
    well as its JSON name; only the JSON (lowerCamelCase) names are accepted
    here, so that one document has one spelling.
    """
    if isinstance(value, _json.JsonObject):
        for name, member in value.items():
            if "_" in name:
                raise WireError(f"member name {name!r} is not the JSON field name")
            check_member_names(member)
    elif isinstance(value, tuple):
        for item in value:
            check_member_names(item)


def first_error(err: ValidationError) -> str:
    """A one-line description of the first schema violation."""
    errors = err.errors()
    if not errors:
        return "invalid"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    return f"{location}: {first.get('msg', 'invalid')}" if location else str(first.get("msg", "invalid"))


def uint64(obj: _json.JsonObject, key: str) -> int | None:
    """A 64-bit integer member written as a decimal string, as protobuf JSON writes it; absent or null is None.

    The value must be non-negative and fit a signed 64-bit integer.
    """
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not _DECIMAL.match(value):
        raise WireError(f"member {key!r} is not a non-negative decimal string")
    number = int(value)
    if number > _MAX_INT64:
        raise WireError(f"member {key!r} overflows int64")
    return number


def rfc3339(text: str, what: str) -> datetime:
    """Parse an RFC 3339 time with a ``Z`` or numeric offset into an aware UTC datetime.

    Up to nine fractional digits are accepted; digits beyond the sixth are
    truncated to the microsecond.
    """
    match = _RFC3339.match(text)
    if match is None:
        raise WireError(f"{what} is not an RFC 3339 time with a zone")
    fraction = match[7] or ""
    microsecond = int(fraction[:6].ljust(6, "0")) if fraction else 0
    zone = match[8]
    if zone == "Z":
        offset = timedelta(0)
    else:
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        if hours > 23 or minutes > 59:
            raise WireError(f"{what} has an invalid zone offset")
        offset = timedelta(hours=hours, minutes=minutes)
        if zone[0] == "-":
            offset = -offset
    try:
        local = datetime(
            int(match[1]),
            int(match[2]),
            int(match[3]),
            int(match[4]),
            int(match[5]),
            int(match[6]),
            microsecond,
            tzinfo=timezone(offset),
        )
    except ValueError as err:
        raise WireError(f"{what} is not a valid calendar time") from err
    return local.astimezone(UTC)


def key_details_of(key: PublicKey) -> str | None:
    """The protobuf key-details name of a key, or None for a key type that no log may use."""
    if isinstance(key, ec.EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP256R1):
            return KEY_DETAILS_P256
        if isinstance(key.curve, ec.SECP384R1):
            return KEY_DETAILS_P384
        return None
    if isinstance(key, ed25519.Ed25519PublicKey):
        return KEY_DETAILS_ED25519
    return None
