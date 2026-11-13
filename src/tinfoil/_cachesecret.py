"""The ``user_cache_secret`` that scopes the prompt cache to one user: its resolution, the requests that carry it,
and its injection into a request body.

The router derives the request's prefix-cache namespace from the field:
requests carrying the same secret under the same API identity share cached
prompt prefixes, and requests carrying different secrets cannot observe
each other's cache timing. Clients for Tinfoil's inference routes resolve
it in this order; a client for an explicit enclave uses only the first two,
since other enclaves do not read the field:

1. a non-empty per-request ``user_cache_secret`` field in the body,
2. the client's ``user_cache_secret`` option,
3. a random secret that is generated in memory once per process and shared by
   every client in the process.

The SDK reads no environment variable or file for the secret. The generated
secret lasts only as long as the process, so applications that want a
stable secret across processes or machines pass ``user_cache_secret``
themselves.

Injection happens in the transport, before the body is sealed or sent over
the pinned connection, so the secret is only ever visible to the verified
enclave.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
from dataclasses import dataclass

logger = logging.getLogger("tinfoil")

FIELD = "user_cache_secret"
"""The router-only request-body field. A non-empty string scopes the prompt cache to that secret."""
CACHE_SALT_FIELD = "cache_salt"
"""The field a gateway client derives from the secret instead of sending it."""
MODEL_FIELD = "model"
_PATHS = ("/chat/completions", "/completions", "/responses")
"""The OpenAI-compatible endpoints whose bodies carry the field, matched by suffix so that custom base URLs with
a path prefix or without a /v1 root qualify. Other endpoints do not prefix-cache and may reject unknown
fields."""

# The whitespace JSON allows around the top-level value (RFC 8259); str.strip's default would also accept
# characters that a strict parser rejects.
_JSON_WHITESPACE = " \t\n\r"

_DECODER = json.JSONDecoder()
"""Decodes member keys only; a key is a string, which never nests."""

MAX_NESTING = 10_000
"""The most containers a value may nest before the body is forwarded unchanged.

The value scanner tracks open containers on an explicit stack, so the depth
a body may reach is this cap on every interpreter rather than the
call-stack limit of a recursive decoder; the cap matches the nesting limit
of the strict document parser."""

# A JSON string token (RFC 8259): no raw control character, and only the eight single-character escapes and
# ``\uXXXX``, which may spell a lone surrogate. Possessive quantifiers keep a failed match linear in the text.
_STRING = re.compile(r'"(?:[^"\\\x00-\x1f]++|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*+"')
# A JSON number token. The fraction and exponent are optional as wholes, so ``1.`` and ``1e`` end after the
# integer part and the rest is left for the caller to reject.
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?")
_LITERALS = ("true", "false", "null")
"""The literal values. ``NaN`` and ``Infinity`` are not JSON and are not among them."""


def _scan_value(text: str, index: int) -> int | None:
    """The end offset of the JSON value that starts at ``index``, or None when no well-formed value starts there
    or the value nests containers deeper than ``MAX_NESTING``. Nothing is decoded; the open containers are
    tracked on an explicit stack so that depth never consumes the call stack."""
    closers: list[str] = []
    length = len(text)
    while True:
        # A value starts at index.
        if index >= length:
            return None
        char = text[index]
        if char in ("[", "{"):
            if len(closers) >= MAX_NESTING:
                return None
            closer = "]" if char == "[" else "}"
            index = _skip(text, index + 1)
            if index < length and text[index] == closer:
                index += 1
            else:
                closers.append(closer)
                if closer == "}":
                    key_end = _scan_key(text, index)
                    if key_end is None:
                        return None
                    index = key_end
                continue
        else:
            scalar_end = _scan_scalar(text, index)
            if scalar_end is None:
                return None
            index = scalar_end
        # A value ended at index: close the containers it completes, or carry on after a comma.
        while closers:
            index = _skip(text, index)
            if index >= length:
                return None
            char = text[index]
            if char == closers[-1]:
                closers.pop()
                index += 1
                continue
            if char != ",":
                return None
            index = _skip(text, index + 1)
            if closers[-1] == "}":
                key_end = _scan_key(text, index)
                if key_end is None:
                    return None
                index = key_end
            break
        else:
            return index


def _scan_key(text: str, index: int) -> int | None:
    """The offset after an object member's key and its colon, with the whitespace around them, or None."""
    key = _STRING.match(text, index)
    if key is None:
        return None
    index = _skip(text, key.end())
    if index >= len(text) or text[index] != ":":
        return None
    return _skip(text, index + 1)


def _scan_scalar(text: str, index: int) -> int | None:
    """The end offset of the string, number or literal at ``index``, or None."""
    if text[index] == '"':
        string = _STRING.match(text, index)
        return None if string is None else string.end()
    number = _NUMBER.match(text, index)
    if number is not None:
        return number.end()
    for literal in _LITERALS:
        if text.startswith(literal, index):
            return index + len(literal)
    return None


def path_eligible(method: str, path: str) -> bool:
    """Whether a request can carry the field: a POST to one of the supported endpoints."""
    return method.upper() == "POST" and path.endswith(_PATHS)


@dataclass(frozen=True, slots=True)
class Member:
    """One top-level member of a JSON object text: its decoded key and the spans of its key and value."""

    key: str
    key_start: int
    value_start: int
    value_end: int


def scan_object(text: str) -> list[Member] | None:
    """The top-level members of ``text``, which must be exactly one JSON object with optional JSON whitespace
    around it, in order; None for anything else, including trailing data and malformed nested values. Keys are
    decoded, so an escaped spelling of a name matches it."""
    i = _skip(text, 0)
    if i >= len(text) or text[i] != "{":
        return None
    members: list[Member] = []
    i = _skip(text, i + 1)
    if i < len(text) and text[i] == "}":
        return members if _skip(text, i + 1) == len(text) else None
    while True:
        i = _skip(text, i)
        if i >= len(text) or text[i] != '"':
            return None
        try:
            key, key_end = _DECODER.raw_decode(text, i)
        except ValueError:
            return None
        if not isinstance(key, str):  # pragma: no cover - a quote always decodes to a string
            return None
        j = _skip(text, key_end)
        if j >= len(text) or text[j] != ":":
            return None
        value_start = _skip(text, j + 1)
        value_end = _scan_value(text, value_start)
        if value_end is None:
            return None
        members.append(Member(key, i, value_start, value_end))
        i = _skip(text, value_end)
        if i >= len(text):
            return None
        if text[i] == ",":
            i += 1
            continue
        if text[i] == "}":
            return members if _skip(text, i + 1) == len(text) else None
        return None


def has_duplicates(members: list[Member], *keys: str) -> bool:
    """Whether any of ``keys`` appears more than once among ``members``."""
    return any(sum(1 for member in members if member.key == key) > 1 for key in keys)


def inject(raw: bytes, secret: str) -> bytes | None:
    """``raw`` with ``secret`` as its ``user_cache_secret`` member, or None when the body must be forwarded
    unchanged: it is not one JSON object, it carries trailing data, or it already carries the field as a non-empty
    string, as a non-string, or more than once. An empty string is replaced. The field is spliced into the text,
    so everything the caller sent, including number precision, stays byte-identical. A body with a repeated
    ``model`` or ``cache_salt`` member is forwarded unchanged as well."""
    if not secret or not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    members = scan_object(text)
    if members is None or has_duplicates(members, FIELD, MODEL_FIELD, CACHE_SALT_FIELD):
        return None
    value = json.dumps(secret)
    existing = [member for member in members if member.key == FIELD]
    if existing:
        member = existing[0]
        if text[member.value_start : member.value_end] != '""':
            return None
        return (text[: member.value_start] + value + text[member.value_end :]).encode()
    close = text.rindex("}")
    comma = "," if members else ""
    return f'{text[:close]}{comma}"{FIELD}":{value}{text[close:]}'.encode()


def _skip(text: str, index: int) -> int:
    while index < len(text) and text[index] in _JSON_WHITESPACE:
        index += 1
    return index


def resolve(explicit: str | None) -> str:
    """The client-level secret: a non-empty ``explicit`` value wins, otherwise the secret that this process
    generated, which is the same for every client in the process."""
    if explicit:
        return explicit
    return _process_secret_value()


def _new_secret() -> str:
    """A fresh 256-bit random secret, hex-encoded; empty when secure random generation fails."""
    try:
        return secrets.token_hex(32)
    except Exception as err:  # pragma: no cover - the OS random source failing
        logger.warning(
            "tinfoil: could not generate a user cache secret; automatic prompt-cache scoping is unavailable: %s", err
        )
        return ""


_process_lock = threading.Lock()
_process_secret: str | None = None


def _process_secret_value() -> str:
    """The secret that this process generates on first use and keeps for its lifetime. It isolates the
    process's cache namespace; prompt-cache continuity resets when the process exits."""
    global _process_secret
    with _process_lock:
        if _process_secret is None:
            _process_secret = _new_secret()
        return _process_secret


__all__ = [
    "CACHE_SALT_FIELD",
    "FIELD",
    "MODEL_FIELD",
    "Member",
    "has_duplicates",
    "inject",
    "path_eligible",
    "resolve",
    "scan_object",
]
