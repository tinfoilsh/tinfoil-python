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
3. the ``TINFOIL_USER_CACHE_SECRET`` environment variable,
4. a generated secret persisted at ``~/.tinfoil/user_cache_secret``
   (mode 0600), shared with the other Tinfoil SDKs on the machine.

Injection happens in the transport, before the body is sealed or sent over
the pinned connection, so the secret is only ever visible to the verified
enclave.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import stat
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("tinfoil")

FIELD = "user_cache_secret"
"""The router-only request-body field. A non-empty string scopes the prompt cache to that secret."""
CACHE_SALT_FIELD = "cache_salt"
"""The field a gateway client derives from the secret instead of sending it."""
MODEL_FIELD = "model"
ENV = "TINFOIL_USER_CACHE_SECRET"
"""The environment variable that provisions the secret. An empty value is treated as unset."""
DIR_NAME = ".tinfoil"
FILE_NAME = "user_cache_secret"
_DIR_MODE = 0o700

_PATHS = ("/chat/completions", "/completions", "/responses")
"""The OpenAI-compatible endpoints whose bodies carry the field, matched by suffix so that custom base URLs with
a path prefix or without a /v1 root qualify. Other endpoints do not prefix-cache and may reject unknown
fields."""

# The whitespace JSON allows around the top-level value (RFC 8259); str.strip's default would also accept
# characters that a strict parser rejects.
_JSON_WHITESPACE = " \t\n\r"

# The Unicode White_Space property, shared by the other SDK runtimes. str.strip's default additionally removes
# U+001C through U+001F, which are secret data.
_UNICODE_WHITESPACE = "".join(
    chr(code)
    for code in (
        0x0009,
        0x000A,
        0x000B,
        0x000C,
        0x000D,
        0x0020,
        0x0085,
        0x00A0,
        0x1680,
        0x2000,
        0x2001,
        0x2002,
        0x2003,
        0x2004,
        0x2005,
        0x2006,
        0x2007,
        0x2008,
        0x2009,
        0x200A,
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
    )
)


def _reject_constant(value: str) -> float:
    # NaN and Infinity are accepted by the json module but are not JSON.
    raise ValueError(f"non-standard JSON constant: {value}")


_DECODER = json.JSONDecoder(parse_constant=_reject_constant)


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
        except (ValueError, RecursionError):
            return None
        if not isinstance(key, str):  # pragma: no cover - a quote always decodes to a string
            return None
        j = _skip(text, key_end)
        if j >= len(text) or text[j] != ":":
            return None
        value_start = _skip(text, j + 1)
        try:
            _, value_end = _DECODER.raw_decode(text, value_start)
        except (ValueError, RecursionError):
            # RecursionError: the scanner recurses per nesting level and gives up on pathologically deep bodies.
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
    """The client-level secret: a non-empty ``explicit`` value wins, then a non-empty environment value, then the
    persisted or generated secret. Never raises: persistence and generation failures fall back as documented on
    the helpers below."""
    if explicit:
        return explicit
    env = os.environ.get(ENV)
    if env:
        return env
    return _load_or_generate()


def _new_secret() -> str:
    """A fresh 256-bit random secret, hex-encoded; empty when secure random generation fails."""
    try:
        return secrets.token_hex(32)
    except Exception as err:  # pragma: no cover - the OS random source failing
        logger.warning(
            "tinfoil: could not generate a user cache secret; automatic prompt-cache scoping is unavailable: %s", err
        )
        return ""


_ephemeral_lock = threading.Lock()
_ephemeral_secret: str | None = None


def _ephemeral_secret_value() -> str:
    """The process-lifetime fallback for when the secret cannot be persisted. It still isolates this process's
    cache namespace, but continuity is lost on restart, so the fallback warns once per process."""
    global _ephemeral_secret
    with _ephemeral_lock:
        if _ephemeral_secret is None:
            secret = _new_secret()
            if secret:
                logger.warning(
                    "tinfoil: could not persist the user cache secret; using an in-memory secret, so prompt-cache "
                    "continuity resets when this process exits (set %s or the user_cache_secret option to pin one)",
                    ENV,
                )
            _ephemeral_secret = secret
        return _ephemeral_secret


def secret_path() -> Path | None:
    """The persisted-secret path, or None when no home directory is available. Only the home environment variable
    is consulted (HOME, or USERPROFILE on Windows), and unset or empty counts as no home, so a daemon with a
    scrubbed environment gets the in-memory fallback."""
    home = os.environ.get("USERPROFILE" if os.name == "nt" else "HOME")
    if not home:
        return None
    return Path(home) / DIR_NAME / FILE_NAME


def _load_or_generate() -> str:
    """The secret persisted under the home directory, generating and persisting one on first use. When the home
    directory is unavailable or unwritable, the in-memory fallback."""
    path = secret_path()
    if path is None:
        return _ephemeral_secret_value()
    # ValueError alongside OSError throughout: a pathological path, such as an embedded NUL in the home
    # variable, surfaces as ValueError, and resolution must never fail client construction.
    try:
        if os.name == "nt":
            try:
                parent_stat = os.lstat(path.parent)
            except FileNotFoundError:
                parent_stat = None
            if parent_stat is not None and not _is_plain_directory(parent_stat):
                return _ephemeral_secret_value()
        path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        if os.name == "nt":
            if not _is_plain_directory(os.lstat(path.parent)):
                return _ephemeral_secret_value()
        else:
            os.close(_open_directory(path.parent))
    except (OSError, ValueError):
        return _ephemeral_secret_value()

    existing, usable = _read(path)
    if not usable:
        return _ephemeral_secret_value()
    if existing is not None:
        return existing
    secret = _new_secret()
    if not secret:
        return ""
    return _persist(path, secret)


def _is_plain_directory(path_stat: os.stat_result) -> bool:
    return stat.S_ISDIR(path_stat.st_mode) and not _is_windows_reparse_point(path_stat)


def _read(path: Path) -> tuple[str | None, bool]:
    """``(secret, usable)`` with surrounding whitespace trimmed. A missing file is usable; a blank or invalid
    UTF-8 file is unusable and stays untouched."""
    fd, usable = _open(path)
    if fd is None:
        return None, usable
    try:
        with os.fdopen(fd, "rb") as secret_file:
            fd = None
            secret = secret_file.read().decode("utf-8").strip(_UNICODE_WHITESPACE)
    except (OSError, UnicodeDecodeError, ValueError):
        return None, False
    finally:
        if fd is not None:
            _close_quietly(fd)
    return (secret, True) if secret else (None, False)


def _open(path: Path) -> tuple[int | None, bool]:
    """A descriptor for the secret file, or None and whether a missing file was the reason. The file must be a
    regular file reached without following a symbolic link."""
    if os.name == "nt":
        try:
            path_stat = os.lstat(path)
        except FileNotFoundError:
            return None, True
        except (OSError, ValueError):
            return None, False
        if not stat.S_ISREG(path_stat.st_mode) or _is_windows_reparse_point(path_stat):
            return None, False
    flags = os.O_RDONLY
    if os.name != "nt":
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None:  # pragma: no cover - every supported POSIX platform has it
            return None, False
        flags |= no_follow | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, True
    except (OSError, ValueError):
        return None, False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None, False
    except (OSError, ValueError):
        _close_quietly(fd)
        return None, False
    return fd, True


def _is_windows_reparse_point(path_stat: os.stat_result) -> bool:
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(path_stat, "st_file_attributes", 0)
    return bool(reparse_point and file_attributes & reparse_point)


def _open_directory(path: Path) -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or no_follow is None:  # pragma: no cover - every supported POSIX platform has them
        raise OSError("secure directory open flags are unavailable")
    fd = os.open(path, os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("cache secret parent is not a directory")
    except (OSError, ValueError):
        _close_quietly(fd)
        raise
    return fd


def _persist(path: Path, secret: str) -> str:
    """Elects one complete secret across concurrent processes: a complete candidate is written to a unique
    temporary file, then linked to the destination; when the destination already exists, its value is adopted."""
    candidate_path: Path | None = None
    candidate_fd: int | None = None
    try:
        candidate_fd, candidate_name = tempfile.mkstemp(prefix=f"{FILE_NAME}.", suffix=".tmp", dir=path.parent)
        candidate_path = Path(candidate_name)
        try:
            candidate = os.fdopen(candidate_fd, "w", encoding="utf-8")
            candidate_fd = None
            with candidate:
                candidate.write(secret)
        except (OSError, ValueError):
            return _ephemeral_secret_value()
        try:
            os.link(candidate_path, path)
        except FileExistsError:
            pass
        except (OSError, ValueError):
            return _ephemeral_secret_value()
        persisted, usable = _read(path)
        if not usable or persisted is None:
            return _ephemeral_secret_value()
        return persisted
    except (OSError, ValueError):
        return _ephemeral_secret_value()
    finally:
        if candidate_fd is not None:
            _close_quietly(candidate_fd)
        if candidate_path is not None:
            with contextlib.suppress(OSError, ValueError):
                candidate_path.unlink(missing_ok=True)


def _close_quietly(fd: int) -> None:
    with contextlib.suppress(OSError):
        os.close(fd)


__all__ = [
    "CACHE_SALT_FIELD",
    "DIR_NAME",
    "ENV",
    "FIELD",
    "FILE_NAME",
    "MODEL_FIELD",
    "Member",
    "has_duplicates",
    "inject",
    "path_eligible",
    "resolve",
    "scan_object",
    "secret_path",
]
