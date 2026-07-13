"""
Provisions the per-user prompt-cache secret defined by the secure prompt
caching contract. The router derives the request's prefix-cache namespace from
the `user_cache_secret` body field: requests carrying the same secret (under
the same API identity) share cached prompt prefixes, requests carrying
different secrets cannot observe each other's cache timing. The secret itself
is stripped by the router and never reaches the model.

Resolution order, mirroring the other Tinfoil clients:

1. an explicit per-request `user_cache_secret` field in the body (never
   overwritten here),
2. the `user_cache_secret` client parameter,
3. the TINFOIL_USER_CACHE_SECRET environment variable,
4. a generated secret persisted at ~/.tinfoil/user_cache_secret (0600), shared
   with the other Tinfoil SDKs on the same machine.

Injection happens in the transport, before the EHBP (or pinned-TLS) transport
seals the body, so the secret is only ever visible to the verified enclave.
"""

import json
import logging
import os
import secrets
import stat
import tempfile
import threading
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("tinfoil")

# USER_CACHE_SECRET_FIELD is the router-only request-body field. A non-empty
# string scopes the prompt cache to that secret; an absent or empty value
# leaves the request in the tenant-wide namespace.
USER_CACHE_SECRET_FIELD = "user_cache_secret"

# USER_CACHE_SECRET_ENV provisions the secret via the environment. Setting it
# to an empty string disables generation entirely (tenant-wide caching), which
# is the right call for pooled multi-user deployments that would otherwise
# mint a fresh namespace per container.
USER_CACHE_SECRET_ENV = "TINFOIL_USER_CACHE_SECRET"

# The persisted-secret path under the home directory. The other Tinfoil SDKs
# use the same file, so one machine gets one cache namespace across tools.
USER_CACHE_SECRET_DIR_NAME = ".tinfoil"
USER_CACHE_SECRET_FILE_NAME = "user_cache_secret"
_USER_CACHE_SECRET_DIR_MODE = 0o700

# The OpenAI-compatible endpoints whose bodies carry the field. Matched by
# suffix with no /v1 prefix required, so custom base URLs (path-prefixed
# proxies or /v1-less roots) still qualify. Other endpoints (embeddings,
# audio, files) are excluded: their engines do not prefix-cache and may
# reject unknown fields.
_USER_CACHE_SECRET_PATHS = (
    "/chat/completions",
    "/completions",
    "/responses",
)

# JSON's whitespace set (RFC 8259): the only bytes allowed to trail the body's
# top-level object. Python's str.strip() default would also accept characters
# a strict JSON parser rejects.
_JSON_WHITESPACE = " \t\n\r"

# Unicode White_Space property, shared by the other SDK runtimes. Python's
# str.strip() additionally removes U+001C through U+001F, which are secret data.
_UNICODE_WHITESPACE = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)


def resolve_user_cache_secret(explicit: Optional[str]) -> str:
    """
    Resolve the client-level secret: the explicit parameter wins (None means
    unset; an empty string disables provisioning entirely), then the
    environment, then the persisted (or generated) secret. An empty result
    means injection is disabled and requests stay in the tenant-wide cache
    namespace. Never raises: persistence and generation failures fall back as
    documented on the helpers below.
    """
    if explicit is not None:
        return explicit
    env = os.environ.get(USER_CACHE_SECRET_ENV)
    if env is not None:
        return env
    return _load_or_generate_user_cache_secret()


def _new_user_cache_secret() -> str:
    """Return a fresh 256-bit random secret, hex-encoded."""
    try:
        return secrets.token_hex(32)
    except Exception as e:
        # Never fall back to a weak secret: no secret means tenant-wide
        # caching, which is safe.
        logger.warning(
            "tinfoil: could not generate a user cache secret; requests stay "
            "in the tenant-wide cache namespace: %s",
            e,
        )
        return ""


# Process-lifetime fallback state for when the secret cannot be persisted; see
# _ephemeral_user_cache_secret.
_ephemeral_lock = threading.Lock()
_ephemeral_secret: Optional[str] = None


def _ephemeral_user_cache_secret() -> str:
    """
    The process-lifetime fallback for when the secret cannot be persisted. An
    unpersisted secret still isolates this process's cache namespace, but
    continuity is lost on restart — like a session ID, it silently resets the
    namespace every deploy — so the fallback warns once per process.
    """
    global _ephemeral_secret
    with _ephemeral_lock:
        if _ephemeral_secret is None:
            secret = _new_user_cache_secret()
            if secret:
                logger.warning(
                    "tinfoil: could not persist the user cache secret; using "
                    "an in-memory secret, so prompt-cache continuity resets "
                    "when this process exits (set %s or the user_cache_secret "
                    "parameter to pin one)",
                    USER_CACHE_SECRET_ENV,
                )
            _ephemeral_secret = secret
        return _ephemeral_secret


def _user_cache_secret_path() -> Optional[Path]:
    """
    The persisted-secret path, or None when no home directory is available.
    Matching the other Tinfoil clients (Go's os.UserHomeDir), only the home
    environment variable is consulted — HOME, or USERPROFILE on Windows —
    and unset or empty counts as no home; the OS account database is never
    used, so scrubbed-environment daemons get the ephemeral fallback.
    """
    home = os.environ.get("USERPROFILE" if os.name == "nt" else "HOME")
    if not home:
        return None
    return Path(home) / USER_CACHE_SECRET_DIR_NAME / USER_CACHE_SECRET_FILE_NAME


def _load_or_generate_user_cache_secret() -> str:
    """
    Return the secret persisted under the user's home directory, generating
    and persisting one on first use. When the home directory is unavailable or
    unwritable it falls back to a process-lifetime in-memory secret.
    """
    path = _user_cache_secret_path()
    if path is None:
        return _ephemeral_user_cache_secret()

    # ValueError alongside OSError throughout: pathological paths (e.g. an
    # embedded null byte in $HOME) surface as ValueError, and resolution must
    # never crash client construction.
    try:
        if os.name == "nt":
            try:
                parent_stat = os.lstat(path.parent)
            except FileNotFoundError:
                parent_stat = None
            if parent_stat is not None and (
                not stat.S_ISDIR(parent_stat.st_mode)
                or _is_windows_reparse_point(parent_stat)
            ):
                return _ephemeral_user_cache_secret()
        path.parent.mkdir(
            mode=_USER_CACHE_SECRET_DIR_MODE, parents=True, exist_ok=True
        )
        if os.name == "nt":
            parent_stat = os.lstat(path.parent)
            if (
                not stat.S_ISDIR(parent_stat.st_mode)
                or _is_windows_reparse_point(parent_stat)
            ):
                return _ephemeral_user_cache_secret()
        else:
            directory_fd = _open_user_cache_secret_directory(path.parent)
            os.close(directory_fd)
    except (OSError, ValueError):
        return _ephemeral_user_cache_secret()

    existing, usable = _read_user_cache_secret(path)
    if not usable:
        return _ephemeral_user_cache_secret()
    if existing is not None:
        return existing

    secret = _new_user_cache_secret()
    if not secret:
        return ""
    return _persist_user_cache_secret(path, secret)


def _read_user_cache_secret(path: Path) -> tuple[Optional[str], bool]:
    """
    Return (secret, usable), trimming surrounding whitespace. A missing file
    is usable; a blank or invalid UTF-8 file is unusable and remains untouched.
    """
    fd, usable = _open_user_cache_secret(path)
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
            try:
                os.close(fd)
            except OSError:
                pass
    return (secret, True) if secret else (None, False)


def _open_user_cache_secret(path: Path) -> tuple[Optional[int], bool]:
    if os.name == "nt":
        try:
            path_stat = os.lstat(path)
        except FileNotFoundError:
            return None, True
        except (OSError, ValueError):
            return None, False
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or _is_windows_reparse_point(path_stat)
        ):
            return None, False

    flags = os.O_RDONLY
    if os.name != "nt":
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None:
            return None, False
        flags |= (
            no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
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
        try:
            os.close(fd)
        except OSError:
            pass
        return None, False
    return fd, True


def _is_windows_reparse_point(path_stat: os.stat_result) -> bool:
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(path_stat, "st_file_attributes", 0)
    return bool(reparse_point and file_attributes & reparse_point)


def _open_user_cache_secret_directory(path: Path) -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or no_follow is None:
        raise OSError("secure directory open flags are unavailable")
    flags = os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("cache secret parent is not a directory")
    except (OSError, ValueError):
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return fd


def _persist_user_cache_secret(path: Path, secret: str) -> str:
    """Elect one complete secret across concurrent processes."""
    candidate_path: Optional[Path] = None
    candidate_fd: Optional[int] = None
    try:
        candidate_fd, candidate_name = tempfile.mkstemp(
            prefix=f"{USER_CACHE_SECRET_FILE_NAME}.",
            suffix=".tmp",
            dir=path.parent,
        )
        candidate_path = Path(candidate_name)
        try:
            candidate = os.fdopen(candidate_fd, "w", encoding="utf-8")
            candidate_fd = None
            with candidate:
                candidate.write(secret)
        except (OSError, ValueError):
            if candidate_fd is not None:
                try:
                    os.close(candidate_fd)
                except (OSError, ValueError):
                    pass
            return _ephemeral_user_cache_secret()

        try:
            os.link(candidate_path, path)
        except FileExistsError:
            pass
        except (OSError, ValueError):
            return _ephemeral_user_cache_secret()

        persisted, usable = _read_user_cache_secret(path)
        if not usable or persisted is None:
            return _ephemeral_user_cache_secret()
        return persisted
    except (OSError, ValueError):
        return _ephemeral_user_cache_secret()
    finally:
        if candidate_fd is not None:
            try:
                os.close(candidate_fd)
            except (OSError, ValueError):
                pass
        if candidate_path is not None:
            try:
                candidate_path.unlink(missing_ok=True)
            except (OSError, ValueError):
                pass


class _UserCacheSecretTransport(httpx.BaseTransport):
    """
    Injects the client-level user_cache_secret into request bodies on the way
    out. It sits above the sealing transport (EHBP or pinned TLS), so the
    field is added before the body is sealed, and above the re-verifying retry
    layer, so retries beneath it (EHBP key rotation) replay the injected body.
    A field already present in the body is never overwritten — an explicit
    per-request value, including an explicit empty string (= opt out for that
    request), always wins.
    """

    def __init__(self, secret: str, inner: httpx.BaseTransport):
        self._secret = secret
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._inner.handle_request(
            _request_with_user_cache_secret(request, self._secret)
        )

    def close(self) -> None:
        self._inner.close()


class _AsyncUserCacheSecretTransport(httpx.AsyncBaseTransport):
    """Async counterpart to :class:`_UserCacheSecretTransport`."""

    def __init__(self, secret: str, inner: httpx.AsyncBaseTransport):
        self._secret = secret
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._inner.handle_async_request(
            await _async_request_with_user_cache_secret(request, self._secret)
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def _request_with_user_cache_secret(request: httpx.Request, secret: str) -> httpx.Request:
    """
    The request to forward: a copy whose body carries the injected field and
    whose Content-Length describes the injected bytes, or the original request
    untouched when injection does not apply (ineligible endpoint or method,
    empty secret or body, or a body the injection must not rewrite — see
    _body_with_user_cache_secret).
    """
    if not _request_eligible(request, secret):
        return request
    try:
        raw = request.content
    except httpx.RequestNotRead:
        return request
    return _request_with_user_cache_secret_body(request, secret, raw)


async def _async_request_with_user_cache_secret(
    request: httpx.Request, secret: str
) -> httpx.Request:
    """Async counterpart to :func:`_request_with_user_cache_secret`."""
    if not _request_eligible(request, secret):
        return request
    try:
        raw = request.content
    except httpx.RequestNotRead:
        return request
    return _request_with_user_cache_secret_body(request, secret, raw)


def _request_eligible(request: httpx.Request, secret: str) -> bool:
    return (
        bool(secret)
        and request.method == "POST"
        and _user_cache_secret_path_eligible(request.url.path)
    )


def _request_with_user_cache_secret_body(
    request: httpx.Request, secret: str, raw: bytes
) -> httpx.Request:
    if not raw:
        return request

    body = _body_with_user_cache_secret(raw, secret)
    if body is None:
        return request

    headers = request.headers.copy()
    headers.pop("Transfer-Encoding", None)
    headers["Content-Length"] = str(len(body))
    return httpx.Request(
        request.method,
        request.url,
        headers=headers,
        content=body,
        extensions=request.extensions,
    )


def _user_cache_secret_path_eligible(path: str) -> bool:
    """Whether the URL path names an endpoint whose body carries the field."""
    return path.endswith(_USER_CACHE_SECRET_PATHS)


def _body_with_user_cache_secret(raw: bytes, secret: str) -> Optional[bytes]:
    """
    The body with the field spliced in before the object's closing brace, or
    None — forward the original bytes — for non-object bodies, trailing data,
    or a body that already carries the field. Splicing instead of
    re-serializing keeps everything the caller sent byte-identical, including
    number precision: int64-range values such as seed would be corrupted by a
    float round-trip.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    start = len(text) - len(text.lstrip(_JSON_WHITESPACE))
    try:
        body, end = _STRICT_JSON_DECODER.raw_decode(text, start)
    except (ValueError, RecursionError):
        # RecursionError: CPython's json scanner recurses per nesting level
        # and gives up on pathologically deep bodies (Go's decoder errors at
        # its own depth limit) — forward them untouched like any other body
        # this layer cannot parse, never raise out of the transport.
        return None
    # Trailing whitespace is legal JSON framing and must not block injection;
    # anything else is trailing data the router-side parser would reject, so
    # a request the server rejects must not quietly become one it accepts.
    if not isinstance(body, dict) or text[end:].strip(_JSON_WHITESPACE):
        return None
    if USER_CACHE_SECRET_FIELD in body:
        return None
    field = f'"{USER_CACHE_SECRET_FIELD}":{json.dumps(secret)}'
    comma = "," if body else ""
    prefix, _, suffix = text.rpartition("}")
    return f"{prefix}{comma}{field}}}{suffix}".encode()


def _reject_json_constant(value: str) -> float:
    # NaN/Infinity are accepted by Python's json module but are not JSON;
    # treat them like any other malformed body and forward it untouched.
    raise ValueError(f"non-standard JSON constant: {value}")


_STRICT_JSON_DECODER = json.JSONDecoder(parse_constant=_reject_json_constant)
