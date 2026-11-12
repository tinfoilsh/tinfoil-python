"""Retrieval of raw attestation documents from enclaves, and the bounded GET it is built on, which the router list
and the gateway catalog share. Nothing here parses a document; verification belongs to the verifier."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Iterator, Mapping
from urllib.parse import quote, urlsplit

import httpx

from tinfoil._errors import TinfoilError, configuration_error, network_error, wrap_network
from tinfoil._sdkinfo import attestation_headers
from tinfoil._types import DEFAULT_HTTP_TIMEOUT, TimeoutTypes
from tinfoil.verifier import NONCE_SIZE

ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation"
"""The path an enclave serves its attestation document on."""
FETCH_TIMEOUT = 30.0
"""The longest a document fetch may take as a whole, in seconds, whatever timeout the caller set for each
operation."""
MAX_DOCUMENT_BYTES = 32 << 20
"""The largest document a fetch accepts."""
MAX_REDIRECTS = 10
"""The most redirects a fetch follows; one more is refused."""

# The transports every fetch sends through when set; tests point them at a mock. None selects httpx's own.
_TRANSPORT: httpx.BaseTransport | None = None
_ASYNC_TRANSPORT: httpx.AsyncBaseTransport | None = None


def document_url(host: str, relay: str, nonce: bytes) -> str:
    """Where the attestation document of ``host`` is fetched with ``nonce``: from ``host`` itself, or from
    ``relay``, which forwards the request to ``host``, when ``relay`` is not empty. Both are a host with an
    optional port, not a URL. Raises ValueError for an input that cannot form the URL."""
    if not host:
        raise ValueError("enclave host is required")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    for authority in (host, relay):
        if authority and not is_authority(authority):
            raise ValueError(f"invalid host {authority!r}: want a host with an optional port")
    query = "nonce=" + nonce.hex()
    if relay:
        return f"https://{relay}{ATTESTATION_ENDPOINT}?{query}&enclave={quote(host, safe='')}"
    return f"https://{host}{ATTESTATION_ENDPOINT}?{query}"


def is_authority(value: str) -> bool:
    """Whether ``value`` is exactly the host of an HTTPS URL, with an optional port: not a URL, a path, a query or
    user information passed as a host."""
    parts = urlsplit(f"https://{value}")
    if (
        parts.scheme != "https"
        or parts.netloc != value
        or parts.username is not None
        or parts.password is not None
        or parts.path
        or parts.query
        or parts.fragment
        or not parts.hostname
    ):
        return False
    try:
        parts.port  # noqa: B018 - a port that does not parse raises
    except ValueError:
        return False
    return True


def fetch_document(
    host: str, relay: str, nonce: bytes, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
) -> bytes:
    """The raw attestation document that ``host`` serves for the challenge ``nonce``, fetched directly or through
    ``relay`` when that is not empty.

    One GET with the SDK identity headers over a fresh connection, so that a
    pooled connection cannot reach a replica that a cutover has drained.
    ``timeout`` bounds each connect, read and write; the fetch as a whole
    stops after ``FETCH_TIMEOUT`` seconds or at ``deadline`` (a
    ``time.monotonic`` instant), whichever comes first, and refuses a body
    over ``MAX_DOCUMENT_BYTES``. Redirects are followed up to
    ``MAX_REDIRECTS`` times, only to HTTPS URLs and never to a URL that
    carries user information. A URL that cannot be built is a
    ConfigurationError; everything else that fails is a NetworkError.
    """
    return get_bounded(
        _url(host, relay, nonce),
        timeout=timeout,
        deadline=deadline,
        overall=FETCH_TIMEOUT,
        max_bytes=MAX_DOCUMENT_BYTES,
        headers=attestation_headers(),
    )


async def fetch_document_async(
    host: str, relay: str, nonce: bytes, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
) -> bytes:
    """``fetch_document`` on the event loop."""
    return await get_bounded_async(
        _url(host, relay, nonce),
        timeout=timeout,
        deadline=deadline,
        overall=FETCH_TIMEOUT,
        max_bytes=MAX_DOCUMENT_BYTES,
        headers=attestation_headers(),
    )


def get_bounded(
    url: str,
    *,
    timeout: TimeoutTypes,
    deadline: float | None,
    overall: float,
    max_bytes: int,
    headers: Mapping[str, str] | None = None,
    ok: tuple[int, int] = (200, 299),
) -> bytes:
    """The body of a GET of ``url`` over a fresh connection pool, bounded in time (``overall`` seconds and
    ``deadline``) and size (``max_bytes``), following at most ``MAX_REDIRECTS`` redirects and only to HTTPS URLs
    without user information. Each request's own timeouts are recomputed from the time left when it is sent, so
    a redirect chain cannot carry the first request's budget past the deadline. A status outside ``ok`` is a
    NetworkError, as is everything else that fails."""
    bound = _Deadline(overall, deadline)
    try:
        with httpx.Client(transport=_TRANSPORT, timeout=timeout, follow_redirects=False, headers=headers) as client:
            request = client.build_request("GET", url)
            redirects = 0
            while True:
                bound.check(url, overall)
                bound.apply(request, timeout)
                response = client.send(request, stream=True)
                try:
                    if response.has_redirect_location:
                        redirects += 1
                        request = _redirect(response, redirects)
                        continue
                    _check_status(response, url, ok)
                    return _read(response.iter_bytes(), bound, url, overall, max_bytes)
                finally:
                    response.close()
    except TinfoilError:
        raise
    except Exception as err:
        raise wrap_network(err) from err


async def get_bounded_async(
    url: str,
    *,
    timeout: TimeoutTypes,
    deadline: float | None,
    overall: float,
    max_bytes: int,
    headers: Mapping[str, str] | None = None,
    ok: tuple[int, int] = (200, 299),
) -> bytes:
    """``get_bounded`` on the event loop."""
    bound = _Deadline(overall, deadline)
    try:
        async with httpx.AsyncClient(
            transport=_ASYNC_TRANSPORT, timeout=timeout, follow_redirects=False, headers=headers
        ) as client:
            request = client.build_request("GET", url)
            redirects = 0
            while True:
                bound.check(url, overall)
                bound.apply(request, timeout)
                response = await client.send(request, stream=True)
                try:
                    if response.has_redirect_location:
                        redirects += 1
                        request = _redirect(response, redirects)
                        continue
                    _check_status(response, url, ok)
                    return await _aread(response.aiter_bytes(), bound, url, overall, max_bytes)
                finally:
                    await response.aclose()
    except TinfoilError:
        raise
    except Exception as err:
        raise wrap_network(err) from err


class _Deadline:
    """The instant a fetch must have completed by: ``overall`` seconds from now, or ``deadline`` if sooner."""

    def __init__(self, overall: float, deadline: float | None) -> None:
        self.at = time.monotonic() + overall
        if deadline is not None:
            self.at = min(self.at, deadline)

    def check(self, url: str, overall: float) -> None:
        if time.monotonic() > self.at:
            raise network_error(f"HTTP GET {url}: no complete response within {overall:g}s")

    def timeout(self, timeout: TimeoutTypes) -> httpx.Timeout:
        """``timeout`` with each operation also capped at the time left now, so no single wait outlasts the
        deadline by more than the time left when the operation began."""
        remaining = max(self.at - time.monotonic(), 0.001)
        configured = httpx.Timeout(timeout)

        def cap(value: float | None) -> float:
            return remaining if value is None else min(value, remaining)

        return httpx.Timeout(
            connect=cap(configured.connect),
            read=cap(configured.read),
            write=cap(configured.write),
            pool=cap(configured.pool),
        )

    def apply(self, request: httpx.Request, timeout: TimeoutTypes) -> None:
        """Sets ``request``'s timeouts to ``timeout`` capped at the time left now. A redirect's request inherits
        the previous one's timeouts, so each is recomputed before it is sent."""
        request.extensions["timeout"] = self.timeout(timeout).as_dict()


def _url(host: str, relay: str, nonce: bytes) -> str:
    try:
        return document_url(host, relay, nonce)
    except ValueError as err:
        raise configuration_error(err) from err


def _redirect(response: httpx.Response, redirects: int) -> httpx.Request:
    """The request a redirect response leads to, refused when it leaves HTTPS, when its URL carries user
    information, or when ``redirects`` (this one included) exceeds ``MAX_REDIRECTS``. A refused URL is reported
    without its user information."""
    request = response.next_request
    if request is None:  # pragma: no cover - httpx builds it for every redirect location
        raise network_error("redirect without a target")
    redacted = request.url.copy_with(userinfo=b"")
    if request.url.scheme != "https":
        raise network_error(f"refusing redirect to non-HTTPS URL {redacted}")
    if request.url.userinfo:
        raise network_error(f"refusing redirect to a URL with user information: {redacted}")
    if redirects > MAX_REDIRECTS:
        raise network_error(f"stopped after {MAX_REDIRECTS} redirects")
    return request


def _check_status(response: httpx.Response, url: str, ok: tuple[int, int]) -> None:
    if not ok[0] <= response.status_code <= ok[1]:
        raise network_error(f"HTTP GET {url}: {response.status_code} {response.reason_phrase}")


def _read(chunks: Iterator[bytes], bound: _Deadline, url: str, overall: float, max_bytes: int) -> bytes:
    """The body ``chunks`` make up, refused before a chunk that would take it over ``max_bytes`` is kept. The
    chunks are taken as they arrive rather than re-chunked to a fixed size: a fixed size would hold back small
    chunks until it filled, and with them the deadline check that each chunk gets."""
    body = bytearray()
    for chunk in chunks:
        bound.check(url, overall)
        _check_size(body, chunk, url, max_bytes)
        body += chunk
    return bytes(body)


async def _aread(chunks: AsyncIterator[bytes], bound: _Deadline, url: str, overall: float, max_bytes: int) -> bytes:
    body = bytearray()
    async for chunk in chunks:
        bound.check(url, overall)
        _check_size(body, chunk, url, max_bytes)
        body += chunk
    return bytes(body)


def _check_size(body: bytearray, chunk: bytes, url: str, max_bytes: int) -> None:
    if len(body) + len(chunk) > max_bytes:
        raise network_error(f"response from {url} exceeds {max_bytes} bytes")


__all__ = [
    "ATTESTATION_ENDPOINT",
    "FETCH_TIMEOUT",
    "MAX_DOCUMENT_BYTES",
    "MAX_REDIRECTS",
    "document_url",
    "fetch_document",
    "fetch_document_async",
    "get_bounded",
    "get_bounded_async",
    "is_authority",
]
