"""How a client obtains attestation documents and the router list: the ``fetch_attestation`` and
``fetch_router_list`` options, and the relays that implement them through an endpoint on another origin.

What a fetcher returns is not trusted. A client verifies a fetched document as it verifies one that it fetched
itself, so a fetcher can make verification fail but cannot make an enclave pass that would not pass otherwise; a
router list only proposes hosts, each of which discovery verifies before it uses it.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TypeAlias, final

from tinfoil._enclave import AsyncDocumentFetch, DocumentFetch
from tinfoil._errors import ConfigurationError, NetworkError, TinfoilError, network_error
from tinfoil._fetch import FETCH_TIMEOUT, fetch_document_at, fetch_document_at_async, relay_document_url
from tinfoil._router import AsyncRouterList, RouterList, fetch_routers, fetch_routers_async, relay_list_url
from tinfoil._types import DEFAULT_HTTP_TIMEOUT, TimeoutTypes
from tinfoil._url import validate_proxy_url

ATTESTATION_RELAY_URL = "attestation relay URL"
ROUTER_LIST_RELAY_URL = "router list relay URL"

AttestationFetcher: TypeAlias = Callable[[str, bytes], bytes]
"""A synchronous client's ``fetch_attestation``: called with the enclave's host, with an optional port, and the
fresh challenge nonce that the document must answer, and returns the raw document. It is called for every
verification: when the client is created, whenever it verifies again after an expiry or a key rotation, and, on
the router route, for each router that discovery tries and for the fallback. An exception that it raises is
reported as a NetworkError caused by it, unless it already is a client error. It should bound its own wait, since
the client cannot interrupt it; the client refuses a document that arrives after its deadline. It may be called
concurrently."""

AsyncAttestationFetcher: TypeAlias = Callable[[str, bytes], Awaitable[bytes]]
"""``AttestationFetcher`` for the asynchronous clients: it returns an awaitable, which the client cancels after 30
seconds or at the deadline of the verification, whichever comes first."""

RouterListFetcher: TypeAlias = Callable[[], Sequence[str]]
"""A synchronous router client's ``fetch_router_list``: returns the candidate router hosts in place of the list at
``https://atc.tinfoil.sh/routers``. The list is not trusted: discovery shuffles it, verifies each host before it
uses it, tries them for at most 30 seconds in all, and falls back to ``inference.tinfoil.sh`` when none passes. An
exception, or a value that is not a sequence of strings, counts as an empty list.

An attestation document does not name the host that serves it, so the list source is trusted not to name a host
that would relay another router's attestation: with EHBP, such a host would receive the request headers, including
the API key, although not the sealed bodies."""

AsyncRouterListFetcher: TypeAlias = Callable[[], Awaitable[Sequence[str]]]
"""``RouterListFetcher`` for the asynchronous router client."""


@final
@dataclass(frozen=True, slots=True)
class AttestationRelay:
    """A ``fetch_attestation`` that fetches documents through a relay, such as an endpoint on the application's own
    origin that forwards each request to the enclave that it names. A client in a browser with a strict content
    security policy, or one that should not reveal its IP address to enclaves, then reaches only that origin. It
    serves the synchronous and the asynchronous clients alike.

    It sends ``GET {url}/.well-known/tinfoil-attestation?nonce={nonce}&enclave={host}``,
    where ``nonce`` is the challenge in lowercase hex and ``host`` is
    query-escaped, with the SDK identity headers that a direct fetch sends,
    and takes the response body as the document. It applies the bounds of a
    direct fetch: 30 seconds, 32 MiB, and no redirect to a URL that is not
    HTTPS. The relay is not trusted, as for any fetcher.

    ``url`` is the relay's base URL. Its path, if any, is where the relay is
    mounted: the request path joins under it, whether or not it ends with
    ``/``. It must use HTTPS; ``http://`` is accepted only when its host is
    localhost or a loopback IP address. A URL with user information, a query
    or a fragment, even an empty one, is a ConfigurationError, which a client
    raises when it is created, before any network I/O.
    """

    url: str

    def fetch(
        self, host: str, nonce: bytes, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
    ) -> bytes:
        """The attestation document of ``host`` for ``nonce``, fetched through the relay."""
        return fetch_document_at(
            relay_document_url(validate_proxy_url(self.url, ATTESTATION_RELAY_URL), host, nonce),
            timeout=timeout,
            deadline=deadline,
        )

    async def fetch_async(
        self, host: str, nonce: bytes, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
    ) -> bytes:
        """``fetch`` on the event loop."""
        return await fetch_document_at_async(
            relay_document_url(validate_proxy_url(self.url, ATTESTATION_RELAY_URL), host, nonce),
            timeout=timeout,
            deadline=deadline,
        )


@final
@dataclass(frozen=True, slots=True)
class RouterListRelay:
    """A ``fetch_router_list`` that fetches the router list through a relay, such as an endpoint on the
    application's own origin that forwards the request to ``https://atc.tinfoil.sh/routers``. It serves the
    synchronous and the asynchronous router clients alike.

    It sends ``GET {url}/routers``, with the query parameters that a direct
    fetch sends, of which this client sends none, and parses the response as
    a direct fetch's: a JSON array of host strings of at most 32 MiB, fetched
    with no redirect to a URL that is not HTTPS. ``url`` follows the rules of
    ``AttestationRelay.url``.
    """

    url: str

    def fetch(self, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None) -> list[str]:
        """The router list, fetched through the relay."""
        url = relay_list_url(validate_proxy_url(self.url, ROUTER_LIST_RELAY_URL))
        return fetch_routers(timeout=timeout, deadline=deadline, url=url)

    async def fetch_async(
        self, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
    ) -> list[str]:
        """``fetch`` on the event loop."""
        url = relay_list_url(validate_proxy_url(self.url, ROUTER_LIST_RELAY_URL))
        return await fetch_routers_async(timeout=timeout, deadline=deadline, url=url)


def _checked_relay(relay: AttestationRelay | RouterListRelay, name: str) -> None:
    validate_proxy_url(relay.url, name)


def _require_callable(option: object, name: str, asynchronous: bool) -> None:
    if not callable(option):
        raise ConfigurationError(f"{name} must be a callable or a relay, not {type(option).__name__}")
    if not asynchronous and _is_async(option):
        raise ConfigurationError(f"{name} is asynchronous; pass it to the asynchronous client's create")


def _is_async(function: object) -> bool:
    call = getattr(type(function), "__dict__", {}).get("__call__")
    return inspect.iscoroutinefunction(function) or inspect.iscoroutinefunction(call)


def _document(value: object, name: str) -> bytes:
    """``value`` as a document; a fetcher that returns anything but bytes failed."""
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value)
    raise network_error(f"{name} returned {type(value).__name__}, not bytes")


def sync_document_fetch(option: object) -> DocumentFetch | None:
    """The document fetch that a synchronous client's ``fetch_attestation`` selects, or None for a direct fetch.
    A relay's URL is checked now, before any network I/O; anything that is neither a relay nor a synchronous
    callable is a ConfigurationError."""
    if option is None:
        return None
    if isinstance(option, AttestationRelay):
        _checked_relay(option, ATTESTATION_RELAY_URL)
        relay = option

        def relayed(host: str, nonce: bytes, timeout: TimeoutTypes, deadline: float | None) -> bytes:
            return relay.fetch(host, nonce, timeout=timeout, deadline=deadline)

        return relayed
    _require_callable(option, "fetch_attestation", asynchronous=False)
    fetcher: Callable[[str, bytes], object] = option  # type: ignore[assignment]

    def fetched(host: str, nonce: bytes, timeout: TimeoutTypes, deadline: float | None) -> bytes:
        try:
            value = fetcher(host, nonce)
        except TinfoilError:
            raise
        except Exception as err:
            raise network_error(err) from err
        if inspect.isawaitable(value):
            if inspect.iscoroutine(value):
                value.close()
            raise ConfigurationError("fetch_attestation returned an awaitable; pass it to the asynchronous client")
        return _document(value, "fetch_attestation")

    return fetched


def async_document_fetch(option: object) -> AsyncDocumentFetch | None:
    """``sync_document_fetch`` for the asynchronous clients, whose callable returns an awaitable. The awaitable is
    cancelled after ``FETCH_TIMEOUT`` seconds or at the deadline, whichever comes first, as a NetworkError; the
    caller's own cancellation passes through."""
    if option is None:
        return None
    if isinstance(option, AttestationRelay):
        _checked_relay(option, ATTESTATION_RELAY_URL)
        relay = option

        async def relayed(host: str, nonce: bytes, timeout: TimeoutTypes, deadline: float | None) -> bytes:
            return await relay.fetch_async(host, nonce, timeout=timeout, deadline=deadline)

        return relayed
    _require_callable(option, "fetch_attestation", asynchronous=True)
    fetcher: Callable[[str, bytes], object] = option  # type: ignore[assignment]

    async def fetched(host: str, nonce: bytes, timeout: TimeoutTypes, deadline: float | None) -> bytes:
        try:
            pending = fetcher(host, nonce)
            if not inspect.isawaitable(pending):
                raise ConfigurationError("fetch_attestation must return an awaitable on an asynchronous client")
            async with asyncio.timeout(_remaining(deadline)):
                value = await pending
        except TinfoilError:
            raise
        except TimeoutError as err:
            raise NetworkError(f"fetch_attestation did not return within {FETCH_TIMEOUT:g}s") from err
        except Exception as err:
            raise network_error(err) from err
        return _document(value, "fetch_attestation")

    return fetched


def _remaining(deadline: float | None) -> float:
    """The seconds left for a fetch: ``FETCH_TIMEOUT``, or less when ``deadline`` comes sooner."""
    remaining = FETCH_TIMEOUT
    if deadline is not None:
        remaining = min(remaining, deadline - time.monotonic())
    return max(remaining, 0.0)


def sync_router_list(option: object) -> RouterList | None:
    """The router-list source that a synchronous router client's ``fetch_router_list`` selects, or None for
    Tinfoil's list. Discovery counts any error from it as an empty list."""
    if option is None:
        return None
    if isinstance(option, RouterListRelay):
        _checked_relay(option, ROUTER_LIST_RELAY_URL)
        relay = option

        def relayed(timeout: TimeoutTypes, deadline: float | None) -> Sequence[str]:
            return relay.fetch(timeout=timeout, deadline=deadline)

        return relayed
    _require_callable(option, "fetch_router_list", asynchronous=False)
    fetcher: Callable[[], Sequence[str]] = option  # type: ignore[assignment]

    def listed(timeout: TimeoutTypes, deadline: float | None) -> Sequence[str]:
        return fetcher()

    return listed


def async_router_list(option: object) -> AsyncRouterList | None:
    """``sync_router_list`` for the asynchronous router client, bounded as ``async_document_fetch`` is."""
    if option is None:
        return None
    if isinstance(option, RouterListRelay):
        _checked_relay(option, ROUTER_LIST_RELAY_URL)
        relay = option

        async def relayed(timeout: TimeoutTypes, deadline: float | None) -> Sequence[str]:
            return await relay.fetch_async(timeout=timeout, deadline=deadline)

        return relayed
    _require_callable(option, "fetch_router_list", asynchronous=True)
    fetcher: Callable[[], Awaitable[Sequence[str]]] = option  # type: ignore[assignment]

    async def listed(timeout: TimeoutTypes, deadline: float | None) -> Sequence[str]:
        async with asyncio.timeout(_remaining(deadline)):
            return await fetcher()

    return listed


__all__ = [
    "AsyncAttestationFetcher",
    "AsyncRouterListFetcher",
    "AttestationFetcher",
    "AttestationRelay",
    "RouterListFetcher",
    "RouterListRelay",
    "async_document_fetch",
    "async_router_list",
    "sync_document_fetch",
    "sync_router_list",
]
