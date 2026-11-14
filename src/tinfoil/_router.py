"""Discovery of Tinfoil's router: the first router from Tinfoil's router list that verifies, and otherwise the
fallback host, which is left to be verified on first use."""

from __future__ import annotations

import json
import time
from collections.abc import Callable

from tinfoil._enclave import Enclave
from tinfoil._errors import ConfigurationError, TinfoilError, network_error
from tinfoil._fetch import get_bounded, get_bounded_async
from tinfoil._transport import AsyncAttestedTransport, AttestedTransport
from tinfoil._types import DEFAULT_HTTP_TIMEOUT, TimeoutTypes, VerificationCheck
from tinfoil.verifier import Verifier

# The router is published under one name in both namespaces, each owned by Tinfoil.
DEFAULT_ROUTER_NAME = "tinfoilsh/confidential-model-router"
"""The GitHub repository and the registry project every router is verified against."""
DEFAULT_ROUTER_URL = "https://atc.tinfoil.sh/routers"
"""Where the router list is fetched from."""
FALLBACK_HOST = "inference.tinfoil.sh"
"""The router used when the list is empty or no router on it verifies in time."""
ROUTER_FETCH_TIMEOUT = 30.0
DISCOVERY_TIMEOUT = 30.0
"""Bounds the router list fetch and every probe together, so a long list of unreachable routers cannot hold up a
client before it falls back."""
MAX_ROUTER_BYTES = 32 << 20


def fetch_routers(*, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None) -> list[str]:
    """The router list, bounded the same way an attestation fetch is: discovery runs before anything is verified,
    so an unresponsive or oversized reply must not stall client construction or exhaust memory. Raises
    NetworkError for a reply that is not a JSON array of strings."""
    body = get_bounded(
        DEFAULT_ROUTER_URL,
        timeout=timeout,
        deadline=deadline,
        overall=ROUTER_FETCH_TIMEOUT,
        max_bytes=MAX_ROUTER_BYTES,
    )
    return parse_routers(body)


async def fetch_routers_async(
    *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
) -> list[str]:
    """``fetch_routers`` on the event loop."""
    body = await get_bounded_async(
        DEFAULT_ROUTER_URL,
        timeout=timeout,
        deadline=deadline,
        overall=ROUTER_FETCH_TIMEOUT,
        max_bytes=MAX_ROUTER_BYTES,
    )
    return parse_routers(body)


def parse_routers(body: bytes) -> list[str]:
    """The router list in ``body``, which must be a JSON array of strings."""
    try:
        routers = json.loads(body)
    except (ValueError, RecursionError) as err:
        # Nesting deep enough to exhaust the decoder's recursion is as malformed as any other reply.
        raise network_error(f"decoding router list: {err}") from err
    if not isinstance(routers, list) or not all(isinstance(router, str) for router in routers):
        raise network_error("decoding router list: want a JSON array of strings")
    return routers


def discover(
    verifier: Verifier | None,
    check: VerificationCheck | None,
    new_transport: Callable[[Enclave], AttestedTransport],
    *,
    timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
) -> AttestedTransport:
    """The transport ``new_transport`` makes for the first router from Tinfoil's router list that verifies under
    ``verifier`` and passes ``check``, and otherwise for the fallback host, which it leaves to be verified on
    first use. None selects the default policy and accepts every router. It stops trying routers after
    ``DISCOVERY_TIMEOUT`` seconds."""
    fallback = Enclave(
        FALLBACK_HOST, DEFAULT_ROUTER_NAME, project=DEFAULT_ROUTER_NAME, verifier=verifier, verification_check=check
    )
    deadline = time.monotonic() + DISCOVERY_TIMEOUT
    try:
        routers = fetch_routers(timeout=timeout, deadline=deadline)
    except TinfoilError:
        routers = []
    for router in routers:
        if time.monotonic() >= deadline:
            break
        enclave = _candidate(router, fallback, check)
        if enclave is None:
            continue
        # The candidate keeps the verification, so the client doesn't repeat it, and a router whose keys the
        # mode can't use is skipped.
        candidate = new_transport(enclave)
        try:
            candidate.verify_once(timeout=timeout, deadline=deadline)
        except TinfoilError:
            candidate.close()
            continue
        except BaseException:
            # An interruption ends discovery; the candidate in flight must not outlive it.
            candidate.close()
            raise
        return candidate
    return new_transport(fallback)


async def discover_async(
    verifier: Verifier | None,
    check: VerificationCheck | None,
    new_transport: Callable[[Enclave], AsyncAttestedTransport],
    *,
    timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
) -> AsyncAttestedTransport:
    """``discover`` on the event loop. The task's cancellation ends discovery with it, without a fallback, and
    closes the candidate it was probing."""
    fallback = Enclave(
        FALLBACK_HOST, DEFAULT_ROUTER_NAME, project=DEFAULT_ROUTER_NAME, verifier=verifier, verification_check=check
    )
    deadline = time.monotonic() + DISCOVERY_TIMEOUT
    try:
        routers = await fetch_routers_async(timeout=timeout, deadline=deadline)
    except TinfoilError:
        routers = []
    for router in routers:
        if time.monotonic() >= deadline:
            break
        enclave = _candidate(router, fallback, check)
        if enclave is None:
            continue
        candidate = new_transport(enclave)
        try:
            await candidate.verify_once(timeout=timeout, deadline=deadline)
        except TinfoilError:
            await candidate.aclose()
            continue
        except BaseException:
            await candidate.aclose()
            raise
        return candidate
    return new_transport(fallback)


def _candidate(router: str, fallback: Enclave, check: VerificationCheck | None) -> Enclave | None:
    """``router`` as an enclave verified like the fallback, or None for an entry that is not a host: the list is
    untrusted, so a malformed entry is skipped rather than failing discovery."""
    try:
        return Enclave(
            router, fallback.repo, project=fallback.project, verifier=fallback.verifier, verification_check=check
        )
    except ConfigurationError:
        return None


__all__ = [
    "DEFAULT_ROUTER_NAME",
    "DEFAULT_ROUTER_URL",
    "DISCOVERY_TIMEOUT",
    "FALLBACK_HOST",
    "discover",
    "discover_async",
    "fetch_routers",
    "fetch_routers_async",
    "parse_routers",
]
