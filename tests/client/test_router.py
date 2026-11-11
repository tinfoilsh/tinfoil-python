"""Router discovery with a mocked router list: the first router that verifies wins, failures and malformed entries
are skipped without a retry, the budget bounds every probe, an interruption closes the candidate being probed,
and the fallback is left unverified."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable

import httpx
import pytest

from tests.client.helpers import Recorder, response, verification
from tinfoil import _fetch, _router
from tinfoil._enclave import Enclave
from tinfoil._errors import ConfigurationError, NetworkError, network_error
from tinfoil._router import (
    DEFAULT_ROUTER_REPO,
    DEFAULT_ROUTER_URL,
    FALLBACK_HOST,
    discover,
    discover_async,
    fetch_routers,
    parse_routers,
)
from tinfoil._transport import CLIENT_CLOSED, AsyncAttestedTransport, AttestedTransport
from tinfoil.verifier import Verification

from .test_transport import AsyncFakeMode, FakeMode


@pytest.fixture
def atc(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    recorder = Recorder(lambda _: response(200, b'["router.example"]'))
    monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
    monkeypatch.setattr(_fetch, "_ASYNC_TRANSPORT", recorder.async_transport)
    return recorder


def probing(verdicts: dict[str, Exception | None], probes: list[str]) -> Callable[[Enclave], AttestedTransport]:
    """``new_transport`` whose enclaves verify by ``verdicts``: None passes, an exception fails."""

    def new_transport(enclave: Enclave) -> AttestedTransport:
        def fetch() -> Verification:
            probes.append(enclave.host)
            failure = verdicts.get(enclave.host, network_error("unreachable"))
            if failure is not None:
                raise failure
            return verification(enclave.host)

        test_enclave = Enclave(
            enclave.host, enclave.repo, verifier=enclave.verifier, verification_check=enclave._check, _fetch=fetch
        )
        return AttestedTransport(test_enclave, FakeMode())

    return new_transport


def test_parse_routers() -> None:
    assert parse_routers(b'["a.example", "b.example"]') == ["a.example", "b.example"]
    assert parse_routers(b"[]") == []
    for bad in (b"{}", b"[1]", b'["a", null]', b"not json", b'"a"'):
        with pytest.raises(NetworkError, match="router list"):
            parse_routers(bad)


def test_fetch_routers_refuses_insecure_redirects(atc: Recorder) -> None:
    for location, refused in (("https://mirror.example/routers", False), ("http://mirror.example/routers", True)):

        def handler(request: httpx.Request, location: str = location) -> httpx.Response:
            if str(request.url) == DEFAULT_ROUTER_URL:
                return response(302, headers={"Location": location})
            return response(200, b'["router.example"]')

        atc.handler = handler
        if refused:
            with pytest.raises(NetworkError, match="refusing redirect to non-HTTPS URL"):
                fetch_routers()
        else:
            assert fetch_routers() == ["router.example"]


def test_discovery_probes_each_router_once_and_falls_back(atc: Recorder) -> None:
    probes: list[str] = []
    atc.handler = lambda _: response(200, b'["a.example", "b.example"]')
    keyed = discover(None, None, probing({}, probes))
    assert keyed.enclave.host == FALLBACK_HOST
    assert keyed.enclave.repo == DEFAULT_ROUTER_REPO
    assert probes == ["a.example", "b.example"], "one candidate probe per router, no retry"
    assert keyed.current is None, "discovery leaves its fallback unverified"
    assert [str(r.url) for r in atc.requests] == [DEFAULT_ROUTER_URL]


def test_discovery_keeps_the_first_router_that_verifies(atc: Recorder) -> None:
    probes: list[str] = []
    atc.handler = lambda _: response(200, b'["a.example", "b.example", "c.example"]')
    keyed = discover(None, None, probing({"a.example": network_error("down"), "b.example": None}, probes))
    assert keyed.enclave.host == "b.example"
    assert probes == ["a.example", "b.example"]
    assert keyed.current is not None, "the candidate keeps its verification, so the client doesn't repeat it"


def test_discovery_skips_malformed_entries_and_bad_lists(atc: Recorder) -> None:
    probes: list[str] = []
    atc.handler = lambda _: response(200, b'["https://a.example", "user@b.example", "c.example"]')
    keyed = discover(None, None, probing({"c.example": None}, probes))
    assert keyed.enclave.host == "c.example"
    assert probes == ["c.example"]
    atc.handler = lambda _: response(200, b'{"not": "a list"}')
    assert discover(None, None, probing({}, probes)).enclave.host == FALLBACK_HOST
    atc.handler = lambda _: response(503)
    assert discover(None, None, probing({}, probes)).enclave.host == FALLBACK_HOST


def test_discovery_bounds_total_probe_time(atc: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    routers = [f"router{i}.example" for i in range(10)]
    atc.handler = lambda _: response(200, json.dumps(routers).encode())
    monkeypatch.setattr(_router, "DISCOVERY_TIMEOUT", 0.2)
    probes: list[str] = []

    def new_transport(enclave: Enclave) -> AttestedTransport:
        def fetch() -> Verification:
            probes.append(enclave.host)
            time.sleep(0.25)  # an unreachable router
            raise network_error("unreachable")

        return AttestedTransport(Enclave(enclave.host, enclave.repo, _fetch=fetch), FakeMode())

    start = time.monotonic()
    keyed = discover(None, None, new_transport)
    assert keyed.enclave.host == FALLBACK_HOST, "discovery falls back"
    assert time.monotonic() - start < 1.0, "one budget for every probe, not one per router"
    assert probes == ["router0.example"], "no router is probed after the budget runs out"


def test_discovery_uses_the_callers_policy(atc: Recorder) -> None:
    from tinfoil.verifier import Verifier

    shared = Verifier()
    seen: list[str] = []
    keyed = discover(shared, lambda v: seen.append(v.code_tag), probing({"router.example": None}, []))
    assert keyed.enclave.verifier is shared
    assert seen == ["router.example"], "the verification check sees each candidate"


@pytest.mark.asyncio
async def test_cancelled_discovery_closes_the_candidate_in_flight(atc: Recorder) -> None:
    probing_started = asyncio.Event()
    built: list[AsyncAttestedTransport] = []

    def new_transport(enclave: Enclave) -> AsyncAttestedTransport:
        async def fetch() -> Verification:
            probing_started.set()
            await asyncio.Event().wait()  # a router that never answers
            raise AssertionError("unreachable")

        built.append(AsyncAttestedTransport(Enclave(enclave.host, enclave.repo, _fetch_async=fetch), AsyncFakeMode()))
        return built[-1]

    discovery = asyncio.create_task(discover_async(None, None, new_transport))
    await probing_started.wait()
    discovery.cancel()
    with pytest.raises(asyncio.CancelledError):
        await discovery
    assert len(built) == 1
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        await built[0].ensure_verified()


def test_interrupted_discovery_closes_the_candidate_in_flight(atc: Recorder) -> None:
    built: list[AttestedTransport] = []

    def new_transport(enclave: Enclave) -> AttestedTransport:
        def fetch() -> Verification:
            raise KeyboardInterrupt

        built.append(AttestedTransport(Enclave(enclave.host, enclave.repo, _fetch=fetch), FakeMode()))
        return built[-1]

    with pytest.raises(KeyboardInterrupt):
        discover(None, None, new_transport)
    assert len(built) == 1
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        built[0].ensure_verified()


@pytest.mark.asyncio
async def test_discovery_async(atc: Recorder) -> None:
    atc.handler = lambda _: response(200, b'["a.example", "b.example"]')
    probes: list[str] = []

    def new_transport(enclave: Enclave) -> AsyncAttestedTransport:
        async def fetch() -> Verification:
            probes.append(enclave.host)
            if enclave.host == "a.example":
                raise network_error("down")
            return verification(enclave.host)

        return AsyncAttestedTransport(Enclave(enclave.host, enclave.repo, _fetch_async=fetch), AsyncFakeMode())

    keyed = await discover_async(None, None, new_transport)
    assert keyed.enclave.host == "b.example"
    assert probes == ["a.example", "b.example"]
