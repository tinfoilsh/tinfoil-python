"""The ``fetch_attestation`` and ``fetch_router_list`` options: a custom fetcher or a relay obtains every document
and the router list in place of a direct fetch, relay URLs are composed and checked before any network I/O, a
fetcher's failure takes the client's error categories, the caller's cancellation passes through, and discovery
shuffles a copy of the list that it is given."""

from __future__ import annotations

import asyncio
import collections
from typing import Any

import httpx
import pytest

from tests import document_builder
from tests.client.helpers import Recorder, report_of, response, verification
from tinfoil import _enclave, _fetch, _router
from tinfoil._clients import AsyncEnclaveHTTPClient, AsyncRouterHTTPClient, EnclaveHTTPClient, RouterHTTPClient
from tinfoil._errors import AttestationError, ConfigurationError, NetworkError
from tinfoil._fetch import relay_document_url
from tinfoil._fetchers import AttestationRelay, RouterListRelay
from tinfoil._router import FALLBACK_HOST, relay_list_url, shuffled
from tinfoil._trust import RepoPin
from tinfoil._types import EHBP
from tinfoil.verifier import Pin, VerificationReport, Verifier

NONCE = bytes(range(32))
ROUTERS = b'["router.example"]'


class Calls:
    """A fetcher's record: the hosts that it was asked for and the nonces that it was given."""

    def __init__(self) -> None:
        self.hosts: list[str] = []
        self.nonces: list[bytes] = []

    def fetch(self, host: str, nonce: bytes) -> bytes:
        self.hosts.append(host)
        self.nonces.append(nonce)
        return b"doc:" + host.encode()

    async def fetch_async(self, host: str, nonce: bytes) -> bytes:
        return self.fetch(host, nonce)


@pytest.fixture
def direct(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    """Every direct fetch, answered with a router list and otherwise a document; the verifier accepts any
    document and records the nonce that it was checked against."""
    recorder = Recorder(lambda request: response(200, ROUTERS if request.url.path.endswith("routers") else b"doc"))
    monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
    monkeypatch.setattr(_fetch, "_ASYNC_TRANSPORT", recorder.async_transport)
    monkeypatch.setattr(_enclave, "VERIFICATION_RETRY_DELAY", 0.0)
    monkeypatch.setattr(_router, "_shuffle", lambda routers: None)

    def verify(self: Verifier, doc: bytes, nonce: bytes, pin: Pin) -> VerificationReport:
        assert len(nonce) == 32
        return report_of(verification("ab" * 32, tag=doc.decode()))

    monkeypatch.setattr(Verifier, "verify_v3", verify)
    return recorder


class TestRelayURLs:
    @pytest.mark.parametrize(
        ("relay", "want"),
        [
            ("https://relay.example", "https://relay.example/.well-known/tinfoil-attestation"),
            ("https://relay.example/", "https://relay.example/.well-known/tinfoil-attestation"),
            ("https://relay.example/tinfoil", "https://relay.example/tinfoil/.well-known/tinfoil-attestation"),
            ("https://relay.example/tinfoil/", "https://relay.example/tinfoil/.well-known/tinfoil-attestation"),
            ("http://localhost:8080/a/b", "http://localhost:8080/a/b/.well-known/tinfoil-attestation"),
        ],
    )
    def test_attestation_path_joins_under_the_relay(self, relay: str, want: str) -> None:
        url = relay_document_url(relay, "enclave.example:8443", NONCE)
        assert url == f"{want}?nonce={NONCE.hex()}&enclave=enclave.example%3A8443"

    @pytest.mark.parametrize(
        ("relay", "want"),
        [
            ("https://relay.example", "https://relay.example/routers"),
            ("https://relay.example/", "https://relay.example/routers"),
            ("https://relay.example/atc/", "https://relay.example/atc/routers"),
            ("http://127.0.0.1:9000", "http://127.0.0.1:9000/routers"),
        ],
    )
    def test_router_list_path_joins_under_the_relay(self, relay: str, want: str) -> None:
        assert relay_list_url(relay) == want

    def test_relay_requests_carry_the_sdk_headers_and_return_the_body(self, direct: Recorder) -> None:
        direct.handler = lambda request: response(
            200, ROUTERS if request.url.path.endswith("/routers") else b"relayed document"
        )
        assert AttestationRelay("https://relay.example/t/").fetch("enclave.example", NONCE) == b"relayed document"
        assert RouterListRelay("https://relay.example/atc").fetch() == ["router.example"]
        attestation, routers = direct.requests
        assert str(attestation.url) == relay_document_url("https://relay.example/t", "enclave.example", NONCE)
        assert attestation.headers["Tinfoil-SDK"] == "tinfoil-python"
        assert "Tinfoil-SDK-Version" in attestation.headers
        assert str(routers.url) == "https://relay.example/atc/routers"

    def test_a_relayed_list_goes_through_the_same_parsing_and_limits(
        self, direct: Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        direct.handler = lambda _: response(200, b'{"not": "a list"}')
        with pytest.raises(NetworkError, match="want a JSON array of strings"):
            RouterListRelay("https://relay.example").fetch()
        monkeypatch.setattr(_router, "MAX_ROUTER_BYTES", 4)
        direct.handler = lambda _: response(200, ROUTERS)
        with pytest.raises(NetworkError):
            RouterListRelay("https://relay.example").fetch()
        direct.handler = lambda _: httpx.Response(302, headers={"Location": "http://relay.example/routers"})
        with pytest.raises(NetworkError, match="non-HTTPS"):
            RouterListRelay("https://relay.example").fetch()


INVALID_RELAY_URLS = [
    "http://relay.example/",
    "http://0.0.0.0:8080/",
    "ftp://relay.example/",
    "/relay",
    "",
    "https://u:p@relay.example/",
    "https://relay.example/?x=1",
    "https://relay.example/?",
    "https://relay.example/#",
]


class TestConstruction:
    @pytest.mark.parametrize("url", INVALID_RELAY_URLS)
    def test_relay_urls_are_checked_before_any_io(self, direct: Recorder, url: str) -> None:
        with pytest.raises(ConfigurationError, match="invalid attestation relay URL"):
            EnclaveHTTPClient("enclave.example", RepoPin("o/r"), fetch_attestation=AttestationRelay(url))
        with pytest.raises(ConfigurationError, match="invalid attestation relay URL"):
            RouterHTTPClient(fetch_attestation=AttestationRelay(url))
        with pytest.raises(ConfigurationError, match="invalid router list relay URL"):
            RouterHTTPClient(fetch_router_list=RouterListRelay(url))
        assert direct.requests == []

    def test_other_values_are_refused_before_any_io(self, direct: Recorder) -> None:
        calls = Calls()
        for value in ("https://relay.example/", RouterListRelay("https://relay.example/"), 5):
            with pytest.raises(ConfigurationError, match="fetch_attestation must be a callable or a relay"):
                EnclaveHTTPClient("enclave.example", RepoPin("o/r"), fetch_attestation=value)  # type: ignore[arg-type]
        with pytest.raises(ConfigurationError, match="fetch_router_list must be a callable or a relay"):
            RouterHTTPClient(fetch_router_list=AttestationRelay("https://relay.example/"))  # type: ignore[arg-type]
        with pytest.raises(ConfigurationError, match="asynchronous"):
            EnclaveHTTPClient("enclave.example", RepoPin("o/r"), fetch_attestation=calls.fetch_async)  # type: ignore[arg-type]
        assert direct.requests == []
        assert calls.hosts == []


class TestCustomFetchers:
    def test_the_fetcher_serves_every_verification_of_an_enclave_client(self, direct: Recorder) -> None:
        calls = Calls()
        client = EnclaveHTTPClient("enclave.example", RepoPin("o/r"), transport=EHBP(), fetch_attestation=calls.fetch)
        assert client.current is not None
        assert client.current.code_tag == "doc:enclave.example"
        client.reverify()
        assert calls.hosts == ["enclave.example", "enclave.example"]
        assert len(set(calls.nonces)) == 2, "each verification has a fresh nonce"
        assert direct.requests == [], "nothing is fetched directly"
        client.close()

    def test_the_fetchers_serve_discovery_candidates_and_the_fallback(self, direct: Recorder) -> None:
        calls = Calls()
        client = RouterHTTPClient(
            transport=EHBP(), fetch_attestation=calls.fetch, fetch_router_list=lambda: ["a.example", "b.example"]
        )
        assert client.enclave == "a.example"
        assert calls.hosts == ["a.example"]
        client.close()

        def failing(host: str, nonce: bytes) -> bytes:
            calls.hosts.append(host)
            if host != FALLBACK_HOST:
                raise RuntimeError("no route")
            return b"fallback"

        calls.hosts.clear()
        client = RouterHTTPClient(transport=EHBP(), fetch_attestation=failing, fetch_router_list=lambda: ["a.example"])
        assert client.enclave == FALLBACK_HOST
        assert calls.hosts == ["a.example", FALLBACK_HOST], "a candidate is tried once; the fallback is fetched too"
        assert direct.requests == []
        client.close()

    def test_a_failing_or_malformed_router_list_falls_back(self, direct: Recorder) -> None:
        calls = Calls()

        def broken() -> list[str]:
            raise RuntimeError("relay down")

        for source in (broken, lambda: "a.example", lambda: [1, 2], lambda: None):
            client = RouterHTTPClient(transport=EHBP(), fetch_attestation=calls.fetch, fetch_router_list=source)  # type: ignore[arg-type]
            assert client.enclave == FALLBACK_HOST
            client.close()
        assert direct.requests == []

    def test_relays_serve_a_router_client(self, direct: Recorder) -> None:
        direct.handler = lambda request: response(
            200, b'["a.example"]' if request.url.path == "/atc/routers" else b"relayed"
        )
        client = RouterHTTPClient(
            transport=EHBP(),
            fetch_attestation=AttestationRelay("https://app.example/att"),
            fetch_router_list=RouterListRelay("https://app.example/atc/"),
        )
        assert client.enclave == "a.example"
        assert {request.url.host for request in direct.requests} == {"app.example"}, "only the relay origin"
        assert [request.url.path for request in direct.requests] == [
            "/atc/routers",
            "/att/.well-known/tinfoil-attestation",
        ]
        assert direct.requests[1].url.params["enclave"] == "a.example"
        client.close()

    def test_errors_take_the_client_categories(self, direct: Recorder) -> None:
        failure = RuntimeError("relay down")

        def raising(host: str, nonce: bytes) -> bytes:
            raise failure

        with pytest.raises(NetworkError) as network:
            EnclaveHTTPClient("enclave.example", RepoPin("o/r"), fetch_attestation=raising)
        assert network.value.__cause__ is failure
        attestation = AttestationError("rejected by the relay")

        def categorized(host: str, nonce: bytes) -> bytes:
            raise attestation

        with pytest.raises(AttestationError) as kept:
            EnclaveHTTPClient("enclave.example", RepoPin("o/r"), fetch_attestation=categorized)
        assert kept.value is attestation
        with pytest.raises(NetworkError, match="returned str, not bytes"):
            EnclaveHTTPClient("enclave.example", RepoPin("o/r"), fetch_attestation=lambda h, n: "doc")  # type: ignore[arg-type,return-value]

    def test_a_document_for_another_nonce_is_an_attestation_error(
        self, direct: Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.undo()  # the real verifier
        monkeypatch.setattr(_enclave, "VERIFICATION_RETRY_DELAY", 0.0)
        stale = document_builder.encode(document_builder.build_raw(document_builder.test_nonce()))
        with pytest.raises(AttestationError):
            EnclaveHTTPClient("enclave.example", RepoPin("o/r"), fetch_attestation=lambda host, nonce: stale)


class TestAsync:
    @pytest.mark.asyncio
    async def test_async_fetchers_serve_the_async_clients(self, direct: Recorder) -> None:
        calls = Calls()
        client = await AsyncEnclaveHTTPClient.create(
            "enclave.example", RepoPin("o/r"), transport=EHBP(), fetch_attestation=calls.fetch_async
        )
        await client.reverify()
        assert calls.hosts == ["enclave.example", "enclave.example"]
        await client.close()

        async def routers() -> list[str]:
            return ["a.example"]

        router = await AsyncRouterHTTPClient.create(
            transport=EHBP(), fetch_attestation=calls.fetch_async, fetch_router_list=routers
        )
        assert router.enclave == "a.example"
        await router.close()
        relayed = await AsyncRouterHTTPClient.create(
            transport=EHBP(),
            fetch_attestation=AttestationRelay("https://app.example/"),
            fetch_router_list=RouterListRelay("https://app.example/"),
        )
        assert {request.url.host for request in direct.requests} == {"app.example"}
        await relayed.close()

    @pytest.mark.asyncio
    async def test_a_synchronous_list_fetcher_is_refused_on_an_async_client(self, direct: Recorder) -> None:
        with pytest.raises(ConfigurationError, match="must return an awaitable"):
            await AsyncRouterHTTPClient.create(fetch_router_list=lambda: ["a.example"])  # type: ignore[arg-type,return-value]
        assert direct.requests == [], "discovery stops rather than falling back"

    def test_an_async_list_fetcher_is_refused_on_a_sync_client(self, direct: Recorder) -> None:
        async def routers() -> list[str]:
            return ["a.example"]

        with pytest.raises(ConfigurationError, match="asynchronous"):
            RouterHTTPClient(fetch_router_list=routers)  # type: ignore[arg-type]
        with pytest.raises(ConfigurationError, match="returned an awaitable"):
            RouterHTTPClient(fetch_router_list=lambda: routers())  # type: ignore[arg-type,return-value]
        assert direct.requests == []

    def test_an_enclave_refuses_a_fetcher_of_the_other_kind_rather_than_fetching_directly(
        self, direct: Recorder
    ) -> None:
        async def fetch_async(host: str, nonce: bytes, limit: object, deadline: object) -> bytes:
            return b"doc"

        def fetch(host: str, nonce: bytes, limit: object, deadline: object) -> bytes:
            return b"doc"

        with pytest.raises(ConfigurationError, match="asynchronous"):
            _enclave.Enclave("enclave.example", Pin(repo="o/r"), fetch_document_async=fetch_async).verify()
        with pytest.raises(ConfigurationError, match="synchronous"):
            asyncio.run(_enclave.Enclave("enclave.example", Pin(repo="o/r"), fetch_document=fetch).verify_async())
        with pytest.raises(ConfigurationError, match="not both"):
            _enclave.Enclave("enclave.example", Pin(repo="o/r"), relay="relay.example", fetch_document=fetch)
        assert direct.requests == []

    @pytest.mark.asyncio
    async def test_a_synchronous_fetcher_is_refused_on_an_async_client(self, direct: Recorder) -> None:
        with pytest.raises(ConfigurationError, match="must return an awaitable"):
            await AsyncEnclaveHTTPClient.create("enclave.example", RepoPin("o/r"), fetch_attestation=Calls().fetch)  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_the_callers_cancellation_passes_through(self, direct: Recorder) -> None:
        started = asyncio.Event()

        async def hanging(host: str, nonce: bytes) -> bytes:
            started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        task = asyncio.create_task(
            AsyncEnclaveHTTPClient.create("enclave.example", RepoPin("o/r"), fetch_attestation=hanging)
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_a_fetcher_that_does_not_return_in_time_is_a_network_error(
        self, direct: Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("tinfoil._fetchers.FETCH_TIMEOUT", 0.05)

        async def hanging(host: str, nonce: bytes) -> bytes:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        with pytest.raises(NetworkError, match="did not return within"):
            await AsyncEnclaveHTTPClient.create("enclave.example", RepoPin("o/r"), fetch_attestation=hanging)


class TestShuffle:
    def test_discovery_shuffles_a_copy_of_the_list(self) -> None:
        routers = [f"r{i}.example" for i in range(5)]
        original = list(routers)
        firsts: collections.Counter[str] = collections.Counter()
        for _ in range(2000):
            copied = shuffled(routers)
            assert sorted(copied) == sorted(original)
            firsts[copied[0]] += 1
        assert routers == original, "the caller's list is not modified"
        assert set(firsts) == set(original)
        assert all(250 < count < 550 for count in firsts.values()), firsts

    def test_anything_but_a_sequence_of_strings_is_an_empty_list(self) -> None:
        values: list[Any] = ["a.example", b"a.example", None, 5, [1], ["a.example", None], {"a.example": 1}]
        for value in values:
            assert shuffled(value) == []
        assert shuffled(("a.example",)) == ["a.example"]

    def test_the_default_list_is_shuffled(self, direct: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
        orders: list[list[str]] = []

        def reverse(routers: list[str]) -> None:
            orders.append(list(routers))
            routers.reverse()

        monkeypatch.setattr(_router, "_shuffle", reverse)
        direct.handler = lambda request: response(
            200, b'["a.example", "b.example"]' if request.url.host == "atc.tinfoil.sh" else b"doc"
        )
        client = RouterHTTPClient(transport=EHBP())
        assert orders == [["a.example", "b.example"]]
        assert client.enclave == "b.example", "the first router of the shuffled list is tried first"
        client.close()
