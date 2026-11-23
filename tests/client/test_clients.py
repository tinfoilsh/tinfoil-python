"""The HTTP clients end to end over a mocked network: option checks before any I/O, verification before the
constructor returns, the chain every request goes through, origin binding, closing, and the router and gateway
routes."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from tests import document_builder
from tests.client.helpers import EHBPServer, facts_of, last_error, last_facts, report_of, response, verification
from tinfoil import _cachesecret, _ehbp, _fetch, _router
from tinfoil._chain import ENCLAVE_URL_HEADER
from tinfoil._clients import (
    GATEWAY_URL_INVALID,
    AsyncEnclaveHTTPClient,
    AsyncGatewayHTTPClient,
    AsyncRouterHTTPClient,
    EnclaveHTTPClient,
    GatewayHTTPClient,
    RouterHTTPClient,
)
from tinfoil._errors import AttestationError, ConfigurationError, NetworkError, TinfoilError
from tinfoil._gateway import Catalog, CatalogEntry, ModelPin, rank
from tinfoil._transport import CLIENT_CLOSED
from tinfoil._trust import AuthorizedBy, EitherPin, EmbeddedConfig, ProjectPin, RepoPin, SignedBy, Trust
from tinfoil._types import EHBP
from tinfoil.verifier import (
    LAYER_PROVENANCE,
    EndorsedArtifacts,
    Pin,
    Policy,
    VerificationError,
    VerificationReport,
    VerifiedFacts,
    Verifier,
)

Handler = Callable[[httpx.Request], httpx.Response]
ATTESTATION_PATH = "/.well-known/tinfoil-attestation"


class Network:
    """The network every client reaches: attestation documents are JSON ``{"key": ..., "deadline": ...}`` that
    the patched verifier turns into a verification; everything else is answered by ``handler``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.requests: list[httpx.Request] = []
        self.documents: dict[str, VerifiedFacts | Exception] = {}
        self.pins: list[Pin] = []
        self.handler: Handler = lambda _: response(200, b"ok")
        self.ehbp = EHBPServer()
        for module, name in (
            (_fetch, "_TRANSPORT"),
            (_fetch, "_ASYNC_TRANSPORT"),
            (_ehbp, "_INNER_TRANSPORT"),
            (_ehbp, "_ASYNC_INNER_TRANSPORT"),
        ):
            monkeypatch.setattr(module, name, httpx.MockTransport(self.handle))
        monkeypatch.setattr(Verifier, "verify_v3", self.verify)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/.well-known/tinfoil-attestation":
            host = request.url.params.get("enclave", request.url.netloc.decode())
            document = self.documents.get(host, NetworkError("no network in this test"))
            if isinstance(document, Exception):
                raise document
            return response(200, document.code_tag.encode())
        return self.handler(request)

    def verify(self, doc: bytes, nonce: bytes, pin: Pin) -> VerificationReport:
        self.pins.append(pin)
        for document in self.documents.values():
            if isinstance(document, VerifiedFacts) and document.code_tag.encode() == doc:
                return report_of(document)
        raise AssertionError("unknown document")

    def hosts(self) -> list[str]:
        seen = [r.url.host for r in self.requests]
        self.requests = []
        return seen

    def serve(
        self, host: str, *, tag: str | None = None, hpke: str | None = None, deadline: datetime | str | None = "default"
    ) -> VerifiedFacts:
        document = verification(
            "key",
            tls="ab" * 32,
            hpke=hpke or self.ehbp.public_key_hex,
            tag=host if tag is None else tag,
            deadline=deadline,
        )
        self.documents[host] = document
        return document


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch) -> Network:
    monkeypatch.setattr(_router, "_shuffle", lambda routers: None)  # keep the router list in order
    return Network(monkeypatch)


def bad_policy() -> Policy:
    """A policy that the verifier refuses: an explicit freshness key set that is empty."""
    return Policy(artifacts=EndorsedArtifacts(freshness_keys=[]))


class TestEnclaveClient:
    @pytest.mark.parametrize(
        ("name", "args"),
        [
            ("no host", ("", RepoPin("org/repo"), {})),
            ("transport of another type", ("enclave.example", RepoPin("org/repo"), {"transport": "ehbp"})),
            ("transport class, not a value", ("enclave.example", RepoPin("org/repo"), {"transport": EHBP})),
            ("proxy URL of another type", ("enclave.example", RepoPin("org/repo"), {"transport": EHBP(b"x")})),  # type: ignore[arg-type]
            (
                "plaintext remote proxy",
                (
                    "enclave.example",
                    RepoPin("org/repo"),
                    {"transport": EHBP("http://proxy.example/v1/")},
                ),
            ),
            ("relative proxy URL", ("enclave.example", RepoPin("org/repo"), {"transport": EHBP("/v1/")})),
            ("ftp proxy URL", ("enclave.example", RepoPin("org/repo"), {"transport": EHBP("ftp://proxy.example")})),
            (
                "unspecified address as a proxy",
                ("enclave.example", RepoPin("org/repo"), {"transport": EHBP("http://0.0.0.0:8080/relay")}),
            ),
            (
                "proxy on the enclave's own origin",
                ("enclave.example", RepoPin("org/repo"), {"transport": EHBP("https://enclave.example/relay")}),
            ),
            (
                "proxy on the enclave's own origin with the default port",
                ("enclave.example", RepoPin("org/repo"), {"transport": EHBP("https://enclave.example:443")}),
            ),
            ("invalid repository", ("enclave.example", RepoPin("not a reference"), {})),
            ("empty repository", ("enclave.example", RepoPin(""), {})),
            ("empty project", ("enclave.example", ProjectPin(""), {})),
            ("empty registry IDs", ("enclave.example", ProjectPin("org/project", registry_ids=[]), {})),
            ("a string of registry IDs", ("enclave.example", ProjectPin("org/project", registry_ids="r"), {})),
            ("malformed registry ID", ("enclave.example", ProjectPin("org/project", registry_ids=[""]), {})),
            ("EitherPin without a project", ("enclave.example", EitherPin("org/repo", ""), {})),
            ("EitherPin without a repository", ("enclave.example", EitherPin("", "org/project"), {})),
            ("SignedBy without keys", ("enclave.example", SignedBy([]), {})),
            ("AuthorizedBy that is not callable", ("enclave.example", AuthorizedBy("allow"), {})),  # type: ignore[arg-type]
            ("EmbeddedConfig without bytes", ("enclave.example", EmbeddedConfig(b""), {})),
            ("invalid policy", ("enclave.example", RepoPin("org/repo"), {"policy": bad_policy()})),
            ("policy of another type", ("enclave.example", RepoPin("org/repo"), {"policy": "strict"})),
            ("invalid project", ("enclave.example", EitherPin("org/repo", "not a reference"), {})),
            (
                "userinfo in the proxy URL",
                (
                    "enclave.example",
                    RepoPin("org/repo"),
                    {"transport": EHBP("https://u:p@proxy.example/v1/")},
                ),
            ),
            (
                "query in the proxy URL",
                (
                    "enclave.example",
                    RepoPin("org/repo"),
                    {"transport": EHBP("https://proxy.example/v1/?x=1")},
                ),
            ),
            (
                "fragment in the proxy URL",
                ("enclave.example", RepoPin("org/repo"), {"transport": EHBP("https://proxy.example/v1/#f")}),
            ),
            (
                "empty query in the proxy URL",
                ("enclave.example", RepoPin("org/repo"), {"transport": EHBP("https://proxy.example/v1?")}),
            ),
        ],
    )
    def test_rejects_invalid_options_before_any_io(
        self, network: Network, name: str, args: tuple[str, Trust, dict[str, object]]
    ) -> None:
        """Every option is checked before the enclave is contacted."""
        host, trust, options = args
        with pytest.raises(ConfigurationError) as err:
            EnclaveHTTPClient(host, trust, **options)  # type: ignore[arg-type]
        assert network.requests == [], name
        assert ":p@" not in str(err.value)

    @pytest.mark.parametrize("not_a_trust", ["org/repo", "", None, Pin(repo="org/repo"), RepoPin, {"repo": "org/repo"}])
    def test_rejects_anything_but_a_trust_before_any_io(self, network: Network, not_a_trust: object) -> None:
        """A bare reference string or a verifier pin is refused rather than read as an empty trust."""
        network.serve("enclave.example")
        with pytest.raises(ConfigurationError, match="trust must be a RepoPin, ProjectPin, SignedBy, AuthorizedBy"):
            EnclaveHTTPClient("enclave.example", not_a_trust, transport=EHBP())  # type: ignore[arg-type]
        assert network.requests == []
        assert network.pins == []

    @pytest.mark.parametrize("not_a_reference", [123, b"org/repo"])
    def test_rejects_a_reference_of_another_type_before_any_io(self, network: Network, not_a_reference: object) -> None:
        network.serve("enclave.example")
        for trust in (RepoPin(not_a_reference), ProjectPin(not_a_reference)):  # type: ignore[arg-type]
            with pytest.raises(ConfigurationError, match="must be a string or None"):
                EnclaveHTTPClient("enclave.example", trust, transport=EHBP())
        assert network.requests == []

    def test_verifies_before_returning(self, network: Network) -> None:
        with pytest.raises(NetworkError, match="no network"):
            EnclaveHTTPClient("enclave.example", RepoPin("org/repo"))
        assert network.hosts() == ["enclave.example", "enclave.example"], (
            "the enclave is verified before the client is returned, once more after a failure"
        )
        document = network.serve("enclave.example")
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        assert last_facts(client) is document
        assert facts_of(client.ensure_verified()) is document
        assert network.hosts() == ["enclave.example"]
        assert facts_of(client.reverify()) is document
        assert network.hosts() == ["enclave.example"]
        client.close()

    def test_reports_its_enclave_trust_and_base_url(self, network: Network) -> None:
        trust = EitherPin("org/repo@v1@sha256:" + "a" * 64, "org/project@v2")
        network.serve("enclave.example:8443")
        client = EnclaveHTTPClient("enclave.example:8443", trust, transport=EHBP("https://proxy.example/v1"))
        assert client.enclave == "enclave.example:8443", "the enclave, not the proxy"
        assert client.trust == trust
        assert network.pins == [Pin(repo=trust.repo, project=trust.project)], (
            "the verifier receives each pin in its own namespace"
        )
        assert client.base_url == "https://proxy.example/v1/"
        client.close()
        network.serve("enclave.example")
        with EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP()) as repository:
            assert repository.trust == RepoPin("org/repo")
            assert network.pins[-1] == Pin(repo="org/repo"), "a repository pin never doubles as a project pin"
        network.serve("enclave.example")
        with EnclaveHTTPClient("enclave.example", ProjectPin("org/project"), transport=EHBP()) as registry:
            assert registry.trust == ProjectPin("org/project")
            assert network.pins[-1] == Pin(project="org/project")
            assert registry.base_url == "https://enclave.example/"

    def test_requests_go_through_every_layer(self, network: Network) -> None:
        network.serve("enclave.example")
        network.ehbp.reply = lambda request, body: (
            200,
            json.dumps(
                {
                    "path": request.url.path,
                    "body": body.decode(),
                    "enclave": request.headers.get(ENCLAVE_URL_HEADER, ""),
                }
            ).encode(),
        )
        network.handler = network.ehbp.handle
        client = EnclaveHTTPClient(
            "enclave.example",
            RepoPin("org/repo"),
            transport=EHBP("https://proxy.example/v1/"),
        )
        reply = client.http_client.post("https://proxy.example/v1/chat/completions", json={"model": "m"}).json()
        assert reply["path"] == "/v1/chat/completions"
        assert json.loads(reply["body"]) == {"model": "m"}, "the enclave client adds no cache secret"
        reply = client.http_client.post(
            "https://proxy.example/v1/chat/completions", json={"model": "m", "user_cache_secret": ""}
        ).json()
        assert json.loads(reply["body"]) == {"model": "m", "user_cache_secret": ""}, "nor changes one"
        assert reply["enclave"] == "https://enclave.example"
        assert network.ehbp.requests[-1].read() != b'{"model":"m"}', "the body was sealed"
        for target in (
            "https://elsewhere.example/v1/models",
            "http://enclave.example/v1/models",
            "https://proxy.example:8443/v1/",
        ):
            with pytest.raises(ConfigurationError, match="refusing to send request"):
                client.http_client.get(target)
        client.close()

    def test_key_rotation_is_recovered_once(self, network: Network) -> None:
        first = network.serve("enclave.example", tag="first")
        network.handler = network.ehbp.handle
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        assert last_facts(client) is first
        assert client.http_client.post("https://enclave.example/v1/x", content=b"hello").content == b"echo:hello"
        network.ehbp.rotated = True
        rotated = EHBPServer()
        second = network.serve("enclave.example", tag="second", hpke=rotated.public_key_hex)
        sealed = 0

        def dispatch(request: httpx.Request) -> httpx.Response:
            # The first sealed attempt reaches the rotated server, which refuses it; the replay reaches the new one.
            nonlocal sealed
            sealed += 1
            return network.ehbp.handle(request) if sealed == 1 else rotated.handle(request)

        network.handler = dispatch
        assert (
            client.http_client.post("https://enclave.example/v1/x", content=iter([b"again"])).content == b"echo:again"
        )
        assert last_facts(client) is second, "the rejection re-verified and the replay went out under the new key"
        assert len(rotated.plaintexts) == 1
        assert rotated.plaintexts[0] == b"again"
        client.close()

    def test_tls_mode_refuses_plaintext_and_ehbp_refuses_upgrades_before_verifying(self, network: Network) -> None:
        network.serve("enclave.example")
        sealed = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        network.requests = []
        with pytest.raises(ConfigurationError, match="EHBP seals only"):
            sealed.http_client.get("https://enclave.example/v1/realtime", headers={"Upgrade": "websocket"})
        assert network.requests == [], "EHBP refuses an upgrade before verifying"
        sealed.close()
        pinned = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"))
        with pytest.raises(ConfigurationError, match="refusing to send request"):
            pinned.http_client.get("http://enclave.example/v1/models")
        pinned.close()

    def test_no_cache_secret_is_resolved(self, network: Network, monkeypatch: pytest.MonkeyPatch) -> None:
        def resolve(explicit: str | None) -> str:
            raise AssertionError("an enclave client uses only the option")

        monkeypatch.setattr(_cachesecret, "resolve", resolve)
        network.serve("enclave.example")
        EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP()).close()

    def test_closed_client_refuses(self, network: Network) -> None:
        network.serve("enclave.example")
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        client.close()
        assert last_facts(client) is not None, "closing keeps the last attempt, which needs no I/O to read"
        with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
            client.ensure_verified()
        with pytest.raises(RuntimeError, match="closed"):
            client.http_client.get("https://enclave.example/v1/models")

    @pytest.mark.parametrize("recovers", [True, False], ids=["recovers", "still-fails"])
    def test_failed_reverify_discards_the_cached_verification(self, network: Network, recovers: bool) -> None:
        network.serve("enclave.example", tag="first")
        network.handler = network.ehbp.handle
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        network.documents["enclave.example"] = AttestationError("document fails verification")
        with pytest.raises(AttestationError, match="fails verification"):
            client.reverify()
        assert last_facts(client) is None, "the last verification is the failure, not the earlier success"
        assert isinstance(last_error(client), AttestationError)
        network.requests = []
        if recovers:
            second = network.serve("enclave.example", tag="second")
            assert client.http_client.post("https://enclave.example/v1/x", content=b"hi").content == b"echo:hi"
            assert last_facts(client) is second, "the request verified again first"
        else:
            with pytest.raises(AttestationError, match="fails verification"):
                client.http_client.post("https://enclave.example/v1/x", content=b"hi")
            assert {r.url.path for r in network.requests} == {ATTESTATION_PATH}, "nothing was sent"
            assert last_facts(client) is None, "the failed attempt is the last one"
        client.close()

    def test_failed_reverify_keeps_the_cached_verification_on_a_network_error(self, network: Network) -> None:
        first = network.serve("enclave.example", tag="first")
        network.handler = network.ehbp.handle
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        network.documents["enclave.example"] = NetworkError("attestation source unreachable")
        with pytest.raises(NetworkError, match="unreachable"):
            client.reverify()
        assert last_facts(client) is None, "the failed attempt is the last one, though it keeps the cached one"
        assert isinstance(last_error(client), NetworkError)
        assert facts_of(client.ensure_verified()) is first
        network.requests = []
        assert client.http_client.post("https://enclave.example/v1/x", content=b"hi").content == b"echo:hi"
        assert ATTESTATION_PATH not in {r.url.path for r in network.requests}, "no new verification was needed"
        client.close()

    def test_expired_document_is_rejected(self, network: Network) -> None:
        network.serve("enclave.example", deadline=datetime.now(UTC) - timedelta(seconds=1))
        with pytest.raises(AttestationError, match="expired"):
            EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())

    def test_verification_check_rejection(self, network: Network) -> None:
        network.serve("enclave.example")
        seen: list[str] = []

        def check(v: VerifiedFacts) -> None:
            seen.append(v.code_tag)
            raise RuntimeError("rejected by the test")

        with pytest.raises(AttestationError, match="rejected by the test"):
            EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), verification_check=check)
        assert seen == ["enclave.example"], "a rejection isn't retried"


class TestRouterClient:
    @pytest.mark.parametrize(
        "options",
        [
            {"transport": "quic"},
            {"transport": EHBP("http://proxy.example/v1/")},
            {"transport": EHBP("https://u:p@proxy.example/v1/")},
            {"transport": EHBP("https://proxy.example/v1/?x=1")},
            {"policy": bad_policy()},
        ],
    )
    def test_rejects_invalid_options_before_discovery(self, network: Network, options: dict[str, object]) -> None:
        with pytest.raises(ConfigurationError):
            RouterHTTPClient(**options)  # type: ignore[arg-type]
        assert network.requests == []

    def test_names_the_transport_it_takes(self, network: Network) -> None:
        with pytest.raises(ConfigurationError, match="transport must be a TLS or EHBP value, not str"):
            RouterHTTPClient(transport="ehbp")  # type: ignore[arg-type]

    def test_discovers_and_verifies_the_fallback(self, network: Network) -> None:
        network.handler = lambda _: response(200, b"[]")
        with pytest.raises(NetworkError):
            RouterHTTPClient(transport=EHBP())
        assert network.hosts() == ["atc.tinfoil.sh", _router.FALLBACK_HOST, _router.FALLBACK_HOST], (
            "the fallback's verification has one retry"
        )

    def test_keeps_the_first_router_that_verifies(self, network: Network) -> None:
        network.handler = lambda _: response(200, b'["a.example", "b.example"]')
        chosen = network.serve("b.example")
        client = RouterHTTPClient(transport=EHBP("http://localhost:8080/v1/"), user_cache_secret="s")
        assert client.enclave == "b.example"
        assert not hasattr(client, "trust"), "a router's trust is fixed, not the caller's"
        assert not hasattr(client, "pin")
        assert set(network.pins) == {Pin(repo=_router.DEFAULT_ROUTER_NAME, project=_router.DEFAULT_ROUTER_NAME)}, (
            "every candidate is verified against the router's name in both namespaces"
        )
        assert last_facts(client) is chosen
        assert client.base_url == "http://localhost:8080/v1/"
        assert network.hosts() == ["atc.tinfoil.sh", "a.example", "b.example"], (
            "a candidate is probed once and the chosen one not again"
        )
        for target in (
            "https://localhost:8080/v1/models",
            "http://localhost:8081/v1/models",
            "http://127.0.0.1:8080/v1/models",
            "http://b.example/v1/models",
        ):
            with pytest.raises(ConfigurationError, match="refusing to send request"):
                client.http_client.get(target)
        client.close()

    def test_failed_reverify_verifies_the_same_router_again(self, network: Network) -> None:
        listed = response(200, b'["a.example", "b.example"]')
        network.handler = lambda request: (
            listed if request.url.host == "atc.tinfoil.sh" else network.ehbp.handle(request)
        )
        network.serve("b.example", tag="first")
        client = RouterHTTPClient(transport=EHBP(), user_cache_secret="s")
        assert client.enclave == "b.example"
        network.documents["b.example"] = AttestationError("document fails verification")
        with pytest.raises(AttestationError, match="fails verification"):
            client.reverify()
        assert last_facts(client) is None
        network.hosts()
        second = network.serve("b.example", tag="second")
        assert client.http_client.post("https://b.example/v1/x", content=b"hi").content == b"echo:hi"
        assert facts_of(client.ensure_verified()) is second
        assert network.hosts() == ["b.example", "b.example"], "the same router verified again, without discovery"
        client.close()


class TestGatewayClient:
    @pytest.mark.parametrize(
        "options",
        [
            {"url": "http://gateway.example/v1/"},
            {"url": "https://:443/v1/"},
            {"url": "https://u:hunter2@gateway.example/v1/"},
            {"url": "https://gateway.example/v1/?x=1"},
            {"url": "https://gateway.example/v1/#f"},
            {"url": "/v1/"},
            {"pinned_models_only": True},
            {"model_pins": {"m": ModelPin("acme/m")}},
            {"model_pins": {"m": ModelPin("tinfoilsh/m@")}},
            {"policy": bad_policy()},
            {"policy": "strict"},
            {"model_pins": {"m": ModelPin("tinfoilsh/m", bad_policy())}},
            {"model_pins": {"m": "tinfoilsh/m"}},
        ],
    )
    def test_rejects_invalid_options(self, network: Network, options: dict[str, object]) -> None:
        with pytest.raises(ConfigurationError) as err:
            GatewayHTTPClient(catalog=dict, **options)  # type: ignore[arg-type]
        assert network.requests == []
        assert "hunter2" not in str(err.value), "a refused gateway URL is never echoed"

    def test_refused_gateway_url_is_not_echoed(self, network: Network) -> None:
        with pytest.raises(ConfigurationError) as err:
            GatewayHTTPClient(url="https://u:hunter2@gateway.example/v1/", catalog=dict)
        assert str(err.value) == GATEWAY_URL_INVALID

    @pytest.mark.parametrize("url", ["https://gateway.example/v1/?", "https://gateway.example/v1/#"])
    def test_refuses_a_bare_query_or_fragment_delimiter(self, network: Network, url: str) -> None:
        with pytest.raises(ConfigurationError) as err:
            GatewayHTTPClient(url=url, catalog=dict)
        assert str(err.value) == GATEWAY_URL_INVALID
        assert network.requests == []

    def test_fetches_the_catalog_before_returning(self, network: Network) -> None:
        with pytest.raises(NetworkError):
            GatewayHTTPClient(url="https://gateway.example/v1/")
        assert network.hosts() == ["gateway.example"]
        network.handler = lambda _: response(200, b'{"m": {"repo": "tinfoilsh/m", "hosts": ["a.example"]}}')
        client = GatewayHTTPClient(url="https://gateway.example/v1")
        assert client.base_url == "https://gateway.example/v1/"
        assert client.models() == ["m"]
        assert client.last_verification() == []
        client.close()

    def test_serves_pinned_models_without_network(self, network: Network) -> None:
        entries: Catalog = {
            "pinned": CatalogEntry("tinfoilsh/pinned", ("a.example",)),
            "unpinned": CatalogEntry("tinfoilsh/unpinned", ("b.example",)),
        }
        client = GatewayHTTPClient(
            catalog=lambda: entries,
            model_pins={"pinned": ModelPin("tinfoilsh/pinned@v1"), "absent": ModelPin("tinfoilsh/absent")},
            pinned_models_only=True,
            user_cache_secret="test-secret",
        )
        assert client.base_url == "https://inference-gateway.tinfoil.sh/v1/"
        assert client.models() == ["pinned"], "pins may name models the catalog doesn't list"
        assert client.last_verification() == [], "a model's replicas are verified on its first request"
        assert network.requests == []
        with pytest.raises(ConfigurationError, match="refusing to send request"):
            client.http_client.get("https://elsewhere.example/v1/models")
        client.close()

    def test_verifies_a_replica_through_the_gateway(self, network: Network) -> None:
        entries: Catalog = {"m": CatalogEntry("tinfoilsh/m", ("replica.example",))}
        network.serve("replica.example")
        client = GatewayHTTPClient(url="https://gateway.example/v1/", catalog=lambda: entries, user_cache_secret="s")
        verified = facts_of(client.ensure_verified("m"))
        assert verified.code_tag == "replica.example"
        assert network.pins == [Pin(repo="tinfoilsh/m", project="tinfoilsh/m")], (
            "a model reference is pinned in both namespaces"
        )
        fetched = network.requests[-1]
        assert fetched.url.host == "gateway.example", "attestation is fetched through the gateway"
        assert fetched.url.params["enclave"] == "replica.example"
        assert [v.host for v in client.last_verification()] == ["replica.example"]
        client.close()
        with pytest.raises(ConfigurationError, match="closed"):
            client.models()

    def test_failed_refresh_discards_the_replicas_verification(self, network: Network) -> None:
        entries: Catalog = {"m": CatalogEntry("tinfoilsh/m", ("replica.example",))}
        first = network.serve("replica.example", deadline=datetime.now(UTC) + timedelta(seconds=0.2))
        client = GatewayHTTPClient(url="https://gateway.example/v1/", catalog=lambda: entries, user_cache_secret="s")
        client.ensure_verified("m")
        [entry] = client.last_verification()
        assert entry.host == "replica.example"
        assert facts_of(entry.report) is first
        time.sleep(0.25)
        network.documents["replica.example"] = AttestationError("document fails verification")
        with pytest.raises(AttestationError, match="fails verification") as failed:
            client.ensure_verified("m")
        [entry] = client.last_verification()
        assert entry.report is None, "the replica's earlier success is not kept once a later attempt fails"
        assert entry.error is failed.value
        network.serve("replica.example", tag="second")
        assert facts_of(client.ensure_verified("m")).code_tag == "second"
        client.close()


@pytest.mark.asyncio
async def test_async_clients(network: Network) -> None:
    for cls in (AsyncEnclaveHTTPClient, AsyncRouterHTTPClient, AsyncGatewayHTTPClient):
        with pytest.raises(ConfigurationError, match="create"):
            cls()
    with pytest.raises(ConfigurationError):
        await AsyncEnclaveHTTPClient.create("", RepoPin("org/repo"))
    for not_a_trust in ("org/repo", None):
        with pytest.raises(ConfigurationError, match="trust must be a RepoPin"):
            await AsyncEnclaveHTTPClient.create("enclave.example", not_a_trust)  # type: ignore[arg-type]
    assert network.requests == []
    network.serve("enclave.example")
    network.handler = network.ehbp.handle
    async with await AsyncEnclaveHTTPClient.create("enclave.example", RepoPin("org/repo"), transport=EHBP()) as client:
        assert client.enclave == "enclave.example"
        assert client.trust == RepoPin("org/repo")
        assert last_facts(client) is not None
        assert facts_of(await client.ensure_verified()) is last_facts(client)
        assert (await client.http_client.post("https://enclave.example/v1/x", content=b"hi")).content == b"echo:hi"
        with pytest.raises(ConfigurationError, match="refusing"):
            await client.http_client.get("https://elsewhere.example/")
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        await client.ensure_verified()

    first = network.serve("enclave.example", tag="first")
    client = await AsyncEnclaveHTTPClient.create("enclave.example", RepoPin("org/repo"), transport=EHBP())
    network.documents["enclave.example"] = NetworkError("attestation source unreachable")
    with pytest.raises(NetworkError):
        await client.reverify()
    assert facts_of(await client.ensure_verified()) is first, "a network failure keeps the cached verification"
    network.documents["enclave.example"] = AttestationError("document fails verification")
    with pytest.raises(AttestationError, match="fails verification"):
        await client.reverify()
    assert last_facts(client) is None, "an attestation failure discards it, and is the last verification"
    with pytest.raises(AttestationError, match="fails verification"):
        await client.http_client.post("https://enclave.example/v1/x", content=b"hi")
    assert isinstance(last_error(client), AttestationError)
    second = network.serve("enclave.example", tag="second")
    assert (await client.http_client.post("https://enclave.example/v1/x", content=b"hi")).content == b"echo:hi"
    assert facts_of(await client.ensure_verified()) is second
    await client.close()

    network.handler = lambda _: response(200, b'["router.example"]')
    network.serve("router.example")
    router = await AsyncRouterHTTPClient.create(transport=EHBP(), user_cache_secret="s")
    assert router.enclave == "router.example"
    await router.close()

    entries: Catalog = {"m": CatalogEntry("tinfoilsh/m", ("replica.example",))}
    network.serve("replica.example")
    gateway = await AsyncGatewayHTTPClient.create(
        url="https://gateway.example/v1/", catalog=lambda: entries, user_cache_secret="s"
    )
    assert await gateway.models() == ["m"]
    assert facts_of(await gateway.ensure_verified("m")).code_tag == "replica.example"
    assert [v.host for v in gateway.last_verification()] == ["replica.example"]
    await gateway.close()


class Attempts:
    """An ``on_verification`` callback that records every call, and optionally runs ``during`` inside it."""

    def __init__(self, during: Callable[[], None] | None = None) -> None:
        self.calls: list[tuple[str, VerificationReport | None, TinfoilError | None]] = []
        self.during = during

    def __call__(self, host: str, report: VerificationReport | None, error: TinfoilError | None) -> None:
        self.calls.append((host, report, error))
        if self.during is not None:
            self.during()

    @property
    def hosts(self) -> list[str]:
        return [host for host, _, _ in self.calls]


_REAL_VERIFY = Verifier.verify_v3
"""The verifier's own ``verify_v3``, which the ``network`` fixture replaces."""


def real_rejection(doc: bytes, nonce: bytes, pin: Pin) -> VerificationReport:
    """A real rejection: the verifier appraises a nonce-bound document without collateral, which the provenance
    step rejects after the envelope passed."""
    _, rejected = document_builder.build(nonce, collateral_entries=[])
    return _REAL_VERIFY(Verifier(), rejected, nonce, Pin(repo="org/repo"))


def rejecting_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    """Makes every verification a real rejection."""
    monkeypatch.setattr(Verifier, "verify_v3", lambda self, doc, nonce, pin: real_rejection(doc, nonce, pin))


class TestVerificationReports:
    """The verification report conformance cases: what ``last_verification`` returns and ``on_verification``
    receives for every kind of attempt."""

    def test_initial_verification(self, network: Network) -> None:
        document = network.serve("enclave.example")
        attempts = Attempts()
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), on_verification=attempts)
        report, error = client.last_verification()
        assert error is None
        assert facts_of(report) is document
        assert attempts.calls == [("enclave.example", report, None)], "called once, with the same report"
        assert client.ensure_verified() is report
        assert len(attempts.calls) == 1, "a valid verification is not an attempt"
        client.close()

    def test_a_rejected_document_reaches_the_caller_with_its_report(
        self, network: Network, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        network.serve("enclave.example")
        attempts = Attempts()
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), on_verification=attempts)
        rejecting_verifier(monkeypatch)
        with pytest.raises(AttestationError) as raised:
            client.reverify()
        err = raised.value
        rejected = err.__cause__
        assert isinstance(rejected, VerificationError), "the verifier's error is the cause, not a subtype"
        report = rejected.report
        assert report is not None
        assert report.verified_facts is None
        failed = report.failed_step
        assert failed is not None
        assert failed.layer == LAYER_PROVENANCE
        assert report.partial_facts is not None
        measured = report.partial_facts.measured
        assert measured is not None
        assert measured.tls_public_key_fp == document_builder.TLS_KEY.hex()
        assert measured.hpke_public_key_fp == hashlib.sha256(document_builder.HPKE_KEY).hexdigest()
        assert client.last_verification() == (None, err), "the same error, and no report"
        assert attempts.calls[-1] == ("enclave.example", None, err)
        assert len(attempts.calls) == 3, "the first verification, then the rejection and its retry"
        client.close()

    def test_a_failed_fetch_has_no_report(self, network: Network) -> None:
        network.serve("enclave.example")
        attempts = Attempts()
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), on_verification=attempts)
        network.documents["enclave.example"] = NetworkError("attestation source unreachable")
        with pytest.raises(NetworkError) as raised:
            client.reverify()
        assert client.last_verification() == (None, raised.value)
        assert raised.value.__cause__ is None or not isinstance(raised.value.__cause__, VerificationError)
        assert attempts.calls[-1] == ("enclave.example", None, raised.value)
        client.close()

    def test_a_failed_reverification_replaces_the_earlier_success(self, network: Network) -> None:
        network.serve("enclave.example")
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        assert client.last_verification()[0] is not None
        network.documents["enclave.example"] = AttestationError("document fails verification")
        with pytest.raises(AttestationError) as raised:
            client.reverify()
        assert client.last_verification() == (None, raised.value)
        client.close()

    def test_a_retried_failure_and_its_retry_are_two_attempts(
        self, network: Network, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        document = network.serve("enclave.example")
        calls = 0

        def first_rejected(self: Verifier, doc: bytes, nonce: bytes, pin: Pin) -> VerificationReport:
            nonlocal calls
            calls += 1
            return (real_rejection if calls == 1 else network.verify)(doc, nonce, pin)

        monkeypatch.setattr(Verifier, "verify_v3", first_rejected)
        attempts = Attempts()
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), on_verification=attempts)
        assert attempts.hosts == ["enclave.example", "enclave.example"], "the rejection and its retry"
        _, first_report, first_error = attempts.calls[0]
        assert first_report is None
        assert isinstance(first_error, AttestationError)
        assert isinstance(first_error.__cause__, VerificationError)
        _, second_report, second_error = attempts.calls[1]
        assert second_error is None
        assert client.last_verification() == (second_report, None), "the last verification is the retry"
        assert facts_of(second_report) is document
        client.close()

    def test_a_key_rotation_reverifies_the_same_host(self, network: Network) -> None:
        network.serve("enclave.example", tag="first")
        network.handler = network.ehbp.handle
        attempts = Attempts()
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), on_verification=attempts)
        network.ehbp.rotated = True
        rotated = EHBPServer()
        second = network.serve("enclave.example", tag="second", hpke=rotated.public_key_hex)
        sealed = 0

        def dispatch(request: httpx.Request) -> httpx.Response:
            nonlocal sealed
            sealed += 1
            return network.ehbp.handle(request) if sealed == 1 else rotated.handle(request)

        network.handler = dispatch
        assert client.http_client.post("https://enclave.example/v1/x", content=b"hi").content == b"echo:hi"
        assert attempts.hosts == ["enclave.example", "enclave.example"], "the re-verification is an attempt"
        assert facts_of(attempts.calls[1][1]) is second
        assert last_facts(client) is second
        client.close()

    def test_concurrent_requests_share_one_attempt(self, network: Network, monkeypatch: pytest.MonkeyPatch) -> None:
        network.serve("enclave.example", deadline=datetime.now(UTC) + timedelta(seconds=0.3))
        attempts = Attempts()
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), on_verification=attempts)
        time.sleep(0.35)
        network.serve("enclave.example")
        release = threading.Event()
        verified: list[VerificationReport] = []

        def slow(self: Verifier, doc: bytes, nonce: bytes, pin: Pin) -> VerificationReport:
            release.wait(5)
            return network.verify(doc, nonce, pin)

        monkeypatch.setattr(Verifier, "verify_v3", slow)
        threads = [threading.Thread(target=lambda: verified.append(client.ensure_verified())) for _ in range(8)]
        for thread in threads:
            thread.start()
        time.sleep(0.05)
        release.set()
        for thread in threads:
            thread.join(5)
        assert len(verified) == 8
        assert all(report is verified[0] for report in verified)
        assert len(attempts.calls) == 2, "the first verification, then one refresh that every caller shared"
        client.close()

    def test_router_discovery_reports_each_router(self, network: Network) -> None:
        network.handler = lambda _: response(200, b'["a.example", "b.example"]')
        network.documents["a.example"] = NetworkError("a.example is down")
        chosen = network.serve("b.example")
        attempts = Attempts()
        client = RouterHTTPClient(transport=EHBP(), user_cache_secret="s", on_verification=attempts)
        assert attempts.hosts == ["a.example", "b.example"], "the skipped router and the chosen one, each with its own"
        assert attempts.calls[0][1] is None
        assert isinstance(attempts.calls[0][2], NetworkError)
        assert last_facts(client) is chosen, "the last verification describes the chosen router"
        client.close()

    def test_a_gateway_keeps_each_replicas_last_attempt(self, network: Network) -> None:
        entries: Catalog = {"m": CatalogEntry("tinfoilsh/m", ("a.example", "b.example"))}
        network.documents["a.example"] = NetworkError("a.example is down")
        network.documents["b.example"] = NetworkError("b.example is down")
        attempts = Attempts()
        client = GatewayHTTPClient(
            url="https://gateway.example/v1/", catalog=lambda: entries, user_cache_secret="s", on_verification=attempts
        )
        order = list(rank(("a.example", "b.example"), "m", ""))
        good = network.serve(order[1])
        assert facts_of(client.ensure_verified("m")) is good
        entries_by_host = {entry.host: entry for entry in client.last_verification()}
        assert entries_by_host[order[0]].report is None
        assert isinstance(entries_by_host[order[0]].error, NetworkError)
        assert facts_of(entries_by_host[order[1]].report) is good
        assert entries_by_host[order[1]].error is None
        assert attempts.hosts == [order[0], order[0], order[1]], "the failed replica and its retry, then the good one"
        client.close()

    def test_the_verification_check_sees_only_verified_facts(
        self, network: Network, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        network.serve("enclave.example")
        checked: list[object] = []
        attempts = Attempts()
        client = EnclaveHTTPClient(
            "enclave.example",
            RepoPin("org/repo"),
            transport=EHBP(),
            verification_check=checked.append,
            on_verification=attempts,
        )
        assert len(checked) == 1
        assert isinstance(checked[0], VerifiedFacts)
        rejecting_verifier(monkeypatch)
        with pytest.raises(AttestationError):
            client.reverify()
        assert len(checked) == 1, "a failed verification never reaches the check"

        def reject(_: VerifiedFacts) -> None:
            raise RuntimeError("not this enclave")

        monkeypatch.setattr(Verifier, "verify_v3", network.verify)
        network.serve("enclave.example")
        refused = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        refused._attested.keyed.enclave._check = reject
        with pytest.raises(AttestationError, match="not this enclave") as raised:
            refused.reverify()
        assert refused.last_verification() == (None, raised.value), "a check's rejection has no report"
        assert not isinstance(raised.value.__cause__, VerificationError)
        client.close()
        refused.close()

    def test_the_callback_can_call_the_client(self, network: Network) -> None:
        network.serve("enclave.example")
        seen: list[tuple[VerificationReport | None, TinfoilError | None]] = []
        reverified: list[VerificationReport] = []
        holder: list[EnclaveHTTPClient] = []

        def during() -> None:
            if not holder:
                return
            seen.append(holder[0].last_verification())
            if len(seen) == 1:
                reverified.append(holder[0].reverify())

        attempts = Attempts(during)
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), on_verification=attempts)
        holder.append(client)
        done = threading.Event()

        def run() -> None:
            client.reverify()
            done.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        assert done.wait(5), "the callback ran without the client's lock, so calling the client did not deadlock"
        assert seen[0][0] is attempts.calls[1][1], "the callback sees the attempt that it was called for"
        assert reverified[0] is attempts.calls[2][1], "a verification that the callback starts is its own attempt"
        client.close()

    def test_a_caller_cannot_change_a_returned_report(self, network: Network) -> None:
        document = network.serve("enclave.example")
        client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP())
        report = client.ensure_verified()
        with pytest.raises(dataclasses.FrozenInstanceError):
            report.verified_facts = None  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            facts_of(report).code_tag = "changed"  # type: ignore[misc]
        with pytest.raises(AttributeError):
            report.steps.append(report.steps[0])  # type: ignore[attr-defined]
        assert facts_of(client.ensure_verified()) is document
        assert facts_of(client.last_verification()[0]).code_tag == document.code_tag
        client.close()


@pytest.mark.asyncio
async def test_async_clients_report_every_attempt(network: Network, monkeypatch: pytest.MonkeyPatch) -> None:
    network.serve("enclave.example")
    attempts = Attempts()
    client = await AsyncEnclaveHTTPClient.create(
        "enclave.example", RepoPin("org/repo"), transport=EHBP(), on_verification=attempts
    )
    report, error = client.last_verification()
    assert error is None
    assert attempts.calls == [("enclave.example", report, None)]
    rejecting_verifier(monkeypatch)
    with pytest.raises(AttestationError) as raised:
        await client.reverify()
    assert isinstance(raised.value.__cause__, VerificationError)
    assert raised.value.__cause__.report is not None
    assert client.last_verification() == (None, raised.value)
    assert attempts.calls[-1] == ("enclave.example", None, raised.value)
    assert len(attempts.calls) == 3
    monkeypatch.setattr(Verifier, "verify_v3", network.verify)
    network.serve("enclave.example")
    waiters = [asyncio.create_task(client.ensure_verified()) for _ in range(4)]
    reports = await asyncio.gather(*waiters)
    assert all(got is reports[0] for got in reports), "concurrent callers share one attempt"
    assert len(attempts.calls) == 4
    await client.close()

    network.handler = lambda _: response(200, b'["a.example", "b.example"]')
    network.documents["a.example"] = NetworkError("a.example is down")
    chosen = network.serve("b.example")
    routers = Attempts()
    router = await AsyncRouterHTTPClient.create(transport=EHBP(), user_cache_secret="s", on_verification=routers)
    assert routers.hosts == ["a.example", "b.example"]
    assert last_facts(router) is chosen
    await router.close()

    entries: Catalog = {"m": CatalogEntry("tinfoilsh/m", ("replica.example",))}
    network.serve("replica.example")
    replicas = Attempts()
    gateway = await AsyncGatewayHTTPClient.create(
        url="https://gateway.example/v1/", catalog=lambda: entries, user_cache_secret="s", on_verification=replicas
    )
    verified = await gateway.ensure_verified("m")
    assert replicas.calls == [("replica.example", verified, None)]
    [entry] = gateway.last_verification()
    assert entry.report is verified
    await gateway.close()
