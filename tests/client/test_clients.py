"""The HTTP clients end to end over a mocked network: option checks before any I/O, verification before the
constructor returns, the chain every request goes through, origin binding, closing, and the router and gateway
routes."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from tests.client.helpers import EHBPServer, response, verification
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
from tinfoil._errors import AttestationError, ConfigurationError, NetworkError
from tinfoil._gateway import Catalog, CatalogEntry, ModelPin
from tinfoil._transport import CLIENT_CLOSED
from tinfoil.verifier import Verification, Verifier

Handler = Callable[[httpx.Request], httpx.Response]


class Network:
    """The network every client reaches: attestation documents are JSON ``{"key": ..., "deadline": ...}`` that
    the patched verifier turns into a verification; everything else is answered by ``handler``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.requests: list[httpx.Request] = []
        self.documents: dict[str, Verification | Exception] = {}
        self.pins: list[tuple[str | None, str | None]] = []
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

    def verify(self, doc: bytes, nonce: bytes, repo: str | None, *, project: str | None = None) -> Verification:
        self.pins.append((repo, project))
        for document in self.documents.values():
            if isinstance(document, Verification) and document.code_tag.encode() == doc:
                return document
        raise AssertionError("unknown document")

    def hosts(self) -> list[str]:
        seen = [r.url.host for r in self.requests]
        self.requests = []
        return seen

    def serve(
        self, host: str, *, tag: str | None = None, hpke: str | None = None, deadline: datetime | str | None = "default"
    ) -> Verification:
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
    return Network(monkeypatch)


def authorizer() -> Verifier:
    return Verifier(config_authorizer=lambda _: None)


class TestEnclaveClient:
    @pytest.mark.parametrize(
        ("name", "args"),
        [
            ("no host", ("", "org/repo", {})),
            ("unknown transport mode", ("enclave.example", "org/repo", {"transport_mode": "quic"})),
            (
                "plaintext remote proxy",
                ("enclave.example", "org/repo", {"transport_mode": "ehbp", "base_url": "http://proxy.example/v1/"}),
            ),
            (
                "TLS through a loopback proxy",
                ("enclave.example", "org/repo", {"base_url": "http://localhost:8080/v1/"}),
            ),
            ("relative base URL", ("enclave.example", "org/repo", {"base_url": "/v1/"})),
            ("TLS through a proxy", ("enclave.example", "org/repo", {"base_url": "https://proxy.example/v1/"})),
            ("invalid repository", ("enclave.example", "not a reference", {})),
            ("config authorizer with a repository pin", ("enclave.example", "org/repo", {"verifier": authorizer()})),
            (
                "config authorizer with a project pin",
                ("enclave.example", None, {"project": "org/project", "verifier": authorizer()}),
            ),
            ("invalid project", ("enclave.example", "org/repo", {"project": "not a reference"})),
            (
                "userinfo in the base URL",
                (
                    "enclave.example",
                    "org/repo",
                    {"transport_mode": "ehbp", "base_url": "https://u:p@proxy.example/v1/"},
                ),
            ),
            (
                "query in the base URL",
                (
                    "enclave.example",
                    "org/repo",
                    {"transport_mode": "ehbp", "base_url": "https://proxy.example/v1/?x=1"},
                ),
            ),
            (
                "fragment in the base URL",
                ("enclave.example", "org/repo", {"base_url": "https://enclave.example/v1/#f"}),
            ),
        ],
    )
    def test_rejects_invalid_options_before_any_io(
        self, network: Network, name: str, args: tuple[str, str, dict[str, object]]
    ) -> None:
        host, repo, options = args
        with pytest.raises(ConfigurationError) as err:
            EnclaveHTTPClient(host, repo, **options)  # type: ignore[arg-type]
        assert network.requests == [], name
        assert ":p@" not in str(err.value)

    def test_verifies_before_returning(self, network: Network) -> None:
        with pytest.raises(NetworkError, match="no network"):
            EnclaveHTTPClient("enclave.example", "org/repo")
        assert network.hosts() == ["enclave.example", "enclave.example"], (
            "the enclave is verified before the client is returned, once more after a failure"
        )
        document = network.serve("enclave.example")
        client = EnclaveHTTPClient("enclave.example", "org/repo", transport_mode="ehbp")
        assert client.current is document
        assert client.ensure_verified() is document
        assert network.hosts() == ["enclave.example"]
        assert client.reverify() is document
        assert network.hosts() == ["enclave.example"]
        client.close()

    def test_reports_its_enclave_pin_and_base_url(self, network: Network) -> None:
        repo = "org/repo@v1@sha256:" + "a" * 64
        project = "org/project@v2"
        network.serve("enclave.example:8443")
        client = EnclaveHTTPClient(
            "enclave.example:8443", repo, project=project, transport_mode="ehbp", base_url="https://proxy.example/v1"
        )
        assert client.enclave == "enclave.example:8443", "the enclave, not the proxy"
        assert (client.repo, client.project) == (repo, project)
        assert network.pins == [(repo, project)], "the verifier receives each pin in its own namespace"
        assert client.base_url == "https://proxy.example/v1/"
        assert client._attested.openai_url == "https://proxy.example/v1/"
        client.close()
        network.serve("enclave.example")
        with EnclaveHTTPClient("enclave.example", None, transport_mode="ehbp") as plain:
            assert (plain.repo, plain.project) == ("", "")
            assert network.pins[-1] == ("", "")
        network.serve("enclave.example")
        with EnclaveHTTPClient("enclave.example", "org/repo", transport_mode="ehbp") as repository:
            assert (repository.repo, repository.project) == ("org/repo", "")
            assert network.pins[-1] == ("org/repo", ""), "a repository pin never doubles as a project pin"
        network.serve("enclave.example")
        with EnclaveHTTPClient("enclave.example", None, project="org/project", transport_mode="ehbp") as registry:
            assert (registry.repo, registry.project) == ("", "org/project")
            assert network.pins[-1] == ("", "org/project")
            assert plain.base_url == "https://enclave.example/"
            assert plain._attested.openai_url == "https://enclave.example/v1/"

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
            "org/repo",
            transport_mode="ehbp",
            base_url="https://proxy.example/v1/",
            user_cache_secret="explicit",
        )
        reply = client.http_client.post("https://proxy.example/v1/chat/completions", json={"model": "m"}).json()
        assert reply["path"] == "/v1/chat/completions"
        assert json.loads(reply["body"]) == {"model": "m", "user_cache_secret": "explicit"}
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
        client = EnclaveHTTPClient("enclave.example", "org/repo", transport_mode="ehbp")
        assert client.current is first
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
        assert client.current is second, "the rejection re-verified and the replay went out under the new key"
        assert len(rotated.plaintexts) == 1
        assert rotated.plaintexts[0] == b"again"
        client.close()

    def test_tls_mode_refuses_plaintext_and_ehbp_refuses_upgrades_before_verifying(self, network: Network) -> None:
        network.serve("enclave.example")
        sealed = EnclaveHTTPClient("enclave.example", "org/repo", transport_mode="ehbp")
        network.requests = []
        with pytest.raises(ConfigurationError, match="EHBP seals only"):
            sealed.http_client.get("https://enclave.example/v1/realtime", headers={"Upgrade": "websocket"})
        assert network.requests == [], "EHBP refuses an upgrade before verifying"
        sealed.close()
        pinned = EnclaveHTTPClient("enclave.example", "org/repo")
        with pytest.raises(ConfigurationError, match="refusing to send request"):
            pinned.http_client.get("http://enclave.example/v1/models")
        pinned.close()

    def test_no_cache_secret_is_resolved(self, network: Network, monkeypatch: pytest.MonkeyPatch) -> None:
        def resolve(explicit: str | None) -> str:
            raise AssertionError("an enclave client uses only the option")

        monkeypatch.setattr(_cachesecret, "resolve", resolve)
        network.serve("enclave.example")
        EnclaveHTTPClient("enclave.example", "org/repo", transport_mode="ehbp").close()

    def test_closed_client_refuses(self, network: Network) -> None:
        network.serve("enclave.example")
        client = EnclaveHTTPClient("enclave.example", "org/repo", transport_mode="ehbp")
        client.close()
        assert client.current is None
        with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
            client.ensure_verified()
        with pytest.raises(RuntimeError, match="closed"):
            client.http_client.get("https://enclave.example/v1/models")

    def test_expired_document_is_rejected(self, network: Network) -> None:
        network.serve("enclave.example", deadline=datetime.now(UTC) - timedelta(seconds=1))
        with pytest.raises(AttestationError, match="expired"):
            EnclaveHTTPClient("enclave.example", "org/repo", transport_mode="ehbp")

    def test_verification_check_rejection(self, network: Network) -> None:
        network.serve("enclave.example")
        seen: list[str] = []

        def check(v: Verification) -> None:
            seen.append(v.code_tag)
            raise RuntimeError("rejected by the test")

        with pytest.raises(AttestationError, match="rejected by the test"):
            EnclaveHTTPClient("enclave.example", "org/repo", transport_mode="ehbp", verification_check=check)
        assert seen == ["enclave.example"], "a rejection isn't retried"


class TestRouterClient:
    @pytest.mark.parametrize(
        "options",
        [
            {"transport_mode": "quic"},
            {"transport_mode": "ehbp", "base_url": "http://proxy.example/v1/"},
            {"base_url": "https://proxy.example/v1/"},
            {"transport_mode": "tls", "base_url": "https://proxy.example/v1/"},
            {"transport_mode": "ehbp", "base_url": "https://proxy.example/v1/?x=1"},
            {"verifier": authorizer()},
        ],
    )
    def test_rejects_invalid_options_before_discovery(self, network: Network, options: dict[str, object]) -> None:
        with pytest.raises(ConfigurationError):
            RouterHTTPClient(**options)  # type: ignore[arg-type]
        assert network.requests == []

    def test_proxy_names_the_mode_it_needs(self, network: Network) -> None:
        with pytest.raises(ConfigurationError, match='requires the "ehbp"'):
            RouterHTTPClient(base_url="https://proxy.example/v1/")

    def test_discovers_and_verifies_the_fallback(self, network: Network) -> None:
        network.handler = lambda _: response(200, b"[]")
        with pytest.raises(NetworkError):
            RouterHTTPClient(transport_mode="ehbp")
        assert network.hosts() == ["atc.tinfoil.sh", _router.FALLBACK_HOST, _router.FALLBACK_HOST], (
            "the fallback's verification has one retry"
        )

    def test_keeps_the_first_router_that_verifies(self, network: Network) -> None:
        network.handler = lambda _: response(200, b'["a.example", "b.example"]')
        chosen = network.serve("b.example")
        client = RouterHTTPClient(transport_mode="ehbp", base_url="http://localhost:8080/v1/", user_cache_secret="s")
        assert client.enclave == "b.example"
        assert (client.repo, client.project) == (_router.DEFAULT_ROUTER_NAME, _router.DEFAULT_ROUTER_NAME)
        assert set(network.pins) == {(_router.DEFAULT_ROUTER_NAME, _router.DEFAULT_ROUTER_NAME)}, (
            "every candidate is verified against the router's name in both namespaces"
        )
        assert client.current is chosen
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
            {"verifier": authorizer()},
            {"model_pins": {"m": ModelPin("tinfoilsh/m", authorizer())}},
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
        assert client.current == []
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
        assert client.current == [], "a model's replicas are verified on its first request"
        assert network.requests == []
        with pytest.raises(ConfigurationError, match="refusing to send request"):
            client.http_client.get("https://elsewhere.example/v1/models")
        client.close()

    def test_verifies_a_replica_through_the_gateway(self, network: Network) -> None:
        entries: Catalog = {"m": CatalogEntry("tinfoilsh/m", ("replica.example",))}
        network.serve("replica.example")
        client = GatewayHTTPClient(url="https://gateway.example/v1/", catalog=lambda: entries, user_cache_secret="s")
        verified = client.ensure_verified("m")
        assert verified.code_tag == "replica.example"
        assert network.pins == [("tinfoilsh/m", "tinfoilsh/m")], "a model reference is pinned in both namespaces"
        fetched = network.requests[-1]
        assert fetched.url.host == "gateway.example", "attestation is fetched through the gateway"
        assert fetched.url.params["enclave"] == "replica.example"
        assert [v.host for v in client.current] == ["replica.example"]
        client.close()
        with pytest.raises(ConfigurationError, match="closed"):
            client.models()


@pytest.mark.asyncio
async def test_async_clients(network: Network) -> None:
    for cls in (AsyncEnclaveHTTPClient, AsyncRouterHTTPClient, AsyncGatewayHTTPClient):
        with pytest.raises(ConfigurationError, match="create"):
            cls()
    with pytest.raises(ConfigurationError):
        await AsyncEnclaveHTTPClient.create("", "org/repo")
    network.serve("enclave.example")
    network.handler = network.ehbp.handle
    async with await AsyncEnclaveHTTPClient.create("enclave.example", "org/repo", transport_mode="ehbp") as client:
        assert client.enclave == "enclave.example"
        assert client.current is not None
        assert (await client.ensure_verified()) is client.current
        assert (await client.http_client.post("https://enclave.example/v1/x", content=b"hi")).content == b"echo:hi"
        with pytest.raises(ConfigurationError, match="refusing"):
            await client.http_client.get("https://elsewhere.example/")
    with pytest.raises(ConfigurationError, match=CLIENT_CLOSED):
        await client.ensure_verified()

    network.handler = lambda _: response(200, b'["router.example"]')
    network.serve("router.example")
    router = await AsyncRouterHTTPClient.create(transport_mode="ehbp", user_cache_secret="s")
    assert router.enclave == "router.example"
    await router.close()

    entries: Catalog = {"m": CatalogEntry("tinfoilsh/m", ("replica.example",))}
    network.serve("replica.example")
    gateway = await AsyncGatewayHTTPClient.create(
        url="https://gateway.example/v1/", catalog=lambda: entries, user_cache_secret="s"
    )
    assert await gateway.models() == ["m"]
    assert (await gateway.ensure_verified("m")).code_tag == "replica.example"
    assert [v.host for v in gateway.current] == ["replica.example"]
    await gateway.close()
