"""The OpenAI layer: ``OpenAIClient`` and ``AsyncOpenAIClient`` take one of the SDK's attested HTTP clients and
nothing else, do no network I/O, send every request through the attested client's protected transport to the API
path under its route, and set the base URL themselves, so that a caller's ``base_url``, ``data_residency`` or
``OPENAI_BASE_URL`` has no effect. The caller's ``http_client`` cannot replace the attested one, the websocket entry
points are refused, copies keep the attested client and the API path, API errors pass through unchanged, and a
client error raised in the transport reaches the caller unwrapped and unretried. The options that would choose
another websocket URL or an HTTP client of their own are refused from every constructor, factory and copy."""

from __future__ import annotations

import functools
import inspect
import json
import secrets
import sys
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import openai
import pytest
from openai._resource import AsyncAPIResource, SyncAPIResource
from openai.providers import bedrock

from tests.client.helpers import Recorder, report_of, response, verification
from tinfoil import _cachesecret, _fetch
from tinfoil._clients import (
    AsyncEnclaveHTTPClient,
    AsyncGatewayHTTPClient,
    AsyncRouterHTTPClient,
    EnclaveHTTPClient,
    GatewayHTTPClient,
    RouterHTTPClient,
)
from tinfoil._errors import AttestationError, ConfigurationError, TinfoilError, tinfoil_error
from tinfoil._gateway import CatalogEntry, ModelPin
from tinfoil._openai import (
    _FORBIDDEN_TRANSPORT_OPTIONS,
    DROP_IN_OPTIONS,
    REALTIME_UNAVAILABLE,
    ROUTE_OPTIONS,
    TRANSPORT_OPTION_UNSUPPORTED,
    WEBSOCKET_UNAVAILABLE,
    AsyncClient,
    AsyncOpenAIClient,
    Client,
    OpenAIClient,
    create_async_client,
    create_client,
    join_api_path,
)
from tinfoil._trust import EitherPin, RepoPin
from tinfoil._types import DEFAULT_HTTP_TIMEOUT, EHBP
from tinfoil.verifier import Policy, Verifier

MODELS = b'{"object":"list","data":[]}'
ENTRIES = {"m": CatalogEntry("tinfoilsh/m", ("a.example",))}
PINS = {"m": ModelPin("tinfoilsh/m")}


def foreign(**options: Any) -> dict[str, Any]:
    """Options that the type-checked surface does not take, splatted so a test can show they are refused."""
    return options


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    """A network that answers every attestation fetch with a document the patched verifier accepts, every router
    list with an empty one, and every application request with an empty model list."""
    recorder = Recorder(
        lambda request: response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
    )
    monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
    monkeypatch.setattr(_fetch, "_ASYNC_TRANSPORT", recorder.async_transport)
    monkeypatch.setattr(Verifier, "verify_v3", lambda self, doc, nonce, pin: report_of(verification("ab" * 32)))
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    return recorder


def enclave(**options: Any) -> EnclaveHTTPClient:
    return EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(), **options)


def gateway() -> GatewayHTTPClient:
    return GatewayHTTPClient(model_pins=PINS, url="https://gateway.example/", catalog=lambda: ENTRIES)


def models_response(_: httpx.Request) -> httpx.Response:
    return response(200, MODELS, {"Content-Type": "application/json"})


def through(client: openai.OpenAI, handler: Any = models_response) -> list[httpx.Request]:
    """Swaps the attested client's transport for a recorder and lists models through ``client``."""
    recorder = Recorder(handler)
    inner: Any = client._client
    original = inner._transport
    inner._transport = recorder.transport
    try:
        client.models.list()
    finally:
        inner._transport = original
    return recorder.requests


def below_the_attested_transport(client: openai.OpenAI | openai.AsyncOpenAI, handler: Any) -> Recorder:
    """Puts a recorder where the enclave's connections would be, under the attested transport and every layer
    above it, so requests arrive through the whole chain."""
    recorder = Recorder(handler)
    holder: Any = client
    holder.http_client._attested.keyed._current.transport._inner = (
        recorder.async_transport if isinstance(client, openai.AsyncOpenAI) else recorder.transport
    )
    return recorder


CHAT = b'{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}'
EMBEDDINGS = b'{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5]}],"model":"m"}'
RESPONSE = (
    b'{"id":"r1","object":"response","created_at":0,"model":"m","parallel_tool_calls":true,"tool_choice":"auto",'
    b'"tools":[],"output":[{"type":"message","id":"m1","status":"completed","role":"assistant",'
    b'"content":[{"type":"output_text","text":"ok","annotations":[]}]}]}'
)


LIVE_SESSION = b'{"session":{"id":"s1"},"transport":{"type":"webrtc","sdp":"v=0"}}'


def realtime_of(holder: object) -> object:
    """The realtime resource of a client or of one of its resource groups; the access itself is what is refused."""
    return getattr(holder, "realtime")  # noqa: B009 - a plain attribute access would be a useless expression


def by_path(request: httpx.Request) -> httpx.Response:
    bodies = {
        "/chat/completions": CHAT,
        "/embeddings": EMBEDDINGS,
        "/audio/transcriptions": b'{"text":"hi"}',
        "/responses": RESPONSE,
        "/live/sessions": LIVE_SESSION,
    }
    path = request.url.path
    return response(200, bodies[path[path.index("/", 1) :]], {"Content-Type": "application/json"})


class TestConstruction:
    def test_enclave_client_sends_through_its_protected_transport(self, offline: Recorder) -> None:
        http_client = enclave()
        fetched = len(offline.requests)
        client = OpenAIClient(http_client, api_key="k", max_retries=0)
        assert len(offline.requests) == fetched, "the constructor does no network I/O"
        assert client.http_client is http_client
        assert client.base_url == "https://enclave.example/v1/"
        inner: object = client._client
        assert inner is http_client._attested.secure, "the protected client, not the caller's"
        assert inner is not http_client.http_client
        requests = through(client)
        assert [str(r.url) for r in requests] == ["https://enclave.example/v1/models"]
        assert requests[0].headers["Authorization"] == "Bearer k"
        client.close()
        with pytest.raises(ConfigurationError, match="closed"):
            http_client.ensure_verified()

    def test_changes_to_the_callers_client_do_not_reach_openai_requests(self, offline: Recorder) -> None:
        http_client = enclave()
        http_client.http_client.headers["X-Leak"] = "1"
        http_client.http_client.auth = ("user", "password")
        client = OpenAIClient(http_client, api_key="k", max_retries=0)
        [request] = through(client)
        assert "X-Leak" not in request.headers
        assert request.headers["Authorization"] == "Bearer k"
        client.close()

    def test_takes_only_the_sdks_http_clients(self, offline: Recorder) -> None:
        async_like: Any = object.__new__(AsyncEnclaveHTTPClient)
        unbuilt: Any = object.__new__(EnclaveHTTPClient)
        for not_a_client in (None, "https://enclave.example/", httpx.Client(), enclave().http_client, unbuilt):
            with pytest.raises(ConfigurationError, match="must be an EnclaveHTTPClient, RouterHTTPClient or"):
                OpenAIClient(not_a_client, api_key="k")  # type: ignore[arg-type]
        with pytest.raises(ConfigurationError, match="not AsyncEnclaveHTTPClient"):
            OpenAIClient(async_like, api_key="k")
        for not_an_async_client in (None, enclave(), httpx.AsyncClient()):
            with pytest.raises(ConfigurationError, match="must be an AsyncEnclaveHTTPClient, AsyncRouterHTTPClient"):
                AsyncOpenAIClient(not_an_async_client, api_key="k")  # type: ignore[arg-type]

    def test_trust_project_is_separate_from_the_openai_project(self, offline: Recorder) -> None:
        http_client = EnclaveHTTPClient("enclave.example", EitherPin("org/repo", "org/project"), transport=EHBP())
        client = OpenAIClient(http_client, api_key="k", project="proj_123")
        assert http_client.trust == EitherPin("org/repo", "org/project")
        assert client.project == "proj_123"
        copy = client.with_options(max_retries=0)
        assert copy.http_client is client.http_client
        assert copy.project == "proj_123"
        assert through(copy)[0].headers["OpenAI-Project"] == "proj_123"
        client.close()

    def test_router_and_gateway_clients(self, offline: Recorder) -> None:
        offline.handler = lambda request: (
            response(200, b'["router.example"]') if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
        )
        router = OpenAIClient(RouterHTTPClient(transport=EHBP("https://proxy.example/relay")), api_key="k")
        assert isinstance(router.http_client, RouterHTTPClient)
        assert router.base_url == "https://proxy.example/relay/v1/"
        assert [str(r.url) for r in through(router)] == ["https://proxy.example/relay/v1/models"]
        router.close()
        gateway_client = OpenAIClient(gateway(), api_key="k")
        assert isinstance(gateway_client.http_client, GatewayHTTPClient)
        assert gateway_client.base_url == "https://gateway.example/v1/"
        gateway_client.close()

    @pytest.mark.parametrize(
        ("proxy_url", "api_path", "want"),
        [
            (None, None, "https://enclave.example/v1/"),
            (None, "", "https://enclave.example/v1/"),
            (None, "/openai/v1", "https://enclave.example/openai/v1/"),
            (None, "/openai/v1/", "https://enclave.example/openai/v1/"),
            ("https://proxy.example/relay", None, "https://proxy.example/relay/v1/"),
            ("https://proxy.example/relay/", None, "https://proxy.example/relay/v1/"),
            ("https://proxy.example/relay", "/openai/v1", "https://proxy.example/relay/openai/v1/"),
            ("https://proxy.example", None, "https://proxy.example/v1/"),
            ("http://localhost:8080/", "/", "http://localhost:8080/"),
        ],
    )
    def test_api_path_joins_under_the_route(
        self, offline: Recorder, proxy_url: str | None, api_path: str | None, want: str
    ) -> None:
        http_client = EnclaveHTTPClient("enclave.example", RepoPin("org/repo"), transport=EHBP(proxy_url))
        client = OpenAIClient(http_client, api_path=api_path, api_key="k")
        assert client.base_url == want
        assert [str(r.url) for r in through(client)] == [want + "models"]
        copied = client.with_options(max_retries=0)
        assert copied.base_url == want, "a copy keeps the API path"
        client.close()

    @pytest.mark.parametrize(
        "api_path",
        [
            "v1/",
            "//v1/",
            "https://other.example/v1/",
            "/v1/?x=1",
            "/v1/?",
            "/v1/#f",
            "/v1/../admin/",
            "/v1/./",
            "/..",
            "/v1/%2e%2e/admin/",
            "/v1/%2E/",
            "/v1%2fadmin/",
            "/v1/%zz/",
            "/v1/\x00/",
            "/v1/\n/",
        ],
    )
    def test_rejects_an_api_path_that_could_leave_its_root(self, offline: Recorder, api_path: str) -> None:
        http_client = enclave()
        with pytest.raises(ConfigurationError, match="invalid API path"):
            OpenAIClient(http_client, api_path=api_path, api_key="k")
        with pytest.raises(ConfigurationError, match="invalid API path"):
            join_api_path("https://enclave.example/", api_path)
        with pytest.raises(ConfigurationError, match="invalid API path: want a string"):
            OpenAIClient(http_client, api_path=b"/v1/", api_key="k")  # type: ignore[arg-type]
        http_client.close()

    @pytest.mark.parametrize(
        ("url", "api_path", "want"),
        [
            ("https://gateway.example", None, "https://gateway.example/v1/"),
            ("https://gateway.example/", "/v2", "https://gateway.example/v2/"),
            ("https://gateway.example/mount", None, "https://gateway.example/mount/v1/"),
            ("https://gateway.example/mount/", "/openai/v1/", "https://gateway.example/mount/openai/v1/"),
        ],
    )
    def test_gateway_client_joins_its_api_path_under_its_url(
        self, offline: Recorder, url: str, api_path: str | None, want: str
    ) -> None:
        """A gateway's URL is its origin or the URL that it is mounted under, never the API path, so the API path
        joins under it as under an ``EHBP`` proxy URL."""
        http_client = GatewayHTTPClient(model_pins=PINS, url=url, catalog=lambda: ENTRIES)
        assert OpenAIClient(http_client, api_path=api_path, api_key="k").base_url == want
        with pytest.raises(ConfigurationError, match="invalid API path"):
            OpenAIClient(http_client, api_path="v1", api_key="k")
        http_client.close()

    def test_the_sdk_sets_the_base_url_after_the_callers_options(
        self, offline: Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A base URL from the caller, from ``OPENAI_BASE_URL`` or from a data residency option has no effect:
        requests go to the base URL that the SDK builds, from the constructor and from copies alike."""
        monkeypatch.setenv("OPENAI_BASE_URL", "https://from-env.example/v1/")
        cases: list[tuple[EnclaveHTTPClient | GatewayHTTPClient, str]] = [
            (enclave(), "https://enclave.example/v1/"),
            (gateway(), "https://gateway.example/v1/"),
        ]
        for http_client, want in cases:
            client = OpenAIClient(
                http_client,
                api_key="k",
                **foreign(base_url="https://other.example/v1/", data_residency="eu"),
            )
            assert client.base_url == want
            for copy in (client.copy, client.with_options):
                copied = copy(**foreign(base_url="https://other.example/v1/", data_residency="us"))
                assert copied.base_url == want
            assert str(through(client)[0].url) == want + "models"
            client.close()
        drop_in = create_client(api_key="k", **foreign(base_url="https://other.example/v1/"))
        assert drop_in.base_url == "https://inference.tinfoil.sh/v1/"
        drop_in.close()

    def test_http_client_timeout_leaves_the_per_request_default_alone(self, offline: Recorder) -> None:
        """The HTTP client's ``timeout`` is the attested client's; the library's own per-request default stays
        unless the caller sets ``timeout``, so a short attestation timeout does not cut a streamed completion
        short."""
        client = OpenAIClient(enclave(timeout=10.0), api_key="k")
        assert client.timeout == openai.DEFAULT_TIMEOUT
        assert client.http_client.http_client.timeout == httpx.Timeout(10.0)
        client.close()
        explicit = OpenAIClient(enclave(timeout=10.0), api_key="k", timeout=2.0)
        assert explicit.timeout == 2.0
        assert explicit.with_options(max_retries=0).timeout == 2.0, "a copy keeps the caller's timeout"
        explicit.close()
        default = OpenAIClient(enclave(), api_key="k")
        assert default.http_client.http_client.timeout == DEFAULT_HTTP_TIMEOUT
        assert default.timeout == openai.DEFAULT_TIMEOUT
        default.close()

    def test_copies_keep_the_attested_client(self, offline: Recorder) -> None:
        client = OpenAIClient(enclave(), api_key="k", max_retries=0)
        attestations = len(offline.requests)
        copied = client.with_options(timeout=1.0, max_retries=2)
        assert isinstance(copied, OpenAIClient)
        assert copied.http_client is client.http_client
        assert copied.base_url == client.base_url
        assert copied.max_retries == 2
        assert len(offline.requests) == attestations, "a copy verifies nothing"
        with pytest.raises(ConfigurationError, match="http_client"):
            client.with_options(**foreign(http_client=httpx.Client()))
        assert [str(r.url) for r in through(copied)] == ["https://enclave.example/v1/models"]
        client.close()

    def test_a_callers_http_client_is_refused_and_the_attested_client_stays_open(self, offline: Recorder) -> None:
        http_client = enclave()
        with pytest.raises(ConfigurationError, match="http_client"):
            OpenAIClient(http_client, api_key="k", **foreign(http_client=httpx.Client()))
        http_client.ensure_verified()
        http_client.close()

    def test_realtime_is_refused_while_http_resources_go_through_the_attested_transport(
        self, offline: Recorder
    ) -> None:
        client = OpenAIClient(RouterHTTPClient(transport=EHBP(), user_cache_secret="s"), api_key="k", max_retries=0)
        for holder in (client, client.beta, client.with_options(), client.with_raw_response):
            with pytest.raises(ConfigurationError, match=REALTIME_UNAVAILABLE):
                realtime_of(holder)
        assert client.beta.chat is not None, "the other beta resources stay available"
        recorder = below_the_attested_transport(client, by_path)
        messages: list[Any] = [{"role": "user", "content": "hi"}]
        assert client.chat.completions.create(model="m", messages=messages).choices[0].message.content == "ok"
        assert client.embeddings.create(model="m", input="hi").data[0].embedding == [0.5]
        assert client.audio.transcriptions.create(model="m", file=("a.wav", b"RIFF")).text == "hi"
        assert [r.url.path for r in recorder.requests] == [
            "/v1/chat/completions",
            "/v1/embeddings",
            "/v1/audio/transcriptions",
        ]
        assert all(r.url.host == "inference.tinfoil.sh" for r in recorder.requests)
        assert json.loads(recorder.bodies[0])["user_cache_secret"] == "s", "the chat body passed the secret layer"
        client.close()

    def test_responses_go_through_the_attested_transport(self, offline: Recorder) -> None:
        """The Responses API takes the path chat does: the attested origin, with the router client's cache secret
        in the body."""
        router = OpenAIClient(RouterHTTPClient(transport=EHBP(), user_cache_secret="s"), api_key="k", max_retries=0)
        drop_in = create_client(api_key="k", max_retries=0)
        for client, secret in ((router, "s"), (drop_in, "test-secret")):
            recorder = below_the_attested_transport(client, by_path)
            assert client.responses.create(model="m", input="hi").output_text == "ok"
            assert [(r.url.host, r.url.path) for r in recorder.requests] == [("inference.tinfoil.sh", "/v1/responses")]
            assert json.loads(recorder.bodies[0])["user_cache_secret"] == secret, "the body passed the secret layer"
            client.close()

    def test_drop_in_constructor_failure_closes_the_router_client_it_created(
        self, offline: Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        closes: list[RouterHTTPClient] = []
        original = RouterHTTPClient.close

        def close(self: RouterHTTPClient) -> None:
            closes.append(self)
            original(self)

        monkeypatch.setattr(RouterHTTPClient, "close", close)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(openai.OpenAIError):
            Client()  # no api_key anywhere
        assert len(closes) == 1, "the router client created for the refused options is closed"
        with pytest.raises(ConfigurationError, match="closed"):
            closes[0].ensure_verified()
        client = Client(api_key="k")
        with pytest.raises(ConfigurationError, match="http_client"):
            client.with_options(**foreign(http_client=httpx.Client()))
        assert len(closes) == 1, "a copy's failure leaves the original's router client open"
        client.http_client.ensure_verified()
        client.close()
        assert len(closes) == 2

    @pytest.mark.parametrize("option", sorted(ROUTE_OPTIONS))
    def test_drop_in_client_refuses_each_route_option(self, offline: Recorder, option: str) -> None:
        with pytest.raises(ConfigurationError) as err:
            Client(api_key="k", **foreign(**{option: "x"}))
        assert str(err.value) == DROP_IN_OPTIONS.format(
            name="Client", keys=option, route="RouterHTTPClient", openai="OpenAIClient"
        )
        assert offline.requests == [], "the options are refused before discovery"

    @pytest.mark.parametrize("option", sorted(ROUTE_OPTIONS))
    def test_drop_in_copies_refuse_each_route_option(self, offline: Recorder, option: str) -> None:
        """A route option is refused on ``copy`` and ``with_options`` as on the constructor, rather than dropped
        in favor of the attested client's own."""
        client = create_client(api_key="k")
        for copy in (client.with_options, client.copy):
            with pytest.raises(ConfigurationError) as err:
                copy(**foreign(**{option: "x"}))
            assert str(err.value) == DROP_IN_OPTIONS.format(
                name="Client", keys=option, route="RouterHTTPClient", openai="OpenAIClient"
            )
        assert isinstance(client.with_options(max_retries=0), Client)
        client.close()

    def test_drop_in_client_is_an_openai_client_over_a_router(self, offline: Recorder) -> None:
        with pytest.raises(ConfigurationError) as err:
            create_client(api_key="k", **foreign(transport=EHBP(), http_timeout=1.0, policy=Policy()))
        assert str(err.value) == DROP_IN_OPTIONS.format(
            name="Client", keys="http_timeout, policy, transport", route="RouterHTTPClient", openai="OpenAIClient"
        ), "every refused option is named"
        assert offline.requests == []
        client = create_client(api_key="k")
        assert isinstance(client, Client)
        assert isinstance(client, OpenAIClient)
        assert isinstance(client.http_client, RouterHTTPClient)
        assert client.http_client.enclave == "inference.tinfoil.sh"
        assert client.base_url == "https://inference.tinfoil.sh/v1/"
        copied = client.with_options(timeout=2.0)
        assert isinstance(copied, Client)
        assert copied.http_client is client.http_client
        client.close()


class TestErrors:
    def test_api_errors_pass_through(self, offline: Recorder) -> None:
        client = OpenAIClient(enclave(), api_key="k", max_retries=0)
        with pytest.raises(openai.RateLimitError) as err:
            through(
                client,
                lambda _: response(429, b'{"error":{"message":"slow down"}}', {"Content-Type": "application/json"}),
            )
        assert not isinstance(err.value, TinfoilError)
        assert tinfoil_error(err.value) is None
        client.close()

    def test_client_errors_reach_the_caller(self, offline: Recorder) -> None:
        """The library reports only its HTTP stack's errors as connection errors, so a client error raised from
        the transport reaches the caller as itself, with or without the library's retries."""
        client = OpenAIClient(enclave(), api_key="k", max_retries=2)
        failure = AttestationError("channel binding failed")
        attempts = 0

        def failing(_: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            raise failure

        with pytest.raises(AttestationError) as err:
            through(client, failing)
        assert err.value is failure
        assert tinfoil_error(err.value) is failure
        assert attempts == 1, "a client error is not retried by the library"
        client.close()

    def test_cache_secret_per_request_wins(self, offline: Recorder) -> None:
        received: list[dict[str, Any]] = []

        def chat(request: httpx.Request) -> httpx.Response:
            received.append(json.loads(request.read()))
            return response(200, CHAT, {"Content-Type": "application/json"})

        router = OpenAIClient(
            RouterHTTPClient(transport=EHBP(), user_cache_secret="client-level"), api_key="k", max_retries=0
        )
        below_the_attested_transport(router, chat)  # below the cache-secret layer, so it sees the injected body
        params: dict[str, Any] = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        router.chat.completions.create(**params)
        router.chat.completions.create(**params, extra_body={"user_cache_secret": "end-user-7"})
        router.chat.completions.create(**params, extra_body={"user_cache_secret": ""})
        assert [body["user_cache_secret"] for body in received] == ["client-level", "end-user-7", "client-level"]
        router.close()

    def test_clients_without_the_option_share_one_generated_secret(
        self, offline: Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Router and gateway clients built without ``user_cache_secret`` send the secret that the process
        generated, the same for each, with the variable and the file that earlier releases read both set; the
        option and a per-request field still win."""
        monkeypatch.setattr(_cachesecret, "_process_secret", None)
        monkeypatch.setenv("TINFOIL_USER_CACHE_SECRET", "from-env")
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        secret_file = tmp_path / ".tinfoil" / "user_cache_secret"
        secret_file.parent.mkdir()
        secret_file.write_text("from-file")
        secret_file.chmod(0o600)
        received: list[dict[str, Any]] = []

        def chat(request: httpx.Request) -> httpx.Response:
            received.append(json.loads(request.read()))
            return response(200, CHAT, {"Content-Type": "application/json"})

        first = create_client(api_key="k", max_retries=0)
        second = OpenAIClient(RouterHTTPClient(), api_key="k", max_retries=0)
        pinned = OpenAIClient(RouterHTTPClient(user_cache_secret="client-level"), api_key="k", max_retries=0)
        gateway_client = gateway()
        params: dict[str, Any] = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        for client in (first, second, pinned):
            below_the_attested_transport(client, chat)
            client.chat.completions.create(**params)
        first.chat.completions.create(**params, extra_body={"user_cache_secret": "end-user-7"})
        generated = received[0]["user_cache_secret"]
        assert len(generated) == 64
        assert generated not in ("from-env", "from-file")
        assert [body["user_cache_secret"] for body in received] == [generated, generated, "client-level", "end-user-7"]
        gateway_transport: Any = gateway_client._transport
        assert gateway_transport.secret == generated, "the gateway client shares the process secret"
        assert secret_file.read_text() == "from-file"
        for client in (first, second, pinned):
            client.close()
        gateway_client.close()

    def test_clients_fail_with_the_random_sources_exception(
        self, offline: Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without ``user_cache_secret``, a router or gateway client whose secret can't be generated raises the
        random source's exception unchanged, before any network I/O; a later client generates the secret."""
        monkeypatch.setattr(_cachesecret, "_process_secret", None)
        failure = OSError("no secure randomness")
        real = secrets.token_hex

        def fail(nbytes: int) -> str:
            raise failure

        monkeypatch.setattr(secrets, "token_hex", fail)
        with pytest.raises(OSError, match="no secure randomness") as raised:
            RouterHTTPClient()
        assert raised.value is failure
        with pytest.raises(OSError, match="no secure randomness") as raised:
            gateway()
        assert raised.value is failure
        assert offline.requests == []
        monkeypatch.setattr(secrets, "token_hex", real)
        router = RouterHTTPClient()
        assert _cachesecret._process_secret is not None
        assert len(_cachesecret._process_secret) == 64
        router.close()


@pytest.mark.asyncio
async def test_async_client(offline: Recorder) -> None:
    http_client = await AsyncEnclaveHTTPClient.create("enclave.example", RepoPin("org/repo"), transport=EHBP())
    fetched = len(offline.requests)
    client = AsyncOpenAIClient(http_client, api_key="k", max_retries=0)
    assert len(offline.requests) == fetched, "the constructor does no network I/O"
    assert client.http_client is http_client
    assert client.base_url == "https://enclave.example/v1/"
    inner: object = client._client
    assert inner is http_client._attested.secure
    copied = client.with_options(timeout=1.0)
    assert copied.http_client is client.http_client
    for holder in (client, client.beta, copied):
        with pytest.raises(ConfigurationError, match=REALTIME_UNAVAILABLE):
            realtime_of(holder)
    recorder = Recorder(models_response)
    inner_client: Any = client._client
    inner_client._transport = recorder.async_transport
    await client.models.list()
    assert [str(r.url) for r in recorder.requests] == ["https://enclave.example/v1/models"]
    await client.close()
    gateway_client = await AsyncGatewayHTTPClient.create(
        model_pins=PINS, url="https://gateway.example/", catalog=lambda: ENTRIES
    )
    assert AsyncOpenAIClient(gateway_client, api_path="/v2/", api_key="k").base_url == "https://gateway.example/v2/"
    async_gateway = AsyncOpenAIClient(gateway_client, api_key="k", **foreign(base_url="https://other.example/v1/"))
    assert async_gateway.base_url == "https://gateway.example/v1/"
    assert async_gateway.with_options(**foreign(base_url="https://other.example/")).base_url == async_gateway.base_url
    await async_gateway.close()
    router = await AsyncRouterHTTPClient.create(transport=EHBP("https://proxy.example/relay/"))
    assert AsyncOpenAIClient(router, api_path="/openai/v1", api_key="k").base_url == (
        "https://proxy.example/relay/openai/v1/"
    )
    await router.close()


@pytest.mark.asyncio
async def test_async_drop_in_client(offline: Recorder) -> None:
    with pytest.raises(ConfigurationError, match="create"):
        AsyncClient(api_key="k")
    for option in sorted(ROUTE_OPTIONS):
        with pytest.raises(ConfigurationError, match=option):
            await AsyncClient.create(api_key="k", **foreign(**{option: "x"}))
    assert offline.requests == []
    drop_in = await create_async_client(api_key="k", **foreign(base_url="https://other.example/v1/"))
    assert isinstance(drop_in, AsyncClient)
    assert isinstance(drop_in, AsyncOpenAIClient)
    assert isinstance(drop_in.http_client, AsyncRouterHTTPClient)
    assert drop_in.http_client.enclave == "inference.tinfoil.sh"
    assert drop_in.base_url == "https://inference.tinfoil.sh/v1/"
    for option in sorted(ROUTE_OPTIONS):
        for copy in (drop_in.with_options, drop_in.copy):
            with pytest.raises(ConfigurationError) as err:
                copy(**foreign(**{option: "x"}))
            assert str(err.value) == DROP_IN_OPTIONS.format(
                name="AsyncClient", keys=option, route="AsyncRouterHTTPClient", openai="AsyncOpenAIClient"
            )
    assert isinstance(drop_in.with_options(max_retries=0), AsyncClient)
    with pytest.raises(ConfigurationError, match=REALTIME_UNAVAILABLE):
        realtime_of(drop_in)
    await drop_in.close()


@pytest.mark.asyncio
async def test_async_responses_go_through_the_attested_transport(offline: Recorder) -> None:
    router = AsyncOpenAIClient(
        await AsyncRouterHTTPClient.create(transport=EHBP(), user_cache_secret="s"), api_key="k", max_retries=0
    )
    drop_in = await create_async_client(api_key="k", max_retries=0)
    for client, secret in ((router, "s"), (drop_in, "test-secret")):
        recorder = below_the_attested_transport(client, by_path)
        assert (await client.responses.create(model="m", input="hi")).output_text == "ok"
        assert [(r.url.host, r.url.path) for r in recorder.requests] == [("inference.tinfoil.sh", "/v1/responses")]
        assert json.loads(recorder.bodies[0])["user_cache_secret"] == secret
        await client.close()


SUBJECT_TOKEN_IDENTITY = {
    "identity_provider_id": "idp",
    "service_account_id": "sa",
    "provider": {"token_type": "jwt", "get_token": lambda: "subject-token"},
}
TRANSPORT_OPTIONS: list[tuple[str, object]] = [
    ("provider", bedrock(region="us-east-1", api_key="b")),
    ("websocket_base_url", "wss://elsewhere.example/v1/"),
    ("workload_identity", SUBJECT_TOKEN_IDENTITY),
    ("workload_identity", {"type": "x509", "identity_provider_id": "idp", "service_account_id": "sa"}),
]
"""A value for each refused option: the subject-token identity is the one that the ``openai`` package itself
accepts next to the attested base URL, exchanging the token through an HTTP client of its own."""
TRANSPORT_OPTION_IDS = [
    "provider",
    "websocket_base_url",
    "subject-token workload_identity",
    "x509 workload_identity",
]
UNSET_TRANSPORT_OPTIONS = dict.fromkeys(_FORBIDDEN_TRANSPORT_OPTIONS)

HTTP_CLIENTS: dict[str, Callable[[], object]] = {
    "enclave": enclave,
    "router": lambda: RouterHTTPClient(transport=EHBP()),
    "gateway": gateway,
}
SYNC_FACTORIES: dict[str, Callable[..., openai.OpenAI]] = {
    **{
        f"OpenAIClient over {name}": functools.partial(
            lambda make, **kw: OpenAIClient(make(), **kw),
            make,
        )
        for name, make in HTTP_CLIENTS.items()
    },
    "Client": lambda **kw: Client(**kw),
    "create_client": lambda **kw: create_client(**kw),
}


async def _async_enclave() -> AsyncEnclaveHTTPClient:
    return await AsyncEnclaveHTTPClient.create("enclave.example", RepoPin("org/repo"), transport=EHBP())


async def _async_router() -> AsyncRouterHTTPClient:
    return await AsyncRouterHTTPClient.create(transport=EHBP())


async def _async_gateway() -> AsyncGatewayHTTPClient:
    return await AsyncGatewayHTTPClient.create(model_pins=PINS, url="https://gateway.example/", catalog=lambda: ENTRIES)


ASYNC_HTTP_CLIENTS: dict[str, Callable[[], Awaitable[Any]]] = {
    "enclave": _async_enclave,
    "router": _async_router,
    "gateway": _async_gateway,
}


async def _async_openai(make: Callable[[], Awaitable[Any]], **kw: Any) -> openai.AsyncOpenAI:
    return AsyncOpenAIClient(await make(), **kw)


ASYNC_FACTORIES: dict[str, Callable[..., Awaitable[openai.AsyncOpenAI]]] = {
    **{
        f"AsyncOpenAIClient over {name}": functools.partial(_async_openai, make)
        for name, make in ASYNC_HTTP_CLIENTS.items()
    },
    "AsyncClient": lambda **kw: AsyncClient.create(**kw),
    "create_async_client": lambda **kw: create_async_client(**kw),
}


def answering_discovery(offline: Recorder) -> None:
    offline.handler = lambda request: (
        response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
    )


def recording(client: openai.OpenAI | openai.AsyncOpenAI) -> Recorder:
    """A recorder under the attested transport, or, for a gateway client, in place of the protected client's own
    transport, which the ``openai`` client must send through."""
    holder: Any = client
    inner_client: object = client._client
    if not isinstance(holder.http_client, (GatewayHTTPClient, AsyncGatewayHTTPClient)):
        assert inner_client is holder.http_client._attested.secure, "the openai client sends through the attested one"
        return below_the_attested_transport(client, by_path)
    assert inner_client is holder.http_client._secure
    recorder = Recorder(by_path)
    inner: Any = client._client
    inner._transport = recorder.async_transport if isinstance(client, openai.AsyncOpenAI) else recorder.transport
    return recorder


def refused(option: str) -> str:
    return TRANSPORT_OPTION_UNSUPPORTED.format(key=option)


class TestTransportOptions:
    """``provider``, ``websocket_base_url`` and ``workload_identity`` would choose another websocket URL or send a
    token exchange through an HTTP client of their own, so each is refused by name, before the ``openai``
    constructor runs, rather than left to the ``openai`` package's own checks; ``None`` is unset."""

    def test_message_names_the_option(self) -> None:
        assert _FORBIDDEN_TRANSPORT_OPTIONS == ("provider", "websocket_base_url", "workload_identity")
        assert refused("provider") == (
            "the provider option is not supported: the Tinfoil client owns the transport and base URL that "
            "requests go to"
        )

    @pytest.mark.parametrize("factory", sorted(SYNC_FACTORIES))
    @pytest.mark.parametrize(("option", "value"), TRANSPORT_OPTIONS, ids=TRANSPORT_OPTION_IDS)
    def test_constructors_refuse_each_option(self, offline: Recorder, factory: str, option: str, value: object) -> None:
        with pytest.raises(ConfigurationError) as err:
            SYNC_FACTORIES[factory](api_key="k", **foreign(**{option: value}))
        assert str(err.value) == refused(option)
        with pytest.raises(ConfigurationError, match=f"the {option} option"):
            SYNC_FACTORIES[factory](**foreign(**{option: value}))  # without an api_key too
        if factory in ("Client", "create_client"):
            assert offline.requests == [], "the drop-in client refuses them before discovery"
        assert not any(r.url.host == "a.example" for r in offline.requests), "no token is exchanged"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("factory", sorted(ASYNC_FACTORIES))
    @pytest.mark.parametrize(("option", "value"), TRANSPORT_OPTIONS, ids=TRANSPORT_OPTION_IDS)
    async def test_async_factories_refuse_each_option(
        self, offline: Recorder, factory: str, option: str, value: object
    ) -> None:
        with pytest.raises(ConfigurationError) as err:
            await ASYNC_FACTORIES[factory](api_key="k", **foreign(**{option: value}))
        assert str(err.value) == refused(option)
        if factory in ("AsyncClient", "create_async_client"):
            assert offline.requests == []

    @pytest.mark.parametrize("factory", sorted(SYNC_FACTORIES))
    def test_copies_refuse_each_option(self, offline: Recorder, factory: str) -> None:
        answering_discovery(offline)
        client = SYNC_FACTORIES[factory](api_key="k", max_retries=0)
        fetched = len(offline.requests)
        for option, value in TRANSPORT_OPTIONS:
            for copy in (client.copy, client.with_options):
                with pytest.raises(ConfigurationError) as err:
                    copy(**foreign(**{option: value}))
                assert str(err.value) == refused(option)
        assert len(offline.requests) == fetched
        copied = client.with_options(**foreign(**UNSET_TRANSPORT_OPTIONS))
        assert copied.base_url == client.base_url
        client.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("factory", sorted(ASYNC_FACTORIES))
    async def test_async_copies_refuse_each_option(self, offline: Recorder, factory: str) -> None:
        answering_discovery(offline)
        client = await ASYNC_FACTORIES[factory](api_key="k", max_retries=0)
        fetched = len(offline.requests)
        for option, value in TRANSPORT_OPTIONS:
            for copy in (client.copy, client.with_options):
                with pytest.raises(ConfigurationError) as err:
                    copy(**foreign(**{option: value}))
                assert str(err.value) == refused(option)
        assert len(offline.requests) == fetched
        assert client.with_options(**foreign(**UNSET_TRANSPORT_OPTIONS)).base_url == client.base_url
        await client.close()

    @pytest.mark.parametrize("factory", sorted(SYNC_FACTORIES))
    def test_none_is_unset_and_other_options_go_through_the_attested_transport(
        self, offline: Recorder, factory: str
    ) -> None:
        answering_discovery(offline)
        client = SYNC_FACTORIES[factory](
            api_key="k",
            organization="org-1",
            default_headers={"X-Trace": "1"},
            default_query={"v": "2"},
            timeout=3.0,
            max_retries=0,
            **foreign(**UNSET_TRANSPORT_OPTIONS),
        )
        assert client.timeout == 3.0
        assert client.workload_identity is None
        copied = client.with_options(default_headers={"X-Copy": "1"}, max_retries=1)
        assert copied.max_retries == 1
        recorder = recording(client)
        messages: list[Any] = [{"role": "user", "content": "hi"}]
        copied.chat.completions.create(model="m", messages=messages)
        [request] = recorder.requests
        assert request.url.host == httpx.URL(str(client.base_url)).host
        assert request.url.params["v"] == "2"
        assert (request.headers["X-Trace"], request.headers["X-Copy"]) == ("1", "1")
        assert request.headers["OpenAI-Organization"] == "org-1"
        assert request.headers["Authorization"] == "Bearer k"
        client.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("factory", sorted(ASYNC_FACTORIES))
    async def test_async_none_is_unset_and_other_options_go_through_the_attested_transport(
        self, offline: Recorder, factory: str
    ) -> None:
        answering_discovery(offline)
        client = await ASYNC_FACTORIES[factory](
            api_key="k",
            organization="org-1",
            default_headers={"X-Trace": "1"},
            default_query={"v": "2"},
            timeout=3.0,
            max_retries=0,
            **foreign(**UNSET_TRANSPORT_OPTIONS),
        )
        assert client.timeout == 3.0
        recorder = recording(client)
        messages: list[Any] = [{"role": "user", "content": "hi"}]
        await client.with_options(max_retries=0).chat.completions.create(model="m", messages=messages)
        [request] = recorder.requests
        assert request.url.host == httpx.URL(str(client.base_url)).host
        assert request.url.params["v"] == "2"
        assert request.headers["X-Trace"] == "1"
        assert request.headers["OpenAI-Organization"] == "org-1"
        await client.close()


WEBSOCKET_CONNECTS: dict[str, dict[str, Any]] = {
    "responses.connect": {},
    "beta.responses.connect": {},
    "live.connect": {},
    "live.sideband.connect": {"session_id": "s"},
    "live.forks.connect": {"session_id": "s"},
}
"""Each websocket ``connect`` method of the ``openai`` package, by its path from the client, with the arguments
that it needs; the ``realtime`` resource, which opens a websocket too, is refused as a whole."""
REALTIME_PATHS = ("realtime", "beta.realtime")


def resolve(client: object, path: str) -> Any:
    holder: Any = client
    for name in path.split("."):
        holder = getattr(holder, name)
    return holder


def connect_methods(holder: object, path: str = "") -> Iterator[str]:
    """The paths of the ``connect`` methods under ``holder``, found by walking its resources, so that a websocket
    entry point that a later ``openai`` release adds is listed here before it is refused. A resource whose access
    is itself refused, such as ``realtime`` on an attested client, is skipped."""
    for name in dir(type(holder)):
        if name.startswith("_") or name in ("with_raw_response", "with_streaming_response"):
            continue
        member = inspect.getattr_static(type(holder), name)
        child = f"{path}.{name}" if path else name
        if name == "connect" and callable(member):
            yield child
        elif isinstance(member, (functools.cached_property, property)):
            try:
                value = getattr(holder, name)
            except ConfigurationError:
                continue
            if isinstance(value, (SyncAPIResource, AsyncAPIResource)):
                yield from connect_methods(value, child)


@pytest.fixture
def no_websockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Makes ``websockets`` unimportable, whether or not it is installed, so that a refusal must come before the
    ``openai`` package imports it."""
    monkeypatch.setitem(sys.modules, "websockets", None)


def assert_websockets_refused(client: openai.OpenAI | openai.AsyncOpenAI) -> None:
    for path, arguments in WEBSOCKET_CONNECTS.items():
        with pytest.raises(ConfigurationError) as err:
            resolve(client, path)(**arguments)
        assert str(err.value) == WEBSOCKET_UNAVAILABLE.format(name=path)
    for path in REALTIME_PATHS:
        with pytest.raises(ConfigurationError, match=REALTIME_UNAVAILABLE):
            resolve(client, path)
    assert set(connect_methods(client)) == set(WEBSOCKET_CONNECTS), "every reachable connect is refused above"


class TestWebsockets:
    """A websocket can't use the attested HTTP client, so every websocket entry point of the ``openai`` package
    is refused, by name and before any network I/O, on every client and copy, while the HTTP methods of the same
    resources still go through the attested transport."""

    @pytest.mark.parametrize("cls", [openai.OpenAI, openai.AsyncOpenAI])
    def test_the_inventory_is_every_connect_of_the_openai_package(self, cls: type[openai.OpenAI]) -> None:
        client = cls(api_key="k")
        assert set(connect_methods(client)) == set(WEBSOCKET_CONNECTS) | {f"{p}.connect" for p in REALTIME_PATHS}

    def test_realtime_message_is_unchanged(self) -> None:
        assert REALTIME_UNAVAILABLE == "realtime is not available over an attested client"
        assert (
            WEBSOCKET_UNAVAILABLE.format(name="live.connect") == "live.connect is not available over an attested client"
        )

    @pytest.mark.usefixtures("no_websockets")
    @pytest.mark.parametrize("factory", sorted(SYNC_FACTORIES))
    def test_each_entry_point_is_refused_on_each_client_and_copy(self, offline: Recorder, factory: str) -> None:
        answering_discovery(offline)
        client = SYNC_FACTORIES[factory](api_key="k", max_retries=0)
        fetched = len(offline.requests)
        for holder in (client, client.copy(), client.with_options(max_retries=1)):
            assert_websockets_refused(holder)
        assert len(offline.requests) == fetched, "nothing is sent"
        client.close()

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("no_websockets")
    @pytest.mark.parametrize("factory", sorted(ASYNC_FACTORIES))
    async def test_async_each_entry_point_is_refused_on_each_client_and_copy(
        self, offline: Recorder, factory: str
    ) -> None:
        answering_discovery(offline)
        client = await ASYNC_FACTORIES[factory](api_key="k", max_retries=0)
        fetched = len(offline.requests)
        for holder in (client, client.copy(), client.with_options(max_retries=1)):
            assert_websockets_refused(holder)
        assert len(offline.requests) == fetched, "nothing is sent"
        await client.close()

    @pytest.mark.parametrize("factory", sorted(SYNC_FACTORIES))
    def test_http_methods_of_the_same_resources_go_through_the_attested_transport(
        self, offline: Recorder, factory: str
    ) -> None:
        answering_discovery(offline)
        client = SYNC_FACTORIES[factory](api_key="k", max_retries=0).with_options(max_retries=0)
        recorder = recording(client)
        session: Any = {"model": "m"}
        assert client.responses.create(model="m", input="hi").output_text == "ok"
        assert client.beta.responses.create(model="m", input="hi").id == "r1"
        assert client.live.create(session=session, transport={"type": "webrtc", "sdp": "v=0"}).session.id == "s1"
        base = httpx.URL(str(client.base_url))
        assert [(r.url.host, r.url.path) for r in recorder.requests] == [
            (base.host, base.path + "responses"),
            (base.host, base.path + "responses"),
            (base.host, base.path + "live/sessions"),
        ]
        client.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("factory", sorted(ASYNC_FACTORIES))
    async def test_async_http_methods_of_the_same_resources_go_through_the_attested_transport(
        self, offline: Recorder, factory: str
    ) -> None:
        answering_discovery(offline)
        client = (await ASYNC_FACTORIES[factory](api_key="k", max_retries=0)).with_options(max_retries=0)
        recorder = recording(client)
        session: Any = {"model": "m"}
        assert (await client.responses.create(model="m", input="hi")).output_text == "ok"
        assert (await client.beta.responses.create(model="m", input="hi")).id == "r1"
        created = await client.live.create(session=session, transport={"type": "webrtc", "sdp": "v=0"})
        assert created.session.id == "s1"
        base = httpx.URL(str(client.base_url))
        assert [(r.url.host, r.url.path) for r in recorder.requests] == [
            (base.host, base.path + "responses"),
            (base.host, base.path + "responses"),
            (base.host, base.path + "live/sessions"),
        ]
        await client.close()
