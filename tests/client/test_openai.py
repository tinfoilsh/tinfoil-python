"""The OpenAI wrappers: every request goes through the attested HTTP client to the route's URL, the caller's
``http_client`` and ``base_url`` cannot replace it, the websocket entry points are refused, copies keep the attested
client, a failed constructor closes the one it created, API errors pass through unchanged, and a client error
raised in the transport reaches the caller unwrapped and unretried, since the library wraps and retries only
the errors of its own HTTP stack. The options that would choose another base URL or an HTTP client of their own
are refused from every constructor, factory and copy, before any network I/O."""

from __future__ import annotations

import functools
import inspect
import json
import sys
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import openai
import pytest
from openai._resource import AsyncAPIResource, SyncAPIResource
from openai.providers import bedrock

from tests.client.helpers import Recorder, response, verification
from tinfoil import _cachesecret, _fetch
from tinfoil._clients import (
    AsyncEnclaveHTTPClient,
    AsyncGatewayHTTPClient,
    EnclaveHTTPClient,
    GatewayHTTPClient,
    RouterHTTPClient,
)
from tinfoil._errors import AttestationError, ConfigurationError, TinfoilError, tinfoil_error
from tinfoil._gateway import CatalogEntry
from tinfoil._openai import (
    _FORBIDDEN_TRANSPORT_OPTIONS,
    BASE_URL_FIXED,
    DROP_IN_OPTIONS,
    REALTIME_UNAVAILABLE,
    ROUTE_OPTIONS,
    TRANSPORT_OPTION_UNSUPPORTED,
    WEBSOCKET_UNAVAILABLE,
    AsyncClient,
    AsyncEnclaveOpenAIClient,
    AsyncGatewayOpenAIClient,
    AsyncRouterOpenAIClient,
    Client,
    EnclaveOpenAIClient,
    GatewayOpenAIClient,
    RouterOpenAIClient,
    create_async_client,
    create_client,
)
from tinfoil._types import DEFAULT_HTTP_TIMEOUT
from tinfoil.verifier import Verifier

MODELS = b'{"object":"list","data":[]}'


def foreign(**options: Any) -> dict[str, Any]:
    """Options that the type-checked surface does not take, splatted so a test can show they are refused."""
    return options


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    """A network that answers every attestation fetch with a document the patched verifier accepts, and every
    application request with an empty model list."""
    recorder = Recorder(lambda _: response(200, b"doc"))
    monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
    monkeypatch.setattr(_fetch, "_ASYNC_TRANSPORT", recorder.async_transport)
    monkeypatch.setattr(Verifier, "verify_v3", lambda self, doc, nonce, repo, project=None: verification("ab" * 32))
    return recorder


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
        "/v1/chat/completions": CHAT,
        "/v1/embeddings": EMBEDDINGS,
        "/v1/audio/transcriptions": b'{"text":"hi"}',
        "/v1/responses": RESPONSE,
        "/v1/live/sessions": LIVE_SESSION,
    }
    return response(200, bodies[request.url.path], {"Content-Type": "application/json"})


class TestConstruction:
    def test_enclave_client_sends_through_its_http_client(self, offline: Recorder) -> None:
        client = EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", api_key="k", max_retries=0)
        assert isinstance(client.http_client, EnclaveHTTPClient)
        assert client.base_url == "https://enclave.example/v1/"
        inner: object = client._client
        assert inner is client.http_client.http_client
        requests = through(client)
        assert [str(r.url) for r in requests] == ["https://enclave.example/v1/models"]
        assert requests[0].headers["Authorization"] == "Bearer k"
        client.close()
        with pytest.raises(ConfigurationError, match="closed"):
            client.http_client.ensure_verified()

    def test_registry_project_is_separate_from_the_openai_project(self, offline: Recorder) -> None:
        client = EnclaveOpenAIClient(
            "enclave.example",
            "org/repo",
            registry_project="org/project",
            transport_mode="ehbp",
            api_key="k",
            project="proj_123",
        )
        assert (client.http_client.repo, client.http_client.project) == ("org/repo", "org/project")
        assert client.project == "proj_123"
        copy = client.with_options(max_retries=0)
        assert copy.http_client is client.http_client
        assert copy.project == "proj_123"
        assert through(copy)[0].headers["OpenAI-Project"] == "proj_123"
        client.close()
        with pytest.raises(ConfigurationError):
            EnclaveOpenAIClient("enclave.example", None, registry_project="not a reference", api_key="k")

    def test_router_and_gateway_clients(self, offline: Recorder) -> None:
        offline.handler = lambda request: (
            response(200, b'["router.example"]') if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
        )
        router = RouterOpenAIClient(
            transport_mode="ehbp", base_url="https://proxy.example/v1/", user_cache_secret="s", api_key="k"
        )
        assert isinstance(router.http_client, RouterHTTPClient)
        assert router.base_url == "https://proxy.example/v1/"
        assert [str(r.url) for r in through(router)] == ["https://proxy.example/v1/models"]
        router.close()
        gateway = GatewayOpenAIClient(
            url="https://gateway.example/v1/",
            catalog=lambda: {"m": CatalogEntry("tinfoilsh/m", ("a.example",))},
            api_key="k",
        )
        assert isinstance(gateway.http_client, GatewayHTTPClient)
        assert gateway.base_url == "https://gateway.example/v1/"
        gateway.close()

    def test_rejects_invalid_options(self, offline: Recorder) -> None:
        with pytest.raises(ConfigurationError):
            EnclaveOpenAIClient("", "org/repo", api_key="k")
        with pytest.raises(ConfigurationError):
            RouterOpenAIClient(transport_mode="quic", api_key="k")  # type: ignore[arg-type]
        with pytest.raises(ConfigurationError):
            GatewayOpenAIClient(url="http://gateway.example/v1/", catalog=dict, api_key="k")
        assert offline.requests == []

    def test_callers_http_client_and_base_url_cannot_replace_the_attested_ones(self, offline: Recorder) -> None:
        with pytest.raises(ConfigurationError, match="http_client"):
            EnclaveOpenAIClient(
                "enclave.example", "org/repo", transport_mode="ehbp", api_key="k", **foreign(http_client=httpx.Client())
            )
        client = EnclaveOpenAIClient(
            "enclave.example",
            "org/repo",
            transport_mode="ehbp",
            api_key="k",
            base_url="https://enclave.example/custom/v1/",
        )
        assert client.base_url == "https://enclave.example/custom/v1/", (
            "base_url is the route option, applied to the attested client"
        )
        client.close()

    def test_http_timeout_leaves_the_per_request_default_alone(self, offline: Recorder) -> None:
        """``http_timeout`` is the attested client's timeout; the library's own per-request default stays unless
        the caller sets ``timeout``, so a short attestation timeout does not cut a streamed completion short."""
        client = EnclaveOpenAIClient(
            "enclave.example", "org/repo", transport_mode="ehbp", api_key="k", http_timeout=10.0
        )
        assert client.timeout == openai.DEFAULT_TIMEOUT
        assert client.http_client.http_client.timeout == httpx.Timeout(10.0)
        client.close()
        explicit = EnclaveOpenAIClient(
            "enclave.example", "org/repo", transport_mode="ehbp", api_key="k", http_timeout=10.0, timeout=2.0
        )
        assert explicit.timeout == 2.0
        assert explicit.with_options(max_retries=0).timeout == 2.0, "a copy keeps the caller's timeout"
        explicit.close()
        default = EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", api_key="k")
        assert default.http_client.http_client.timeout == DEFAULT_HTTP_TIMEOUT
        assert default.timeout == openai.DEFAULT_TIMEOUT
        default.close()

    def test_copies_keep_the_attested_client(self, offline: Recorder) -> None:
        client = EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", api_key="k", max_retries=0)
        attestations = len(offline.requests)
        copied = client.with_options(timeout=1.0, max_retries=2)
        assert isinstance(copied, EnclaveOpenAIClient)
        assert copied.http_client is client.http_client
        assert copied.base_url == client.base_url
        assert copied.max_retries == 2
        assert len(offline.requests) == attestations, "a copy verifies nothing"
        with pytest.raises(ConfigurationError, match="http_client"):
            client.with_options(**foreign(http_client=httpx.Client()))
        assert [str(r.url) for r in through(copied)] == ["https://enclave.example/v1/models"]
        client.close()

    def test_realtime_is_refused_while_http_resources_go_through_the_attested_transport(
        self, offline: Recorder
    ) -> None:
        client = EnclaveOpenAIClient(
            "enclave.example", "org/repo", transport_mode="ehbp", user_cache_secret="s", api_key="k", max_retries=0
        )
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
        assert all(r.url.host == "enclave.example" for r in recorder.requests)
        assert json.loads(recorder.bodies[0])["user_cache_secret"] == "s", "the chat body passed the secret layer"
        client.close()

    def test_responses_go_through_the_attested_transport(self, offline: Recorder) -> None:
        """The Responses API is reachable on each wrapper and takes the path chat does: the attested origin,
        with the client-level cache secret in the body."""
        offline.handler = lambda request: (
            response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
        )
        enclave = EnclaveOpenAIClient(
            "enclave.example", "org/repo", transport_mode="ehbp", user_cache_secret="s", api_key="k", max_retries=0
        )
        drop_in = create_client(api_key="k", max_retries=0)
        for client, host, secret in (
            (enclave, "enclave.example", "s"),
            (drop_in, "inference.tinfoil.sh", "test-secret"),
        ):
            recorder = below_the_attested_transport(client, by_path)
            assert client.responses.create(model="m", input="hi").output_text == "ok"
            assert [(r.url.host, r.url.path) for r in recorder.requests] == [(host, "/v1/responses")]
            assert json.loads(recorder.bodies[0])["user_cache_secret"] == secret, "the body passed the secret layer"
            client.close()

    def test_gateway_client_refuses_a_base_url(self, offline: Recorder) -> None:
        """The gateway's base URL is its ``url`` option: a ``base_url`` is refused rather than dropped, from the
        constructor and from copies alike, while a copy passing the gateway's own back is accepted."""
        entries = {"m": CatalogEntry("tinfoilsh/m", ("a.example",))}
        with pytest.raises(ConfigurationError) as err:
            GatewayOpenAIClient(
                url="https://gateway.example/v1/",
                catalog=lambda: entries,
                api_key="k",
                **foreign(base_url="https://other.example/v1/"),
            )
        assert str(err.value) == BASE_URL_FIXED
        gateway = GatewayOpenAIClient(url="https://gateway.example/v1/", catalog=lambda: entries, api_key="k")
        for copy in (gateway.copy, gateway.with_options):
            with pytest.raises(ConfigurationError, match="base_url"):
                copy(**foreign(base_url="https://other.example/v1/"))
        copied = gateway.with_options(timeout=1.0)
        assert copied.base_url == gateway.base_url == "https://gateway.example/v1/"
        assert copied.http_client is gateway.http_client
        gateway.close()

    def test_constructor_failure_closes_the_attested_client_it_created(
        self, offline: Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        closes: list[EnclaveHTTPClient] = []
        original = EnclaveHTTPClient.close

        def close(self: EnclaveHTTPClient) -> None:
            closes.append(self)
            original(self)

        monkeypatch.setattr(EnclaveHTTPClient, "close", close)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ConfigurationError, match="http_client"):
            EnclaveOpenAIClient(
                "enclave.example", "org/repo", transport_mode="ehbp", **foreign(http_client=httpx.Client())
            )
        assert len(closes) == 1, "the attested client created for the refused options is closed"
        with pytest.raises(openai.OpenAIError):
            EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp")  # no api_key anywhere
        assert len(closes) == 2, "so is one the openai constructor refuses"
        for closed in closes:
            with pytest.raises(ConfigurationError, match="closed"):
                closed.ensure_verified()
        client = EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", api_key="k")
        with pytest.raises(ConfigurationError, match="http_client"):
            client.with_options(**foreign(http_client=httpx.Client()))
        assert len(closes) == 2, "a copy's failure leaves the original's attested client open"
        client.http_client.ensure_verified()
        client.close()
        assert len(closes) == 3

    def test_host_and_repo_are_required(self, offline: Recorder) -> None:
        """Both are positional and have no defaults, so leaving one out fails at the call, before any I/O."""
        host_only: list[Any] = ["enclave.example"]
        with pytest.raises(TypeError, match="repo"):
            EnclaveOpenAIClient(*host_only, api_key="k")
        with pytest.raises(TypeError, match="repo"):
            EnclaveHTTPClient(*host_only)
        with pytest.raises(TypeError, match="host"):
            EnclaveOpenAIClient(api_key="k")  # type: ignore[call-arg]
        assert offline.requests == []
        client = EnclaveOpenAIClient("enclave.example", None, transport_mode="ehbp", api_key="k")
        copied = client.with_options(max_retries=0)
        assert copied.http_client is client.http_client
        assert (copied.http_client.enclave, copied.http_client.repo) == ("enclave.example", "")
        client.close()

    @pytest.mark.parametrize("option", sorted(ROUTE_OPTIONS))
    def test_drop_in_client_refuses_each_route_option(self, offline: Recorder, option: str) -> None:
        with pytest.raises(ConfigurationError) as err:
            Client(api_key="k", **foreign(**{option: "x"}))
        assert option in str(err.value)
        assert "RouterOpenAIClient" in str(err.value)
        assert offline.requests == [], "the options are refused before discovery"

    @pytest.mark.parametrize("option", sorted(ROUTE_OPTIONS))
    def test_drop_in_copies_refuse_each_route_option(self, offline: Recorder, option: str) -> None:
        """A route option is refused on ``copy`` and ``with_options`` as on the constructor, rather than dropped
        in favor of the attested client's own."""
        offline.handler = lambda request: (
            response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
        )
        client = create_client(api_key="k")
        for copy in (client.with_options, client.copy):
            with pytest.raises(ConfigurationError) as err:
                copy(**foreign(**{option: "x"}))
            assert str(err.value) == DROP_IN_OPTIONS.format(name="Client", keys=option, route="RouterOpenAIClient")
        assert isinstance(client.with_options(max_retries=0), Client)
        client.close()

    def test_drop_in_client_takes_only_openai_options(self, offline: Recorder) -> None:
        offline.handler = lambda request: (
            response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
        )
        with pytest.raises(ConfigurationError, match="RouterOpenAIClient"):
            create_client(api_key="k", **foreign(base_url="https://proxy.example/v1/"))
        with pytest.raises(ConfigurationError) as err:
            create_client(api_key="k", **foreign(transport_mode="ehbp", http_timeout=1.0, verifier=Verifier()))
        assert str(err.value) == DROP_IN_OPTIONS.format(
            name="Client", keys="http_timeout, transport_mode, verifier", route="RouterOpenAIClient"
        ), "every refused option is named"
        assert offline.requests == []
        client = create_client(api_key="k")
        assert isinstance(client, Client)
        assert client.http_client.enclave == "inference.tinfoil.sh"
        assert client.base_url == "https://inference.tinfoil.sh/v1/"
        assert isinstance(client.with_options(timeout=2.0), Client)
        client.close()


class TestErrors:
    def test_api_errors_pass_through(self, offline: Recorder) -> None:
        client = EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", api_key="k", max_retries=0)
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
        client = EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", api_key="k", max_retries=2)
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
            return response(
                200,
                b'{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}',
                {"Content-Type": "application/json"},
            )

        enclave = EnclaveOpenAIClient(
            "enclave.example",
            "org/repo",
            transport_mode="ehbp",
            user_cache_secret="client-level",
            api_key="k",
            max_retries=0,
        )
        below_the_attested_transport(enclave, chat)  # below the cache-secret layer, so it sees the injected body
        params: dict[str, Any] = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        enclave.chat.completions.create(**params)
        enclave.chat.completions.create(**params, extra_body={"user_cache_secret": "end-user-7"})
        enclave.chat.completions.create(**params, extra_body={"user_cache_secret": ""})
        assert [body["user_cache_secret"] for body in received] == ["client-level", "end-user-7", "client-level"]
        enclave.close()

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
        answering_discovery(offline)
        received: list[dict[str, Any]] = []

        def chat(request: httpx.Request) -> httpx.Response:
            received.append(json.loads(request.read()))
            return response(200, CHAT, {"Content-Type": "application/json"})

        first = create_client(api_key="k", max_retries=0)
        second = RouterOpenAIClient(api_key="k", max_retries=0)
        pinned = RouterOpenAIClient(user_cache_secret="client-level", api_key="k", max_retries=0)
        gateway = GatewayOpenAIClient(
            url="https://gateway.example/v1/",
            catalog=lambda: {"m": CatalogEntry("tinfoilsh/m", ("a.example",))},
            api_key="k",
        )
        params: dict[str, Any] = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        for client in (first, second, pinned):
            below_the_attested_transport(client, chat)
            client.chat.completions.create(**params)
        first.chat.completions.create(**params, extra_body={"user_cache_secret": "end-user-7"})
        generated = received[0]["user_cache_secret"]
        assert len(generated) == 64
        assert generated not in ("from-env", "from-file")
        assert [body["user_cache_secret"] for body in received] == [generated, generated, "client-level", "end-user-7"]
        gateway_transport: Any = gateway.http_client._transport
        assert gateway_transport.secret == generated, "the gateway client shares the process secret"
        assert secret_file.read_text() == "from-file"
        for client in (first, second, pinned):
            client.close()
        gateway.close()


@pytest.mark.asyncio
async def test_async_responses_go_through_the_attested_transport(offline: Recorder) -> None:
    offline.handler = lambda request: (
        response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
    )
    enclave = await AsyncEnclaveOpenAIClient.create(
        "enclave.example", "org/repo", transport_mode="ehbp", user_cache_secret="s", api_key="k", max_retries=0
    )
    drop_in = await create_async_client(api_key="k", max_retries=0)
    for client, host, secret in ((enclave, "enclave.example", "s"), (drop_in, "inference.tinfoil.sh", "test-secret")):
        recorder = below_the_attested_transport(client, by_path)
        assert (await client.responses.create(model="m", input="hi")).output_text == "ok"
        assert [(r.url.host, r.url.path) for r in recorder.requests] == [(host, "/v1/responses")]
        assert json.loads(recorder.bodies[0])["user_cache_secret"] == secret
        await client.close()


@pytest.mark.asyncio
async def test_async_gateway_client_refuses_a_base_url(offline: Recorder) -> None:
    entries = {"m": CatalogEntry("tinfoilsh/m", ("a.example",))}
    with pytest.raises(ConfigurationError) as err:
        await AsyncGatewayOpenAIClient.create(
            url="https://gateway.example/v1/",
            catalog=lambda: entries,
            api_key="k",
            **foreign(base_url="https://other.example/v1/"),
        )
    assert str(err.value) == BASE_URL_FIXED
    gateway = await AsyncGatewayOpenAIClient.create(
        url="https://gateway.example/v1/", catalog=lambda: entries, api_key="k"
    )
    with pytest.raises(ConfigurationError, match="base_url"):
        gateway.with_options(**foreign(base_url="https://other.example/v1/"))
    assert gateway.with_options(timeout=1.0).base_url == "https://gateway.example/v1/"
    await gateway.close()


@pytest.mark.asyncio
async def test_async_wrappers(offline: Recorder) -> None:
    with pytest.raises(ConfigurationError, match="create"):
        AsyncEnclaveOpenAIClient(api_key="k")
    host_only: list[Any] = ["enclave.example"]
    with pytest.raises(TypeError, match="repo"):
        await AsyncEnclaveOpenAIClient.create(*host_only, api_key="k")
    with pytest.raises(TypeError, match="repo"):
        await AsyncEnclaveHTTPClient.create(*host_only)
    assert offline.requests == []
    client = await AsyncEnclaveOpenAIClient.create(
        "enclave.example", "org/repo", transport_mode="ehbp", api_key="k", max_retries=0
    )
    assert client.base_url == "https://enclave.example/v1/"
    inner: object = client._client
    assert inner is client.http_client.http_client
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
    offline.handler = lambda request: (
        response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
    )
    with pytest.raises(ConfigurationError, match="AsyncRouterOpenAIClient"):
        await create_async_client(api_key="k", **foreign(base_url="https://proxy.example/v1/"))
    for option in sorted(ROUTE_OPTIONS):
        with pytest.raises(ConfigurationError, match=option):
            await AsyncClient.create(api_key="k", **foreign(**{option: "x"}))
    drop_in = await create_async_client(api_key="k")
    assert isinstance(drop_in, AsyncClient)
    assert isinstance(drop_in, AsyncRouterOpenAIClient)
    assert drop_in.http_client.enclave == "inference.tinfoil.sh"
    for option in sorted(ROUTE_OPTIONS):
        for copy in (drop_in.with_options, drop_in.copy):
            with pytest.raises(ConfigurationError) as err:
                copy(**foreign(**{option: "x"}))
            assert str(err.value) == DROP_IN_OPTIONS.format(
                name="AsyncClient", keys=option, route="AsyncRouterOpenAIClient"
            )
    assert isinstance(drop_in.with_options(max_retries=0), AsyncClient)
    with pytest.raises(ConfigurationError, match=REALTIME_UNAVAILABLE):
        realtime_of(drop_in)
    await drop_in.close()


SUBJECT_TOKEN_IDENTITY = {
    "identity_provider_id": "idp",
    "service_account_id": "sa",
    "provider": {"token_type": "jwt", "get_token": lambda: "subject-token"},
}
TRANSPORT_OPTIONS: list[tuple[str, object]] = [
    ("data_residency", "us"),
    ("provider", bedrock(region="us-east-1", api_key="b")),
    ("websocket_base_url", "wss://elsewhere.example/v1/"),
    ("workload_identity", SUBJECT_TOKEN_IDENTITY),
    ("workload_identity", {"type": "x509", "identity_provider_id": "idp", "service_account_id": "sa"}),
]
"""A value for each refused option: the subject-token identity is the one that the ``openai`` package itself
accepts next to the attested base URL, exchanging the token through an HTTP client of its own."""
TRANSPORT_OPTION_IDS = [
    "data_residency",
    "provider",
    "websocket_base_url",
    "subject-token workload_identity",
    "x509 workload_identity",
]
UNSET_TRANSPORT_OPTIONS = dict.fromkeys(_FORBIDDEN_TRANSPORT_OPTIONS)
ENTRIES = {"m": CatalogEntry("tinfoilsh/m", ("a.example",))}

SYNC_FACTORIES: dict[str, Callable[..., openai.OpenAI]] = {
    "EnclaveOpenAIClient": lambda **kw: EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", **kw),
    "RouterOpenAIClient": lambda **kw: RouterOpenAIClient(transport_mode="ehbp", **kw),
    "GatewayOpenAIClient": lambda **kw: GatewayOpenAIClient(
        url="https://gateway.example/v1/", catalog=lambda: ENTRIES, **kw
    ),
    "Client": lambda **kw: Client(**kw),
    "create_client": lambda **kw: create_client(**kw),
}
ASYNC_FACTORIES: dict[str, Callable[..., Awaitable[openai.AsyncOpenAI]]] = {
    "AsyncEnclaveOpenAIClient": lambda **kw: AsyncEnclaveOpenAIClient.create(
        "enclave.example", "org/repo", transport_mode="ehbp", **kw
    ),
    "AsyncRouterOpenAIClient": lambda **kw: AsyncRouterOpenAIClient.create(transport_mode="ehbp", **kw),
    "AsyncGatewayOpenAIClient": lambda **kw: AsyncGatewayOpenAIClient.create(
        url="https://gateway.example/v1/", catalog=lambda: ENTRIES, **kw
    ),
    "AsyncClient": lambda **kw: AsyncClient.create(**kw),
    "create_async_client": lambda **kw: create_async_client(**kw),
}


def answering_discovery(offline: Recorder) -> None:
    offline.handler = lambda request: (
        response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
    )


def recording(client: openai.OpenAI | openai.AsyncOpenAI) -> Recorder:
    """A recorder under the attested transport, or, for a gateway client, in place of the gateway client's own
    transport, which the ``openai`` client must send through."""
    holder: Any = client
    assert client._client is holder.http_client.http_client, "the openai client sends through the attested one"
    if not isinstance(holder.http_client, (GatewayHTTPClient, AsyncGatewayHTTPClient)):
        return below_the_attested_transport(client, by_path)
    recorder = Recorder(by_path)
    inner: Any = client._client
    inner._transport = recorder.async_transport if isinstance(client, openai.AsyncOpenAI) else recorder.transport
    return recorder


def refused(option: str) -> str:
    return TRANSPORT_OPTION_UNSUPPORTED.format(key=option)


class TestTransportOptions:
    """``data_residency``, ``provider``, ``websocket_base_url`` and ``workload_identity`` would choose another
    base URL or send a token exchange through an HTTP client of their own, so each is refused by name, before any
    network I/O, rather than left to the ``openai`` package's own checks; ``None`` is unset."""

    def test_message_names_the_option(self) -> None:
        assert _FORBIDDEN_TRANSPORT_OPTIONS == ("data_residency", "provider", "websocket_base_url", "workload_identity")
        assert refused("provider") == (
            "the provider option is not supported: the Tinfoil client owns the transport and base URL that "
            "requests go to"
        )

    @pytest.mark.parametrize("factory", sorted(SYNC_FACTORIES))
    @pytest.mark.parametrize(("option", "value"), TRANSPORT_OPTIONS, ids=TRANSPORT_OPTION_IDS)
    def test_constructors_refuse_each_option_before_any_io(
        self, offline: Recorder, factory: str, option: str, value: object
    ) -> None:
        with pytest.raises(ConfigurationError) as err:
            SYNC_FACTORIES[factory](api_key="k", **foreign(**{option: value}))
        assert str(err.value) == refused(option)
        with pytest.raises(ConfigurationError, match=f"the {option} option"):
            SYNC_FACTORIES[factory](**foreign(**{option: value}))  # without an api_key too
        assert offline.requests == [], "nothing is fetched, verified or exchanged"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("factory", sorted(ASYNC_FACTORIES))
    @pytest.mark.parametrize(("option", "value"), TRANSPORT_OPTIONS, ids=TRANSPORT_OPTION_IDS)
    async def test_async_factories_refuse_each_option_before_any_io(
        self, offline: Recorder, factory: str, option: str, value: object
    ) -> None:
        with pytest.raises(ConfigurationError) as err:
            await ASYNC_FACTORIES[factory](api_key="k", **foreign(**{option: value}))
        assert str(err.value) == refused(option)
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
        host = httpx.URL(str(client.base_url)).host
        assert [(r.url.host, r.url.path) for r in recorder.requests] == [
            (host, "/v1/responses"),
            (host, "/v1/responses"),
            (host, "/v1/live/sessions"),
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
        host = httpx.URL(str(client.base_url)).host
        assert [(r.url.host, r.url.path) for r in recorder.requests] == [
            (host, "/v1/responses"),
            (host, "/v1/responses"),
            (host, "/v1/live/sessions"),
        ]
        await client.close()
