"""The OpenAI wrappers: every request goes through the attested HTTP client to the route's URL, the caller's
``http_client`` and ``base_url`` cannot replace it, the realtime resource is refused, copies keep the attested
client, a failed constructor closes the one it created, API errors pass through unchanged and a client error
raised from the transport is reachable behind the library's connection error."""

from __future__ import annotations

import json
from typing import Any

import httpx
import openai
import pytest

from tests.v3.client.helpers import Recorder, response, verification
from tinfoil._v3 import _fetch
from tinfoil._v3._clients import EnclaveHTTPClient, GatewayHTTPClient, RouterHTTPClient
from tinfoil._v3._errors import AttestationError, ConfigurationError, TinfoilError, tinfoil_error
from tinfoil._v3._gateway import CatalogEntry
from tinfoil._v3._openai import (
    REALTIME_UNAVAILABLE,
    AsyncClient,
    AsyncEnclaveOpenAIClient,
    AsyncRouterOpenAIClient,
    Client,
    EnclaveOpenAIClient,
    GatewayOpenAIClient,
    RouterOpenAIClient,
    create_async_client,
    create_client,
)
from tinfoil._v3.verifier import Verifier

MODELS = b'{"object":"list","data":[]}'


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    """A network that answers every attestation fetch with a document the patched verifier accepts, and every
    application request with an empty model list."""
    recorder = Recorder(lambda _: response(200, b"doc"))
    monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
    monkeypatch.setattr(_fetch, "_ASYNC_TRANSPORT", recorder.async_transport)
    monkeypatch.setattr(Verifier, "verify_v3", lambda self, doc, nonce, repo: verification("ab" * 32))
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


def below_the_attested_transport(client: EnclaveOpenAIClient, handler: Any) -> Recorder:
    """Puts a recorder where the enclave's connections would be, under the attested transport and every layer
    above it, so requests arrive through the whole chain."""
    recorder = Recorder(handler)
    client.http_client._attested.keyed._current.transport._inner = recorder.transport  # type: ignore[union-attr]
    return recorder


CHAT = b'{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}'
EMBEDDINGS = b'{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5]}],"model":"m"}'


def realtime_of(holder: object) -> object:
    """The realtime resource of a client or of one of its resource groups; the access itself is what is refused."""
    return getattr(holder, "realtime")  # noqa: B009 - a plain attribute access would be a useless expression


def by_path(request: httpx.Request) -> httpx.Response:
    bodies = {"/v1/chat/completions": CHAT, "/v1/embeddings": EMBEDDINGS, "/v1/audio/transcriptions": b'{"text":"hi"}'}
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
                "enclave.example", "org/repo", transport_mode="ehbp", api_key="k", http_client=httpx.Client()
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
            client.with_options(http_client=httpx.Client())
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
            EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", http_client=httpx.Client())
        assert len(closes) == 1, "the attested client created for the refused options is closed"
        with pytest.raises(openai.OpenAIError):
            EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp")  # no api_key anywhere
        assert len(closes) == 2, "so is one the openai constructor refuses"
        for closed in closes:
            with pytest.raises(ConfigurationError, match="closed"):
                closed.ensure_verified()
        client = EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", api_key="k")
        with pytest.raises(ConfigurationError, match="http_client"):
            client.with_options(http_client=httpx.Client())
        assert len(closes) == 2, "a copy's failure leaves the original's attested client open"
        client.http_client.ensure_verified()
        client.close()
        assert len(closes) == 3

    def test_drop_in_client_takes_only_openai_options(self, offline: Recorder) -> None:
        offline.handler = lambda request: (
            response(200, b"[]") if request.url.host == "atc.tinfoil.sh" else response(200, b"doc")
        )
        with pytest.raises(ConfigurationError, match="RouterOpenAIClient"):
            create_client(api_key="k", base_url="https://proxy.example/v1/")
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


@pytest.mark.asyncio
async def test_async_wrappers(offline: Recorder) -> None:
    with pytest.raises(ConfigurationError, match="create"):
        AsyncEnclaveOpenAIClient(api_key="k")
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
        await create_async_client(api_key="k", base_url="https://proxy.example/v1/")
    drop_in = await create_async_client(api_key="k")
    assert isinstance(drop_in, AsyncClient)
    assert isinstance(drop_in, AsyncRouterOpenAIClient)
    assert drop_in.http_client.enclave == "inference.tinfoil.sh"
    with pytest.raises(ConfigurationError, match=REALTIME_UNAVAILABLE):
        realtime_of(drop_in)
    await drop_in.close()
