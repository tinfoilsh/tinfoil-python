"""The layered transports: the origin guard, the enclave-URL header, the single replay and the cache-secret
injector, each on its own and stacked as an enclave client stacks them."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from tests.v3.client.helpers import Recorder, response
from tinfoil._v3._chain import (
    ENCLAVE_URL_HEADER,
    NOT_REPLAYABLE,
    AsyncCacheSecretInjector,
    AsyncOriginGuard,
    AsyncReplay,
    CacheSecretInjector,
    EnclaveURLHeader,
    OriginGuard,
    Replay,
    replayable,
    with_cache_secret,
    with_enclave_url,
    with_origin_restriction,
)
from tinfoil._v3._errors import AttestationError, ConfigurationError, NetworkError, network_error
from tinfoil._v3._keys import KeyRejectedError, key_rejection
from tinfoil._v3._keys import PeerLacksKeyError as _PeerLacksKey


def rejection(message: str = "rejected key") -> AttestationError:
    """A key rejection as the attested transport reports one."""
    return key_rejection(_PeerLacksKey(RuntimeError(message)))


class Consuming(httpx.BaseTransport):
    """A transport that iterates the request stream as a network transport does, so a streamed body is consumed
    rather than buffered the way ``httpx.MockTransport`` buffers it."""

    def __init__(self, handler: Callable[[httpx.Request, bytes], httpx.Response]) -> None:
        self.handler = handler

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.SyncByteStream)
        return self.handler(request, b"".join(request.stream))


class AsyncConsuming(httpx.AsyncBaseTransport):
    def __init__(self, handler: Callable[[httpx.Request, bytes], httpx.Response]) -> None:
        self.handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.AsyncByteStream)
        return self.handler(request, b"".join([chunk async for chunk in request.stream]))


def post_json(url: str, body: bytes) -> httpx.Request:
    return httpx.Request("POST", url, headers={"Content-Type": "application/json"}, content=body)


class TestOriginGuard:
    def test_allows_enclave_and_proxy_origins(self) -> None:
        recorder = Recorder()
        guard = with_origin_restriction(recorder.transport, "enclave.example.com", "http://proxy.example.com/v1/")
        for target in (
            "https://enclave.example.com/v1/models",
            "https://enclave.example.com:443/v1/models",
            "https://ENCLAVE.example.com/v1/models",
            "http://proxy.example.com/v1/chat/completions",
            "http://proxy.example.com:80/v1/chat/completions",
        ):
            assert guard.handle_request(httpx.Request("GET", target)).status_code == 200
        assert len(recorder.requests) == 5

    @pytest.mark.parametrize(
        "target",
        [
            "https://evil.example.com/v1/models",
            "http://enclave.example.com/v1/models",
            "https://enclave.example.com:8443/v1/models",
            "ftp://enclave.example.com/v1/models",
        ],
    )
    def test_rejects_foreign_host_scheme_and_port(self, target: str) -> None:
        def unreachable(_: httpx.Request) -> httpx.Response:
            pytest.fail("inner transport must not be called for a rejected request")

        guard = OriginGuard(
            httpx.MockTransport(unreachable), frozenset({"https://enclave.example.com"}), "enclave.example.com"
        )
        with pytest.raises(ConfigurationError, match="refusing to send request") as err:
            guard.handle_request(httpx.Request("GET", target))
        assert "enclave.example.com" in str(err.value)

    def test_rejects_userinfo_without_echoing_it(self) -> None:
        guard = OriginGuard(Recorder().transport, frozenset({"https://enclave.example.com"}), "enclave.example.com")
        with pytest.raises(ConfigurationError, match="user information") as err:
            guard.handle_request(httpx.Request("GET", "https://user:hunter2@enclave.example.com/v1/models"))
        assert "hunter2" not in str(err.value)

    def test_closes_the_chain(self) -> None:
        closed: list[bool] = []

        class Inner(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                return response(200)

            def close(self) -> None:
                closed.append(True)

        with_origin_restriction(Inner(), "enclave.example", "").close()
        assert closed == [True]

    @pytest.mark.asyncio
    async def test_async_guard(self) -> None:
        recorder = Recorder()
        guard = AsyncOriginGuard(recorder.async_transport, frozenset({"https://enclave.example"}), "enclave.example")
        assert (await guard.handle_async_request(httpx.Request("GET", "https://enclave.example/v1"))).status_code == 200
        with pytest.raises(ConfigurationError):
            await guard.handle_async_request(httpx.Request("GET", "https://elsewhere.example/v1"))


class TestEnclaveURLHeader:
    def test_injects_the_header_without_mutating_the_request(self) -> None:
        recorder = Recorder()
        transport = EnclaveURLHeader(recorder.transport, "https://enclave.example.com")
        request = httpx.Request("POST", "https://proxy.example.com/v1/chat/completions", content=b"payload")
        assert transport.handle_request(request).status_code == 200
        assert recorder.requests[0].headers[ENCLAVE_URL_HEADER] == "https://enclave.example.com"
        assert recorder.bodies[0] == b"payload"
        assert ENCLAVE_URL_HEADER not in request.headers, "the original request must not be mutated"

    def test_only_a_proxy_gets_the_header(self) -> None:
        recorder = Recorder()
        assert (
            with_enclave_url(recorder.transport, "enclave.example", "https://enclave.example/v1/") is recorder.transport
        )
        assert with_enclave_url(recorder.transport, "enclave.example", "") is recorder.transport
        proxied = with_enclave_url(recorder.transport, "enclave.example", "https://proxy.example/v1/")
        assert isinstance(proxied, EnclaveURLHeader)
        for _ in range(2):
            proxied.handle_request(httpx.Request("GET", "https://proxy.example/v1/models"))
        assert [r.headers[ENCLAVE_URL_HEADER] for r in recorder.requests] == ["https://enclave.example"] * 2

    def test_keeps_the_admission_failure_of_the_transport_below(self) -> None:
        failure = AttestationError("expired witnesses")

        def failing(_: httpx.Request) -> httpx.Response:
            raise failure

        transport = EnclaveURLHeader(httpx.MockTransport(failing), "https://enclave.example")
        with pytest.raises(AttestationError) as err:
            transport.handle_request(httpx.Request("GET", "https://proxy.example/v1/models"))
        assert err.value is failure


class TestReplay:
    @pytest.mark.parametrize(
        ("name", "first", "last", "can_replay", "attempts"),
        [
            ("success", rejection(), None, True, 2),
            ("second rejection", rejection(), rejection("second failure"), True, 2),
            ("refresh failure", rejection(), network_error("second failure"), True, 2),
            ("network failure", httpx.ConnectError("refused"), None, True, 1),
            ("unreplayable", rejection(), None, False, 1),
        ],
    )
    def test_request_recovery(
        self, name: str, first: Exception, last: Exception | None, can_replay: bool, attempts: int
    ) -> None:
        seen = 0

        def handler(request: httpx.Request, body: bytes) -> httpx.Response:
            nonlocal seen
            seen += 1
            assert body == b"payload"
            assert request.headers["Authorization"] == "secret"
            if seen == 1:
                raise first
            if last is not None:
                raise last
            return response(200)

        transport = Replay(Consuming(handler), buffer_bodies=False)
        content = b"payload" if can_replay else iter([b"pay", b"load"])
        request = httpx.Request(
            "POST", "https://enclave.example/path?q=1", headers={"Authorization": "secret"}, content=content
        )
        if attempts == 2 and last is None:
            assert transport.handle_request(request).status_code == 200
        else:
            with pytest.raises(Exception, match=r"failure|rejected key|refused") as err:
                transport.handle_request(request)
            if last is None:
                assert err.value is first
                if not can_replay:
                    assert NOT_REPLAYABLE in err.value.__notes__
            else:
                assert err.value is last
                assert err.value.__context__ is first, "the rejection stays reachable"
        assert seen == attempts, name

    def test_buffers_bodies_for_the_sealing_mode(self) -> None:
        bodies: list[bytes] = []

        def handler(request: httpx.Request) -> httpx.Response:
            bodies.append(request.read())
            if len(bodies) == 1:
                raise rejection()
            return response(200)

        transport = Replay(httpx.MockTransport(handler), buffer_bodies=True)
        request = httpx.Request("POST", "https://enclave.example/v1", content=iter([b"pay", b"load"]))
        assert not replayable(request)
        assert transport.handle_request(request).status_code == 200
        assert bodies == [b"payload", b"payload"], "a buffered stream replays in full"

    def test_asks_only_about_errors(self) -> None:
        transport = Replay(httpx.MockTransport(lambda _: response(200, b"ok")), buffer_bodies=False)
        assert transport.handle_request(httpx.Request("GET", "https://enclave.example")).content == b"ok"

    @pytest.mark.asyncio
    async def test_async_replay(self) -> None:
        seen = 0

        def handler(request: httpx.Request, body: bytes) -> httpx.Response:
            nonlocal seen
            seen += 1
            assert body == b"payload"
            if seen == 1:
                raise rejection()
            return response(200)

        transport = AsyncReplay(AsyncConsuming(handler), buffer_bodies=True)

        async def chunks() -> AsyncIterator[bytes]:
            yield b"pay"
            yield b"load"

        request = httpx.Request("POST", "https://enclave.example/v1", content=chunks())
        assert (await transport.handle_async_request(request)).status_code == 200
        assert seen == 2
        unbuffered = AsyncReplay(AsyncConsuming(handler), buffer_bodies=False)
        seen = 0
        with pytest.raises(AttestationError) as err:
            await unbuffered.handle_async_request(httpx.Request("POST", "https://enclave.example/v1", content=chunks()))
        assert NOT_REPLAYABLE in err.value.__notes__
        assert seen == 1


ELIGIBLE_PATHS = [
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/responses",
    "/api/v1/chat/completions",  # proxy base URL with a path prefix
    "/chat/completions",  # custom base URL without a /v1 root
]


def roundtrip(secret: str, request: httpx.Request) -> Recorder:
    recorder = Recorder()
    CacheSecretInjector(recorder.transport, secret).handle_request(request)
    return recorder


class TestCacheSecretInjector:
    @pytest.mark.parametrize("path", ELIGIBLE_PATHS)
    def test_injects_on_eligible_paths(self, path: str) -> None:
        recorder = roundtrip("s1", post_json(f"https://enclave.example.com{path}", b'{"model":"m"}'))
        body = json.loads(recorder.bodies[0])
        assert body["user_cache_secret"] == "s1"
        sent = recorder.requests[0]
        assert sent.headers["Content-Length"] == str(len(recorder.bodies[0]))
        assert replayable(sent), "retries below this layer re-send the injected body"
        assert b"".join(sent.stream) == recorder.bodies[0]  # type: ignore[arg-type]

    @pytest.mark.parametrize("path", ["/v1/embeddings", "/embeddings"])
    def test_skips_other_endpoints(self, path: str) -> None:
        raw = b'{"model":"m","input":"text"}'
        request = post_json(f"https://enclave.example.com{path}", raw)
        recorder = roundtrip("s1", request)
        assert recorder.bodies == [raw]
        assert recorder.requests[0] is request

    def test_skips_requests_without_a_body_or_secret(self) -> None:
        request = httpx.Request("GET", "https://enclave.example.com/v1/models")
        assert roundtrip("s1", request).requests[0] is request
        empty = post_json("https://enclave.example.com/v1/chat/completions", b"")
        assert roundtrip("s1", empty).requests[0] is empty
        raw = b'{"model":"m"}'
        unscoped = post_json("https://enclave.example.com/v1/chat/completions", raw)
        assert roundtrip("", unscoped).bodies == [raw]
        transport = Recorder().transport
        assert with_cache_secret(transport, "") is transport, "an empty secret adds no layer"

    def test_injects_into_a_streaming_body(self) -> None:
        request = httpx.Request(
            "POST",
            "https://enclave.example.com/v1/chat/completions",
            headers={"Transfer-Encoding": "chunked"},
            content=iter([b'{"model":', b'"m"}']),
        )
        recorder = roundtrip("s1", request)
        assert recorder.bodies == [b'{"model":"m","user_cache_secret":"s1"}']
        assert "Transfer-Encoding" not in recorder.requests[0].headers
        assert replayable(recorder.requests[0])

    @pytest.mark.parametrize(
        "raw",
        [b'{"model":"m","user_cache_secret":"end-user-7"}', b'{"model":"m","user_cache_secret":null}'],
    )
    def test_never_clobbers_non_empty_or_non_string_values(self, raw: bytes) -> None:
        assert roundtrip("client-level", post_json("https://e.example/v1/chat/completions", raw)).bodies == [raw]

    @pytest.mark.parametrize(
        ("raw", "want"),
        [
            (
                b'{"model":"m","seed":9007199254740993,"user_cache_secret":""}',
                b'{"model":"m","seed":9007199254740993,"user_cache_secret":"client-level"}',
            ),
            (b'{"model":"m","user_cache_secre\\u0074":""}', b'{"model":"m","user_cache_secre\\u0074":"client-level"}'),
            (b'{ "user_cache_secret" : "" , "x":1 }', b'{ "user_cache_secret" : "client-level" , "x":1 }'),
        ],
    )
    def test_replaces_an_empty_per_request_secret(self, raw: bytes, want: bytes) -> None:
        assert roundtrip("client-level", post_json("https://e.example/v1/chat/completions", raw)).bodies == [want]

    @pytest.mark.parametrize(
        "raw",
        [
            b'{"user_cache_secret":"","user_cache_secret":""}',
            b'{"user_cache_secret":"end-user-7","user_cache_secre\\u0074":""}',
            b'{"model":"a","model":"b"}',
            b'{"cache_salt":"x","cache_salt":"y"}',
        ],
    )
    def test_duplicate_members_are_forwarded_untouched(self, raw: bytes) -> None:
        assert roundtrip("client-level", post_json("https://e.example/v1/chat/completions", raw)).bodies == [raw]

    @pytest.mark.parametrize(
        "raw",
        [
            b"not json",
            b"[1,2,3]",
            b"null",
            b'{"model":"m"} trailing',
            b'{"model":"m"}}',
            b'{"model":"m"}]',
            b'{"model":"m"}} garbage',
            b'{"model":NaN}',
            b'{"x":"\xff"}',
        ],
    )
    def test_non_object_bodies_are_forwarded_untouched(self, raw: bytes) -> None:
        assert roundtrip("s1", post_json("https://e.example/v1/chat/completions", raw)).bodies == [raw]

    def test_trailing_whitespace_and_number_precision(self) -> None:
        recorder = roundtrip(
            "s1", post_json("https://e.example/v1/chat/completions", b'{"model":"m","seed":9007199254740993}\n\t ')
        )
        assert recorder.bodies == [b'{"model":"m","seed":9007199254740993,"user_cache_secret":"s1"}\n\t ']

    def test_pathologically_nested_body_is_forwarded_untouched(self) -> None:
        raw = b'{"a":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
        assert roundtrip("s1", post_json("https://e.example/v1/chat/completions", raw)).bodies == [raw]

    @pytest.mark.asyncio
    async def test_async_injector(self) -> None:
        recorder = Recorder()
        transport = AsyncCacheSecretInjector(recorder.async_transport, "s1")
        await transport.handle_async_request(post_json("https://e.example/v1/chat/completions", b'{"model":"m"}'))
        assert json.loads(recorder.bodies[0])["user_cache_secret"] == "s1"


def test_enclave_chain_stacks_every_layer() -> None:
    """A body that can't be read twice: only the cache-secret layer, above the replay, makes it replayable."""
    attempts: list[httpx.Request] = []
    bodies: list[dict[str, object]] = []

    def conn(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        bodies.append(json.loads(request.read()))
        if len(attempts) == 1:
            raise rejection("rotated key")
        return response(200)

    chain: httpx.BaseTransport = with_enclave_url(
        httpx.MockTransport(conn), "enclave.example", "https://proxy.example/v1/"
    )
    chain = Replay(chain, buffer_bodies=False)
    chain = with_cache_secret(chain, "cache-secret")
    guard = with_origin_restriction(chain, "enclave.example", "https://proxy.example/v1/")
    request = httpx.Request("POST", "https://proxy.example/v1/chat/completions", content=iter([b'{"model":"m"}']))
    assert guard.handle_request(request).status_code == 200
    assert len(attempts) == 2, "a key rejection is replayed once"
    for attempt, body in zip(attempts, bodies, strict=True):
        assert attempt.headers[ENCLAVE_URL_HEADER] == "https://enclave.example"
        assert body["user_cache_secret"] == "cache-secret"
    with pytest.raises(ConfigurationError):
        guard.handle_request(httpx.Request("GET", "https://elsewhere.example/v1/models"))
    assert len(attempts) == 2


def test_key_rejection_markers() -> None:
    err = rejection("rotated")
    assert isinstance(err, AttestationError)
    assert isinstance(err.__cause__, KeyRejectedError)
    assert str(err) == "attestation error: rotated"
    plain: Callable[[], NetworkError] = lambda: network_error("x")  # noqa: E731
    assert not replayable(httpx.Request("POST", "https://e.example", content=iter([b"x"])))
    assert replayable(httpx.Request("GET", "https://e.example"))
    assert isinstance(plain(), NetworkError)
