"""The gateway: the catalog, the pin policy, routing headers and the cache salt, seal redirects with their single
replay and bound, replica selection and the catalog cache."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import replace

import httpx
import pytest

from tests.v3.client.helpers import Recorder, response, verification
from tinfoil._v3 import _cachesecret, _fetch, _gateway
from tinfoil._v3._chain import ENCLAVE_URL_HEADER, replayable
from tinfoil._v3._errors import AttestationError, ConfigurationError, NetworkError, network_error
from tinfoil._v3._gateway import (
    CACHE_PREFIX_HEADER,
    MAX_CATALOG_BYTES,
    MODEL_HEADER,
    SEAL_HEADER,
    AsyncGatewayTransport,
    AsyncReplicaTransport,
    Catalog,
    CatalogEntry,
    GatewayTransport,
    ModelPin,
    ReplicaTransport,
    _CatalogCache,
    _Policy,
    _Replica,
    bearer_credential,
    cache_prefix,
    cache_salt,
    fetch_catalog,
    multipart_model,
    parse_catalog,
    prepare,
    prompt_head,
    rank,
    replica_chain,
)
from tinfoil._v3._keys import PeerLacksKeyError, key_rejection
from tinfoil._v3._types import TimeoutTypes
from tinfoil._v3.verifier import Verification, Verifier

MODEL = "test-model"
INITIAL = "initial.example"
SPEC_BODY = b'{"model":"test-model","messages":[{"role":"user","content":"hello"}]}'
SPEC_SALT = "DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8"
SPEC_PREFIX = "ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6"

Connect = Callable[[str], httpx.BaseTransport]


def catalog(hosts: tuple[str, ...] = (INITIAL,), repo: str = "tinfoilsh/test") -> Catalog:
    return {MODEL: CatalogEntry(repo, hosts)}


class FakeKeyed:
    """A replica's attested transport: verifies by calling ``connect`` until it succeeds, then reuses the result."""

    def __init__(self, host: str, connect: Connect) -> None:
        self.host = host
        self.connect = connect
        self.transport: httpx.BaseTransport | None = None
        self.verified = verification(host)

    @property
    def current(self) -> Verification | None:
        return self.verified if self.transport is not None else None

    def ensure_verified(self, *, timeout: object = None) -> Verification:
        if self.transport is None:
            self.transport = self.connect(self.host)
        return self.verified


class FakeChain(httpx.BaseTransport):
    def __init__(self, keyed: FakeKeyed) -> None:
        self.keyed = keyed

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        assert self.keyed.transport is not None
        return self.keyed.transport.handle_request(request)


def seal_transport(
    connect: Connect, *, catalog_entries: Catalog | None = None, secret: str | None = ""
) -> GatewayTransport:
    def build(replica: _Replica) -> ReplicaTransport:
        keyed = FakeKeyed(replica.host, connect)
        return ReplicaTransport(keyed, FakeChain(keyed))

    entries = catalog() if catalog_entries is None else catalog_entries
    return GatewayTransport(
        base_url="https://gateway.example/v1/",
        relay="gateway.example",
        catalog=lambda: entries,
        user_cache_secret=secret,
        _build=build,
    )


def seal_mismatch(host: str) -> httpx.Response:
    return response(412, headers={SEAL_HEADER: host})


def fixed_response(status: int, body: bytes = b"") -> Callable[[httpx.Request], httpx.Response]:
    return lambda _: response(status, body)


class TestCatalog:
    def test_parse_keeps_only_trusted_entries(self) -> None:
        parsed = parse_catalog(
            json.dumps(
                {
                    "ok": {"repo": "tinfoilsh/ok", "hosts": ["a.example"]},
                    "tagged": {"repo": "tinfoilsh/ok@v1", "hosts": ["a.example"]},
                    "other": {"repo": "acme/ok", "hosts": ["a.example"]},
                    "empty": {"repo": "tinfoilsh/empty", "hosts": []},
                    "bare": {"repo": "tinfoilsh/bare"},
                }
            ).encode()
        )
        assert parsed == {"ok": CatalogEntry("tinfoilsh/ok", ("a.example",))}

    @pytest.mark.parametrize(
        "body", [b"[]", b"not json", b'{"m": "x"}', b'{"m": {"repo": 1}}', b'{"m": {"hosts": "a"}}']
    )
    def test_parse_rejects_other_shapes(self, body: bytes) -> None:
        with pytest.raises(NetworkError, match="decoding gateway catalog"):
            parse_catalog(body)

    def test_fetch_rejects_an_oversized_catalog(self, monkeypatch: pytest.MonkeyPatch) -> None:
        entry = b'{"m":{"repo":"tinfoilsh/m","hosts":["a.example"]}}'
        maximal = entry + b" " * (MAX_CATALOG_BYTES - len(entry))
        recorder = Recorder(lambda _: response(200, maximal))
        monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
        assert "m" in fetch_catalog("gateway.example")
        assert str(recorder.requests[0].url) == "https://gateway.example/catalog"
        recorder.handler = lambda _: response(200, maximal + b" ")
        with pytest.raises(NetworkError, match="exceeds"):
            fetch_catalog("gateway.example")
        recorder.handler = lambda _: response(204)
        with pytest.raises(NetworkError, match="204"):
            fetch_catalog("gateway.example")

    def test_fetch_refuses_insecure_redirects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == "https://gateway.example/catalog":
                return response(302, headers={"Location": "http://mirror.example/catalog"})
            return response(200, b'{"m": {"repo": "tinfoilsh/m", "hosts": ["a.example"]}}')

        monkeypatch.setattr(_fetch, "_TRANSPORT", httpx.MockTransport(handler))
        with pytest.raises(NetworkError, match="refusing redirect to non-HTTPS URL"):
            fetch_catalog("gateway.example")


class TestPolicy:
    def test_rejects_invalid_options(self) -> None:
        authorizer = Verifier(config_authorizer=lambda _: None)
        with pytest.raises(ConfigurationError, match="pinned-only"):
            _Policy({}, True, None)
        with pytest.raises(ConfigurationError, match="caller-authorized"):
            _Policy({}, False, authorizer)
        with pytest.raises(ConfigurationError, match="caller-authorized"):
            _Policy({"m": ModelPin("tinfoilsh/m", authorizer)}, False, None)
        with pytest.raises(ConfigurationError, match="must belong to tinfoilsh/"):
            _Policy({"m": ModelPin("acme/m")}, False, None)
        with pytest.raises(ConfigurationError, match="must belong to tinfoilsh/"):
            _Policy({" ": ModelPin("tinfoilsh/m")}, False, None)
        with pytest.raises(ConfigurationError, match='model "m"'):
            _Policy({"m": ModelPin("tinfoilsh/m@")}, False, None)

    def test_resolve(self) -> None:
        gateway_verifier = Verifier()
        pin_verifier = Verifier()
        policy = _Policy(
            {"pinned": ModelPin("tinfoilsh/pinned@v1", pin_verifier), "inherits": ModelPin("tinfoilsh/inherits")},
            False,
            gateway_verifier,
        )
        entries: Catalog = {
            "pinned": CatalogEntry("tinfoilsh/pinned", ("a.example",)),
            "inherits": CatalogEntry("tinfoilsh/inherits", ("b.example",)),
            "unpinned": CatalogEntry("tinfoilsh/unpinned", ("c.example",)),
            "mismatch": CatalogEntry("tinfoilsh/other", ("d.example",)),
            "untrusted": CatalogEntry("acme/x", ("e.example",)),
        }
        hosts, replica = policy.resolve("pinned", entries)
        assert hosts == ("a.example",)
        assert replica == _Replica("", "tinfoilsh/pinned@v1", "pinned")
        assert policy.verifier_for(replica) is pin_verifier
        _, inherits = policy.resolve("inherits", entries)
        assert policy.verifier_for(inherits) is gateway_verifier
        _, unpinned = policy.resolve("unpinned", entries)
        assert unpinned == _Replica("", "tinfoilsh/unpinned", "")
        assert policy.verifier_for(unpinned) is gateway_verifier
        with pytest.raises(ConfigurationError, match="no valid bare tinfoilsh/ repository"):
            policy.resolve("missing", entries)
        with pytest.raises(ConfigurationError, match="no valid bare"):
            policy.resolve("untrusted", entries)
        policy.pins["mismatch"] = ModelPin("tinfoilsh/pinned@v2", gateway_verifier)
        with pytest.raises(
            AttestationError, match='expected repository "tinfoilsh/pinned", gateway offered "tinfoilsh/other"'
        ):
            policy.resolve("mismatch", entries)
        pinned_only = _Policy({"pinned": ModelPin("tinfoilsh/pinned")}, True, None)
        with pytest.raises(ConfigurationError, match="is not pinned"):
            pinned_only.resolve("unpinned", entries)

    def test_pins_are_copied(self) -> None:
        pins = {"m": ModelPin("tinfoilsh/m")}
        policy = _Policy(pins, False, None)
        pins["later"] = ModelPin("tinfoilsh/later")
        assert "later" not in policy.pins


class TestRouting:
    def test_spec_vector(self) -> None:
        assert cache_salt("test-secret", "test-api-key") == SPEC_SALT
        assert cache_prefix("test-secret", "test-api-key", b'{"role":"user","content":"hello"}') == SPEC_PREFIX

    @pytest.mark.parametrize("authorization", ["Bearer test-api-key", "bearer test-api-key", " BEARER  test-api-key "])
    def test_bearer_credential(self, authorization: str) -> None:
        assert bearer_credential(authorization) == "test-api-key"

    @pytest.mark.parametrize("authorization", ["Basic test-api-key", "Bearertest-api-key", "Bearer", ""])
    def test_other_schemes_carry_no_credential(self, authorization: str) -> None:
        assert bearer_credential(authorization) == ""

    def test_prepare_sets_routing_headers_and_the_salt(self) -> None:
        for content_type in ("application/json", "application/json; charset=utf-8"):
            headers = httpx.Headers({"Content-Type": content_type, "Authorization": "Bearer test-api-key"})
            prepared = prepare("POST", "/v1/chat/completions", headers, SPEC_BODY, "test-secret")
            assert prepared.headers[MODEL_HEADER] == MODEL
            assert prepared.headers[CACHE_PREFIX_HEADER] == SPEC_PREFIX
            assert prepared.body is not None
            fields = json.loads(prepared.body)
            assert "user_cache_secret" not in fields
            assert fields["cache_salt"] == SPEC_SALT
            assert fields["messages"] == [{"role": "user", "content": "hello"}]
            assert "Authorization" not in prepared.headers or prepared.headers["Authorization"] == "Bearer test-api-key"

    def test_prepare_preserves_number_tokens_and_caller_values(self) -> None:
        body = b'{"model":"m","seed":9007199254740993,"messages":[],"cache_salt":"old"}'
        headers = httpx.Headers(
            {"Content-Type": "application/json", MODEL_HEADER: "caller", CACHE_PREFIX_HEADER: "caller"}
        )
        prepared = prepare("POST", "/v1/chat/completions", headers, body, "s")
        assert prepared.headers[MODEL_HEADER] == "caller", "a caller-set model header is kept"
        assert CACHE_PREFIX_HEADER not in prepared.headers, "no prompt head: the derived prefix is absent"
        assert prepared.body is not None
        assert b'"seed":9007199254740993' in prepared.body
        assert json.loads(prepared.body)["cache_salt"] == cache_salt("s", "")
        assert prepared.body.count(b"cache_salt") == 1

    def test_prepare_without_a_secret_keeps_the_callers_prefix(self) -> None:
        headers = httpx.Headers({"Content-Type": "application/json", CACHE_PREFIX_HEADER: "caller"})
        prepared = prepare("POST", "/v1/chat/completions", headers, b'{"model":"m","messages":[]}', "")
        assert prepared.headers[CACHE_PREFIX_HEADER] == "caller"
        assert prepared.headers[MODEL_HEADER] == "m"
        assert prepared.body == b'{"model":"m","messages":[]}'

    def test_prepare_per_request_secret_wins(self) -> None:
        headers = httpx.Headers({"Content-Type": "application/json", "Authorization": "Bearer test-api-key"})
        prepared = prepare(
            "POST", "/v1/chat/completions", headers, b'{"model":"m","user_cache_secret":"end-user"}', "client"
        )
        assert prepared.body is not None
        assert json.loads(prepared.body)["cache_salt"] == cache_salt("end-user", "test-api-key")
        other = prepare("POST", "/v1/chat/completions", headers, b'{"model":"m"}', "client")
        assert other.body is not None
        assert json.loads(other.body)["cache_salt"] == cache_salt("client", "test-api-key")

    @pytest.mark.parametrize(
        ("path", "body", "want_model", "want_body_unchanged"),
        [
            ("/v1/embeddings", b'{"model":"m","input":"x"}', "m", True),
            ("/v1/chat/completions", b"[1]", None, True),
            ("/v1/chat/completions", b"not json", None, True),
            ("/v1/chat/completions", b'{"model":1}', None, False),
            ("/v1/chat/completions", b'{"model":""}', None, False),
        ],
    )
    def test_prepare_bodies_without_routing(
        self, path: str, body: bytes, want_model: str | None, want_body_unchanged: bool
    ) -> None:
        headers = httpx.Headers({"Content-Type": "application/json"})
        prepared = prepare("POST", path, headers, body, "s")
        assert prepared.headers.get(MODEL_HEADER) == want_model
        if want_body_unchanged:
            assert prepared.body == body
            assert CACHE_PREFIX_HEADER not in prepared.headers

    def test_prepare_leaves_other_requests_alone(self) -> None:
        headers = httpx.Headers({"Content-Type": "text/plain"})
        assert prepare("POST", "/v1/chat/completions", headers, b"x", "s").body is None
        assert prepare("GET", "/v1/models", httpx.Headers(), None, "s").body is None
        assert (
            prepare("POST", "/v1/chat/completions", httpx.Headers({"Content-Type": "application/json"}), b"", "s").body
            is None
        )

    def test_prepare_refuses_repeated_security_members(self) -> None:
        headers = httpx.Headers({"Content-Type": "application/json"})
        for body in (
            b'{"model":"a","model":"b"}',
            b'{"user_cache_secret":"a","user_cache_secret":"b"}',
            b'{"cache_salt":"a","cache_salt":"b"}',
        ):
            with pytest.raises(ConfigurationError, match="repeats"):
                prepare("POST", "/v1/chat/completions", headers, body, "s")

    def test_prompt_head_selection(self) -> None:
        def head(text: str) -> str | None:
            members = _cachesecret.scan_object(text)
            assert members is not None
            return prompt_head({m.key: m for m in members}, text)

        assert head('{"instructions":"sys","input":[{"a":1}]}') == '"sys"'
        assert head('{"instructions":"","input":[{"a":1}]}') == '{"a":1}'
        assert head('{"messages":[ {"role":"user"} , 2]}') == '{"role":"user"}'
        assert head('{"messages":[],"prompt":"p"}') == '"p"'
        assert head('{"messages":null,"input":"text"}') == '"text"'
        assert head('{"model":"m"}') is None
        assert head('{"prompt":[]}') is None
        assert head('{"messages":{"not":"array"}}') == '{"not":"array"}'

    def test_rank(self) -> None:
        hosts = ("a.example", "b.example", "c.example")
        ordered = rank(hosts, SPEC_PREFIX, "")
        assert sorted(ordered) == sorted(hosts)
        assert rank(hosts, SPEC_PREFIX, "") == ordered, "the rendezvous order is fixed for a prefix"
        assert rank(hosts, SPEC_PREFIX, ordered[2]) == [ordered[2], ordered[0], ordered[1]]
        assert rank(hosts, SPEC_PREFIX, "other.example") == ordered
        assert sorted(rank(hosts, "", "")) == sorted(hosts)


class TestMultipart:
    def body(self, parts: list[tuple[str, str | None, bytes]], boundary: str = "b1") -> bytes:
        chunks = []
        for name, filename, content in parts:
            disposition = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
            chunks.append(f"--{boundary}\r\nContent-Disposition: {disposition}\r\n\r\n".encode() + content + b"\r\n")
        return b"".join(chunks) + f"--{boundary}--\r\n".encode()

    def test_extracts_the_model_field(self) -> None:
        body = self.body([("file", "a.wav", b"RIFF"), ("model", None, b"whisper")])
        assert multipart_model(body, "b1") == "whisper"

    @pytest.mark.parametrize(
        "parts",
        [
            [("file", "a.wav", b"RIFF")],
            [("model", None, b"a"), ("model", None, b"b")],
            [("model", None, b"  ")],
            [("model", "model.txt", b"whisper")],
        ],
    )
    def test_rejects_missing_repeated_empty_or_file_models(self, parts: list[tuple[str, str | None, bytes]]) -> None:
        with pytest.raises(ConfigurationError, match="exactly one non-empty model field"):
            multipart_model(self.body(parts), "b1")

    def test_rejects_missing_boundary_and_malformed_bodies(self) -> None:
        with pytest.raises(ConfigurationError, match="missing its boundary"):
            multipart_model(b"--b1\r\n", "")
        with pytest.raises(ConfigurationError, match="invalid multipart upload"):
            multipart_model(b"no boundary here", "b1")
        with pytest.raises(ConfigurationError, match="invalid multipart upload"):
            multipart_model(self.body([("model", None, b"m")], "other"), "b1")

    def test_prepare_routes_an_upload(self) -> None:
        body = self.body([("model", None, b"whisper")])
        headers = httpx.Headers({"Content-Type": "multipart/form-data; boundary=b1"})
        prepared = prepare("POST", "/v1/audio/transcriptions", headers, body, "s")
        assert prepared.headers[MODEL_HEADER] == "whisper"
        assert prepared.body == body
        routed = prepare(
            "POST", "/v1/audio/transcriptions", httpx.Headers({**headers, MODEL_HEADER: "caller"}), None, "s"
        )
        assert routed.body is None, "an explicitly routed upload streams"


class TestSeal:
    def test_reroute_is_per_request(self) -> None:
        verification_error = network_error("verification failed")
        next_builds = 0
        initial_hits = 0

        def connect(host: str) -> httpx.BaseTransport:
            nonlocal next_builds
            if host != INITIAL:
                next_builds += 1
                if next_builds == 1:
                    raise verification_error

            def handler(_: httpx.Request) -> httpx.Response:
                nonlocal initial_hits
                if host == INITIAL:
                    initial_hits += 1
                    return seal_mismatch("next.example")
                return response(204)

            return httpx.MockTransport(handler)

        seal = seal_transport(connect)

        def get() -> httpx.Response:
            return seal.handle_request(
                httpx.Request("GET", "https://gateway.example/reroute", headers={MODEL_HEADER: MODEL})
            )

        with pytest.raises(NetworkError, match=r"following gateway route to enclave next\.example") as err:
            get()
        assert err.value.__cause__ is verification_error
        for _ in range(2):
            assert get().status_code == 204
        assert initial_hits == 3, "every request starts from its own pick, not the last reroute"
        assert next_builds == 2, "a failed verification is retried, a successful one is reused"

    def test_refuses_upgrades_before_touching_replicas(self) -> None:
        def connect(_: str) -> httpx.BaseTransport:
            pytest.fail("an upgrade reached a replica")

        seal = seal_transport(connect)
        request = httpx.Request(
            "GET", "https://gateway.example/v1/realtime", headers={MODEL_HEADER: MODEL, "Upgrade": "websocket"}
        )
        with pytest.raises(ConfigurationError, match="WebSocket"):
            seal.handle_request(request)

    def test_upload_replay(self) -> None:
        payload = b"upload contents"
        attempts = 0

        def connect(host: str) -> httpx.BaseTransport:
            def handler(request: httpx.Request) -> httpx.Response:
                nonlocal attempts
                attempts += 1
                if host == INITIAL:
                    return seal_mismatch("next.example")
                assert request.read() == payload
                return response(204)

            return httpx.MockTransport(handler)

        seal = seal_transport(connect)
        headers = {"Content-Type": "multipart/form-data; boundary=test", MODEL_HEADER: MODEL}
        buffered = httpx.Request(
            "POST", "https://gateway.example/v1/audio/transcriptions", headers=headers, content=payload
        )
        assert seal.handle_request(buffered).status_code == 204
        assert attempts == 2

        attempts = 0
        streaming = httpx.Request(
            "POST", "https://gateway.example/v1/audio/transcriptions", headers=headers, content=iter([payload])
        )
        resp = seal.handle_request(streaming)
        assert resp.status_code == 412, "a seal redirect on a body that can't be replayed passes through"
        assert attempts == 1

    def test_json_routing_preserves_the_injected_body_across_retries(self) -> None:
        bodies: list[bytes] = []
        prefixes: list[str] = []

        def connect(host: str) -> httpx.BaseTransport:
            def handler(request: httpx.Request) -> httpx.Response:
                bodies.append(request.read())
                assert request.headers[MODEL_HEADER] == MODEL
                assert request.headers[SEAL_HEADER] == host
                prefixes.append(request.headers[CACHE_PREFIX_HEADER])
                if host == INITIAL:
                    return seal_mismatch("next.example")
                return response(204)

            return httpx.MockTransport(handler)

        seal = seal_transport(connect, secret="test-secret")
        request = httpx.Request(
            "POST",
            "https://gateway.example/v1/chat/completions",
            headers={"Content-Type": "application/json", "Authorization": "Bearer test-api-key"},
            content=SPEC_BODY,
        )
        assert seal.handle_request(request).status_code == 204
        assert len(bodies) == 2
        assert bodies[0] == bodies[1]
        fields = json.loads(bodies[0])
        assert "user_cache_secret" not in fields
        assert fields["cache_salt"] == SPEC_SALT
        assert prefixes == [SPEC_PREFIX, SPEC_PREFIX]
        for name in (MODEL_HEADER, CACHE_PREFIX_HEADER, SEAL_HEADER):
            assert name not in request.headers, "the caller's request is not mutated"

    def test_falls_over_to_a_replica_that_verifies(self) -> None:
        hosts = ("a.example", "b.example", "c.example")
        order = rank(hosts, SPEC_PREFIX, "")
        verified: list[str] = []
        sent: list[str] = []

        def connect(host: str) -> httpx.BaseTransport:
            verified.append(host)
            if host != order[2]:
                raise network_error("verification failed")

            def handler(request: httpx.Request) -> httpx.Response:
                sent.append(request.headers[SEAL_HEADER])
                return response(204)

            return httpx.MockTransport(handler)

        seal = seal_transport(connect, catalog_entries=catalog(hosts), secret="test-secret")
        request = httpx.Request(
            "POST",
            "https://gateway.example/v1/chat/completions",
            headers={"Content-Type": "application/json", "Authorization": "Bearer test-api-key"},
            content=SPEC_BODY,
        )
        assert seal.handle_request(request).status_code == 204
        assert verified == order, "replicas are verified in rank order until one passes"
        assert sent == [order[2]], "the request is sealed only to a replica that verified"

    def test_reseal_bound(self) -> None:
        hosts = ["a.example", "b.example"]
        attempts: list[str] = []

        def connect(host: str) -> httpx.BaseTransport:
            def handler(_: httpx.Request) -> httpx.Response:
                attempts.append(host)
                return seal_mismatch(hosts[(hosts.index(host) + 1) % 2])

            return httpx.MockTransport(handler)

        seal = seal_transport(connect, catalog_entries=catalog(tuple(hosts)))
        request = httpx.Request(
            "POST",
            "https://gateway.example/v1/chat/completions",
            headers={"Content-Type": "application/json"},
            content=b'{"model":"test-model"}',
        )
        with pytest.raises(NetworkError, match="kept routing away"):
            seal.handle_request(request)
        assert len(attempts) == 4, "the initial attempt and three re-seals"

    @pytest.mark.parametrize(
        "reply",
        [
            response(412),
            response(412, headers={SEAL_HEADER: INITIAL}),
            response(422, headers={SEAL_HEADER: "next.example"}),
        ],
        ids=["bare 412", "412 naming the sealed enclave", "422 naming another host"],
    )
    def test_other_responses_pass_through(self, reply: httpx.Response) -> None:
        verified: list[str] = []

        def connect(host: str) -> httpx.BaseTransport:
            verified.append(host)
            return httpx.MockTransport(lambda _: reply)

        seal = seal_transport(connect)
        resp = seal.handle_request(
            httpx.Request(
                "POST",
                "https://gateway.example/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                content=b'{"model":"test-model"}',
            )
        )
        assert resp.status_code == reply.status_code
        assert verified == [INITIAL], "no verification of the named host is attempted"

    def test_cache_scope_per_request_and_bearer(self) -> None:
        def scope(client_secret: str, authorization: str, body: bytes) -> tuple[str, str]:
            fields: dict[str, object] = {}
            prefix = ""

            def connect(_: str) -> httpx.BaseTransport:
                def handler(request: httpx.Request) -> httpx.Response:
                    nonlocal prefix
                    fields.update(json.loads(request.read()))
                    prefix = request.headers.get(CACHE_PREFIX_HEADER, "")
                    return response(204)

                return httpx.MockTransport(handler)

            seal = seal_transport(connect, secret=client_secret)
            headers = {"Content-Type": "application/json"}
            if authorization:
                headers["Authorization"] = authorization
            seal.handle_request(
                httpx.Request("POST", "https://gateway.example/v1/chat/completions", headers=headers, content=body)
            )
            assert "user_cache_secret" not in fields, "the secret never leaves the client"
            return str(fields["cache_salt"]), prefix

        got = scope("client-secret", "Bearer test-api-key", b'{"model":"test-model","user_cache_secret":"end-user"}')
        assert got == scope("end-user", "Bearer test-api-key", b'{"model":"test-model"}')
        assert scope("client-secret", "Bearer test-api-key", b'{"model":"test-model"}')[0] != got[0]
        assert scope("test-secret", "Bearer test-api-key", SPEC_BODY) == (SPEC_SALT, SPEC_PREFIX)
        no_key = scope("test-secret", "", SPEC_BODY)
        assert scope("test-secret", "Basic test-api-key", SPEC_BODY) == no_key
        other = scope("test-secret", "Bearer other-api-key", SPEC_BODY)
        assert no_key != other != (SPEC_SALT, SPEC_PREFIX), "each API key scopes its own cache"

    def test_no_secret_sets_only_the_model_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_cachesecret, "resolve", lambda explicit: explicit or "")
        seen: list[httpx.Headers] = []

        def connect(_: str) -> httpx.BaseTransport:
            def handler(request: httpx.Request) -> httpx.Response:
                seen.append(request.headers)
                return response(204)

            return httpx.MockTransport(handler)

        seal = seal_transport(connect, secret="")
        seal.handle_request(
            httpx.Request(
                "POST",
                "https://gateway.example/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                content=SPEC_BODY,
            )
        )
        assert seen[0][MODEL_HEADER] == MODEL
        assert CACHE_PREFIX_HEADER not in seen[0]


class TestVerifications:
    def test_names_replica_hosts_in_order(self) -> None:
        seal = seal_transport(lambda _: httpx.MockTransport(fixed_response(204)))
        for host in ("b.example", "a.example"):
            seal._transport(_Replica(host, "tinfoilsh/model")).keyed.ensure_verified()
        got = seal.verifications()
        assert [v.host for v in got] == ["a.example", "b.example"]
        assert got[0].reference == "tinfoilsh/model"
        assert got[0].pinned_model == ""
        assert seal_transport(lambda _: httpx.MockTransport(fixed_response(204))).verifications() == []

    def test_ensure_verified_falls_over(self) -> None:
        hosts = ("a.example", "b.example", "c.example")
        order = rank(hosts, MODEL, "")
        attempts: list[str] = []

        def connect(host: str) -> httpx.BaseTransport:
            attempts.append(host)
            if host != order[2]:
                raise network_error("verification failed")
            return httpx.MockTransport(fixed_response(204))

        seal = seal_transport(connect, catalog_entries=catalog(hosts))
        verified = seal.ensure_verified(MODEL)
        assert verified.code_tag == order[2]
        assert attempts == order, "replicas are tried in the model's fixed order until one verifies"
        assert [v.host for v in seal.verifications()] == [order[2]]
        unreachable = seal_transport(
            lambda _: (_ for _ in ()).throw(network_error("verification failed")), catalog_entries=catalog(hosts)
        )
        with pytest.raises(NetworkError, match="verification failed"):
            unreachable.ensure_verified(MODEL)
        assert seal.models() == [MODEL]

    def test_keeps_one_transport_per_replica(self) -> None:
        arrived = threading.Barrier(2, timeout=5)
        builds = 0

        def build(replica: _Replica) -> ReplicaTransport:
            nonlocal builds
            builds += 1
            keyed = FakeKeyed(replica.host, lambda _: httpx.MockTransport(fixed_response(204)))
            return ReplicaTransport(keyed, FakeChain(keyed))

        seal = GatewayTransport(
            base_url="https://gateway.example/v1/", relay="gateway.example", catalog=catalog, _build=build
        )
        results: list[ReplicaTransport] = []

        def use() -> None:
            arrived.wait()
            results.append(seal._transport(_Replica("a.example", "tinfoilsh/test")))

        threads = [threading.Thread(target=use) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        assert results[0] is results[1], "concurrent first uses share one replica transport"
        assert builds == 1


def test_replica_chain_replays_and_names_the_replica() -> None:
    attempts: list[httpx.Request] = []

    def conn(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        if len(attempts) == 1:
            raise key_rejection(PeerLacksKeyError(RuntimeError("rotated key")))
        return response(200)

    chain = replica_chain(httpx.MockTransport(conn), "replica.example", "https://gateway.example/v1/")
    request = httpx.Request("POST", "https://gateway.example/v1/chat/completions", content=iter([b'{"model":"m"}']))
    assert chain.handle_request(request).status_code == 200
    assert len(attempts) == 2, "a key rejection is replayed once"
    for attempt in attempts:
        assert attempt.headers[ENCLAVE_URL_HEADER] == "https://replica.example"
        assert replayable(attempt)


class TestCatalogCache:
    def test_fetches_on_first_use_and_keeps_success(self) -> None:
        failure = network_error("gateway unavailable")
        release = threading.Event()
        fetches = 0

        def fetch(timeout: TimeoutTypes) -> Catalog:
            nonlocal fetches
            fetches += 1
            release.wait(5)
            if fetches == 1:
                raise failure
            return catalog()

        cache = _CatalogCache(fetch)
        results: list[BaseException | Catalog] = []

        def get() -> None:
            try:
                results.append(cache.get(5.0))
            except BaseException as err:
                results.append(err)

        threads = [threading.Thread(target=get) for _ in range(3)]
        for thread in threads:
            thread.start()
        time.sleep(0.05)
        release.set()
        for thread in threads:
            thread.join(5)
        assert all(result is failure for result in results)
        assert fetches == 1, "concurrent first uses share one fetch"
        assert MODEL in cache.get(5.0), "a failed fetch is retried on the next use"
        cache.get(5.0)
        assert fetches == 2, "a fetched catalog is kept"

    def test_refreshes_without_blocking(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_gateway, "CATALOG_REFRESH_INTERVAL", 0.1)
        catalogs: list[Catalog | None] = [
            {"old": CatalogEntry("tinfoilsh/old", ("a",))},
            None,
            {"new": CatalogEntry("tinfoilsh/new", ("b",))},
        ]
        release = threading.Semaphore(0)
        fetches = 0

        def fetch(timeout: TimeoutTypes) -> Catalog:
            nonlocal fetches
            fetches += 1
            current = catalogs[fetches - 1]
            release.acquire(timeout=5)
            if current is None:
                raise network_error("gateway unavailable")
            return current

        cache = _CatalogCache(fetch)
        release.release()
        assert "old" in cache.get(5.0)
        assert "old" in cache.get(5.0)
        assert fetches == 1, "a catalog is kept for the refresh interval"
        time.sleep(0.15)
        assert "old" in cache.get(5.0), "a stale catalog is returned while it refreshes"
        assert "old" in cache.get(5.0)
        assert fetches == 2, "a use during a refresh starts no second fetch"
        release.release()
        time.sleep(0.05)
        assert "old" in cache.get(5.0), "a failed refresh keeps the last catalog"
        time.sleep(0.15)
        assert "old" in cache.get(5.0)
        release.release()
        time.sleep(0.05)
        assert "new" in cache.get(5.0), "the gateway's catalog is refreshed"
        assert fetches == 3


def test_models_and_current_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    entries: Catalog = {
        "pinned": CatalogEntry("tinfoilsh/pinned", ("a.example",)),
        "unpinned": CatalogEntry("tinfoilsh/unpinned", ("b.example",)),
    }
    seal = GatewayTransport(
        base_url="https://gateway.example/v1/",
        relay="gateway.example",
        catalog=lambda: entries,
        model_pins={"pinned": ModelPin("tinfoilsh/pinned@v1")},
        pinned_models_only=True,
        user_cache_secret="test-secret",
    )
    assert seal.models() == ["pinned"]
    assert seal.verifications() == []
    with pytest.raises(ConfigurationError, match="is not pinned"):
        seal.ensure_verified("unpinned")


@pytest.mark.asyncio
async def test_async_gateway_transport() -> None:
    bodies: list[bytes] = []

    class AsyncFakeKeyed:
        def __init__(self, host: str) -> None:
            self.host = host
            self.verified = verification(host)

        @property
        def current(self) -> Verification | None:
            return self.verified

        async def ensure_verified(self) -> Verification:
            return self.verified

    class AsyncFakeChain(httpx.AsyncBaseTransport):
        def __init__(self, host: str) -> None:
            self.host = host

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            bodies.append(await request.aread())
            if self.host == INITIAL:
                return seal_mismatch("next.example")
            return response(204)

    def build(replica: _Replica) -> AsyncReplicaTransport:
        return AsyncReplicaTransport(AsyncFakeKeyed(replica.host), AsyncFakeChain(replica.host))

    seal = AsyncGatewayTransport(
        base_url="https://gateway.example/v1/",
        relay="gateway.example",
        catalog=catalog,
        user_cache_secret="test-secret",
        _build=build,
    )
    assert await seal.models() == [MODEL]
    request = httpx.Request(
        "POST",
        "https://gateway.example/v1/chat/completions",
        headers={"Content-Type": "application/json", "Authorization": "Bearer test-api-key"},
        content=SPEC_BODY,
    )
    assert (await seal.handle_async_request(request)).status_code == 204
    assert len(bodies) == 2
    assert bodies[0] == bodies[1]
    assert json.loads(bodies[0])["cache_salt"] == SPEC_SALT
    assert (await seal.ensure_verified(MODEL)).code_tag == INITIAL
    assert [v.host for v in seal.verifications()] == [INITIAL, "next.example"]
    await seal.aclose()
    with pytest.raises(ConfigurationError, match="closed"):
        await seal.models()
    assert replace(_Replica("a", "r"), host="b") == _Replica("b", "r")
