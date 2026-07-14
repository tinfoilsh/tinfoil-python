"""
Tests for user_cache_secret provisioning (per-user prompt cache scoping).

The router derives the request's prefix-cache namespace from the
`user_cache_secret` body field: requests carrying the same secret share cached
prompt prefixes, requests carrying different secrets cannot observe each
other's cache timing. The SDK provisions the field automatically — explicit
parameter, then TINFOIL_USER_CACHE_SECRET, then a secret persisted at
~/.tinfoil/user_cache_secret — and injects it inside the sealing transport so
it only ever travels encrypted.
"""

import asyncio
import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from openai import AsyncOpenAI, OpenAI

import tinfoil.user_cache_secret as user_cache_secret_module
from tinfoil import SecureClient
from tinfoil.client import (
    GroundTruth,
    _AsyncEHBPReVerifyingTransport,
    _AsyncHostBoundTransport,
    _EHBPReVerifyingTransport,
    _HostBoundTransport,
    _ReVerifyingTransport,
)
from tinfoil.user_cache_secret import (
    USER_CACHE_SECRET_DIR_NAME,
    USER_CACHE_SECRET_ENV,
    USER_CACHE_SECRET_FIELD,
    USER_CACHE_SECRET_FILE_NAME,
    _AsyncUserCacheSecretTransport,
    _UserCacheSecretTransport,
    resolve_user_cache_secret,
)


@pytest.fixture
def secret_home(monkeypatch, tmp_path):
    """A tmp home directory with TINFOIL_USER_CACHE_SECRET removed, so
    resolution falls through to the persisted/generated secret."""
    monkeypatch.delenv(USER_CACHE_SECRET_ENV, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


class TestResolvePrecedence:
    def test_explicit_parameter_beats_environment(self, monkeypatch):
        monkeypatch.setenv(USER_CACHE_SECRET_ENV, "from-env")
        assert resolve_user_cache_secret("explicit") == "explicit"

    def test_explicit_empty_is_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv(USER_CACHE_SECRET_ENV, "from-env")
        assert resolve_user_cache_secret("") == "from-env"

    def test_environment_beats_generation_and_touches_no_file(self, secret_home, monkeypatch):
        monkeypatch.setenv(USER_CACHE_SECRET_ENV, "from-env")
        assert resolve_user_cache_secret(None) == "from-env"
        assert not (secret_home / USER_CACHE_SECRET_DIR_NAME).exists(), (
            "an environment-provided secret must not create the secret file"
        )

    def test_environment_set_but_empty_falls_through(self, secret_home, monkeypatch):
        monkeypatch.setenv(USER_CACHE_SECRET_ENV, "")
        resolved = resolve_user_cache_secret(None)
        assert len(resolved) == 64
        assert (secret_home / USER_CACHE_SECRET_DIR_NAME).exists()


class TestPersistence:
    def test_generates_and_persists(self, secret_home):
        first = resolve_user_cache_secret(None)
        assert len(first) == 64
        assert set(first) <= set("0123456789abcdef")

        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        path = secret_dir / USER_CACHE_SECRET_FILE_NAME
        assert stat.S_IMODE(secret_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_text() == first
        assert resolve_user_cache_secret(None) == first
        assert list(secret_dir.iterdir()) == [path]

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
    def test_accepts_permissive_preexisting_modes(self, secret_home):
        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        secret_dir.mkdir()
        path = secret_dir / USER_CACHE_SECRET_FILE_NAME
        path.write_text("shared-secret")
        secret_dir.chmod(0o777)
        path.chmod(0o666)

        assert resolve_user_cache_secret(None) == "shared-secret"
        assert stat.S_IMODE(secret_dir.stat().st_mode) == 0o777
        assert stat.S_IMODE(path.stat().st_mode) == 0o666

    def test_adopts_existing_file_with_unicode_whitespace(self, secret_home):
        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        secret_dir.mkdir(mode=0o700)
        path = secret_dir / USER_CACHE_SECRET_FILE_NAME
        path.write_text("\u2003shared-secret\n")

        assert resolve_user_cache_secret(None) == "shared-secret"
        assert path.read_text() == "\u2003shared-secret\n"

    def test_preserves_non_unicode_separator_controls(self, secret_home):
        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        secret_dir.mkdir(mode=0o700)
        (secret_dir / USER_CACHE_SECRET_FILE_NAME).write_text(
            "\x1cshared-secret\x1f"
        )

        assert resolve_user_cache_secret(None) == "\x1cshared-secret\x1f"

    @pytest.mark.parametrize(
        "contents", [b"  \n", b"\xff\xfegarbage"], ids=["blank", "invalid-utf8"]
    )
    def test_unusable_existing_file_is_untouched(
        self, secret_home, monkeypatch, contents
    ):
        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        secret_dir.mkdir(mode=0o700)
        path = secret_dir / USER_CACHE_SECRET_FILE_NAME
        path.write_bytes(contents)
        monkeypatch.setattr(
            user_cache_secret_module,
            "_ephemeral_user_cache_secret",
            lambda: "ephemeral",
        )

        assert resolve_user_cache_secret(None) == "ephemeral"
        assert path.read_bytes() == contents

    @pytest.mark.skipif(os.name == "nt", reason="O_NOFOLLOW is POSIX")
    def test_rejects_secret_file_symlink_without_reading_target(
        self, secret_home, monkeypatch
    ):
        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        secret_dir.mkdir()
        path = secret_dir / USER_CACHE_SECRET_FILE_NAME
        target = secret_home / "symlink-target"
        target.write_text("target-secret")
        path.symlink_to(target)
        monkeypatch.setattr(
            user_cache_secret_module,
            "_ephemeral_user_cache_secret",
            lambda: "ephemeral",
        )

        assert resolve_user_cache_secret(None) == "ephemeral"
        assert target.read_text() == "target-secret"

    @pytest.mark.skipif(os.name == "nt", reason="FIFO files are POSIX")
    def test_rejects_non_regular_secret_file(self, secret_home, monkeypatch):
        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        secret_dir.mkdir()
        path = secret_dir / USER_CACHE_SECRET_FILE_NAME
        os.mkfifo(path, mode=0o644)
        monkeypatch.setattr(
            user_cache_secret_module,
            "_ephemeral_user_cache_secret",
            lambda: "ephemeral",
        )

        assert resolve_user_cache_secret(None) == "ephemeral"
        assert stat.S_ISFIFO(path.stat().st_mode)

    @pytest.mark.skipif(os.name == "nt", reason="directory symlinks are POSIX")
    def test_rejects_cache_directory_symlink(self, secret_home, monkeypatch):
        target = secret_home / "directory-target"
        target.mkdir(mode=0o755)
        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        secret_dir.symlink_to(target, target_is_directory=True)
        monkeypatch.setattr(
            user_cache_secret_module,
            "_ephemeral_user_cache_secret",
            lambda: "ephemeral",
        )

        assert resolve_user_cache_secret(None) == "ephemeral"
        assert list(target.iterdir()) == []

    @pytest.mark.skipif(os.name == "nt", reason="hard-link election is POSIX")
    def test_concurrent_first_use_converges(self, secret_home):
        script = textwrap.dedent(
            """
            import sys
            from tinfoil.user_cache_secret import resolve_user_cache_secret

            sys.stdin.read(1)
            print(resolve_user_cache_secret(None))
            """
        )
        env = os.environ.copy()
        env["HOME"] = str(secret_home)
        env.pop(USER_CACHE_SECRET_ENV, None)
        source_dir = str(Path(__file__).parents[1] / "src")
        env["PYTHONPATH"] = os.pathsep.join(
            value for value in (source_dir, env.get("PYTHONPATH")) if value
        )
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            for _ in range(12)
        ]
        for process in processes:
            assert process.stdin is not None
            process.stdin.write("x")
            process.stdin.close()

        results = []
        for process in processes:
            assert process.stdout is not None
            assert process.stderr is not None
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            assert process.wait(timeout=30) == 0, stderr
            results.append(stdout.strip())

        path = (
            secret_home
            / USER_CACHE_SECRET_DIR_NAME
            / USER_CACHE_SECRET_FILE_NAME
        )
        assert len(set(results)) == 1
        assert results[0] == path.read_text()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert list(path.parent.iterdir()) == [path]

    def test_hard_link_failure_uses_process_fallback(
        self, secret_home, monkeypatch
    ):
        monkeypatch.setattr(
            user_cache_secret_module.os,
            "link",
            lambda source, destination: (_ for _ in ()).throw(
                OSError("hard links unavailable")
            ),
        )
        monkeypatch.setattr(
            user_cache_secret_module,
            "_ephemeral_user_cache_secret",
            lambda: "ephemeral",
        )

        assert resolve_user_cache_secret(None) == "ephemeral"
        secret_dir = secret_home / USER_CACHE_SECRET_DIR_NAME
        assert list(secret_dir.iterdir()) == []

    @pytest.mark.parametrize("home", [None, ""], ids=["unset", "empty"])
    def test_falls_back_without_home(self, monkeypatch, home):
        monkeypatch.delenv(USER_CACHE_SECRET_ENV, raising=False)
        if home is None:
            monkeypatch.delenv("HOME", raising=False)
        else:
            monkeypatch.setenv("HOME", home)

        first = resolve_user_cache_secret(None)
        assert first
        assert resolve_user_cache_secret(None) == first

    def test_falls_back_on_pathological_secret_path(self, monkeypatch):
        monkeypatch.delenv(USER_CACHE_SECRET_ENV, raising=False)
        monkeypatch.setattr(
            user_cache_secret_module,
            "_user_cache_secret_path",
            lambda: Path("nul\x00l") / USER_CACHE_SECRET_FILE_NAME,
        )

        assert resolve_user_cache_secret(None)

    def test_falls_back_when_home_not_a_directory(self, monkeypatch, tmp_path):
        monkeypatch.delenv(USER_CACHE_SECRET_ENV, raising=False)
        home_file = tmp_path / "not-a-dir"
        home_file.write_text("x")
        monkeypatch.setenv("HOME", str(home_file))

        assert resolve_user_cache_secret(None)


class _RecordingTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """Records the request and body the injection transport forwards."""

    def __init__(self) -> None:
        self.request = None
        self.body = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.request = request
        self.body = request.read()
        return httpx.Response(200, content=b"ok")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.request = request
        self.body = await request.aread()
        return httpx.Response(200, content=b"ok")


def _roundtrip(secret: str, request: httpx.Request, use_async: bool):
    """Send request through the sync or async injection transport and return
    (recorder, response)."""
    recorder = _RecordingTransport()
    if use_async:
        async_transport = _AsyncUserCacheSecretTransport(secret, recorder)
        response = asyncio.run(async_transport.handle_async_request(request))
    else:
        transport = _UserCacheSecretTransport(secret, recorder)
        response = transport.handle_request(request)
    return recorder, response


def _post(path: str, body: bytes) -> httpx.Request:
    return httpx.Request(
        "POST",
        f"https://enclave.test{path}",
        headers={"Content-Type": "application/json"},
        content=body,
    )


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
class TestTransportInjects:
    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/responses",
            "/api/v1/chat/completions",  # proxy base URL with a path prefix
            "/chat/completions",  # custom base URL without a /v1 root
        ],
    )
    def test_injects_on_eligible_paths(self, path, use_async):
        recorder, response = _roundtrip("s1", _post(path, b'{"model":"m"}'), use_async)
        assert response.status_code == 200

        body = json.loads(recorder.body)
        assert body[USER_CACHE_SECRET_FIELD] == "s1"
        assert body["model"] == "m"

        # Length metadata and the replayable body must describe the injected
        # bytes: retries below this layer (EHBP key rotation) re-read the
        # request stream.
        assert recorder.request.headers["Content-Length"] == str(len(recorder.body))
        assert b"".join(recorder.request.stream) == recorder.body

    def test_trailing_whitespace_still_injected(self, use_async):
        # Trailing whitespace is not trailing data: strict JSON parsers accept
        # it, so the injection must too — clients routinely end bodies with \n.
        recorder, _ = _roundtrip(
            "s1", _post("/v1/chat/completions", b'{"model":"m"}\n\t '), use_async
        )
        assert recorder.body == b'{"model":"m","user_cache_secret":"s1"}\n\t '

    def test_preserves_number_precision(self, use_async):
        # 2^53+1 is not representable as float64; a decode/re-encode through
        # floats would corrupt it.
        recorder, _ = _roundtrip(
            "s1",
            _post("/v1/chat/completions", b'{"model":"m","seed":9007199254740993}'),
            use_async,
        )
        assert b'"seed":9007199254740993' in recorder.body
        assert json.loads(recorder.body)[USER_CACHE_SECRET_FIELD] == "s1"


@pytest.mark.parametrize("use_async", [False, True], ids=["sync", "async"])
class TestTransportSkips:
    @pytest.mark.parametrize("path", ["/v1/embeddings", "/embeddings"])
    def test_non_allowlisted_endpoint_forwards_body_untouched(self, path, use_async):
        raw = b'{"model":"m","input":"text"}'
        request = _post(path, raw)
        recorder, _ = _roundtrip("s1", request, use_async)
        assert recorder.body == raw
        assert recorder.request is request

    def test_get_with_no_body_forwarded_as_is(self, use_async):
        request = httpx.Request("GET", "https://enclave.test/v1/models")
        recorder, response = _roundtrip("s1", request, use_async)
        assert response.status_code == 200
        assert recorder.request is request

    def test_post_with_empty_body_forwarded_as_is(self, use_async):
        request = _post("/v1/chat/completions", b"")
        recorder, _ = _roundtrip("s1", request, use_async)
        assert recorder.body == b""
        assert recorder.request is request

    def test_missing_resolved_secret_skips_injection(self, use_async):
        raw = b'{"model":"m"}'
        request = _post("/v1/chat/completions", raw)
        recorder, _ = _roundtrip("", request, use_async)
        assert recorder.body == raw
        assert recorder.request is request

    @pytest.mark.parametrize(
        "raw",
        [
            b'{"model":"m","user_cache_secret":"end-user-7"}',
            b'{"model":"m","user_cache_secret":null}',
        ],
        ids=["explicit per-request secret", "explicit null"],
    )
    def test_never_clobbers_a_non_empty_or_non_string_field(self, raw, use_async):
        request = _post("/v1/chat/completions", raw)
        recorder, _ = _roundtrip("client-level", request, use_async)
        assert recorder.body == raw, (
            "a body that already carries the field must pass through byte-identical"
        )
        assert recorder.request is request

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (
                b'{"large":9007199254740993,"user_cache_secret":"","nested":{"value":1}}  ',
                b'{"large":9007199254740993,"user_cache_secret":"client-level","nested":{"value":1}}  ',
            ),
            (
                b'{"user_cache_secre\\u0074":""}',
                b'{"user_cache_secre\\u0074":"client-level"}',
            ),
        ],
    )
    def test_replaces_empty_per_request_field(self, raw, expected, use_async):
        recorder, _ = _roundtrip(
            "client-level",
            _post("/v1/chat/completions", raw),
            use_async,
        )
        assert recorder.body == expected

    @pytest.mark.parametrize(
        "raw",
        [
            b'{"user_cache_secret":"","user_cache_secret":""}',
            b'{"user_cache_secret":"end-user-7","user_cache_secre\\u0074":""}',
            b'{"user_cache_secre\\u0074":"","user_cache_secret":""}',
        ],
        ids=[
            "duplicate literal keys",
            "escaped effective key",
            "escaped first key",
        ],
    )
    def test_duplicate_per_request_fields_forwarded_untouched(self, raw, use_async):
        request = _post("/v1/chat/completions", raw)
        recorder, _ = _roundtrip("client-level", request, use_async)
        assert recorder.body == raw
        assert recorder.request is request

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
        ],
    )
    def test_non_object_bodies_forwarded_untouched(self, raw, use_async):
        # The trailing '}' / ']' cases matter: a parser that stops at the end
        # of the object would re-serialize with the trailing bytes silently
        # dropped, quietly turning a request the server rejects into one it
        # accepts.
        request = _post("/v1/chat/completions", raw)
        recorder, _ = _roundtrip("s1", request, use_async)
        assert recorder.body == raw, (
            "bodies the router-side schema would reject must be forwarded untouched"
        )
        assert recorder.request is request

    def test_pathologically_nested_body_forwarded_untouched(self, use_async):
        # CPython's json scanner raises RecursionError on very deep nesting
        # (Go's decoder errors at its own depth limit): the body must be
        # forwarded untouched — never a RecursionError out of the transport.
        raw = b'{"a":' + b"[" * 1_000_000 + b"]" * 1_000_000 + b"}"
        request = _post("/v1/chat/completions", raw)
        recorder, _ = _roundtrip("s1", request, use_async)
        assert recorder.body == raw
        assert recorder.request is request


class TestStreamingBodies:
    """Streaming bodies are forwarded without being consumed."""

    def test_sync_streaming_body_unchanged(self):
        request = httpx.Request(
            "POST",
            "https://enclave.test/v1/chat/completions",
            headers={"tRaNsFeR-EnCoDiNg": "chunked"},
            content=iter([b'{"model":', b'"m"}']),
        )
        recorder, _ = _roundtrip("s1", request, use_async=False)
        assert recorder.request is request
        assert recorder.body == b'{"model":"m"}'
        assert recorder.request.headers["Transfer-Encoding"] == "chunked"

    def test_async_streaming_body_unchanged(self):
        async def chunks():
            yield b'{"model":'
            yield b'"m"}'

        request = httpx.Request(
            "POST",
            "https://enclave.test/v1/chat/completions",
            headers={"TrAnSfEr-EnCoDiNg": "chunked"},
            content=chunks(),
        )
        recorder, _ = _roundtrip("s1", request, use_async=True)
        assert recorder.request is request
        assert recorder.body == b'{"model":"m"}'
        assert recorder.request.headers["Transfer-Encoding"] == "chunked"


def _hpke_hex() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    pk = X25519PrivateKey.generate().public_key()
    return pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _secure_client(**kwargs) -> SecureClient:
    # An explicit enclave avoids the router lookup (network) in __init__.
    sc = SecureClient(enclave="enclave.test", repo="org/repo", **kwargs)
    sc.verify = MagicMock(
        return_value=GroundTruth(
            public_key="fp", digest="d", measurement="m", hpke_public_key=_hpke_hex()
        )
    )
    return sc


class TestSecureClientResolution:
    """SecureClient resolves the client-level secret once at construction; the
    conftest fixture pins TINFOIL_USER_CACHE_SECRET=test-secret."""

    def test_explicit_parameter_wins(self):
        assert _secure_client(user_cache_secret="s1")._user_cache_secret == "s1"

    def test_explicit_empty_falls_back_to_environment(self):
        assert _secure_client(user_cache_secret="")._user_cache_secret == "test-secret"

    def test_unset_falls_back_to_environment(self):
        assert _secure_client()._user_cache_secret == "test-secret"


class TestSecureClientWiring:
    """The cache-secret layer must sit inside any header-level wrapping and
    above the sealing transport, so the injected field is encrypted with the
    rest of the body."""

    def test_sync_ehbp_stack(self):
        client = _secure_client().make_secure_http_client()
        try:
            bound = client._transport
            assert isinstance(bound, _HostBoundTransport)
            ucs = bound._inner
            assert isinstance(ucs, _UserCacheSecretTransport)
            assert isinstance(ucs._inner, _EHBPReVerifyingTransport)
        finally:
            client.close()

    def test_sync_tls_stack(self):
        client = _secure_client(transport="tls").make_secure_http_client()
        try:
            bound = client._transport
            assert isinstance(bound, _HostBoundTransport)
            ucs = bound._inner
            assert isinstance(ucs, _UserCacheSecretTransport)
            assert isinstance(ucs._inner, _ReVerifyingTransport)
        finally:
            client.close()

    def test_async_ehbp_stack(self):
        client = _secure_client().make_secure_async_http_client()
        try:
            bound = client._transport
            assert isinstance(bound, _AsyncHostBoundTransport)
            ucs = bound._inner
            assert isinstance(ucs, _AsyncUserCacheSecretTransport)
            assert isinstance(ucs._inner, _AsyncEHBPReVerifyingTransport)
        finally:
            asyncio.run(client.aclose())

    def test_empty_secret_uses_the_resolved_layer(self):
        client = _secure_client(user_cache_secret="").make_secure_http_client()
        try:
            assert isinstance(client._transport, _HostBoundTransport)
            user_cache_secret = client._transport._inner
            assert isinstance(user_cache_secret, _UserCacheSecretTransport)
            assert isinstance(user_cache_secret._inner, _EHBPReVerifyingTransport)
        finally:
            client.close()


def _chat_completion_handler(received: list):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        received.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "c1",
                "object": "chat.completion",
                "created": 0,
                "model": "m",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    return handler


class TestThroughOpenAIClient:
    """Drives the real OpenAI client through the injection transport to a mock
    server, pinning that the secret rides requests exactly as the SDK builds
    them — and that a per-request field set via the public API (extra_body)
    wins over the client-level secret."""

    _params = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}

    def test_sync_client(self):
        received: list = []
        http_client = httpx.Client(
            transport=_UserCacheSecretTransport(
                "client-level", httpx.MockTransport(_chat_completion_handler(received))
            )
        )
        oai = OpenAI(api_key="test", base_url="http://localhost/v1", http_client=http_client)

        oai.chat.completions.create(**self._params)
        assert received[-1][USER_CACHE_SECRET_FIELD] == "client-level"

        oai.chat.completions.create(
            **self._params, extra_body={USER_CACHE_SECRET_FIELD: "end-user-7"}
        )
        assert received[-1][USER_CACHE_SECRET_FIELD] == "end-user-7", (
            "a per-request field must win over the client-level secret"
        )

    def test_async_client(self):
        received: list = []

        async def run():
            http_client = httpx.AsyncClient(
                transport=_AsyncUserCacheSecretTransport(
                    "client-level",
                    httpx.MockTransport(_chat_completion_handler(received)),
                )
            )
            oai = AsyncOpenAI(
                api_key="test", base_url="http://localhost/v1", http_client=http_client
            )

            await oai.chat.completions.create(**self._params)
            assert received[-1][USER_CACHE_SECRET_FIELD] == "client-level"

            await oai.chat.completions.create(
                **self._params, extra_body={USER_CACHE_SECRET_FIELD: "end-user-7"}
            )
            assert received[-1][USER_CACHE_SECRET_FIELD] == "end-user-7", (
                "a per-request field must win over the client-level secret"
            )

        asyncio.run(run())
