import httpx
from openai import NOT_GIVEN

import tinfoil


class FakeSecureClient:
    def __init__(self, enclave, repo, measurement):
        self.enclave = enclave
        self.repo = repo
        self.measurement = measurement

    def make_secure_http_client(self):
        return "sync-http-client"

    def make_secure_async_http_client(self):
        return "async-http-client"


class FakeOpenAIClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.chat = object()
        self.embeddings = object()
        self.audio = object()


def test_tinfoilai_forwards_timeout_to_openai(monkeypatch):
    captured = {}

    def fake_openai(**kwargs):
        captured.update(kwargs)
        return FakeOpenAIClient(**kwargs)

    monkeypatch.setattr(tinfoil, "SecureClient", FakeSecureClient)
    monkeypatch.setattr(tinfoil, "OpenAI", fake_openai)

    timeout = httpx.Timeout(12.5)
    client = tinfoil.TinfoilAI(
        enclave="router.test",
        repo="tinfoilsh/confidential-model-router",
        api_key="test-key",
        timeout=timeout,
    )

    assert client.enclave == "router.test"
    assert captured["base_url"] == "https://router.test/v1/"
    assert captured["api_key"] == "test-key"
    assert captured["timeout"] is timeout
    assert captured["http_client"] == "sync-http-client"


def test_tinfoilai_uses_openai_default_timeout_when_unspecified(monkeypatch):
    captured = {}

    def fake_openai(**kwargs):
        captured.update(kwargs)
        return FakeOpenAIClient(**kwargs)

    monkeypatch.setattr(tinfoil, "SecureClient", FakeSecureClient)
    monkeypatch.setattr(tinfoil, "OpenAI", fake_openai)

    tinfoil.TinfoilAI(
        enclave="router.test",
        repo="tinfoilsh/confidential-model-router",
        api_key="test-key",
    )

    assert captured["timeout"] is NOT_GIVEN


def test_async_tinfoilai_forwards_timeout_to_async_openai(monkeypatch):
    captured = {}

    def fake_async_openai(**kwargs):
        captured.update(kwargs)
        return FakeOpenAIClient(**kwargs)

    monkeypatch.setattr(tinfoil, "SecureClient", FakeSecureClient)
    monkeypatch.setattr(tinfoil, "AsyncOpenAI", fake_async_openai)

    timeout = httpx.Timeout(8.0)
    client = tinfoil.AsyncTinfoilAI(
        enclave="router.test",
        repo="tinfoilsh/confidential-model-router",
        api_key="test-key",
        timeout=timeout,
    )

    assert client.enclave == "router.test"
    assert captured["base_url"] == "https://router.test/v1/"
    assert captured["api_key"] == "test-key"
    assert captured["timeout"] is timeout
    assert captured["http_client"] == "async-http-client"


def test_async_tinfoilai_uses_openai_default_timeout_when_unspecified(monkeypatch):
    captured = {}

    def fake_async_openai(**kwargs):
        captured.update(kwargs)
        return FakeOpenAIClient(**kwargs)

    monkeypatch.setattr(tinfoil, "SecureClient", FakeSecureClient)
    monkeypatch.setattr(tinfoil, "AsyncOpenAI", fake_async_openai)

    tinfoil.AsyncTinfoilAI(
        enclave="router.test",
        repo="tinfoilsh/confidential-model-router",
        api_key="test-key",
    )

    assert captured["timeout"] is NOT_GIVEN
