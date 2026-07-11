"""
Tests for the EHBP (Encrypted HTTP Body Protocol) transport mode.

In EHBP mode request bodies are encrypted end-to-end to the enclave's attested
HPKE public key, and the transport re-verifies attestation and retries once when
the server rotates its HPKE key (surfaced as KeyConfigMismatchError).
"""

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from ehbp import EHBPTransport, KeyConfigMismatchError

from tinfoil import AsyncTinfoilAI, SecureClient, TinfoilAI
from tinfoil.client import (
    DEFAULT_TRANSPORT_MODE,
    GroundTruth,
    get_router_address,
    _AsyncEHBPReVerifyingTransport,
    _EHBPReVerifyingTransport,
    _ReVerifyingTransport,
)


def _valid_hpke_hex() -> str:
    pk = X25519PrivateKey.generate().public_key()
    return pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _ground_truth(hpke: str) -> GroundTruth:
    return GroundTruth(public_key="fp", digest="d", measurement="m", hpke_public_key=hpke)


def _secure_client(transport: str = "ehbp") -> SecureClient:
    # An explicit enclave avoids the router lookup (network) in __init__.
    return SecureClient(enclave="enclave.test", repo="org/repo", transport=transport)


class TestDefaultsAndValidation:
    def test_default_transport_is_ehbp(self):
        assert DEFAULT_TRANSPORT_MODE == "ehbp"
        assert _secure_client().transport == "ehbp"

    def test_ground_truth_has_hpke_field(self):
        assert _ground_truth("abcd").hpke_public_key == "abcd"
        assert GroundTruth("fp", "d", "m").hpke_public_key == ""

    def test_invalid_transport_rejected(self):
        with pytest.raises(ValueError):
            SecureClient(enclave="enclave.test", repo="org/repo", transport="bogus")


class TestRequireHPKEKey:
    def test_returns_attested_key(self):
        sc = _secure_client()
        key = _valid_hpke_hex()
        sc.verify = MagicMock(return_value=_ground_truth(key))
        assert sc._require_hpke_public_key() == key

    def test_raises_without_key(self):
        sc = _secure_client()
        sc.verify = MagicMock(return_value=_ground_truth(""))
        with pytest.raises(ValueError):
            sc._require_hpke_public_key()


class TestTransportSelection:
    def test_ehbp_mode_builds_ehbp_transport(self):
        sc = _secure_client("ehbp")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc.make_secure_http_client()
        try:
            assert isinstance(client._transport, _EHBPReVerifyingTransport)
        finally:
            client.close()

    def test_tls_mode_builds_pinned_transport(self):
        sc = _secure_client("tls")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc.make_secure_http_client()
        try:
            assert isinstance(client._transport, _ReVerifyingTransport)
        finally:
            client.close()

    def test_async_ehbp_mode_builds_ehbp_transport(self):
        sc = _secure_client("ehbp")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc.make_secure_async_http_client()
        try:
            assert isinstance(client._transport, _AsyncEHBPReVerifyingTransport)
        finally:
            asyncio.run(client.aclose())

    def test_build_ehbp_sync_transport_returns_ehbp(self):
        sc = _secure_client("ehbp")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        inner = sc._build_ehbp_sync_transport()
        try:
            assert isinstance(inner, EHBPTransport)
        finally:
            inner.close()


class TestRedirectsDisabled:
    """The secure clients must not follow redirects: a redirect target is not
    re-checked against the enclave/proxy host binding, so following one could
    disclose sensitive headers (including the API key) to an arbitrary host."""

    def test_sync_ehbp_client_does_not_follow_redirects(self):
        sc = _secure_client("ehbp")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc.make_secure_http_client()
        try:
            assert client.follow_redirects is False
        finally:
            client.close()

    def test_sync_tls_client_does_not_follow_redirects(self):
        sc = _secure_client("tls")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc.make_secure_http_client()
        try:
            assert client.follow_redirects is False
        finally:
            client.close()

    def test_async_ehbp_client_does_not_follow_redirects(self):
        sc = _secure_client("ehbp")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc.make_secure_async_http_client()
        try:
            assert client.follow_redirects is False
        finally:
            asyncio.run(client.aclose())

    def test_async_tls_client_does_not_follow_redirects(self):
        sc = _secure_client("tls")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc.make_secure_async_http_client()
        try:
            assert client.follow_redirects is False
        finally:
            asyncio.run(client.aclose())


class TestLowLevelHonorsTransport:
    """The low-level get()/post() path must respect the configured transport."""

    def test_low_level_client_uses_ehbp_transport(self):
        sc = _secure_client("ehbp")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc._secure_http_client()
        try:
            assert isinstance(client._transport, _EHBPReVerifyingTransport)
        finally:
            client.close()

    def test_low_level_client_uses_pinned_transport_in_tls_mode(self):
        sc = _secure_client("tls")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = sc._secure_http_client()
        try:
            assert isinstance(client._transport, _ReVerifyingTransport)
        finally:
            client.close()

    def test_get_http_client_rejected_in_ehbp_mode(self):
        sc = _secure_client("ehbp")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        with pytest.raises(ValueError):
            sc.get_http_client()

    def test_get_http_client_allowed_in_tls_mode(self):
        sc = _secure_client("tls")
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        assert sc.get_http_client() is not None


class TestMakeRequestHostBinding:
    """make_request() must stay bound to the attested enclave (headers are not
    encrypted by EHBP) and preserve the prior unbounded timeout."""

    def _client_with_mock(self, transport: str = "ehbp"):
        sc = _secure_client(transport)
        http_client = MagicMock()
        http_client.request.return_value = httpx.Response(200, content=b"ok")
        sc._low_level_http_client = http_client
        return sc, http_client

    def test_rejects_absolute_url_to_foreign_host(self):
        sc, http_client = self._client_with_mock()
        with pytest.raises(ValueError, match="evil.example.com"):
            sc.get("https://evil.example.com/v1/models")
        http_client.request.assert_not_called()

    def test_rejects_foreign_host_in_tls_mode_too(self):
        sc, http_client = self._client_with_mock("tls")
        with pytest.raises(ValueError):
            sc.get("https://evil.example.com/v1/models")
        http_client.request.assert_not_called()

    def test_allows_absolute_url_to_enclave_host(self):
        sc, http_client = self._client_with_mock()
        resp = sc.get("https://enclave.test/v1/models")
        assert resp.status_code == 200
        assert http_client.request.call_args.args[1] == "https://enclave.test/v1/models"

    def test_preserves_unbounded_timeout(self):
        sc, http_client = self._client_with_mock()
        sc.post("https://enclave.test/v1/chat/completions", headers={}, body=b"payload")
        assert http_client.request.call_args.kwargs["timeout"] is None


class _RaiseKeyMismatch(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.read()  # EHBP consumes the body before reporting the mismatch
        raise KeyConfigMismatchError("rotated")


class _OK(httpx.BaseTransport):
    def __init__(self) -> None:
        self.calls = 0
        self.seen_body = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.seen_body = request.read()
        return httpx.Response(200, content=b"recovered")


class _RaiseOther(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")


class TestSyncReverify:
    def test_retries_on_key_rotation_and_replays_body(self):
        sc = _secure_client()
        ok = _OK()
        sc._build_ehbp_sync_transport = MagicMock(return_value=ok)

        wrapper = _EHBPReVerifyingTransport(sc, _RaiseKeyMismatch())
        request = httpx.Request("POST", "https://enclave.test/v1/chat/completions", content=b"payload")
        resp = wrapper.handle_request(request)

        assert resp.status_code == 200
        assert resp.read() == b"recovered"
        assert ok.calls == 1
        assert ok.seen_body == b"payload"
        assert sc._build_ehbp_sync_transport.call_count == 1

    def test_passes_through_other_errors_without_reverify(self):
        sc = _secure_client()
        sc._build_ehbp_sync_transport = MagicMock()

        wrapper = _EHBPReVerifyingTransport(sc, _RaiseOther())
        request = httpx.Request("POST", "https://enclave.test/v1/chat/completions", content=b"payload")
        with pytest.raises(httpx.ConnectError):
            wrapper.handle_request(request)
        sc._build_ehbp_sync_transport.assert_not_called()

    def test_surfaces_original_error_when_reverify_fails(self):
        sc = _secure_client()
        sc._build_ehbp_sync_transport = MagicMock(side_effect=RuntimeError("attestation failed"))

        wrapper = _EHBPReVerifyingTransport(sc, _RaiseKeyMismatch())
        request = httpx.Request("POST", "https://enclave.test/v1/chat/completions", content=b"payload")
        with pytest.raises(KeyConfigMismatchError):
            wrapper.handle_request(request)


class _AsyncRaiseKeyMismatch(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        raise KeyConfigMismatchError("rotated")


class _AsyncOK(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.calls = 0
        self.seen_body = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.seen_body = await request.aread()
        return httpx.Response(200, content=b"recovered")


class TestAsyncReverify:
    def test_retries_on_key_rotation_and_replays_body(self):
        async def run():
            sc = _secure_client()
            ok = _AsyncOK()
            sc._build_ehbp_async_transport = AsyncMock(return_value=ok)

            wrapper = _AsyncEHBPReVerifyingTransport(sc, _AsyncRaiseKeyMismatch())
            request = httpx.Request("POST", "https://enclave.test/v1/chat/completions", content=b"payload")
            resp = await wrapper.handle_async_request(request)

            assert resp.status_code == 200
            assert await resp.aread() == b"recovered"
            assert ok.calls == 1
            assert ok.seen_body == b"payload"
            assert sc._build_ehbp_async_transport.await_count == 1

        asyncio.run(run())


def _require_api_key() -> str:
    """
    Return TINFOIL_API_KEY, failing the test if it is missing.

    Integration tests must not be silently skipped when a required secret is
    absent: that hides misconfigured CI and lets coverage regress unnoticed.
    """
    api_key = os.getenv("TINFOIL_API_KEY")
    if not api_key:
        pytest.fail("TINFOIL_API_KEY must be set to run the integration tests")
    return api_key


@pytest.mark.integration
class TestIntegration:
    @pytest.mark.parametrize("transport", ["ehbp", "tls"])
    def test_chat_completion(self, transport):
        api_key = _require_api_key()

        client = TinfoilAI(api_key=api_key, transport=transport)
        response = client.chat.completions.create(
            model="llama3-3-70b",
            messages=[
                {"role": "system", "content": "No matter what the user says, only respond with: Done."},
                {"role": "user", "content": "Is this a test?"},
            ],
        )
        assert response.choices[0].message.content

    @pytest.mark.asyncio
    @pytest.mark.parametrize("transport", ["ehbp", "tls"])
    async def test_async_streaming_chat_completion(self, transport):
        api_key = _require_api_key()

        client = AsyncTinfoilAI(api_key=api_key, transport=transport)
        stream = await client.chat.completions.create(
            model="llama3-3-70b",
            messages=[
                {"role": "system", "content": "No matter what the user says, only respond with: Done."},
                {"role": "user", "content": "Is this a test?"},
            ],
            stream=True,
        )
        collected = []
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                collected.append(chunk.choices[0].delta.content)
        assert "".join(collected)


@pytest.mark.integration
class TestLowLevelEHBPIntegration:
    """The low-level SecureClient.get()/post() path against a live enclave.

    Covers both transport modes and, for EHBP, both request shapes: a bodyless
    GET (which SPEC 7.4 sends without body encryption) and a POST whose body is
    sealed end-to-end to the enclave's HPKE key.
    """

    REPO = "tinfoilsh/confidential-model-router"

    def _client(self, transport: str) -> SecureClient:
        try:
            enclave = get_router_address()
        except Exception as e:
            pytest.skip(f"Could not fetch router address from ATC service: {e}")
        return SecureClient(enclave=enclave, repo=self.REPO, transport=transport)

    @pytest.mark.parametrize("transport", ["ehbp", "tls"])
    def test_low_level_bodyless_get_models(self, transport):
        api_key = _require_api_key()
        client = self._client(transport)
        resp = client.get(
            f"https://{client.enclave}/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200, resp.body

    @pytest.mark.parametrize("transport", ["ehbp", "tls"])
    def test_low_level_post_chat(self, transport):
        api_key = _require_api_key()
        client = self._client(transport)
        body = json.dumps(
            {
                "model": "llama3-3-70b",
                "max_tokens": 5,
                "messages": [
                    {"role": "system", "content": "No matter what the user says, only respond with: Done."},
                    {"role": "user", "content": "Is this a test?"},
                ],
            }
        ).encode()
        resp = client.post(
            f"https://{client.enclave}/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            body=body,
        )
        assert resp.status_code == 200, resp.body
        assert json.loads(resp.body)["choices"]
