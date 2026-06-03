"""
Tests for the EHBP (Encrypted HTTP Body Protocol) transport mode.

In EHBP mode request bodies are encrypted end-to-end to the enclave's attested
HPKE public key, and the transport re-verifies attestation and retries once when
the server rotates its HPKE key (surfaced as KeyConfigMismatchError).
"""

import asyncio
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


@pytest.mark.integration
class TestIntegration:
    @pytest.mark.parametrize("transport", ["ehbp", "tls"])
    def test_chat_completion(self, transport):
        api_key = os.getenv("TINFOIL_API_KEY")
        if not api_key:
            pytest.skip("TINFOIL_API_KEY not set")

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
        api_key = os.getenv("TINFOIL_API_KEY")
        if not api_key:
            pytest.skip("TINFOIL_API_KEY not set")

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
