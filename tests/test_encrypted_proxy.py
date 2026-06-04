"""
Tests for encrypted-proxy support: routing EHBP requests (and attestation)
through a proxy whose origin differs from the verified enclave's.

When a proxy is configured the request body stays sealed to the enclave's HPKE
key while the X-Tinfoil-Enclave-Url header tells the proxy which enclave to
forward to. Attestation can likewise be performed from a bundle fetched through
the proxy, so the enclave never needs to be reached directly to verify it.
"""

import asyncio
import base64
import json
import os
from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import tinfoil as tinfoil_module
from tinfoil import AsyncTinfoilAI, SecureClient, TinfoilAI
from tinfoil.attestation import Bundle, fetch_bundle_from
from tinfoil.attestation.bundle import _decode_domains, _matches_hostname
from tinfoil.client import (
    ENCLAVE_URL_HEADER,
    GroundTruth,
    _AsyncEnclaveURLHeaderTransport,
    _EHBPReVerifyingTransport,
    _EnclaveURLHeaderTransport,
    _enclave_url_header,
)


def _valid_hpke_hex() -> str:
    pk = X25519PrivateKey.generate().public_key()
    return pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _ground_truth(hpke: str) -> GroundTruth:
    return GroundTruth(public_key="fp", digest="d", measurement="m", hpke_public_key=hpke)


class TestEnclaveURLHeaderValue:
    @pytest.mark.parametrize(
        "base_url,enclave,want_val,want_ok",
        [
            ("https://proxy.example.com/", "enclave.example.com", "https://enclave.example.com", True),
            ("https://proxy.example.com/api/v1/", "enclave.example.com", "https://enclave.example.com", True),
            ("https://enclave.example.com/v1/", "enclave.example.com", "", False),
            ("", "enclave.example.com", "", False),
            ("https://proxy.example.com/", "", "", False),
        ],
    )
    def test_header_value(self, base_url, enclave, want_val, want_ok):
        val, ok = _enclave_url_header(base_url, enclave)
        assert ok is want_ok
        assert val == want_val


class _RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self.seen_header = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.seen_header = request.headers.get(ENCLAVE_URL_HEADER)
        return httpx.Response(200, content=b"ok")


class _AsyncRecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.seen_header = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.seen_header = request.headers.get(ENCLAVE_URL_HEADER)
        return httpx.Response(200, content=b"ok")


class TestEnclaveURLHeaderTransport:
    def test_sync_injects_header(self):
        inner = _RecordingTransport()
        transport = _EnclaveURLHeaderTransport(inner, "https://enclave.example.com")
        request = httpx.Request("POST", "https://proxy.example.com/v1/chat/completions", content=b"payload")
        resp = transport.handle_request(request)
        assert resp.status_code == 200
        assert inner.seen_header == "https://enclave.example.com"

    def test_async_injects_header(self):
        async def run():
            inner = _AsyncRecordingTransport()
            transport = _AsyncEnclaveURLHeaderTransport(inner, "https://enclave.example.com")
            request = httpx.Request("POST", "https://proxy.example.com/v1/chat/completions", content=b"payload")
            resp = await transport.handle_async_request(request)
            assert resp.status_code == 200
            assert inner.seen_header == "https://enclave.example.com"

        asyncio.run(run())


class TestProxyTransportWiring:
    """make_secure_http_client wraps the EHBP transport with the header
    transport only when routing through a proxy of a different origin."""

    def _client(self, base_url: str):
        sc = SecureClient(enclave="enclave.test", repo="org/repo", transport="ehbp", base_url=base_url)
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        return sc

    def test_sync_wraps_when_proxying(self):
        sc = self._client("https://proxy.example.com/")
        client = sc.make_secure_http_client()
        try:
            assert isinstance(client._transport, _EnclaveURLHeaderTransport)
            assert isinstance(client._transport._inner, _EHBPReVerifyingTransport)
        finally:
            client.close()

    def test_sync_no_wrap_when_same_origin(self):
        sc = self._client("https://enclave.test/v1/")
        client = sc.make_secure_http_client()
        try:
            assert isinstance(client._transport, _EHBPReVerifyingTransport)
        finally:
            client.close()

    def test_async_wraps_when_proxying(self):
        sc = self._client("https://proxy.example.com/")
        client = sc.make_secure_async_http_client()
        try:
            assert isinstance(client._transport, _AsyncEnclaveURLHeaderTransport)
        finally:
            asyncio.run(client.aclose())


class TestProxyHostBinding:
    """make_request must accept the configured proxy host in addition to the
    enclave host, and still reject unrelated hosts (headers are plaintext)."""

    def _client_with_mock(self, base_url: str = ""):
        sc = SecureClient(enclave="enclave.test", repo="org/repo", transport="ehbp", base_url=base_url)
        http_client = MagicMock()
        http_client.request.return_value = httpx.Response(200, content=b"ok")
        sc._low_level_http_client = http_client
        return sc, http_client

    def test_allows_proxy_host(self):
        sc, http_client = self._client_with_mock("https://proxy.example.com/")
        resp = sc.get("https://proxy.example.com/v1/models")
        assert resp.status_code == 200
        assert http_client.request.call_args.args[1] == "https://proxy.example.com/v1/models"

    def test_still_allows_enclave_host(self):
        sc, http_client = self._client_with_mock("https://proxy.example.com/")
        resp = sc.get("https://enclave.test/v1/models")
        assert resp.status_code == 200

    def test_rejects_foreign_host_even_with_proxy(self):
        sc, http_client = self._client_with_mock("https://proxy.example.com/")
        with pytest.raises(ValueError, match="evil.example.com"):
            sc.get("https://evil.example.com/v1/models")
        http_client.request.assert_not_called()


class TestAssertRequestAllowed:
    """The low-level escape hatches must stay bound to the enclave/proxy host
    and refuse plaintext (non-https) destinations."""

    def _sc(self, base_url: str = ""):
        return SecureClient(enclave="enclave.test", repo="org/repo", transport="ehbp", base_url=base_url)

    def test_allows_enclave_https(self):
        self._sc().assert_request_allowed("https://enclave.test/v1/models")

    def test_allows_proxy_https(self):
        self._sc("https://proxy.example.com/").assert_request_allowed("https://proxy.example.com/v1/models")

    def test_rejects_foreign_host(self):
        with pytest.raises(ValueError, match="evil.example.com"):
            self._sc().assert_request_allowed("https://evil.example.com/v1/models")

    def test_rejects_non_https(self):
        with pytest.raises(ValueError, match="non-https"):
            self._sc().assert_request_allowed("http://enclave.test/v1/models")


class TestLowLevelHostBinding:
    """NewSecureClient's get()/post() must enforce the host/scheme guard so an
    API key in headers cannot be sent to a caller-supplied host."""

    def _client(self, base_url: str = ""):
        sc = SecureClient(enclave="enclave.test", repo="org/repo", transport="ehbp", base_url=base_url)
        sc.verify = MagicMock(return_value=_ground_truth(_valid_hpke_hex()))
        client = tinfoil_module._HTTPSecureClient("enclave.test", sc)
        client._http_client = MagicMock()
        client._http_client.get.return_value = "ok-get"
        client._http_client.post.return_value = "ok-post"
        return client

    def test_get_rejects_foreign_host(self):
        client = self._client()
        with pytest.raises(ValueError, match="evil.example.com"):
            client.get("https://evil.example.com/v1/models")
        client._http_client.get.assert_not_called()

    def test_post_rejects_non_https(self):
        client = self._client()
        with pytest.raises(ValueError, match="non-https"):
            client.post("http://enclave.test/v1/chat/completions", json={})
        client._http_client.post.assert_not_called()

    def test_get_allows_enclave_host(self):
        client = self._client()
        assert client.get("https://enclave.test/v1/models") == "ok-get"

    def test_get_allows_proxy_host(self):
        client = self._client("https://proxy.example.com/")
        assert client.get("https://proxy.example.com/v1/models") == "ok-get"


class TestDecodeDomains:
    """_decode_domains reverses the dcode SAN encoding used by enclave certs."""

    def test_round_trip_single_chunk(self):
        data = b"hpke-public-key-bytes"
        b32 = base64.b32encode(data).decode().rstrip("=")
        sans = [f"00{b32}.hpke.enclave.example.com"]
        assert _decode_domains(sans, "hpke") == data

    def test_orders_chunks_by_index(self):
        data = b"the quick brown fox jumps over the lazy dog!!"
        b32 = base64.b32encode(data).decode().rstrip("=")
        mid = len(b32) // 2
        # Present the chunks out of order; decoding must reorder by index.
        sans = [
            f"01{b32[mid:]}.hatt.enclave.example.com",
            f"00{b32[:mid]}.hatt.enclave.example.com",
        ]
        assert _decode_domains(sans, "hatt") == data

    def test_ignores_other_prefixes(self):
        data = b"key"
        b32 = base64.b32encode(data).decode().rstrip("=")
        sans = [f"00{b32}.hpke.enclave.example.com", "00ZZZZ.hatt.enclave.example.com"]
        assert _decode_domains(sans, "hpke") == data

    def test_raises_without_matching_prefix(self):
        with pytest.raises(ValueError):
            _decode_domains(["00ABCD.hatt.example.com"], "hpke")


class TestMatchesHostname:
    def test_exact_match(self):
        assert _matches_hostname("inference.tinfoil.sh", ["inference.tinfoil.sh"]) is True

    def test_case_insensitive(self):
        assert _matches_hostname("Inference.Tinfoil.SH", ["inference.tinfoil.sh"]) is True

    def test_wildcard_single_label(self):
        assert _matches_hostname("foo.tinfoil.sh", ["*.tinfoil.sh"]) is True

    def test_wildcard_does_not_span_labels(self):
        assert _matches_hostname("foo.bar.tinfoil.sh", ["*.tinfoil.sh"]) is False

    def test_no_match(self):
        assert _matches_hostname("evil.com", ["inference.tinfoil.sh"]) is False


class TestFetchBundleParsing:
    def test_parses_bundle_fields(self):
        payload = {
            "domain": "inference.tinfoil.sh",
            "enclaveAttestationReport": {
                "format": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
                "body": "Zm9v",
            },
            "digest": "abc123",
            "sigstoreBundle": {"mediaType": "application/vnd.dev.sigstore.bundle+json"},
            "vcek": "AAECAw==",
            "enclaveCert": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        }
        response = MagicMock()
        response.json.return_value = payload
        response.raise_for_status.return_value = None

        with patch("tinfoil.attestation.bundle.requests.get", return_value=response) as mock_get:
            bundle = fetch_bundle_from("https://atc.tinfoil.sh/")

        mock_get.assert_called_once()
        assert mock_get.call_args.args[0] == "https://atc.tinfoil.sh/attestation"
        assert isinstance(bundle, Bundle)
        assert bundle.domain == "inference.tinfoil.sh"
        assert bundle.digest == "abc123"
        assert bundle.vcek == "AAECAw=="
        assert bundle.enclave_attestation_report.body == "Zm9v"
        # The Sigstore bundle is re-serialized to bytes for downstream verification.
        assert json.loads(bundle.sigstore_bundle) == payload["sigstoreBundle"]

    def test_rejects_malformed_bundle(self):
        response = MagicMock()
        response.json.return_value = {"domain": "x"}  # missing required fields
        response.raise_for_status.return_value = None
        with patch("tinfoil.attestation.bundle.requests.get", return_value=response):
            with pytest.raises(ValueError, match="Invalid attestation bundle"):
                fetch_bundle_from("https://atc.tinfoil.sh")


def _require_api_key() -> str:
    api_key = os.getenv("TINFOIL_API_KEY")
    if not api_key:
        pytest.fail("TINFOIL_API_KEY must be set to run the integration tests")
    return api_key


ATTESTATION_BUNDLE_URL = "https://atc.tinfoil.sh"


@pytest.mark.integration
class TestAttestationBundleIntegration:
    """Exercises the attestation-through-proxy path against the live ATC bundle
    endpoint: the bundle is fetched and verified entirely client-side and the
    enclave host is taken from the verified bundle."""

    def test_verify_from_bundle_directly(self):
        sc = SecureClient(repo="tinfoilsh/confidential-model-router", attestation_bundle_url=ATTESTATION_BUNDLE_URL)
        ground_truth = sc.verify()
        assert sc.enclave, "enclave host should come from the verified bundle"
        assert ground_truth.hpke_public_key
        doc = sc.get_verification_document()
        assert doc is not None and doc.security_verified
        assert doc.enclave_host == sc.enclave

    def test_bundle_chat_completion(self):
        api_key = _require_api_key()
        client = TinfoilAI(api_key=api_key, attestation_bundle_url=ATTESTATION_BUNDLE_URL)
        assert client.enclave, "enclave host should come from the verified bundle"
        response = client.chat.completions.create(
            model="llama3-3-70b",
            messages=[
                {"role": "system", "content": "No matter what the user says, only respond with: Done."},
                {"role": "user", "content": "Is this a test?"},
            ],
        )
        assert response.choices[0].message.content

    @pytest.mark.asyncio
    async def test_async_bundle_chat_completion(self):
        api_key = _require_api_key()
        client = AsyncTinfoilAI(api_key=api_key, attestation_bundle_url=ATTESTATION_BUNDLE_URL)
        assert client.enclave, "enclave host should come from the verified bundle"
        response = await client.chat.completions.create(
            model="llama3-3-70b",
            messages=[
                {"role": "system", "content": "No matter what the user says, only respond with: Done."},
                {"role": "user", "content": "Is this a test?"},
            ],
        )
        assert response.choices[0].message.content
