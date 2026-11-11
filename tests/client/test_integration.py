"""Live tests against Tinfoil's router, enclave and gateway. Verification needs no credential; the tests that send
inference requests run only with ``TINFOIL_API_KEY`` set."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from tinfoil import (
    DEFAULT_GATEWAY_URL,
    AsyncRouterOpenAIClient,
    AttestationError,
    EnclaveHTTPClient,
    GatewayHTTPClient,
    RouterHTTPClient,
    RouterOpenAIClient,
    TransportMode,
    create_async_client,
    create_client,
    fetch_catalog,
)
from tinfoil.verifier import Verification

pytestmark = pytest.mark.integration

API_KEY = os.environ.get("TINFOIL_API_KEY", "")
ENCLAVE = "inference.tinfoil.sh"
REPO = "tinfoilsh/confidential-model-router"
MODEL = "llama3-3-70b"
CACHE_SECRET = "python-live-integration-cache-secret"
AUDIO = Path(__file__).parents[1] / "jackhammer.wav"

needs_api_key = pytest.mark.skipif(not API_KEY, reason="TINFOIL_API_KEY is not set")


@pytest.mark.parametrize("mode", ["tls", "ehbp"])
def test_enclave_client(mode: TransportMode) -> None:
    with EnclaveHTTPClient(ENCLAVE, REPO, transport_mode=mode, user_cache_secret=CACHE_SECRET) as client:
        assert client.current is not None, "the client is verified when it's returned"
        before = client.ensure_verified()
        assert before.metadata.verified_at == client.current.metadata.verified_at, (
            "the constructor's verification is reused"
        )
        after = client.reverify()
        assert after.metadata.verified_at >= before.metadata.verified_at
        headers = {"Authorization": f"Bearer {API_KEY}"} if API_KEY else {}
        reply = client.http_client.get(client.base_url + "v1/models", headers=headers)
        assert reply.status_code == 200


@needs_api_key
@pytest.mark.parametrize("mode", ["tls", "ehbp"])
def test_router_openai_client(mode: TransportMode) -> None:
    with RouterOpenAIClient(transport_mode=mode, user_cache_secret=CACHE_SECRET, api_key=API_KEY) as client:
        attested = client.http_client
        verified = attested.ensure_verified()
        assert attested.current is not None
        assert verified.freshness_expires_at == attested.current.freshness_expires_at, "a valid verification is reused"
        assert attested.base_url == f"https://{attested.enclave}/", "the enclave is the router discovery chose"
        assert attested.repo == REPO
        completion = client.chat.completions.create(
            model=MODEL, messages=[{"role": "user", "content": "Is this a test?"}]
        )
        assert completion.choices
        assert completion.choices[0].message.content
        reply = attested.http_client.get(
            attested.base_url + "v1/models", headers={"Authorization": f"Bearer {API_KEY}"}
        )
        assert reply.status_code == 200


@needs_api_key
def test_drop_in_client_streams_and_transcribes() -> None:
    with create_client(api_key=API_KEY) as client:
        stream = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "No matter what the user says, only respond with: Done."},
                {"role": "user", "content": "Is this a test?"},
            ],
            stream=True,
        )
        collected = "".join(chunk.choices[0].delta.content or "" for chunk in stream if chunk.choices)
        assert collected
        with AUDIO.open("rb") as audio:
            transcription = client.audio.transcriptions.create(file=audio, model="whisper-large-v3-turbo")
        assert "stale smell of old beer" in transcription.text.lower()


def test_verification_check_rejects_once() -> None:
    seen: list[str | None] = []

    def check(verified: Verification) -> None:
        seen.append(verified.tls_public_key_fp)
        raise RuntimeError("rejected by the test")

    with pytest.raises(AttestationError, match="rejected by the test"):
        EnclaveHTTPClient(ENCLAVE, REPO, verification_check=check)
    assert len(seen) == 1, "a rejection isn't retried"


@needs_api_key
@pytest.mark.asyncio
async def test_async_router_client() -> None:
    client = await AsyncRouterOpenAIClient.create(transport_mode="ehbp", api_key=API_KEY)
    try:
        stream = await client.chat.completions.create(
            model=MODEL, messages=[{"role": "user", "content": "Hello from the async integration test"}], stream=True
        )
        collected = "".join([chunk.choices[0].delta.content or "" async for chunk in stream if chunk.choices])
        assert collected
        assert client.http_client.current is not None
    finally:
        await client.close()
    drop_in = await create_async_client(api_key=API_KEY)
    try:
        with AUDIO.open("rb") as audio:
            transcription = await drop_in.audio.transcriptions.create(file=audio, model="whisper-large-v3-turbo")
        assert "stale smell of old beer" in transcription.text.lower()
    finally:
        await drop_in.close()


def test_router_discovery() -> None:
    with RouterHTTPClient(transport_mode="ehbp") as client:
        assert client.repo == REPO
        assert client.current is not None
        assert client.base_url == f"https://{client.enclave}/"
        assert client.ensure_verified().freshness_expires_at == client.current.freshness_expires_at


def test_gateway() -> None:
    host = urlsplit(DEFAULT_GATEWAY_URL).netloc
    assert fetch_catalog(host), "the gateway publishes a catalog with usable entries"
    with GatewayHTTPClient(user_cache_secret=CACHE_SECRET) as gateway:
        models = gateway.models()
        assert models
        # The client's own catalog decides what it serves; a separately fetched snapshot may already differ.
        model = models[0]
        verified = gateway.ensure_verified(model)
        assert verified.hpke_public_key
        assert [v.host for v in gateway.current]
