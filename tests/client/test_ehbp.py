"""The sealing transport against a fake EHBP server: bodies are sealed and responses opened chunk by chunk,
bodyless requests pass through, a key configuration mismatch is the peer lacking the key, and other protocol
failures are attestation errors, whether detected before the body is handed over or while it is read."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from ehbp import EHBPError
from ehbp.protocol import ENCAPSULATED_KEY_HEADER

from tests.client.helpers import EHBPServer
from tinfoil._ehbp import (
    EHBP_TUNNEL,
    AsyncSealingTransport,
    SealingTransport,
    check_ehbp,
    server_identity,
)
from tinfoil._errors import AttestationError, ConfigurationError
from tinfoil._keys import PeerLacksKeyError


@pytest.fixture
def server() -> EHBPServer:
    return EHBPServer()


def sealing(server: EHBPServer) -> SealingTransport:
    return SealingTransport(server_identity(server.public_key_hex), inner=server.transport)


def test_bodies_are_sealed_and_responses_opened(server: EHBPServer) -> None:
    body = b'{"model":"m","messages":[]}' * 5000  # several request frames
    with httpx.Client(transport=sealing(server)) as client:
        response = client.post("https://enclave.example/v1/chat/completions", content=body)
    assert response.status_code == 200
    assert response.content == b"echo:" + body
    sent = server.requests[-1]
    assert ENCAPSULATED_KEY_HEADER in sent.headers
    assert sent.read() != body, "the wire carries ciphertext"
    assert server.plaintexts[-1] == body


def test_streaming_responses_are_opened_as_they_arrive(server: EHBPServer) -> None:
    server.reply = lambda _, body: (200, b"data: one\n\ndata: two\n\n")
    with (
        httpx.Client(transport=sealing(server)) as client,
        client.stream("POST", "https://enclave.example/v1", content=b"x") as response,
    ):
        chunks = list(response.iter_raw())
    assert b"".join(chunks) == b"data: one\n\ndata: two\n\n"
    assert len(chunks) > 1


def test_bodyless_requests_pass_through_unsealed(server: EHBPServer) -> None:
    with httpx.Client(transport=sealing(server)) as client:
        response = client.get("https://enclave.example/v1/models")
    assert response.status_code == 200
    assert ENCAPSULATED_KEY_HEADER not in server.requests[-1].headers


def test_key_config_mismatch_is_the_peer_lacking_the_key(server: EHBPServer) -> None:
    server.rotated = True
    with httpx.Client(transport=sealing(server)) as client, pytest.raises(PeerLacksKeyError) as err:
        client.post("https://enclave.example/v1", content=b"x")
    assert "KEY_CONFIG_MISMATCH" in str(err.value)


def test_plaintext_error_responses_pass_through(server: EHBPServer) -> None:
    """An intermediary may reject a request before it reaches the enclave."""
    inner = httpx.MockTransport(lambda _: httpx.Response(429, content=b"slow down"))
    transport = SealingTransport(server_identity(server.public_key_hex), inner=inner)
    with httpx.Client(transport=transport) as client:
        response = client.post("https://enclave.example/v1", content=b"x")
    assert response.status_code == 429
    assert response.content == b"slow down"


def test_success_without_a_nonce_fails_closed(server: EHBPServer) -> None:
    inner = httpx.MockTransport(lambda _: httpx.Response(200, content=b"plaintext"))
    transport = SealingTransport(server_identity(server.public_key_hex), inner=inner)
    with httpx.Client(transport=transport) as client, pytest.raises(AttestationError, match="MISSING_RESPONSE_NONCE"):
        client.post("https://enclave.example/v1", content=b"x")


def test_a_chunk_that_does_not_open_fails_the_read_as_an_attestation_error(server: EHBPServer) -> None:
    """The first chunks of a streamed response are delivered; the damaged one is reported from the read that
    reaches it, as the client's error with the protocol's as its cause, not as the protocol's own."""
    body = b"data: one\n\ndata: two\n\ndata: three\n\n"
    server.reply = lambda _, __: (200, body)
    server.corrupt_chunk = 3
    delivered: list[bytes] = []
    with (
        httpx.Client(transport=sealing(server)) as client,
        client.stream("POST", "https://enclave.example/v1", content=b"x") as response,
    ):
        assert response.status_code == 200
        with pytest.raises(AttestationError) as err:
            delivered.extend(response.iter_raw())
    assert isinstance(err.value.__cause__, EHBPError)
    assert not isinstance(err.value, EHBPError)
    assert len(delivered) == 3, "the chunks before the damaged one are opened and delivered"
    assert b"".join(delivered) == body[: 7 * 3]


@pytest.mark.asyncio
async def test_async_chunk_that_does_not_open_fails_the_read_as_an_attestation_error(server: EHBPServer) -> None:
    server.reply = lambda _, body: (200, b"data: one\n\ndata: two\n\n")
    server.corrupt_chunk = 2
    transport = AsyncSealingTransport(server_identity(server.public_key_hex), inner=server.transport)
    delivered: list[bytes] = []
    async with (
        httpx.AsyncClient(transport=transport) as client,
        client.stream("POST", "https://enclave.example/v1", content=b"x") as response,
    ):
        with pytest.raises(AttestationError) as err:
            await collect(response.aiter_raw(), delivered)
    assert isinstance(err.value.__cause__, EHBPError)
    assert len(delivered) == 2


async def collect(chunks: AsyncIterator[bytes], into: list[bytes]) -> None:
    async for chunk in chunks:
        into.append(chunk)


def test_server_identity_rejects_a_malformed_key() -> None:
    with pytest.raises(AttestationError, match="HPKE public key"):
        server_identity("zz")


def test_check_ehbp_refuses_upgrades_and_tunnels() -> None:
    upgrade = httpx.Request("GET", "https://enclave.example/v1/realtime", headers={"Upgrade": "websocket"})
    with pytest.raises(ConfigurationError, match=EHBP_TUNNEL):
        check_ehbp(upgrade)
    with pytest.raises(ConfigurationError, match="CONNECT"):
        check_ehbp(httpx.Request("CONNECT", "https://enclave.example/"))
    check_ehbp(httpx.Request("GET", "https://enclave.example/v1/models"))
    check_ehbp(httpx.Request("POST", "https://enclave.example/v1/chat/completions", content=b"{}"))


@pytest.mark.asyncio
async def test_async_sealing_transport(server: EHBPServer) -> None:
    transport = AsyncSealingTransport(server_identity(server.public_key_hex), inner=server.transport)
    body = b'{"a":1}' * 3000
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("https://enclave.example/v1", content=body)
        assert response.content == b"echo:" + body
        assert (await client.get("https://enclave.example/v1/models")).status_code == 200
        server.rotated = True
        with pytest.raises(PeerLacksKeyError):
            await client.post("https://enclave.example/v1", content=b"x")
