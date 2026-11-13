"""The pinned TLS transport against a loopback listener: the pin passes, a mismatch, an untrusted chain and a
hostname mismatch are reported as the peer lacking the key before any request is served, connections pool, and
plaintext is refused."""

from __future__ import annotations

import ssl
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from tests import pki
from tests.client.helpers import TLSServer, make_ca, server_certificate, start_tls_server, trust
from tinfoil._errors import AttestationError, ConfigurationError
from tinfoil._keys import PeerLacksKeyError
from tinfoil._tls import (
    CERT_MISMATCH,
    NO_TLS,
    AsyncPinnedTransport,
    PinMismatchError,
    PinnedTransport,
    is_certificate_error,
)


@pytest.fixture
def ca() -> pki.Issued:
    return make_ca()


@pytest.fixture
def server(ca: pki.Issued, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TLSServer]:
    monkeypatch.setenv("SSL_CERT_FILE", trust(ca, tmp_path))
    listener = start_tls_server(server_certificate(ca), tmp_path, status=204)
    yield listener
    listener.close()


def test_pinned_requests_reach_the_server_and_pool(server: TLSServer) -> None:
    with httpx.Client(transport=PinnedTransport(server.fingerprint)) as client:
        for path in ("/a", "/b"):
            assert client.get(server.url + path).status_code == 204
    assert server.requests == ["/a", "/b"]
    assert len(server.connections) == 1, "the pin check lives on the connection, so the pool reuses it"


def test_pin_mismatch_is_refused_before_the_request(server: TLSServer) -> None:
    with httpx.Client(transport=PinnedTransport("ab" * 32)) as client, pytest.raises(PeerLacksKeyError) as err:
        client.get(server.url + "/secret")
    cause = err.value.__cause__
    assert isinstance(cause, AttestationError)
    assert cause.message == CERT_MISMATCH
    assert isinstance(cause.__cause__, PinMismatchError)
    assert is_certificate_error(err.value)
    assert server.requests == [], "the request must not reach the server after a pin mismatch"


def test_untrusted_certificate_is_refused_with_the_pin_matching(
    server: TLSServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE")
    with httpx.Client(transport=PinnedTransport(server.fingerprint)) as client, pytest.raises(PeerLacksKeyError) as err:
        client.get(server.url + "/secret")
    assert "CERTIFICATE_VERIFY_FAILED" in str(err.value)
    assert isinstance(err.value.__cause__, AttestationError)
    assert server.requests == []


def test_hostname_mismatch_is_refused(server: TLSServer) -> None:
    with httpx.Client(transport=PinnedTransport(server.fingerprint)) as client, pytest.raises(PeerLacksKeyError):
        # The certificate names 127.0.0.1, not localhost.
        client.get(f"https://localhost:{server.port}/secret")
    assert server.requests == []


def test_plaintext_is_refused_before_connecting(server: TLSServer) -> None:
    with (
        httpx.Client(transport=PinnedTransport(server.fingerprint)) as client,
        pytest.raises(ConfigurationError, match=NO_TLS),
    ):
        client.get(f"http://127.0.0.1:{server.port}/secret")
    assert server.connections == []


def test_network_errors_are_not_certificate_errors(server: TLSServer) -> None:
    server.close()
    with (
        httpx.Client(transport=PinnedTransport(server.fingerprint)) as client,
        pytest.raises(httpx.ConnectError) as err,
    ):
        client.get(server.url + "/gone")
    assert not is_certificate_error(err.value)


@pytest.mark.asyncio
async def test_async_pinned_transport(server: TLSServer) -> None:
    async with httpx.AsyncClient(transport=AsyncPinnedTransport(server.fingerprint)) as client:
        assert (await client.get(server.url + "/a")).status_code == 204
        assert (await client.get(server.url + "/b")).status_code == 204
    assert len(server.connections) == 1
    async with httpx.AsyncClient(transport=AsyncPinnedTransport("ab" * 32)) as client:
        with pytest.raises(PeerLacksKeyError) as err:
            await client.get(server.url + "/secret")
        assert isinstance(err.value.__cause__.__cause__, PinMismatchError)  # type: ignore[union-attr]
        with pytest.raises(ConfigurationError, match=NO_TLS):
            await client.get(f"http://127.0.0.1:{server.port}/x")
    assert server.requests == ["/a", "/b"]


class TestIsCertificateError:
    def test_detects_pin_mismatch(self) -> None:
        assert is_certificate_error(PinMismatchError(CERT_MISMATCH))

    def test_detects_ssl_cert_verification_error(self) -> None:
        assert is_certificate_error(ssl.SSLCertVerificationError("bad cert"))

    def test_detects_certificate_verify_failed_ssl_error(self) -> None:
        assert is_certificate_error(ssl.SSLError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"))

    def test_detects_through_cause_and_context_chains(self) -> None:
        inner = ssl.SSLCertVerificationError("bad cert")
        outer = httpx.ConnectError("connect failed")
        outer.__cause__ = inner
        assert is_certificate_error(outer)
        contextual = RuntimeError("wrapped")
        contextual.__context__ = PinMismatchError(CERT_MISMATCH)
        assert is_certificate_error(contextual)

    @pytest.mark.parametrize(
        "err",
        [
            ValueError("certificate verify failed"),
            ssl.SSLError(1, "unexpected eof while reading"),
            ssl.SSLWantReadError(),
            ConnectionResetError(),
            httpx.ReadTimeout("slow"),
        ],
    )
    def test_ignores_other_errors(self, err: BaseException) -> None:
        assert not is_certificate_error(err)

    def test_ends_a_cycle(self) -> None:
        looped = ssl.SSLError(1, "handshake")
        looped.__context__ = looped
        assert not is_certificate_error(looped)
