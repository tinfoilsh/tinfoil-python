"""Fixtures for the client tests: synthetic verifications, fake enclaves, a loopback TLS server whose certificate
can be swapped, a fake EHBP server and recording transports."""

from __future__ import annotations

import http.server
import os
import socket
import ssl
import struct
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.x509.oid import ExtendedKeyUsageOID
from ehbp.derive import derive_response_keys, encrypt_chunk, frame_chunk
from ehbp.protocol import (
    ENCAPSULATED_KEY_HEADER,
    EXPORT_LABEL,
    EXPORT_LENGTH,
    HPKE_REQUEST_INFO,
    RESPONSE_NONCE_HEADER,
)
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from tests import pki
from tinfoil._enclave import Enclave
from tinfoil.verifier import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    REGISTER_SIZE,
    SEVSNP,
    CryptoMaterialItem,
    ExpectedSEVSNP,
    SoftwareIdentity,
    Verification,
    VerificationMetadata,
    cert_pubkey_fp,
)

HOST = "enclave.example"
HPKE_KEY = "01" * 32
Handler = Callable[[httpx.Request], httpx.Response]


def in_an_hour() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


def verification(
    key: str = "key",
    *,
    deadline: datetime | str | None = "default",
    tls: str | None = None,
    hpke: str | None = HPKE_KEY,
    tag: str | None = None,
) -> Verification:
    """A verification endorsing a TLS fingerprint and an HPKE key. ``key`` is the TLS fingerprint and the code
    tag unless ``tls`` or ``tag`` overrides it; ``deadline`` defaults to an hour from now, and None leaves the
    verification without a deadline."""
    items: list[CryptoMaterialItem] = []
    fingerprint = key if tls is None else tls
    if fingerprint:
        items.append(CryptoMaterialItem(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT, fingerprint))
    if hpke:
        items.append(CryptoMaterialItem(CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT, hpke))
    expires = in_an_hour() if deadline == "default" else deadline
    assert expires is None or isinstance(expires, datetime)
    register = bytes(REGISTER_SIZE)
    return Verification(
        code_digest="d" * 64,
        code_tag=key if tag is None else tag,
        config_repo="org/repo",
        code_measurement=ExpectedSEVSNP(launch=register),
        enclave_measurement=SEVSNP(launch=register),
        crypto_material=tuple(items),
        freshness_expires_at=expires,
        metadata=VerificationMetadata(SoftwareIdentity("test", "0"), datetime.now(UTC)),
    )


def fake_enclave(
    fetch: Callable[[], Verification],
    *,
    host: str = HOST,
    repo: str = "org/repo",
    check: Callable[[Verification], None] | None = None,
) -> Enclave:
    """An enclave that verifies by calling ``fetch`` instead of fetching and verifying a document."""

    async def fetch_async() -> Verification:
        return fetch()

    return Enclave(host, repo, verification_check=check, _fetch=fetch, _fetch_async=fetch_async)


def response(status: int = 200, content: bytes = b"", headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, content=content, headers=headers)


class Recorder:
    """A transport that records every request and answers with ``handler``."""

    def __init__(self, handler: Handler | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []
        self.handler = handler or (lambda _: response(200, b"ok"))
        self.transport = httpx.MockTransport(self.handle)
        self.async_transport = httpx.MockTransport(self.ahandle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.bodies.append(request.read())
        return self.handler(request)

    async def ahandle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.bodies.append(await request.aread())
        return self.handler(request)


class _TLSHTTPServer(http.server.ThreadingHTTPServer):
    """A threading HTTP server that wraps each accepted connection in the TLS context it holds at that moment."""

    context: ssl.SSLContext


@dataclass
class TLSServer:
    """A loopback HTTPS server. ``context`` is the server's own, used for each new connection, so a test that
    assigns it swaps the certificate the server presents. ``requests`` counts the requests its handler served."""

    server: _TLSHTTPServer
    thread: threading.Thread
    fingerprint: str
    requests: list[str]
    connections: list[int]

    @property
    def context(self) -> ssl.SSLContext:
        return self.server.context

    @context.setter
    def context(self, context: ssl.SSLContext) -> None:
        self.server.context = context

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def make_ca() -> pki.Issued:
    """A self-signed CA that OpenSSL accepts as a trust anchor: it carries a subject key identifier."""
    key = pki.p256()
    return pki.certificate(
        "test ca",
        key,
        ca=True,
        key_usage=pki.CA_USAGE,
        serial=1,
        extra=[(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)],
    )


def server_certificate(ca: pki.Issued) -> pki.Issued:
    """A leaf for 127.0.0.1 issued by ``ca``."""
    key = pki.p256()
    return pki.certificate(
        "127.0.0.1",
        key,
        ca,
        key_usage=pki.SIGNING_USAGE,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        sans=[x509.IPAddress(IPv4Address("127.0.0.1"))],
        extra=[
            (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), False),
        ],
        not_before=datetime.now(UTC) - timedelta(hours=1),
        not_after=datetime.now(UTC) + timedelta(hours=1),
        serial=int.from_bytes(os.urandom(8), "big"),
    )


def server_context(leaf: pki.Issued, tmp_path: Path) -> ssl.SSLContext:
    cert_path = tmp_path / f"{leaf.der[:8].hex()}-cert.pem"
    key_path = tmp_path / f"{leaf.der[:8].hex()}-key.pem"
    cert_path.write_bytes(x509.load_der_x509_certificate(leaf.der).public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


def start_tls_server(leaf: pki.Issued, tmp_path: Path, *, body: bytes = b"ok", status: int = 200) -> TLSServer:
    requests: list[str] = []
    connections: list[int] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self._answer()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self._answer()

        def _answer(self) -> None:
            requests.append(self.path)
            self.send_response(status)
            if status in (204, 304):
                self.end_headers()
                return
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    class Server(_TLSHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

        def get_request(self) -> tuple[socket.socket, Any]:
            sock, address = super().get_request()
            connections.append(1)
            return self.context.wrap_socket(sock, server_side=True), address

        def handle_error(self, request: Any, client_address: Any) -> None:
            # A connection the client closes after a failed pin check is expected.
            pass

    server = Server(("127.0.0.1", 0), Handler)
    server.context = server_context(leaf, tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return TLSServer(server, thread, cert_pubkey_fp(leaf.der), requests, connections)


def trust(ca: pki.Issued, tmp_path: Path) -> str:
    """Writes ``ca`` as a PEM bundle and returns its path, for ``SSL_CERT_FILE``."""
    path = tmp_path / "ca.pem"
    path.write_bytes(x509.load_der_x509_certificate(ca.der).public_bytes(serialization.Encoding.PEM))
    return str(path)


class EHBPServer:
    """A fake enclave speaking EHBP behind an ``httpx.MockTransport``: it opens sealed request bodies and seals
    its responses, so a client's whole path through the sealing transport can be exercised in memory."""

    def __init__(self) -> None:
        self.private_key = x25519.X25519PrivateKey.generate()
        raw = self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key_hex = raw.hex()
        self.suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
        self.requests: list[httpx.Request] = []
        self.plaintexts: list[bytes] = []
        self.reply: Callable[[httpx.Request, bytes], tuple[int, bytes]] = lambda _, body: (200, b"echo:" + body)
        self.rotated = False
        self.corrupt_chunk: int | None = None
        """The index of the sealed response chunk whose ciphertext is damaged before it is sent, if any."""

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        enc_hex = request.headers.get(ENCAPSULATED_KEY_HEADER)
        if enc_hex is None:
            self.plaintexts.append(request.read())
            status, body = self.reply(request, request.read())
            return httpx.Response(status, content=body)
        if self.rotated:
            return httpx.Response(
                422,
                headers={"Content-Type": "application/problem+json"},
                content=b'{"type":"urn:ietf:params:ehbp:error:key-config","title":"rotated"}',
            )
        enc = bytes.fromhex(enc_hex)
        recipient = self.suite.create_recipient_context(
            enc, KEMKey.from_pyca_cryptography_key(self.private_key), info=HPKE_REQUEST_INFO
        )
        plaintext = b"".join(recipient.open(frame, b"") for frame in _frames(request.read()))
        self.plaintexts.append(plaintext)
        exported = recipient.export(EXPORT_LABEL, EXPORT_LENGTH)
        status, body = self.reply(request, plaintext)
        nonce = os.urandom(32)
        material = derive_response_keys(exported, enc, nonce)
        chunks = [body[i : i + 7] for i in range(0, len(body), 7)] or [b""]
        frames = [encrypt_chunk(material, seq, chunk) for seq, chunk in enumerate(chunks)]
        if self.corrupt_chunk is not None:
            damaged = bytearray(frames[self.corrupt_chunk])
            damaged[-1] ^= 0xFF
            frames[self.corrupt_chunk] = bytes(damaged)
        # One frame per response chunk, so a client that streams reaches a damaged chunk only after the others.
        return httpx.Response(
            status, headers={RESPONSE_NONCE_HEADER: nonce.hex()}, stream=_Chunked([frame_chunk(f) for f in frames])
        )

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)


class _Chunked(httpx.SyncByteStream, httpx.AsyncByteStream):
    """A response body delivered one frame at a time, for synchronous and asynchronous clients alike."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


def _frames(body: bytes) -> Iterator[bytes]:
    offset = 0
    while offset < len(body):
        (length,) = struct.unpack(">I", body[offset : offset + 4])
        offset += 4
        yield body[offset : offset + length]
        offset += length
