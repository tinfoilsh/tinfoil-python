"""The adapter's integration lane without a network: the document fetch and the TLS dial against local fakes, and
``live-verify``, ``capture`` and the full-verify stage's routing against a verifier double.

The real enclave run is the gate for the lane; these tests pin the wiring
around it: which verifier is used, what is fetched, how each failure maps
to an exit code, and the shape of the frozen fixture.
"""

from __future__ import annotations

import io
import json
import socket
import ssl
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization

import tinfoil_conformance as adapter
from tests.v3 import pki
from tinfoil._v3.verifier import (
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    SEVSNP,
    CryptoMaterialItem,
    ExpectedSEVSNP,
    SoftwareIdentity,
    UsageError,
    Verification,
    VerificationError,
    VerificationMetadata,
    cert_pubkey_fp,
)

HOST = "enclave.example"
REPO = "org/repo"
NONCE = bytes(range(32))
LAUNCH = bytes([0x5A]) * 48
TLS_FP = "ab" * 32
HPKE_KEY = "cd" * 32
DOCUMENT = b'{"document": "bytes"}'
REQUEST = {"host": HOST, "repo": REPO}


def verification(*items: CryptoMaterialItem) -> Verification:
    """A record such as the verifier would build, endorsing ``items``."""
    return Verification(
        code_digest="11" * 32,
        code_tag="v1.0.0",
        config_repo=REPO,
        code_measurement=ExpectedSEVSNP(launch=LAUNCH),
        enclave_measurement=SEVSNP(launch=LAUNCH),
        crypto_material=items,
        metadata=VerificationMetadata(
            verifier=SoftwareIdentity(name="tinfoil-python", version="0"), verified_at=datetime.now(UTC)
        ),
    )


ENDORSED = verification(
    CryptoMaterialItem(id="tls", format=KEY_SPKI_FP_SHA256_V1_FORMAT, data=TLS_FP),
    CryptoMaterialItem(id="hpke", format=KEY_X25519_HPKE_V1_FORMAT, data=HPKE_KEY),
)
FACTS = {
    "code_digest": "11" * 32,
    "code_measurement": {"type": adapter.SEV_SNP_MEASUREMENT_TYPE, "registers": [LAUNCH.hex()]},
    "enclave_measurement": {"type": adapter.SEV_SNP_MEASUREMENT_TYPE, "registers": [LAUNCH.hex()]},
    "tls_public_key_fp": TLS_FP,
    "hpke_public_key": HPKE_KEY,
}


class VerifierDouble:
    """Stands in for the public verifier: records every call and answers with a fixed outcome."""

    calls: list[tuple[bytes, bytes, str, datetime | None]]
    outcome: Verification | Exception

    def verify_v3(self, doc: bytes, nonce: bytes, repo: str) -> Verification:
        type(self).calls.append((doc, nonce, repo, None))
        return self._answer()

    def verify_v3_at(self, doc: bytes, nonce: bytes, repo: str, verification_time: datetime) -> Verification:
        type(self).calls.append((doc, nonce, repo, verification_time))
        return self._answer()

    def _answer(self) -> Verification:
        outcome = type(self).outcome
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture
def double(monkeypatch: pytest.MonkeyPatch) -> type[VerifierDouble]:
    """The adapter's public verifier replaced by the double, accepting with the endorsed keys by default."""
    VerifierDouble.calls = []
    VerifierDouble.outcome = ENDORSED
    monkeypatch.setattr(adapter, "Verifier", VerifierDouble)
    return VerifierDouble


@pytest.fixture
def fetched(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, bytes]]:
    """The document fetch replaced by one that records the host and nonce and serves DOCUMENT."""
    fetches: list[tuple[str, bytes]] = []

    def fake_fetch(host: str, nonce: bytes, *, transport: httpx.BaseTransport | None = None) -> bytes:
        fetches.append((host, nonce))
        return DOCUMENT

    monkeypatch.setattr(adapter, "_fetch_document", fake_fetch)
    return fetches


@pytest.fixture
def dialed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The channel-binding dial replaced by one that records the host and reports the endorsed fingerprint."""
    dials: list[str] = []

    def fake_dial(host: str) -> str:
        dials.append(host)
        return TLS_FP

    monkeypatch.setattr(adapter, "_live_tls_fingerprint", fake_dial)
    return dials


# --- live-verify ------------------------------------------------------------------------------------------------


def test_live_verify_accepts_through_the_public_verifier(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]], dialed: list[str]
) -> None:
    result = adapter.run(adapter.STAGE_LIVE_VERIFY, REQUEST)
    assert result.exit_code == adapter.EXIT_ACCEPTED, result
    assert result.output == {
        "stage": adapter.STAGE_LIVE_VERIFY,
        "accepted": True,
        "outputs": {**FACTS, "channel_binding": adapter.CHANNEL_BINDING},
    }
    # One fetch with a fresh 32-byte nonce, verified at the current time with that nonce, then one dial.
    assert len(fetched) == 1
    host, nonce = fetched[0]
    assert host == HOST
    assert len(nonce) == 32
    assert double.calls == [(DOCUMENT, nonce, REPO, None)]
    assert dialed == [HOST]


def test_live_verify_uses_a_fresh_nonce_per_run(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]], dialed: list[str]
) -> None:
    adapter.run(adapter.STAGE_LIVE_VERIFY, REQUEST)
    adapter.run(adapter.STAGE_LIVE_VERIFY, REQUEST)
    assert fetched[0][1] != fetched[1][1]


@pytest.mark.parametrize(
    "raw",
    [
        [],
        "text",
        {},
        {"host": HOST},
        {"repo": REPO},
        {"host": "", "repo": REPO},
        {"host": HOST, "repo": ""},
        {"host": None, "repo": REPO},
        {"host": 1, "repo": REPO},
    ],
)
def test_live_verify_rejects_a_malformed_request_before_any_connection(
    raw: Any, double: type[VerifierDouble], fetched: list[tuple[str, bytes]], dialed: list[str]
) -> None:
    result = adapter.run(adapter.STAGE_LIVE_VERIFY, raw)
    assert result.exit_code == adapter.EXIT_MALFORMED
    assert result.output == {
        "stage": adapter.STAGE_LIVE_VERIFY,
        "accepted": False,
        "rejection": {"code": adapter.MALFORMED_INPUT},
    }
    assert fetched == []
    assert dialed == []
    assert double.calls == []


def test_live_verify_gives_no_verdict_when_the_fetch_fails(
    double: type[VerifierDouble], dialed: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_fetch(host: str, nonce: bytes, *, transport: httpx.BaseTransport | None = None) -> bytes:
        raise adapter.FetchError("HTTP GET: 503 Service Unavailable")

    monkeypatch.setattr(adapter, "_fetch_document", failing_fetch)
    result = adapter.run(adapter.STAGE_LIVE_VERIFY, REQUEST)
    assert result.exit_code == adapter.EXIT_INTERNAL
    assert result.output == {"stage": adapter.STAGE_LIVE_VERIFY, "accepted": False}
    assert "503" in result.diagnostic
    assert double.calls == []
    assert dialed == []


@pytest.mark.parametrize(
    ("outcome", "exit_code", "code"),
    [
        (VerificationError(LAYER_QUOTE, "bad signature"), adapter.EXIT_REJECTED, adapter.QUOTE_REJECTED),
        (VerificationError(LAYER_PROVENANCE, "stale"), adapter.EXIT_REJECTED, adapter.PROVENANCE_REJECTED),
        (UsageError("bad repo"), adapter.EXIT_MALFORMED, adapter.MALFORMED_INPUT),
        (verification(), adapter.EXIT_REJECTED, adapter.ENVELOPE_REJECTED),
        (
            verification(CryptoMaterialItem(id="tls", format=KEY_SPKI_FP_SHA256_V1_FORMAT, data=TLS_FP)),
            adapter.EXIT_REJECTED,
            adapter.ENVELOPE_REJECTED,
        ),
    ],
)
def test_live_verify_maps_the_verifier_outcome(
    outcome: Verification | Exception,
    exit_code: int,
    code: str,
    double: type[VerifierDouble],
    fetched: list[tuple[str, bytes]],
    dialed: list[str],
) -> None:
    double.outcome = outcome
    result = adapter.run(adapter.STAGE_LIVE_VERIFY, REQUEST)
    assert result.exit_code == exit_code, result
    assert result.output == {"stage": adapter.STAGE_LIVE_VERIFY, "accepted": False, "rejection": {"code": code}}
    assert dialed == [], "the channel is only bound after the document verified"


def test_live_verify_gives_no_verdict_for_an_unknown_layer(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]], dialed: list[str]
) -> None:
    double.outcome = VerificationError("future-layer", "unknown")
    result = adapter.run(adapter.STAGE_LIVE_VERIFY, REQUEST)
    assert result.exit_code == adapter.EXIT_INTERNAL
    assert result.output == {"stage": adapter.STAGE_LIVE_VERIFY, "accepted": False}


def test_live_verify_rejects_a_live_key_other_than_the_endorsed_one(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adapter, "_live_tls_fingerprint", lambda host: "ef" * 32)
    result = adapter.run(adapter.STAGE_LIVE_VERIFY, REQUEST)
    assert result.exit_code == adapter.EXIT_REJECTED
    assert result.output["rejection"] == {"code": adapter.POLICY_REJECTED}
    assert TLS_FP in result.diagnostic
    assert "ef" * 32 in result.diagnostic


def test_live_verify_gives_no_verdict_when_the_dial_fails(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_dial(host: str) -> str:
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(adapter, "_live_tls_fingerprint", failing_dial)
    result = adapter.run(adapter.STAGE_LIVE_VERIFY, REQUEST)
    assert result.exit_code == adapter.EXIT_INTERNAL
    assert result.output == {"stage": adapter.STAGE_LIVE_VERIFY, "accepted": False}


def test_main_writes_the_live_diagnostic_to_stderr(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]], dialed: list[str]
) -> None:
    double.outcome = VerificationError(LAYER_QUOTE, "bad signature")
    stdout, stderr = io.StringIO(), io.StringIO()
    code = adapter.main([adapter.STAGE_LIVE_VERIFY], io.BytesIO(json.dumps(REQUEST).encode()), stdout, stderr)
    assert code == adapter.EXIT_REJECTED
    assert json.loads(stdout.getvalue())["rejection"] == {"code": adapter.QUOTE_REJECTED}
    assert "bad signature" in stderr.getvalue()


# --- the full-verify stage's routing -----------------------------------------------------------------------------


def test_verify_stage_without_roots_uses_the_public_verifier(double: type[VerifierDouble]) -> None:
    raw = {
        "schema_version": "1",
        "document_b64": "e30=",
        "nonce_hex": NONCE.hex(),
        "repo": REPO,
        "verification_time_unix": 1_700_000_000,
    }
    result = adapter.run(adapter.STAGE_VERIFY, raw)
    assert result.exit_code == adapter.EXIT_ACCEPTED, result
    assert result.output["outputs"] == FACTS
    assert double.calls == [(b"{}", NONCE, REPO, datetime.fromtimestamp(1_700_000_000, UTC))]


def test_verify_stage_with_an_injected_root_bypasses_the_public_verifier(double: type[VerifierDouble]) -> None:
    from tests.conformance.test_adapter import _world_inputs

    _, base = _world_inputs()
    raw = {**base, "document_b64": "e30=", "nonce_hex": NONCE.hex(), "repo": REPO}
    result = adapter.run(adapter.STAGE_VERIFY, raw)
    assert result.exit_code == adapter.EXIT_REJECTED
    assert result.output["rejection"] == {"code": adapter.ENVELOPE_REJECTED}
    assert double.calls == [], "an injected root builds the verifier through the harness seam"


# --- capture ----------------------------------------------------------------------------------------------------


def _capture(args: list[str]) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = adapter.capture(args, stdout, stderr)
    return code, stdout.getvalue(), stderr.getvalue()


def test_capture_freezes_an_accepted_document_at_the_capture_time(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]], tmp_path: Path
) -> None:
    out = tmp_path / "fixture.json"
    before = int(datetime.now(UTC).timestamp())
    code, stdout, stderr = _capture(["--host", HOST, "--repo", REPO, "--nonce", NONCE.hex(), "--out", str(out)])
    assert code == adapter.EXIT_ACCEPTED, stderr
    assert stdout == ""
    assert str(out) in stderr
    fixture = json.loads(out.read_text())
    assert fixture["id"] == adapter.DEFAULT_CAPTURE_ID
    assert fixture["stage"] == adapter.STAGE_VERIFY
    assert fixture["expected"] == {"accepted": True}
    fixture_input = fixture["input"]
    assert set(fixture_input) == {"schema_version", "document_b64", "nonce_hex", "repo", "verification_time_unix"}
    assert fixture_input["schema_version"] == adapter.SCHEMA_VERSION
    assert fixture_input["repo"] == REPO
    assert fixture_input["nonce_hex"] == NONCE.hex()
    assert fetched == [(HOST, NONCE)]
    captured_at = fixture_input["verification_time_unix"]
    assert before <= captured_at <= int(datetime.now(UTC).timestamp())
    # The frozen input is exactly what was verified, pinned to the capture instant.
    decoded = adapter.Input.from_json(fixture_input)
    assert decoded.document == DOCUMENT
    assert double.calls == [(DOCUMENT, NONCE, REPO, datetime.fromtimestamp(captured_at, UTC))]
    # And it replays as an accept through the stage.
    assert adapter.run(adapter.STAGE_VERIFY, fixture_input).exit_code == adapter.EXIT_ACCEPTED


def test_capture_writes_to_stdout_by_default_with_a_fresh_nonce_and_the_given_id(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]]
) -> None:
    code, stdout, stderr = _capture(["--host=" + HOST, "--repo=" + REPO, "--id", "live-sev"])
    assert code == adapter.EXIT_ACCEPTED, stderr
    fixture = json.loads(stdout)
    assert fixture["id"] == "live-sev"
    assert bytes.fromhex(fixture["input"]["nonce_hex"]) == fetched[0][1]
    assert len(fetched[0][1]) == 32


def test_capture_refuses_to_freeze_a_rejected_document(
    double: type[VerifierDouble], fetched: list[tuple[str, bytes]], tmp_path: Path
) -> None:
    double.outcome = VerificationError(LAYER_PROVENANCE, "witness too old")
    out = tmp_path / "fixture.json"
    code, stdout, stderr = _capture(["--host", HOST, "--repo", REPO, "--out", str(out)])
    assert code == adapter.EXIT_REJECTED
    assert stdout == ""
    assert not out.exists()
    assert "refusing to freeze" in stderr
    assert adapter.PROVENANCE_REJECTED in stderr
    assert "witness too old" in stderr


def test_capture_gives_no_verdict_when_the_fetch_fails(
    double: type[VerifierDouble], monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_fetch(host: str, nonce: bytes, *, transport: httpx.BaseTransport | None = None) -> bytes:
        raise httpx.ConnectError("unreachable")

    monkeypatch.setattr(adapter, "_fetch_document", failing_fetch)
    code, stdout, stderr = _capture(["--host", HOST, "--repo", REPO])
    assert code == adapter.EXIT_INTERNAL
    assert stdout == ""
    assert "unreachable" in stderr
    assert double.calls == []


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--host", HOST],
        ["--repo", REPO],
        ["--host", HOST, "--repo"],
        ["--host", HOST, "--repo", REPO, "--bogus", "x"],
        ["--host", HOST, "--repo", REPO, "positional"],
        ["--host", HOST, "--repo", REPO, "--nonce", "zz"],
        ["--host", HOST, "--repo", REPO, "--nonce", "ab" * 31],
        ["--host", HOST, "--repo", REPO, "--nonce", "AB" * 32],
    ],
)
def test_capture_rejects_bad_flags_before_any_connection(
    args: list[str], double: type[VerifierDouble], fetched: list[tuple[str, bytes]]
) -> None:
    code, stdout, stderr = _capture(args)
    assert code == adapter.EXIT_MALFORMED
    assert stdout == ""
    assert stderr != ""
    assert fetched == []
    assert double.calls == []


# --- the document fetch ---------------------------------------------------------------------------------------------


def _serving(status: int, content: bytes, seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, content=content)

    return httpx.MockTransport(handler)


def test_fetch_document_requests_the_well_known_document_for_the_nonce() -> None:
    seen: list[httpx.Request] = []
    body = adapter._fetch_document("enclave.example:8443", NONCE, transport=_serving(200, DOCUMENT, seen))
    assert body == DOCUMENT
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "GET"
    assert str(request.url) == f"https://enclave.example:8443/.well-known/tinfoil-attestation?nonce={NONCE.hex()}"
    assert request.headers["Tinfoil-SDK"] == "tinfoil-python"
    assert request.headers["Tinfoil-SDK-Version"] != ""


@pytest.mark.parametrize("status", [301, 302, 307, 404, 500])
def test_fetch_document_rejects_a_status_outside_2xx_without_following(status: int) -> None:
    seen: list[httpx.Request] = []
    with pytest.raises(adapter.FetchError, match=str(status)):
        adapter._fetch_document(HOST, NONCE, transport=_serving(status, b"elsewhere", seen))
    assert len(seen) == 1


def test_fetch_document_bounds_the_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "MAX_DOCUMENT_BYTES", 16)
    assert adapter._fetch_document(HOST, NONCE, transport=_serving(200, b"x" * 16, [])) == b"x" * 16
    with pytest.raises(adapter.FetchError, match="exceeds 16 bytes"):
        adapter._fetch_document(HOST, NONCE, transport=_serving(200, b"x" * 17, []))


@pytest.mark.parametrize(
    "host",
    [
        "",
        "https://enclave.example",
        "enclave.example/path",
        "user@enclave.example",
        "enclave.example:port",
        "enclave.example?x=1",
        "enclave.example#f",
        ":443",
    ],
)
def test_fetch_document_rejects_anything_but_a_host(host: str) -> None:
    with pytest.raises(ValueError, match="host"):
        adapter._fetch_document(host, NONCE, transport=_serving(200, DOCUMENT, []))


def test_fetch_document_rejects_a_nonce_of_the_wrong_size() -> None:
    with pytest.raises(ValueError, match="nonce"):
        adapter._fetch_document(HOST, NONCE[1:], transport=_serving(200, DOCUMENT, []))


def test_authority_splits_host_and_port() -> None:
    assert adapter._authority("enclave.example") == ("enclave.example", 443)
    assert adapter._authority("enclave.example:8443") == ("enclave.example", 8443)
    assert adapter._authority("[::1]:8443") == ("::1", 8443)
    assert adapter._authority("127.0.0.1") == ("127.0.0.1", 443)


# --- the channel-binding dial -----------------------------------------------------------------------------------


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[tuple[str, bytes]]:
    """A TLS listener on the loopback interface with a self-signed leaf, yielding its host:port and leaf DER."""
    issued = pki.certificate("localhost", pki.p256())
    cert_pem = pki.load(issued.der).public_bytes(serialization.Encoding.PEM)
    key_pem = issued.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (tmp_path / "cert.pem").write_bytes(cert_pem)
    (tmp_path / "key.pem").write_bytes(key_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(tmp_path / "cert.pem"), str(tmp_path / "key.pem"))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            raw, _ = listener.accept()
        except OSError:
            return
        try:
            with context.wrap_socket(raw, server_side=True) as connection:
                connection.recv(1)
        except (OSError, ssl.SSLError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield f"127.0.0.1:{port}", issued.der
    listener.close()
    thread.join(timeout=5)


def test_live_tls_fingerprint_is_the_spki_fingerprint_of_the_presented_leaf(tls_server: tuple[str, bytes]) -> None:
    host, leaf = tls_server
    assert adapter._live_tls_fingerprint(host) == cert_pubkey_fp(leaf)


def test_live_tls_fingerprint_reports_a_closed_port() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(ConnectionRefusedError):
        adapter._live_tls_fingerprint(f"127.0.0.1:{port}")
