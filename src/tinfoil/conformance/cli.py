"""stdin/stdout/exit-code wrapper of the conformance adapter, mirroring
tinfoil-go cmd/tinfoil-conformance: `tinfoil-conformance <stage>` reads an
Input JSON on stdin and writes an Output JSON on stdout, exiting with the
adapter code; `tinfoil-conformance capabilities` prints the SDK's
capabilities; `tinfoil-conformance live-verify` verifies a live enclave
through the public production entry point and binds the TLS channel
(spec §7, Go: cmd/tinfoil-conformance/live.go)."""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
import sys

from . import run as runner
from .capabilities import capabilities

_STAGE_LIVE = "live-verify"


def _write_json(v) -> None:
    json.dump(v, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _reject_live(code: str) -> int:
    _write_json(
        {"stage": _STAGE_LIVE, "accepted": False, "rejection": {"code": code}}
    )
    return runner.EXIT_REJECTED


def _split_host_port(host: str) -> tuple[str, int]:
    """host may already carry a port (Go: net.SplitHostPort fallback :443)."""
    name, sep, port = host.rpartition(":")
    if sep and port.isdigit():
        return name, int(port)
    return host, 443


def _tls_spki_fingerprint(host: str) -> str:
    """Dial host:443 and return the SHA-256 hex fingerprint of the presented
    leaf's SPKI DER — the same computation the product transport enforces
    (Go: conformance.TLSSPKIFingerprint). Chain verification is skipped on
    purpose: trust comes from matching the attested fingerprint, not the
    public PKI."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    name, port = _split_host_port(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((name, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=name) as tls:
            leaf_der = tls.getpeercert(binary_form=True)
    if leaf_der is None:
        raise RuntimeError("no peer certificate")
    spki = x509.load_der_x509_certificate(leaf_der).public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).hexdigest()


def _run_live() -> int:
    """Verify a live enclave through the SDK's public production entry point —
    verify_document_v3 with no overrides (embedded roots, current time), never
    the adapter's composed flow — then assert the live connection's SPKI
    fingerprint equals the endorsed one (Go: cmd runLive)."""
    # Public surface only (SDK_SURFACE_SPEC §1).
    from tinfoil import (
        VerificationError,
        fetch_attestation,
        hpke_public_key,
        random_nonce,
        tls_public_key_fp,
        verify_document_v3,
    )

    try:
        req = json.loads(sys.stdin.buffer.read())
    except ValueError:
        req = None
    host = req.get("host") if isinstance(req, dict) else None
    repo = req.get("repo") if isinstance(req, dict) else None
    if not isinstance(host, str) or not isinstance(repo, str) or not host or not repo:
        _write_json(
            {
                "stage": _STAGE_LIVE,
                "accepted": False,
                "rejection": {"code": "MALFORMED_INPUT"},
            }
        )
        return runner.EXIT_MALFORMED

    nonce = random_nonce()
    try:
        doc = fetch_attestation(host, nonce)  # public path (Go: envelope.Fetch)
    except Exception as e:
        print(f"fetching attestation from {host}: {e}", file=sys.stderr)
        return runner.EXIT_INTERNAL

    try:
        verified = verify_document_v3(doc, nonce, repo)  # embedded roots, current time
    except VerificationError as e:
        print(f"live verification: {e}", file=sys.stderr)
        return _reject_live(e.layer)

    try:
        tls_fp = tls_public_key_fp(verified)
        hpke = hpke_public_key(verified)
    except ValueError as e:
        print(f"endorsed keys: {e}", file=sys.stderr)
        return _reject_live("ENVELOPE_REJECTED")

    # Channel binding: the endorsed TLS key must be the key the live enclave
    # actually presents on the wire.
    try:
        live = _tls_spki_fingerprint(host)
    except Exception as e:
        print(f"dialing {host} for channel binding: {e}", file=sys.stderr)
        return runner.EXIT_INTERNAL
    if live != tls_fp:
        print(f"channel binding: live TLS key {live} != endorsed {tls_fp}", file=sys.stderr)
        return _reject_live("POLICY_REJECTED")

    _write_json(
        {
            "stage": _STAGE_LIVE,
            "accepted": True,
            "outputs": {
                "code_digest": verified.code_digest,
                "code_measurement": {
                    "type": verified.code_measurement.type,
                    "registers": list(verified.code_measurement.registers),
                },
                "enclave_measurement": {
                    "type": verified.enclave_measurement.type,
                    "registers": list(verified.enclave_measurement.registers),
                },
                "tls_public_key_fp": tls_fp,
                "hpke_public_key": hpke,
                "channel_binding": "tls-spki",
            },
        }
    )
    return runner.EXIT_ACCEPTED


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "usage: tinfoil-conformance <stage>|capabilities|live-verify",
            file=sys.stderr,
        )
        sys.exit(runner.EXIT_MALFORMED)
    cmd = sys.argv[1]

    if cmd == "capabilities":
        _write_json(capabilities())
        sys.exit(0)

    if cmd == "live-verify":
        try:
            sys.exit(_run_live())
        except Exception as e:  # unexpected adapter error
            print(f"internal error: {e}", file=sys.stderr)
            sys.exit(runner.EXIT_INTERNAL)

    try:
        # Exactly one JSON value; json.loads rejects trailing data.
        obj = json.loads(sys.stdin.buffer.read())
        in_ = runner.parse_input(obj)
    except (ValueError, runner.MalformedInput):
        _write_json(
            {"stage": cmd, "accepted": False, "rejection": {"code": "MALFORMED_INPUT"}}
        )
        sys.exit(runner.EXIT_MALFORMED)

    try:
        out, code = runner.run(cmd, in_)
    except Exception as e:  # unexpected adapter error
        print(f"internal error: {e}", file=sys.stderr)
        sys.exit(runner.EXIT_INTERNAL)
    _write_json(out)
    sys.exit(code)


if __name__ == "__main__":
    main()
