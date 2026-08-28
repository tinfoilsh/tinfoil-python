"""Adapter wire-contract tests (CONFORMANCE_ADAPTER_SPEC v1.1): exit codes,
output shapes, malformed-input handling, and the v3-check-envelope stage."""

import base64
import json
import subprocess
import sys

import pytest

from tinfoil.conformance import run as runner
from tinfoil.conformance.capabilities import capabilities

from docbuilder import NONCE, build_doc


def make_input(doc_bytes: bytes, nonce: bytes = NONCE, **extra) -> runner.Input:
    obj = {
        "schema_version": "1",
        "document_b64": base64.b64encode(doc_bytes).decode(),
        "nonce_hex": nonce.hex(),
        "repo": "tinfoilsh/example",
    }
    obj.update(extra)
    return runner.parse_input(obj)


def test_check_envelope_accepts_happy_document():
    out, code = runner.run(runner.STAGE_CHECK_ENVELOPE, make_input(build_doc()))
    assert code == runner.EXIT_ACCEPTED
    assert out == {"stage": "v3-check-envelope", "accepted": True}


def test_check_envelope_rejects_tampered_document():
    def mutate(d):
        d["challenge"]["report_data"] = "cc" * 64

    out, code = runner.run(runner.STAGE_CHECK_ENVELOPE, make_input(build_doc(mutate=mutate)))
    assert code == runner.EXIT_REJECTED
    assert out["accepted"] is False
    assert out["rejection"] == {"code": "ENVELOPE_REJECTED"}


def test_check_envelope_uses_verifier_nonce_not_document_echo():
    out, code = runner.run(
        runner.STAGE_CHECK_ENVELOPE, make_input(build_doc(), nonce=bytes(32))
    )
    assert code == runner.EXIT_REJECTED
    assert out["rejection"] == {"code": "ENVELOPE_REJECTED"}


def test_short_nonce_is_envelope_rejected_not_malformed():
    # Decodable hex of the wrong size fails envelope.check (Go parity).
    out, code = runner.run(runner.STAGE_CHECK_ENVELOPE, make_input(build_doc(), nonce=b"\x01"))
    assert code == runner.EXIT_REJECTED
    assert out["rejection"] == {"code": "ENVELOPE_REJECTED"}


def test_malformed_inputs_exit_30():
    good = make_input(build_doc())
    for mutate in (
        {"schema_version": "2"},
        {"document_b64": "!!!"},
        {"document_b64": "aGk"},  # missing padding
        {"nonce_hex": "xyz"},
        {"nonce_hex": "abc"},  # odd length
        {"amd_root_ca_pem": "ARK"},  # without ask_pem
        {"ask_pem": "ASK"},  # without amd_root_ca_pem
        {"sigstore_trusted_root_json_b64": "%%%"},
    ):
        obj = {
            "schema_version": good.schema_version,
            "document_b64": good.document_b64,
            "nonce_hex": good.nonce_hex,
            "repo": good.repo,
        }
        obj.update(mutate)
        out, code = runner.run(list(runner.SUPPORTED_STAGES)[0], runner.parse_input(obj))
        assert code == runner.EXIT_MALFORMED, mutate
        assert out["rejection"] == {"code": "MALFORMED_INPUT"}


def test_input_type_mismatch_is_malformed():
    with pytest.raises(runner.MalformedInput):
        runner.parse_input({"document_b64": 5})
    with pytest.raises(runner.MalformedInput):
        runner.parse_input({"verification_time_unix": "0"})
    with pytest.raises(runner.MalformedInput):
        runner.parse_input({"verification_time_unix": True})
    with pytest.raises(runner.MalformedInput):
        runner.parse_input([])
    # Unknown members are tolerated (Go json decode without DisallowUnknownFields).
    runner.parse_input({"schema_version": "1", "future_field": 1})


def test_unknown_stage_exits_20():
    out, code = runner.run("bogus-stage", make_input(build_doc()))
    assert code == runner.EXIT_UNSUPPORTED
    assert out["accepted"] is False and "rejection" not in out


def test_capabilities_shape():
    caps = capabilities()
    assert caps["schema_version"] == "1"
    assert caps["sdk"] == "tinfoil-python"
    v3 = caps["v3"]
    assert v3["supported"] is True
    assert set(v3["stages_supported"]) == set(runner.SUPPORTED_STAGES)
    assert v3["channel_binding"] in ("tls-spki", "hpke", "none")


def _cli(args, stdin=b""):
    return subprocess.run(
        [sys.executable, "-m", "tinfoil.conformance.cli", *args],
        input=stdin,
        capture_output=True,
    )


def test_cli_end_to_end():
    doc = build_doc()
    req = json.dumps(
        {
            "schema_version": "1",
            "document_b64": base64.b64encode(doc).decode(),
            "nonce_hex": NONCE.hex(),
            "repo": "tinfoilsh/example",
        }
    ).encode()
    p = _cli(["v3-check-envelope"], req)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout) == {"stage": "v3-check-envelope", "accepted": True}

    p = _cli(["capabilities"])
    assert p.returncode == 0
    assert json.loads(p.stdout)["sdk"] == "tinfoil-python"

    # Not JSON / trailing data / non-object are malformed (exit 30).
    for bad in (b"not json", req + b" {}", b"[1]"):
        p = _cli(["v3-check-envelope"], bad)
        assert p.returncode == 30
        assert json.loads(p.stdout)["rejection"] == {"code": "MALFORMED_INPUT"}

    # The synthetic docbuilder document carries no verifiable quote.
    p = _cli(["v3-authenticate-quote"], req)
    assert p.returncode == 10
    assert json.loads(p.stdout)["rejection"] == {"code": "QUOTE_REJECTED"}

    # live-verify without host/repo is malformed input.
    p = _cli(["live-verify"], b"{}")
    assert p.returncode == 30
    assert json.loads(p.stdout)["rejection"] == {"code": "MALFORMED_INPUT"}

    p = _cli([])
    assert p.returncode == 30
