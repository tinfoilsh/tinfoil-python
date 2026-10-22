"""The conformance adapter, and the shared tinfoil-conformance v3 fixtures.

Point TINFOIL_CONFORMANCE_FIXTURES at a tinfoil-conformance checkout's
``vectors/v3`` directory (or one suite under it) to run the fixtures.
Fixtures whose verification steps are not implemented yet are skipped.
"""

import base64
import io
import json
import os
from pathlib import Path

import pytest
import tinfoil_conformance as adapter

from tinfoil.verify import Layer, UsageError, VerificationError, document

FACTS = ("code_digest", "code_measurement", "enclave_measurement", "tls_public_key_fp", "hpke_public_key")
FIXTURES = os.environ.get("TINFOIL_CONFORMANCE_FIXTURES")


def fixture_paths() -> list[Path]:
    if not FIXTURES:
        return []
    root = Path(FIXTURES)
    return sorted(path for path in root.rglob("*.json") if "stage" in json.loads(path.read_bytes()))


@pytest.mark.skipif(not FIXTURES, reason="TINFOIL_CONFORMANCE_FIXTURES is not set")
@pytest.mark.parametrize("path", fixture_paths(), ids=lambda path: str(path.relative_to(FIXTURES or "")))
def test_fixture(path):
    fixture = json.loads(path.read_bytes())
    output, exit_code = adapter.run(fixture["stage"], fixture["input"])
    if exit_code == adapter.EXIT_UNSUPPORTED:
        pytest.skip("not implemented")

    expected = fixture["expected"]
    assert output["accepted"] == expected["accepted"], output
    if expected["accepted"]:
        assert exit_code == adapter.EXIT_ACCEPTED
        # An adapter that accepts but recovers different facts is not
        # conformant: this is what forces cross-SDK output equivalence.
        facts = output.get("outputs", {})
        for name in FACTS:
            if name in expected:
                assert facts.get(name) == expected[name], name
    else:
        assert exit_code in (adapter.EXIT_REJECTED, adapter.EXIT_MALFORMED)
        assert output["rejection"]["code"] == expected["code"]


def valid_input(**overrides):
    return {
        "schema_version": "1",
        "document_b64": base64.b64encode(b"{}").decode(),
        "nonce_hex": "00" * 32,
        "repo": "org/repo",
        **overrides,
    }


@pytest.mark.parametrize(
    ("err", "code", "exit_code"),
    [
        (VerificationError(Layer.ENVELOPE, "x"), "ENVELOPE_REJECTED", adapter.EXIT_REJECTED),
        (VerificationError(Layer.PROVENANCE, "x"), "PROVENANCE_REJECTED", adapter.EXIT_REJECTED),
        (VerificationError(Layer.QUOTE, "x"), "QUOTE_REJECTED", adapter.EXIT_REJECTED),
        (VerificationError(Layer.POLICY, "x"), "POLICY_REJECTED", adapter.EXIT_REJECTED),
        (UsageError("x"), "MALFORMED_INPUT", adapter.EXIT_MALFORMED),
        # A rejection without a known layer, or without a verify type, is a
        # verifier bug and must not pass for a verdict.
        (VerificationError("device", "x"), None, adapter.EXIT_INTERNAL),  # type: ignore[arg-type]
        (ValueError("x"), None, adapter.EXIT_INTERNAL),
    ],
)
def test_rejection_code_reads_the_layer(err, code, exit_code):
    assert adapter.rejection_code(err) == (code, exit_code)


@pytest.mark.parametrize(
    "request_json",
    [
        [],
        valid_input(schema_version="2"),
        valid_input(document_b64="not base64!"),
        valid_input(nonce_hex="0"),
        valid_input(nonce_hex="zz"),
        valid_input(repo=7),
        valid_input(ask_pem="-----BEGIN CERTIFICATE-----"),
        valid_input(verification_time_unix=1.5),
        valid_input(verification_time_unix=True),
        valid_input(verification_time_unix=2**63),
        valid_input(sigstore_trusted_root_json_b64="%%%"),
    ],
)
def test_malformed_input(request_json):
    output, exit_code = adapter.run(adapter.STAGE_VERIFY, request_json)
    assert exit_code == adapter.EXIT_MALFORMED
    assert output == {"stage": adapter.STAGE_VERIFY, "accepted": False, "rejection": {"code": "MALFORMED_INPUT"}}


def test_unknown_stages_are_unsupported():
    assert adapter.run("v3-bind-channel", valid_input()) == (
        {"stage": "v3-bind-channel", "accepted": False},
        adapter.EXIT_UNSUPPORTED,
    )


@pytest.mark.parametrize("stage", [adapter.STAGE_VERIFY, adapter.STAGE_CHECK_ENVELOPE])
def test_unimplemented_steps_are_unsupported(monkeypatch, stage):
    def unimplemented(*args):
        raise NotImplementedError

    monkeypatch.setattr(document, "parse", unimplemented)
    assert adapter.run(stage, valid_input()) == ({"stage": stage, "accepted": False}, adapter.EXIT_UNSUPPORTED)


def test_check_envelope_rejects_any_parse_failure(monkeypatch):
    def reject(*args):
        raise document.InvalidInputError("expected nonce must be 32 bytes")

    monkeypatch.setattr(document, "parse", reject)
    output, exit_code = adapter.run(adapter.STAGE_CHECK_ENVELOPE, valid_input())
    assert exit_code == adapter.EXIT_REJECTED
    assert output["rejection"] == {"code": "ENVELOPE_REJECTED"}


def run_main(*args: str, stdin: bytes = b"") -> tuple[int, str]:
    stdout = io.StringIO()
    exit_code = adapter.main(list(args), stdin=io.BytesIO(stdin), stdout=stdout)
    return exit_code, stdout.getvalue()


def test_main_prints_capabilities():
    exit_code, stdout = run_main("capabilities")
    assert exit_code == adapter.EXIT_ACCEPTED
    capabilities = json.loads(stdout)
    assert capabilities["sdk"] == "tinfoil-python"
    assert capabilities["v3"]["supported"] is True


@pytest.mark.parametrize("stdin", [b"not json", json.dumps(valid_input()).encode() + b" {}"])
def test_main_rejects_input_that_is_not_one_json_value(stdin):
    exit_code, stdout = run_main(adapter.STAGE_VERIFY, stdin=stdin)
    assert exit_code == adapter.EXIT_MALFORMED
    assert json.loads(stdout)["rejection"] == {"code": "MALFORMED_INPUT"}


def test_main_reports_unexpected_errors_as_internal(monkeypatch):
    def crash(*args):
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(adapter, "run", crash)
    exit_code, stdout = run_main(adapter.STAGE_VERIFY, stdin=json.dumps(valid_input()).encode())
    assert exit_code == adapter.EXIT_INTERNAL
    assert json.loads(stdout) == {"stage": adapter.STAGE_VERIFY, "accepted": False}
