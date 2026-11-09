"""The conformance adapter's wire contract, driven in-process.

Every v3 vector is run through ``run``: an implemented stage must produce the
fixture's verdict and facts; an unimplemented one must exit unsupported and
nothing else. The CLI is exercised once end to end as a subprocess.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import tinfoil_conformance as adapter

_CLI = Path(__file__).resolve().parents[2] / "conformance" / "tinfoil_conformance.py"

_FACTS = (
    "code_digest",
    "code_measurement",
    "enclave_measurement",
    "tls_public_key_fp",
    "hpke_public_key",
    "signing_key_hint",
    "timestamp",
)

_WELL_FORMED: dict[str, Any] = {
    "schema_version": "1",
    "document_b64": "e30=",
    "nonce_hex": "00" * 32,
    "repo": "tinfoilsh/confidential-model-router",
}


def test_capabilities_shape() -> None:
    caps = adapter.capabilities()
    assert caps["schema_version"] == "1"
    assert caps["sdk"] == "tinfoil-python"
    v3 = caps["v3"]
    assert v3["supported"] is bool(v3["stages_supported"])
    assert set(v3["stages_supported"]) <= set(adapter.ALL_STAGES)
    assert set(v3["synthetic_roots"]) == {"amd", "intel", "sigstore"}
    assert v3["channel_binding"] in {"tls-spki", "hpke", "none"}


@pytest.mark.parametrize(
    "raw",
    [
        [],
        "text",
        {},
        {"schema_version": "2"},
        {"schema_version": 1},
        {**_WELL_FORMED, "document_b64": "not base64!"},
        {**_WELL_FORMED, "document_b64": "e30"},  # missing padding
        {**_WELL_FORMED, "nonce_hex": "AB"},  # upper case
        {**_WELL_FORMED, "nonce_hex": "abc"},  # odd length
        {**_WELL_FORMED, "amd_root_ca_pem": "x"},  # without ask_pem
        {**_WELL_FORMED, "ask_pem": "x"},  # without amd_root_ca_pem
        {**_WELL_FORMED, "verification_time_unix": "1"},
        {**_WELL_FORMED, "verification_time_unix": -1},
        {**_WELL_FORMED, "verification_time_unix": True},
        {**_WELL_FORMED, "signing_keys_pem": "pem"},
        {**_WELL_FORMED, "signing_keys_pem": [1]},
        {**_WELL_FORMED, "artifact_digest_hex": "AB" * 32},
        {**_WELL_FORMED, "sigstore_trusted_root_json_b64": "@@"},
    ],
)
def test_malformed_input_is_reported_first(raw: Any) -> None:
    for stage in adapter.ALL_STAGES:
        result = adapter.run(stage, raw)
        assert result.exit_code == adapter.EXIT_MALFORMED
        assert result.output == {"stage": stage, "accepted": False, "rejection": {"code": "MALFORMED_INPUT"}}


def test_unknown_stage_is_unsupported() -> None:
    result = adapter.run("no-such-stage", _WELL_FORMED)
    assert result.exit_code == adapter.EXIT_UNSUPPORTED
    assert result.output == {"stage": "no-such-stage", "accepted": False}


def test_unimplemented_stages_are_unsupported() -> None:
    for stage in adapter.ALL_STAGES:
        if stage in adapter.STAGES_SUPPORTED:
            continue
        result = adapter.run(stage, _WELL_FORMED)
        assert result.exit_code == adapter.EXIT_UNSUPPORTED
        assert result.output == {"stage": stage, "accepted": False}


def test_input_decodes_every_member() -> None:
    decoded = adapter.Input.from_json(
        {
            **_WELL_FORMED,
            "amd_root_ca_pem": "ARK\n",
            "ask_pem": "ASK\n",
            "intel_sgx_root_pem": "ROOT\n",
            "sigstore_trusted_root_json_b64": "e30=",
            "verification_time_unix": 1_700_000_000,
            "bundle_json_b64": "e30=",
            "signing_keys_pem": ["k1", "k2"],
            "artifact_digest_hex": "ab" * 32,
            "timestamp_response_b64": "AA==",
            "timestamp_input_b64": "AQ==",
        }
    )
    assert decoded.document == b"{}"
    assert decoded.nonce == bytes(32)
    assert decoded.repo == "tinfoilsh/confidential-model-router"
    assert decoded.amd_chain_pem == b"ASK\nARK\n"
    assert decoded.intel_root_pem == b"ROOT\n"
    assert decoded.sigstore_trusted_root == b"{}"
    assert decoded.verification_time is not None
    assert decoded.verification_time.timestamp() == 1_700_000_000
    assert decoded.verification_time.tzinfo is not None
    assert decoded.bundle_json == b"{}"
    assert decoded.signing_keys_pem == ("k1", "k2")
    assert decoded.artifact_digest == "ab" * 32
    assert decoded.timestamp_response == b"\x00"
    assert decoded.timestamp_input == b"\x01"


def test_absent_members_select_defaults() -> None:
    decoded = adapter.Input.from_json({"schema_version": "1"})
    assert decoded.document is None
    assert decoded.nonce is None
    assert decoded.repo == ""
    assert decoded.amd_chain_pem is None
    assert decoded.intel_root_pem is None
    assert decoded.sigstore_trusted_root is None
    assert decoded.verification_time is None
    assert decoded.signing_keys_pem == ()
    assert decoded.artifact_digest == ""


def test_vector(fixture: dict[str, Any]) -> None:
    """Each vector: the fixture's verdict and facts, or a clean unsupported."""
    stage = fixture["stage"]
    expected = fixture["expected"]
    result = adapter.run(stage, fixture["input"])
    if stage not in adapter.STAGES_SUPPORTED:
        assert result.exit_code == adapter.EXIT_UNSUPPORTED
        assert result.output == {"stage": stage, "accepted": False}
        return
    assert result.output["stage"] == stage
    if expected["accepted"]:
        assert result.exit_code == adapter.EXIT_ACCEPTED, result.output
        assert result.output["accepted"] is True
        facts = result.output["outputs"]
        for key in _FACTS:
            if key in expected:
                assert facts.get(key) == expected[key], key
    else:
        assert result.exit_code in (adapter.EXIT_REJECTED, adapter.EXIT_MALFORMED), result.output
        assert result.output["accepted"] is False
        if expected.get("code"):
            assert result.output["rejection"]["code"] == expected["code"]


def _cli(args: list[str], stdin: bytes = b"") -> tuple[int, dict[str, Any]]:
    proc = subprocess.run([sys.executable, str(_CLI), *args], input=stdin, capture_output=True, check=False)
    return proc.returncode, json.loads(proc.stdout)


def test_cli_capabilities() -> None:
    code, out = _cli(["capabilities"])
    assert code == adapter.EXIT_ACCEPTED
    assert out == adapter.capabilities()


def test_cli_rejects_non_json_stdin_as_malformed() -> None:
    code, out = _cli([adapter.STAGE_VERIFY], b"{not json")
    assert code == adapter.EXIT_MALFORMED
    assert out["rejection"] == {"code": "MALFORMED_INPUT"}


def test_cli_live_and_capture_unsupported() -> None:
    for command in (adapter.STAGE_LIVE_VERIFY, adapter.STAGE_CAPTURE):
        code, out = _cli([command], b"{}")
        assert code == adapter.EXIT_UNSUPPORTED
        assert out == {"stage": command, "accepted": False}


def test_main_without_arguments_is_usage_error() -> None:
    stderr = io.StringIO()
    code = adapter.main([], io.BytesIO(b""), io.StringIO(), stderr)
    assert code == adapter.EXIT_MALFORMED
    assert "usage" in stderr.getvalue()
