"""The conformance adapter's wire contract, driven in-process.

Every v3 vector is run through ``run``: an implemented stage must produce the
fixture's verdict and facts; an unimplemented one must exit unsupported and
nothing else. The CLI is exercised once end to end as a subprocess.
"""

from __future__ import annotations

import base64
import hashlib
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
        {**_WELL_FORMED, "nonce_hex": " abcd"},  # whitespace
        {**_WELL_FORMED, "nonce_hex": "0xabcd"},  # prefix
        {**_WELL_FORMED, "repo": None},  # null is not an absent member
        {**_WELL_FORMED, "verification_time_unix": None},
        {**_WELL_FORMED, "signing_keys_pem": None},
        {**_WELL_FORMED, "extra": 1},  # unknown member
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


@pytest.mark.parametrize("stage", [adapter.STAGE_CHECK_ENVELOPE, adapter.STAGE_AUTHENTICATE_QUOTE])
def test_document_stages_treat_an_unparseable_sigstore_root_as_malformed(stage: str) -> None:
    # "e30=" is "{}": well-formed base64 and JSON that is not a trusted-root document.
    result = adapter.run(stage, {**_WELL_FORMED, "sigstore_trusted_root_json_b64": "e30="})
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


def test_zero_verification_time_selects_the_current_time() -> None:
    decoded = adapter.Input.from_json({"schema_version": "1", "verification_time_unix": 0})
    assert decoded.verification_time is None


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
    expects_malformed = expected.get("code") == adapter.MALFORMED_INPUT
    if stage not in adapter.STAGES_SUPPORTED:
        # Input decoding runs before the stage dispatch, so a fixture whose
        # verdict is MALFORMED_INPUT may already be reported as such; any
        # other input must come back as a clean unsupported.
        if expects_malformed and result.exit_code == adapter.EXIT_MALFORMED:
            return
        assert result.exit_code == adapter.EXIT_UNSUPPORTED, result.output
        assert result.output == {"stage": stage, "accepted": False}
        return
    if result.exit_code == adapter.EXIT_UNSUPPORTED and _pending_platform(fixture):
        # A supported stage reports a platform whose authentication has not
        # landed yet as a clean unsupported, never as a verdict.
        assert result.output == {"stage": stage, "accepted": False}
        return
    assert result.output["stage"] == stage
    if expected["accepted"]:
        assert result.exit_code == adapter.EXIT_ACCEPTED, result.output
        assert result.output["accepted"] is True
        # A stage that yields no facts, such as the envelope check, omits outputs.
        facts = result.output.get("outputs") or {}
        for key in _FACTS:
            if key in expected:
                assert facts.get(key) == expected[key], key
    else:
        want_exit = adapter.EXIT_MALFORMED if expects_malformed else adapter.EXIT_REJECTED
        assert result.exit_code == want_exit, result.output
        assert result.output["accepted"] is False
        if expected.get("code"):
            assert result.output["rejection"]["code"] == expected["code"]


_PENDING_EVIDENCE_FORMATS = frozenset({"https://tinfoil.sh/format/tdx-quote/v1"})
"""CPU evidence formats whose authentication the quote stage cannot run yet."""


def _pending_platform(fixture: dict[str, Any]) -> bool:
    """Whether the fixture's document carries CPU evidence of a format that the quote stage cannot authenticate yet."""
    if fixture["stage"] != adapter.STAGE_AUTHENTICATE_QUOTE:
        return False
    try:
        doc = json.loads(base64.b64decode(fixture["input"].get("document_b64", "")))
        return doc["cpu_evidence"]["format"] in _PENDING_EVIDENCE_FORMATS
    except (ValueError, KeyError, TypeError):
        return False


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


# --- the provenance, policy and approval stages over a synthetic Sigstore world ----------------


def _world_inputs() -> tuple[Any, dict[str, Any]]:
    from tests.v3.sigstore_world import World

    world = World()
    return world, {"schema_version": "1", "sigstore_trusted_root_json_b64": _b64(world.trusted_root_json())}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _document_with(entries: list[dict[str, Any]]) -> str:
    from tests.v3 import document_builder

    _, raw = document_builder.build(document_builder.test_nonce(), collateral_entries=entries)
    return _b64(raw)


def _code_entry(world: Any, repo: str, tag: str) -> tuple[dict[str, Any], str, dict[str, str]]:
    from tests.v3.sigstore_world import FulcioIdentity, statement

    digest = "3b" * 32
    registers = {"snp": "aa" * 48, "rtmr1": "bb" * 48, "rtmr2": "cc" * 48}
    predicate = {
        "snp_measurement": registers["snp"],
        "tdx_measurement": {"rtmr1": registers["rtmr1"], "rtmr2": registers["rtmr2"]},
        "vm_shape": {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2},
    }
    payload = statement(
        [{"name": "cip", "digest": {"sha256": digest}}],
        "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
        predicate,
    )
    identity = FulcioIdentity(
        san=f"https://github.com/{repo}/.github/workflows/release.yml@refs/tags/{tag}",
        source_repository_ref=f"refs/tags/{tag}",
    )
    entry = {
        "id": "sigstore-code",
        "role": "reference-values",
        "format": "https://tinfoil.sh/collateral/sigstore-code/v1",
        "subjects": [],
        "data": {"repo": repo, "tag": tag, "digest": digest, "sigstore_bundle": world.fulcio_bundle(payload, identity)},
    }
    return entry, digest, registers


def test_authenticate_provenance_stage() -> None:
    world, base = _world_inputs()
    repo = "tinfoilsh/confidential-inference-proxy"
    entry, digest, registers = _code_entry(world, repo, "v1.0.0")
    accepted = {**base, "document_b64": _document_with([entry]), "repo": repo}
    result = adapter.run(adapter.STAGE_AUTHENTICATE_PROVENANCE, accepted)
    assert result.exit_code == adapter.EXIT_ACCEPTED, result.output
    assert result.output["outputs"] == {
        "code_digest": digest,
        "code_measurement": {
            "type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
            "registers": [registers["snp"], registers["rtmr1"], registers["rtmr2"]],
        },
    }
    # The pins in the reference take precedence over the document's hints.
    assert adapter.run(adapter.STAGE_AUTHENTICATE_PROVENANCE, {**accepted, "repo": repo + "@v1.0.0"}).exit_code == 0
    for name, raw, want in [
        ("no document", {**base, "repo": repo}, adapter.EXIT_MALFORMED),
        ("undecodable document", {**accepted, "document_b64": _b64(b"{")}, adapter.EXIT_MALFORMED),
        ("unparseable root", {**accepted, "sigstore_trusted_root_json_b64": _b64(b"{}")}, adapter.EXIT_MALFORMED),
        ("no code entry", {**accepted, "document_b64": _document_with([])}, adapter.EXIT_REJECTED),
        ("bad reference", {**accepted, "repo": "no-slash"}, adapter.EXIT_REJECTED),
        ("other repository", {**accepted, "repo": "tinfoilsh/other"}, adapter.EXIT_REJECTED),
        ("other tag", {**accepted, "repo": repo + "@v2.0.0"}, adapter.EXIT_REJECTED),
        ("other digest", {**accepted, "repo": repo + "@sha256:" + "ff" * 32}, adapter.EXIT_REJECTED),
        (
            "unknown root",
            {**accepted, "sigstore_trusted_root_json_b64": _world_inputs()[1]["sigstore_trusted_root_json_b64"]},
            adapter.EXIT_REJECTED,
        ),
    ]:
        result = adapter.run(adapter.STAGE_AUTHENTICATE_PROVENANCE, raw)
        assert result.exit_code == want, (name, result.output)
        code = "MALFORMED_INPUT" if want == adapter.EXIT_MALFORMED else "PROVENANCE_REJECTED"
        assert result.output == {
            "stage": adapter.STAGE_AUTHENTICATE_PROVENANCE,
            "accepted": False,
            "rejection": {"code": code},
        }


def test_assemble_policy_stage() -> None:
    from pathlib import Path

    from tests.v3.sigstore_world import FulcioIdentity, statement

    world, base = _world_inputs()
    artifact = (Path(__file__).resolve().parents[1] / "v3" / "testdata" / "platform-endorsements.json").read_bytes()
    digest = hashlib.sha256(artifact).hexdigest()
    payload = (
        b'{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"platform-endorsements.json","digest":{"sha256":"'
        + digest.encode()
        + b'"}}],"predicateType":"https://tinfoil.sh/predicate/platform-endorsements/v1","predicate":'
        + artifact
        + b"}"
    )
    identity = FulcioIdentity(
        san="https://github.com/tinfoilsh/cvmimage/.github/workflows/platform-release.yml@refs/tags/platform-v1.0.0",
        source_repository_ref="refs/tags/platform-v1.0.0",
        source_repository_identifier="902195777",
        source_repository_owner_identifier="168487856",
    )

    def entry(bundle: dict[str, Any], repo: str = "tinfoilsh/cvmimage") -> dict[str, Any]:
        return {
            "id": "sigstore-platform",
            "role": "reference-values",
            "format": "https://tinfoil.sh/collateral/sigstore-platform/v1",
            "subjects": [],
            "data": {"repo": repo, "tag": "platform-v1.0.0", "digest": digest, "sigstore_bundle": bundle},
        }

    accepted = {**base, "document_b64": _document_with([entry(world.fulcio_bundle(payload, identity))]), "repo": "x/y"}
    result = adapter.run(adapter.STAGE_ASSEMBLE_POLICY, accepted)
    assert result.exit_code == adapter.EXIT_ACCEPTED, result.output
    assert result.output == {"stage": adapter.STAGE_ASSEMBLE_POLICY, "accepted": True}
    other_workflow = FulcioIdentity(**{**identity.__dict__, "san": identity.san.replace("platform-release", "release")})
    for name, raw, want in [
        ("no document", base, adapter.EXIT_MALFORMED),
        ("undecodable document", {**accepted, "document_b64": _b64(b"nope")}, adapter.EXIT_MALFORMED),
        ("no platform entry", {**accepted, "document_b64": _document_with([])}, adapter.EXIT_REJECTED),
        (
            "wrong repo",
            {**accepted, "document_b64": _document_with([entry(world.fulcio_bundle(payload, identity), "o/r")])},
            adapter.EXIT_REJECTED,
        ),
        (
            "other workflow",
            {**accepted, "document_b64": _document_with([entry(world.fulcio_bundle(payload, other_workflow))])},
            adapter.EXIT_REJECTED,
        ),
        (
            "v2 statement",
            {
                **accepted,
                "document_b64": _document_with(
                    [entry(world.fulcio_bundle(payload.replace(b"endorsements/v1", b"endorsements/v2", 1), identity))]
                ),
            },
            adapter.EXIT_REJECTED,
        ),
    ]:
        result = adapter.run(adapter.STAGE_ASSEMBLE_POLICY, raw)
        assert result.exit_code == want, (name, result.output)
    assert statement is not None


def test_authenticate_approval_stage() -> None:
    from tests.v3 import pki
    from tests.v3.sigstore_world import statement

    world, base = _world_inputs()
    digest = "ab" * 32
    payload = statement(
        [{"name": "artifact", "digest": {"sha256": digest}}], "https://tinfoil.sh/predicate/test/v1", {}
    )
    bundle = json.dumps(world.keyed_bundle(payload)).encode()
    accepted = {
        **base,
        "bundle_json_b64": _b64(bundle),
        "signing_keys_pem": [world.public_key_pem],
        "artifact_digest_hex": digest,
    }
    result = adapter.run(adapter.STAGE_AUTHENTICATE_APPROVAL, accepted)
    assert result.exit_code == adapter.EXIT_ACCEPTED, result.output
    assert result.output["outputs"] == {"signing_key_hint": world.hint}
    # Document members are not read by this stage, even undecodable ones.
    assert (
        adapter.run(
            adapter.STAGE_AUTHENTICATE_APPROVAL, {**accepted, "document_b64": "%%%", "nonce_hex": "zz"}
        ).exit_code
        == adapter.EXIT_MALFORMED
    )
    assert (
        adapter.run(
            adapter.STAGE_AUTHENTICATE_APPROVAL, {**accepted, "document_b64": "e30=", "nonce_hex": "zz"}
        ).exit_code
        == adapter.EXIT_MALFORMED
    )
    assert (
        adapter.run(
            adapter.STAGE_AUTHENTICATE_APPROVAL, {**accepted, "document_b64": "e30=", "nonce_hex": "ab"}
        ).exit_code
        == adapter.EXIT_ACCEPTED
    )
    other = _world_inputs()[0]
    for name, raw, want in [
        (
            "malformed key",
            {**accepted, "signing_keys_pem": ["-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n"]},
            adapter.EXIT_MALFORMED,
        ),
        ("no keys", {**accepted, "signing_keys_pem": []}, adapter.EXIT_MALFORMED),
        ("repeated key", {**accepted, "signing_keys_pem": [world.public_key_pem] * 2}, adapter.EXIT_MALFORMED),
        ("unsupported key", {**accepted, "signing_keys_pem": [pki.public_pem(pki.p384())]}, adapter.EXIT_MALFORMED),
        ("unparseable root", {**accepted, "sigstore_trusted_root_json_b64": _b64(b"[]")}, adapter.EXIT_MALFORMED),
        (
            "root without logs",
            {**accepted, "sigstore_trusted_root_json_b64": _b64(world.trusted_root_json(tlogs=False))},
            adapter.EXIT_REJECTED,
        ),
        (
            "no bundle",
            {**base, "signing_keys_pem": [world.public_key_pem], "artifact_digest_hex": digest},
            adapter.EXIT_REJECTED,
        ),
        ("unparseable bundle", {**accepted, "bundle_json_b64": _b64(b"{")}, adapter.EXIT_REJECTED),
        ("wrong digest", {**accepted, "artifact_digest_hex": "cd" * 32}, adapter.EXIT_REJECTED),
        ("no digest", {**accepted, "artifact_digest_hex": ""}, adapter.EXIT_REJECTED),
        ("unpinned key", {**accepted, "signing_keys_pem": [other.public_key_pem]}, adapter.EXIT_REJECTED),
        (
            "unknown log",
            {**accepted, "sigstore_trusted_root_json_b64": _b64(other.trusted_root_json())},
            adapter.EXIT_REJECTED,
        ),
    ]:
        result = adapter.run(adapter.STAGE_AUTHENTICATE_APPROVAL, raw)
        assert result.exit_code == want, (name, result.output)
        code = "MALFORMED_INPUT" if want == adapter.EXIT_MALFORMED else "PROVENANCE_REJECTED"
        assert result.output["rejection"] == {"code": code}, name


def test_verify_timestamp_stage_uses_the_approval_window() -> None:
    from datetime import timedelta

    world, base = _world_inputs()
    data = b"tinfoil-approval-core"
    gen_time = world.now - timedelta(hours=1)

    def raw(now: Any) -> dict[str, Any]:
        return {
            **base,
            "timestamp_response_b64": _b64(world.timestamp(data, gen_time)),
            "timestamp_input_b64": _b64(data),
            "verification_time_unix": int(now.timestamp()),
        }

    result = adapter.run(adapter.STAGE_VERIFY_TIMESTAMP, raw(world.now))
    assert result.exit_code == adapter.EXIT_ACCEPTED, result.output
    assert result.output["outputs"] == {"timestamp": gen_time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    assert (
        adapter.run(adapter.STAGE_VERIFY_TIMESTAMP, raw(gen_time + timedelta(days=7))).exit_code
        == adapter.EXIT_ACCEPTED
    )
    assert (
        adapter.run(adapter.STAGE_VERIFY_TIMESTAMP, raw(gen_time + timedelta(days=7, seconds=1))).exit_code
        == adapter.EXIT_REJECTED
    )
    assert (
        adapter.run(adapter.STAGE_VERIFY_TIMESTAMP, raw(gen_time - timedelta(minutes=5))).exit_code
        == adapter.EXIT_ACCEPTED
    )
    assert (
        adapter.run(adapter.STAGE_VERIFY_TIMESTAMP, raw(gen_time - timedelta(minutes=5, seconds=1))).exit_code
        == adapter.EXIT_REJECTED
    )
    assert (
        adapter.run(adapter.STAGE_VERIFY_TIMESTAMP, {**raw(world.now), "timestamp_input_b64": _b64(b"other")}).exit_code
        == adapter.EXIT_REJECTED
    )
    assert (
        adapter.run(adapter.STAGE_VERIFY_TIMESTAMP, {**raw(world.now), "verification_time_unix": 0}).exit_code
        == adapter.EXIT_MALFORMED
    )
