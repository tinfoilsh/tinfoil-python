"""Adapter wiring tests for the provenance stages (Go: conformance.Run for
StageAuthenticateProvenance / StageAssemblePolicy): stage verdicts, accept
outputs, and the malformed-input mapping for envelope parse failures and
unparseable trusted roots."""

import base64
import hashlib
import json

from tinfoil.conformance import run as runner
from tinfoil.v3 import envelope

import sigstore_builder as sb
from docbuilder import build_doc

REPO = "tinfoilsh/confidential-inference-proxy"
PLAT_REPO = "tinfoilsh/platform-endorsements"
TAG = "v1.0.0"
CODE_DIGEST = hashlib.sha256(b"code-artifact-v1").hexdigest()
PLAT_DIGEST = hashlib.sha256(b"platform-endorsements-v1").hexdigest()
COMMIT = hashlib.sha1(b"code-commit-v1").hexdigest()
ARTIFACT_FMT = "https://tinfoil.sh/predicate/platform-endorsements/v1"

CODE_IDENTITY = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{TAG}"
PLAT_IDENTITY = f"https://github.com/{PLAT_REPO}/.github/workflows/build.yml@refs/tags/{TAG}"


def code_statement():
    return json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "cip", "digest": {"sha256": CODE_DIGEST}}],
            "predicateType": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
            "predicate": {
                "snp_measurement": "aa" * 48,
                "tdx_measurement": {"rtmr1": "bb" * 48, "rtmr2": "cc" * 48},
                "vm_shape": {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2},
            },
        },
        separators=(",", ":"),
    ).encode()


def platform_statement():
    tcb = {"bl_spl": 0, "tee_spl": 0, "snp_spl": 0, "ucode_spl": 0}
    artifact = {
        "format": ARTIFACT_FMT,
        "measurements": {},
        "machines": {},
        "policies": {
            "sev-policy": {
                "platform": "sev-snp",
                "sev_snp": {
                    "minimum_build": 0,
                    "minimum_api_version": "1.0",
                    "minimum_abi_version": "1.0",
                    "minimum_guest_svn": 0,
                    "minimum_tcb": dict(tcb),
                    "minimum_launch_tcb": dict(tcb),
                    "guest_policy": {"debug": False, "smt": True},
                    "platform_info": {"smt_enabled": True},
                    "permit_provisional_firmware": False,
                    "vmpl": 0,
                    "host_data": "00" * 32,
                    "image_id": "00" * 16,
                    "family_id": "00" * 16,
                    "minimum_launch_mitigation_vector": 0,
                    "minimum_current_mitigation_vector": 0,
                },
            }
        },
    }
    return json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "platform", "digest": {"sha256": PLAT_DIGEST}}],
            "predicateType": ARTIFACT_FMT,
            "predicate": artifact,
        },
        separators=(",", ":"),
    ).encode()


def code_collateral():
    bundle, troot = sb.build_bundle(
        CODE_IDENTITY, code_statement(), source_ref="refs/tags/" + TAG, source_digest=COMMIT
    )
    entry = {
        "id": "sigstore-code",
        "role": envelope.ROLE_REFERENCE_VALUES,
        "format": envelope.COLLATERAL_SIGSTORE_CODE_V1_FORMAT,
        "data": {"repo": REPO, "tag": TAG, "digest": CODE_DIGEST, "sigstore_bundle": bundle},
    }
    return entry, troot


def platform_collateral():
    bundle, troot = sb.build_bundle(
        PLAT_IDENTITY, platform_statement(), source_ref="refs/tags/" + TAG, source_digest=COMMIT
    )
    entry = {
        "id": "sigstore-platform",
        "role": envelope.ROLE_REFERENCE_VALUES,
        "format": envelope.COLLATERAL_SIGSTORE_PLATFORM_V1_FORMAT,
        "data": {
            "repo": PLAT_REPO,
            "tag": TAG,
            "digest": PLAT_DIGEST,
            "sigstore_bundle": bundle,
        },
    }
    return entry, troot


def make_input(doc_bytes: bytes, troot: dict | None, **extra) -> runner.Input:
    obj = {
        "schema_version": "1",
        "document_b64": base64.b64encode(doc_bytes).decode(),
        "nonce_hex": "",
        "repo": REPO,
    }
    if troot is not None:
        obj["sigstore_trusted_root_json_b64"] = base64.b64encode(
            json.dumps(troot).encode()
        ).decode()
    obj.update(extra)
    return runner.parse_input(obj)


def test_authenticate_provenance_accepts_and_emits_facts():
    entry, troot = code_collateral()
    doc = build_doc(collateral=[entry])
    out, code = runner.run(runner.STAGE_AUTHENTICATE_PROVENANCE, make_input(doc, troot))
    assert code == runner.EXIT_ACCEPTED, out
    assert out["accepted"] is True
    assert out["outputs"]["code_digest"] == CODE_DIGEST
    assert out["outputs"]["code_measurement"] == {
        "type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
        "registers": ["aa" * 48, "bb" * 48, "cc" * 48],
    }


def test_authenticate_provenance_missing_collateral_rejects():
    _, troot = code_collateral()
    doc = build_doc(collateral=[])
    out, code = runner.run(runner.STAGE_AUTHENTICATE_PROVENANCE, make_input(doc, troot))
    assert code == runner.EXIT_REJECTED
    assert out["rejection"] == {"code": "PROVENANCE_REJECTED"}


def test_authenticate_provenance_wrong_repo_rejects():
    entry, troot = code_collateral()
    doc = build_doc(collateral=[entry])
    in_ = make_input(doc, troot, repo="tinfoilsh/other-repo")
    out, code = runner.run(runner.STAGE_AUTHENTICATE_PROVENANCE, in_)
    assert code == runner.EXIT_REJECTED
    assert out["rejection"] == {"code": "PROVENANCE_REJECTED"}


def test_assemble_policy_accepts_without_outputs():
    entry, troot = platform_collateral()
    doc = build_doc(collateral=[entry])
    out, code = runner.run(runner.STAGE_ASSEMBLE_POLICY, make_input(doc, troot))
    assert code == runner.EXIT_ACCEPTED, out
    assert out == {"stage": "v3-assemble-policy", "accepted": True}


def test_assemble_policy_unpinned_repo_rejects():
    entry, troot = platform_collateral()
    entry["data"]["repo"] = "tinfoilsh/not-platform-endorsements"
    doc = build_doc(collateral=[entry])
    out, code = runner.run(runner.STAGE_ASSEMBLE_POLICY, make_input(doc, troot))
    assert code == runner.EXIT_REJECTED
    assert out["rejection"] == {"code": "PROVENANCE_REJECTED"}


def test_envelope_parse_failure_is_malformed_for_provenance_stages():
    _, troot = code_collateral()
    bad_doc = b'{"format":"https://tinfoil.sh/predicate/attestation/v2"}'
    for stage in (runner.STAGE_AUTHENTICATE_PROVENANCE, runner.STAGE_ASSEMBLE_POLICY):
        out, code = runner.run(stage, make_input(bad_doc, troot))
        assert code == runner.EXIT_MALFORMED, stage
        assert out["rejection"] == {"code": "MALFORMED_INPUT"}


def test_unparseable_trust_root_is_malformed_for_every_stage():
    entry, _ = code_collateral()
    doc = build_doc(collateral=[entry])
    in_ = make_input(doc, None)
    in_.sigstore_trusted_root_json_b64 = base64.b64encode(b"{not a trusted root").decode()
    for stage in (
        runner.STAGE_CHECK_ENVELOPE,
        runner.STAGE_AUTHENTICATE_PROVENANCE,
        runner.STAGE_ASSEMBLE_POLICY,
    ):
        out, code = runner.run(stage, in_)
        assert code == runner.EXIT_MALFORMED, stage
        assert out["rejection"] == {"code": "MALFORMED_INPUT"}


def test_supported_stages_cover_provenance_slice():
    assert runner.STAGE_AUTHENTICATE_PROVENANCE in runner.SUPPORTED_STAGES
    assert runner.STAGE_ASSEMBLE_POLICY in runner.SUPPORTED_STAGES
