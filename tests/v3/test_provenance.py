"""Provenance slice unit tests (Go: verifier/provenance provenance_test
coverage): bundle-format gates, core Sigstore verification wiring, certificate
identity, artifact digest binding, predicate parsing, and the authenticated
release identity."""

import copy
import hashlib
import json

import pytest

from tinfoil.v3.errors import PROVENANCE_REJECTED, VerificationError
from tinfoil.v3.measurement import SNP_TDX_MULTI_PLATFORM_V1
from tinfoil.v3.provenance import (
    authenticate_code,
    authenticate_platform_endorsements,
)
from tinfoil.v3.provenance.bundle_format import (
    parse_bundle,
    reject_legacy_bundle_format,
    require_exactly_one_dsse_signature,
)

import sigstore_builder as sb

REPO = "tinfoilsh/confidential-inference-proxy"
TAG = "v1.0.0"
IDENTITY = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{TAG}"
DIGEST = hashlib.sha256(b"code-artifact-v1").hexdigest()
COMMIT = hashlib.sha1(b"code-commit-v1").hexdigest()

PLAT_REPO = "tinfoilsh/platform-endorsements"
PLAT_IDENTITY = f"https://github.com/{PLAT_REPO}/.github/workflows/build.yml@refs/tags/{TAG}"
PLAT_DIGEST = hashlib.sha256(b"platform-endorsements-v1").hexdigest()
ARTIFACT_FMT = "https://tinfoil.sh/predicate/platform-endorsements/v1"


def base_predicate():
    return {
        "snp_measurement": "aa" * 48,
        "tdx_measurement": {"rtmr1": "bb" * 48, "rtmr2": "cc" * 48},
        "vm_shape": {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2},
    }


def statement(pred_type=SNP_TDX_MULTI_PLATFORM_V1, predicate=None, digest=DIGEST, subject=None):
    return json.dumps({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "cip", "digest": {"sha256": digest}}] if subject is None else subject,
        "predicateType": pred_type,
        "predicate": base_predicate() if predicate is None else predicate,
    }, separators=(",", ":")).encode()


def code_bundle(ident=IDENTITY, stmt=None, **kw):
    kw.setdefault("source_ref", "refs/tags/" + TAG)
    kw.setdefault("source_digest", COMMIT)
    return sb.build_bundle(ident, statement() if stmt is None else stmt, **kw)


def encode(bundle, troot):
    return json.dumps(bundle).encode(), json.dumps(troot).encode()


def assert_rejects(bundle_json, troot_json, match=None):
    with pytest.raises(VerificationError, match=match) as ei:
        authenticate_code(bundle_json, REPO, TAG, DIGEST, trust_root_json=troot_json)
    assert ei.value.layer == PROVENANCE_REJECTED


# --- happy path -----------------------------------------------------------------


def test_authenticate_code_happy():
    b, t = encode(*code_bundle())
    code = authenticate_code(b, REPO, TAG, DIGEST, trust_root_json=t)
    assert code.repo == REPO
    assert code.tag == TAG
    assert code.commit == COMMIT
    assert code.subject_name == "cip"
    assert code.digest == DIGEST
    assert code.measurement.type == SNP_TDX_MULTI_PLATFORM_V1
    assert code.measurement.registers == ["aa" * 48, "bb" * 48, "cc" * 48]
    assert (code.shape.cpus, code.shape.memory_mb, code.shape.gpus, code.shape.disks) == (
        8, 32768, 1, 2,
    )


def test_authenticate_code_empty_declared_tag_accepts_any_tag():
    b, t = encode(*code_bundle())
    code = authenticate_code(b, REPO, "", DIGEST, trust_root_json=t)
    assert code.tag == TAG  # tag recovered from the certificate


def test_multi_subject_accepts_when_subject0_matches():
    stmt = statement(subject=[
        {"name": "cip", "digest": {"sha256": DIGEST}},
        {"name": "extra", "digest": {"sha256": "11" * 32}},
    ])
    b, t = encode(*code_bundle(stmt=stmt))
    assert authenticate_code(b, REPO, TAG, DIGEST, trust_root_json=t).subject_name == "cip"


def test_embedded_root_is_default_and_rejects_synthetic_material():
    b, _ = encode(*code_bundle())
    with pytest.raises(VerificationError) as ei:
        authenticate_code(b, REPO, TAG, DIGEST)  # trust_root_json=None -> embedded
    assert ei.value.layer == PROVENANCE_REJECTED


# --- bundle format gates ----------------------------------------------------------


def test_bad_media_type_rejects():
    bundle, troot = code_bundle()
    bundle["mediaType"] = "application/vnd.dev.sigstore.bundle.v9.9+json"
    assert_rejects(*encode(bundle, troot), match="unsupported media type")


def test_missing_media_type_rejects():
    bundle, troot = code_bundle()
    del bundle["mediaType"]
    assert_rejects(*encode(bundle, troot), match="missing media type")


def test_media_type_gate_accepts_go_forms():
    for mt in (
        "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.dev.sigstore.bundle.v0.3+json",
    ):
        parse_bundle(json.dumps({"mediaType": mt}).encode())


def test_legacy_certificate_chain_layout_rejects():
    bundle, troot = code_bundle()
    leaf = bundle["verificationMaterial"].pop("certificate")
    bundle["verificationMaterial"]["x509CertificateChain"] = {"certificates": [leaf]}
    assert_rejects(*encode(bundle, troot), match="legacy bundle format")


def test_zero_dsse_signatures_reject():
    bundle, troot = code_bundle()
    bundle["dsseEnvelope"]["signatures"] = []
    assert_rejects(*encode(bundle, troot), match="exactly one signature, got 0")


def test_two_dsse_signatures_reject():
    bundle, troot = code_bundle()
    bundle["dsseEnvelope"]["signatures"].append(dict(bundle["dsseEnvelope"]["signatures"][0]))
    assert_rejects(*encode(bundle, troot), match="exactly one signature, got 2")


def test_duplicate_bundle_members_reject():
    bundle, troot = code_bundle()
    b = json.dumps(bundle).encode()
    dup = b[:-1] + b',"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}'
    assert_rejects(dup, json.dumps(troot).encode(), match="duplicate object member")


def test_format_gate_helpers_pass_non_dsse_bundles():
    reject_legacy_bundle_format({"verificationMaterial": {}})
    require_exactly_one_dsse_signature({})  # message-signature bundle: nothing to check


# --- core Sigstore verification -----------------------------------------------------


def test_untrusted_fulcio_root_rejects():
    bundle, troot = code_bundle()
    troot = copy.deepcopy(troot)
    troot["certificateAuthorities"][0]["certChain"]["certificates"] = sb.rogue_ca_cert_chain()
    assert_rejects(*encode(bundle, troot))


def test_no_trusted_ct_log_key_rejects():
    bundle, troot = code_bundle()
    troot = copy.deepcopy(troot)
    troot["ctlogs"] = []
    assert_rejects(*encode(bundle, troot))


def test_no_tlog_entry_rejects():
    bundle, troot = code_bundle()
    bundle["verificationMaterial"]["tlogEntries"] = []
    assert_rejects(*encode(bundle, troot))


def test_tampered_set_rejects():
    bundle, troot = code_bundle()
    entry = bundle["verificationMaterial"]["tlogEntries"][0]
    entry["integratedTime"] = str(int(entry["integratedTime"]) + 1)  # breaks the SET binding
    assert_rejects(*encode(bundle, troot))


def test_integrated_time_outside_cert_validity_rejects():
    b, t = sb.build_bundle(IDENTITY, statement(),
                           integrated_time=sb.INTEGRATED_TIME + 3600 * 24 * 400,
                           source_ref="refs/tags/" + TAG, source_digest=COMMIT)
    assert_rejects(*encode(b, t))


def test_dsse_signature_not_under_leaf_rejects():
    b, t = sb.build_bundle(IDENTITY, statement(), bad_dsse=True,
                           source_ref="refs/tags/" + TAG, source_digest=COMMIT)
    assert_rejects(*encode(b, t))


def test_duplicate_sct_log_id_rejects():
    b, t = code_bundle(dup_sct=True)
    assert_rejects(*encode(b, t))


# --- certificate identity ------------------------------------------------------------


def test_wrong_repository_san_rejects():
    ident = "https://github.com/attacker/evil/.github/workflows/release.yml@refs/tags/v1.0.0"
    b, t = sb.build_bundle(ident, statement())
    assert_rejects(*encode(b, t))


def test_wrong_oidc_issuer_rejects():
    b, t = code_bundle(issuer="https://accounts.evil.example")
    assert_rejects(*encode(b, t))


def test_self_hosted_runner_rejects():
    b, t = code_bundle(runner_environment="self-hosted")
    assert_rejects(*encode(b, t))


def test_branch_ref_san_rejects():
    ident = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/heads/main"
    b, t = sb.build_bundle(ident, statement())
    assert_rejects(*encode(b, t))


def test_nested_workflow_path_san_rejects():
    ident = f"https://github.com/{REPO}/.github/workflows/nested/release.yml@refs/tags/{TAG}"
    b, t = sb.build_bundle(ident, statement())
    assert_rejects(*encode(b, t))


def test_invalid_repository_name_rejects():
    b, t = encode(*code_bundle())
    with pytest.raises(VerificationError, match="invalid repository name"):
        authenticate_code(b, "evil/(repo", TAG, DIGEST, trust_root_json=t)


# --- artifact digest -----------------------------------------------------------------


def test_subject0_digest_mismatch_rejects():
    b, t = encode(*code_bundle())
    other = hashlib.sha256(b"different-artifact").hexdigest()
    with pytest.raises(VerificationError) as ei:
        authenticate_code(b, REPO, TAG, other, trust_root_json=t)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_uppercase_expected_digest_accepts_case_insensitively():
    b, t = encode(*code_bundle())
    code = authenticate_code(b, REPO, TAG, DIGEST.upper(), trust_root_json=t)
    assert code.digest == DIGEST.upper()


def test_no_subject_rejects():
    b, t = code_bundle(stmt=statement(subject=[]))
    assert_rejects(*encode(b, t))


def test_bad_hex_expected_digest_rejects():
    b, t = encode(*code_bundle())
    with pytest.raises(VerificationError, match="decoding hex digest"):
        authenticate_code(b, REPO, TAG, "zz", trust_root_json=t)


# --- code predicate --------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda p: p.pop("tdx_measurement"), "no tdx measurement"),
        (lambda p: p.update(tdx_measurement="not-an-object"), "not a struct"),
        (lambda p: p.pop("snp_measurement"), "no snp measurement"),
        (lambda p: p.update(tdx_measurement={"rtmr2": "cc" * 48}), "no rtmr1"),
        (lambda p: p.pop("vm_shape"), "declares no vm_shape"),
        (lambda p: p.update(vm_shape="not-an-object"), "vm_shape is not an object"),
        (lambda p: p["vm_shape"].pop("cpus"), "missing 'cpus'"),
        (lambda p: p["vm_shape"].update(cpus=-1), "not a non-negative integer"),
        (lambda p: p["vm_shape"].update(cpus=1.5), "not a non-negative integer"),
        (lambda p: p["vm_shape"].update(cpus=True), "not a non-negative integer"),
    ],
)
def test_bad_code_predicate_rejects(mutate, match):
    p = base_predicate()
    mutate(p)
    b, t = code_bundle(stmt=statement(predicate=p))
    assert_rejects(*encode(b, t), match=match)


def test_wrong_predicate_type_rejects():
    b, t = code_bundle(stmt=statement(pred_type=SNP_TDX_MULTI_PLATFORM_V1 + "-wrong"))
    assert_rejects(*encode(b, t), match="unsupported predicate type")


def test_integral_float_shape_member_accepts():
    # Go decodes vm_shape via structpb float64: 8.0 is a valid integer there.
    p = base_predicate()
    p["vm_shape"]["cpus"] = 8.0
    b, t = encode(*code_bundle(stmt=statement(predicate=p)))
    assert authenticate_code(b, REPO, TAG, DIGEST, trust_root_json=t).shape.cpus == 8


# --- authenticated release identity ------------------------------------------------------


def test_source_ref_not_a_tag_rejects():
    b, t = code_bundle(source_ref="refs/heads/main")
    assert_rejects(*encode(b, t), match="is not a tag")


def test_source_ref_missing_rejects():
    b, t = sb.build_bundle(IDENTITY, statement(), source_digest=COMMIT)
    assert_rejects(*encode(b, t), match="is not a tag")


def test_tag_mismatch_rejects():
    b, t = code_bundle(source_ref="refs/tags/v2.0.0")
    assert_rejects(*encode(b, t), match="does not match tag")


def test_bad_source_commit_rejects():
    b, t = code_bundle(source_digest="not-a-commit")
    assert_rejects(*encode(b, t), match="not a lowercase Git commit")


def test_uppercase_source_commit_rejects():
    b, t = code_bundle(source_digest=COMMIT.upper())
    assert_rejects(*encode(b, t), match="not a lowercase Git commit")


# --- platform endorsements ------------------------------------------------------------------


def base_artifact():
    sev_chip = "ab" * 64
    tcb = {"bl_spl": 0, "tee_spl": 0, "snp_spl": 0, "ucode_spl": 0}
    return {
        "format": ARTIFACT_FMT,
        "measurements": {"m1": {"mrtd": "dd" * 48, "rtmr0": "ee" * 48,
                                "shape": {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2}}},
        "machines": {sev_chip: "sev-policy"},
        "policies": {
            "sev-policy": {"platform": "sev-snp", "sev_snp": {
                "minimum_build": 0, "minimum_api_version": "1.0", "minimum_abi_version": "1.0",
                "minimum_guest_svn": 0, "minimum_tcb": dict(tcb), "minimum_launch_tcb": dict(tcb),
                "guest_policy": {"debug": False, "smt": True, "migrate_ma": False, "single_socket": False},
                "platform_info": {"smt_enabled": True, "tsme_enabled": True, "ecc_enabled": True,
                                  "rapl_disabled": False, "ciphertext_hiding_dram": False},
                "permit_provisional_firmware": False, "vmpl": 0,
                "host_data": "00" * 32, "image_id": "00" * 16, "family_id": "00" * 16,
                "minimum_launch_mitigation_vector": 0, "minimum_current_mitigation_vector": 0,
            }},
        },
    }


def plat_statement(artifact):
    return json.dumps({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "platform", "digest": {"sha256": PLAT_DIGEST}}],
        "predicateType": ARTIFACT_FMT,
        "predicate": artifact,
    }, separators=(",", ":")).encode()


def plat_bundle(artifact=None, identity=PLAT_IDENTITY, **kw):
    kw.setdefault("source_ref", "refs/tags/" + TAG)
    kw.setdefault("source_digest", COMMIT)
    return sb.build_bundle(identity, plat_statement(base_artifact() if artifact is None else artifact), **kw)


def test_authenticate_platform_endorsements_happy():
    b, t = encode(*plat_bundle())
    pe = authenticate_platform_endorsements(b, PLAT_REPO, TAG, PLAT_DIGEST, trust_root_json=t)
    assert pe.repo == PLAT_REPO
    assert pe.tag == TAG
    assert pe.subject_name == "platform"
    assert "ab" * 64 in pe.artifact.machines


def test_platform_wrong_workflow_identity_rejects():
    ident = f"https://github.com/{PLAT_REPO}/.github/workflows/other.yml@refs/tags/{TAG}"
    b, t = encode(*plat_bundle(identity=ident))
    with pytest.raises(VerificationError) as ei:
        authenticate_platform_endorsements(b, PLAT_REPO, TAG, PLAT_DIGEST, trust_root_json=t)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_platform_tag_without_v_digit_prefix_rejects():
    ident = f"https://github.com/{PLAT_REPO}/.github/workflows/build.yml@refs/tags/release"
    b, t = encode(*plat_bundle(identity=ident, source_ref="refs/tags/release"))
    with pytest.raises(VerificationError):
        authenticate_platform_endorsements(b, PLAT_REPO, "release", PLAT_DIGEST, trust_root_json=t)


def test_platform_repo_pin_rejects_other_repo():
    b, t = encode(*plat_bundle())
    with pytest.raises(VerificationError, match="does not equal"):
        authenticate_platform_endorsements(
            b, "tinfoilsh/not-platform-endorsements", TAG, PLAT_DIGEST, trust_root_json=t
        )


def test_platform_wrong_predicate_type_rejects():
    stmt = json.dumps({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "platform", "digest": {"sha256": PLAT_DIGEST}}],
        "predicateType": ARTIFACT_FMT + "-wrong",
        "predicate": base_artifact(),
    }, separators=(",", ":")).encode()
    b, t = encode(*sb.build_bundle(PLAT_IDENTITY, stmt,
                                   source_ref="refs/tags/" + TAG, source_digest=COMMIT))
    with pytest.raises(VerificationError, match="unexpected predicate type"):
        authenticate_platform_endorsements(b, PLAT_REPO, TAG, PLAT_DIGEST, trust_root_json=t)


def test_platform_artifact_unknown_member_rejects_as_provenance():
    a = base_artifact()
    a["policies"]["sev-policy"]["sev_snp"]["extra_field"] = 1
    b, t = encode(*plat_bundle(artifact=a))
    with pytest.raises(VerificationError) as ei:
        authenticate_platform_endorsements(b, PLAT_REPO, TAG, PLAT_DIGEST, trust_root_json=t)
    assert ei.value.layer == PROVENANCE_REJECTED
