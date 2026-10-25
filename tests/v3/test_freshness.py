"""Freshness witness unit tests (Go: verifier/provenance freshness_test
coverage): witness identity, statement shape, endorsement equality, and the
transparency-log time appraisal."""

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from tinfoil.v3.errors import PROVENANCE_REJECTED, VerificationError
from tinfoil.v3.provenance import (
    MAX_FRESHNESS_AGE,
    MAX_FRESHNESS_FUTURE_SKEW,
    AuthenticatedArtifact,
    authenticate_freshness,
)

import sigstore_builder as sb

REPO = "tinfoilsh/confidential-inference-proxy"
TAG = "v1.0.0"
DIGEST = hashlib.sha256(b"code-artifact-v1").hexdigest()
COMMIT = hashlib.sha1(b"code-commit-v1").hexdigest()
SUBJECT = "cip"

LOGGED_AT = datetime.fromtimestamp(sb.INTEGRATED_TIME, tz=timezone.utc)
NOW = LOGGED_AT + timedelta(hours=1)


def expected_artifact(**overrides):
    fields = dict(repo=REPO, tag=TAG, commit=COMMIT, subject_name=SUBJECT, digest=DIGEST)
    fields.update(overrides)
    return AuthenticatedArtifact(**fields)


def fresh_bundle(**kw):
    bundle, troot = sb.build_freshness_bundle(SUBJECT, DIGEST, REPO, TAG, COMMIT, **kw)
    return json.dumps(bundle).encode(), json.dumps(troot).encode()


def assert_rejects(bundle_json, troot_json, expected=None, now=NOW, match=None):
    with pytest.raises(VerificationError, match=match) as ei:
        authenticate_freshness(
            bundle_json,
            expected_artifact() if expected is None else expected,
            now,
            trust_root_json=troot_json,
        )
    assert ei.value.layer == PROVENANCE_REJECTED


def test_authenticate_freshness_happy_returns_logged_at():
    b, t = fresh_bundle()
    logged_at = authenticate_freshness(b, expected_artifact(), NOW, trust_root_json=t)
    assert logged_at == LOGGED_AT


def test_naive_now_is_treated_as_utc():
    b, t = fresh_bundle()
    naive = NOW.replace(tzinfo=None)
    assert authenticate_freshness(b, expected_artifact(), naive, trust_root_json=t) == LOGGED_AT


def test_stale_witness_rejects():
    b, t = fresh_bundle()
    now = LOGGED_AT + MAX_FRESHNESS_AGE + timedelta(seconds=1)
    assert_rejects(b, t, now=now, match="stale")


def test_age_boundary_accepts():
    b, t = fresh_bundle()
    now = LOGGED_AT + MAX_FRESHNESS_AGE  # exactly MaxFreshnessAge: not stale
    assert authenticate_freshness(b, expected_artifact(), now, trust_root_json=t) == LOGGED_AT


def test_future_witness_rejects():
    b, t = fresh_bundle()
    now = LOGGED_AT - MAX_FRESHNESS_FUTURE_SKEW - timedelta(seconds=1)
    assert_rejects(b, t, now=now, match="in the future")


def test_future_skew_boundary_accepts():
    b, t = fresh_bundle()
    now = LOGGED_AT - MAX_FRESHNESS_FUTURE_SKEW
    assert authenticate_freshness(b, expected_artifact(), now, trust_root_json=t) == LOGGED_AT


def test_wrong_signer_identity_rejects():
    code_identity = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{TAG}"
    b, t = fresh_bundle(identity=code_identity)
    assert_rejects(b, t, match="verifying freshness witness bundle")


def test_witness_identity_from_tag_ref_rejects():
    ident = ("https://github.com/tinfoilsh/freshness-witness"
             "/.github/workflows/freshness.yml@refs/tags/v1.0.0")
    b, t = fresh_bundle(identity=ident)
    assert_rejects(b, t)


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda s: s.update(_type="https://in-toto.io/Statement/v0.9"),
         "unexpected freshness statement type"),
        (lambda s: s.update(predicateType=sb.FRESHNESS_PREDICATE + "-wrong"),
         "unexpected freshness predicate format"),
        (lambda s: s["predicate"].update(format=sb.FRESHNESS_PREDICATE + "-wrong"),
         "unexpected freshness predicate format"),
        (lambda s: s.update(subject=s["subject"] + s["subject"]),
         "subject does not match"),
        (lambda s: s["subject"][0].update(name="other"), "subject does not match"),
        (lambda s: s["predicate"]["endorses"].update(tag="v2.0.0"),
         "witness does not match"),
        (lambda s: s["predicate"]["endorses"].update(repo="tinfoilsh/other"),
         "witness does not match"),
        (lambda s: s["predicate"]["endorses"].update(commit="0" * 40),
         "witness does not match"),
        (lambda s: s["predicate"]["endorses"]["subject"].update(digest=DIGEST),
         "witness does not match"),  # missing the "sha256:" prefix
    ],
)
def test_mutated_statement_rejects(mutate, match):
    stmt = sb.freshness_statement(SUBJECT, DIGEST, REPO, TAG, COMMIT)
    mutate(stmt)
    b, t = fresh_bundle(stmt=stmt)
    assert_rejects(b, t, match=match)


def test_unknown_statement_member_rejects():
    # Rejected during core verification's protojson statement parse, before
    # the freshness-specific strict parse would see it (same order as Go).
    stmt = sb.freshness_statement(SUBJECT, DIGEST, REPO, TAG, COMMIT)
    stmt["extra"] = 1
    b, t = fresh_bundle(stmt=stmt)
    assert_rejects(b, t, match="unknown member")


def test_witness_digest_must_be_lowercase_sha256_uri():
    # Both the equality and the shape gate run; equality trips first when the
    # expected digest is uppercase because expected.digest is pre-validated.
    stmt = sb.freshness_statement(SUBJECT, DIGEST, REPO, TAG, COMMIT)
    stmt["predicate"]["endorses"]["subject"]["digest"] = "sha512:" + DIGEST
    b, t = fresh_bundle(stmt=stmt)
    assert_rejects(b, t, match="witness does not match")


@pytest.mark.parametrize(
    "expected,match",
    [
        (None, "artifact is nil"),
        (expected_artifact(repo="not-a-slug"), "repository is invalid"),
        (expected_artifact(tag=""), "tag is empty"),
        (expected_artifact(commit="xyz"), "commit is malformed"),
        (expected_artifact(subject_name=""), "subject name is empty"),
        (expected_artifact(digest="ZZ"), "digest is malformed"),
        (expected_artifact(digest=DIGEST.upper()), "digest is malformed"),
    ],
)
def test_invalid_expected_artifact_rejects(expected, match):
    b, t = fresh_bundle()
    with pytest.raises(VerificationError, match=match) as ei:
        authenticate_freshness(b, expected, NOW, trust_root_json=t)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_digest_mismatch_between_expected_and_bundle_rejects():
    other = hashlib.sha256(b"different-artifact").hexdigest()
    b, t = fresh_bundle()
    assert_rejects(b, t, expected=expected_artifact(digest=other))


def test_tampered_bundle_rejects():
    bundle, troot = sb.build_freshness_bundle(SUBJECT, DIGEST, REPO, TAG, COMMIT)
    bundle = copy.deepcopy(bundle)
    entry = bundle["verificationMaterial"]["tlogEntries"][0]
    entry["integratedTime"] = str(int(entry["integratedTime"]) + 60)  # breaks the SET
    assert_rejects(json.dumps(bundle).encode(), json.dumps(troot).encode())
