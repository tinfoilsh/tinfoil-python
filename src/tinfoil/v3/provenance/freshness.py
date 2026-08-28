"""Freshness witness verification (Go: verifier/provenance/freshness.go): a
freshness proof is a Sigstore bundle signed under the pinned freshness-witness
identity whose in-toto statement endorses exactly the authenticated artifact,
anchored in time by its transparency-log entry. All errors carry
PROVENANCE_REJECTED."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .. import strictjson
from ..bytesutil import decode_base64
from ..errors import PROVENANCE_REJECTED, VerificationError
from ..strictjson import STR, array_of, field, map_of, struct_of
from .bundle_format import parse_bundle
from .provenance import (
    FRESHNESS_WITNESS_IDENTITY,
    REPO_NAME_RE,
    AuthenticatedArtifact,
    verify_bundle_with_identity,
)

FRESHNESS_PREDICATE_FORMAT = "https://tinfoil.sh/predicate/freshness-witness/v1"
_IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
MAX_FRESHNESS_AGE = timedelta(days=7)
MAX_FRESHNESS_FUTURE_SKEW = timedelta(minutes=5)

_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ARTIFACT_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _prov_error(message: str) -> VerificationError:
    return VerificationError(PROVENANCE_REJECTED, message)


# Strict schema of the freshness statement (Go: freshnessStatement via
# strictjson.Unmarshal): unknown and duplicate members reject; missing
# members yield zero values.
_FRESHNESS_STATEMENT_SCHEMA = struct_of(
    {
        "_type": field("type", STR),
        "subject": field(
            "subject",
            array_of(
                struct_of(
                    {
                        "name": field("name", STR),
                        "digest": field("digest", map_of(STR)),
                    }
                )
            ),
        ),
        "predicateType": field("predicate_type", STR),
        "predicate": field(
            "predicate",
            struct_of(
                {
                    "format": field("format", STR),
                    "endorses": field(
                        "endorses",
                        struct_of(
                            {
                                "repo": field("repo", STR),
                                "tag": field("tag", STR),
                                "commit": field("commit", STR),
                                "subject": field(
                                    "subject",
                                    struct_of(
                                        {
                                            "name": field("name", STR),
                                            "digest": field("digest", STR),
                                        }
                                    ),
                                ),
                            }
                        ),
                    ),
                }
            ),
        ),
    }
)


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def authenticate_freshness(
    bundle_json: bytes,
    expected: Optional[AuthenticatedArtifact],
    now: datetime,
    trust_root_json: Optional[bytes] = None,
) -> datetime:
    """Verify a freshness witness bundle for the given authenticated artifact
    and return the verified transparency-log time (Go:
    Client.AuthenticateFreshness)."""
    _validate_authenticated_artifact(expected)
    assert expected is not None
    try:
        result = verify_bundle_with_identity(
            bundle_json, FRESHNESS_WITNESS_IDENTITY, expected.digest, trust_root_json
        )
    except VerificationError as e:
        raise _prov_error(f"verifying freshness witness bundle: {e}") from None
    statement = _parse_freshness_statement(bundle_json)
    if statement["type"] != _IN_TOTO_STATEMENT_V1:
        raise _prov_error(f"unexpected freshness statement type {statement['type']!r}")
    if (
        statement["predicate_type"] != FRESHNESS_PREDICATE_FORMAT
        or statement["predicate"]["format"] != FRESHNESS_PREDICATE_FORMAT
    ):
        raise _prov_error("unexpected freshness predicate format")
    subjects = statement["subject"] or []
    if (
        len(subjects) != 1
        or subjects[0]["name"] != expected.subject_name
        or subjects[0]["digest"].get("sha256") != expected.digest
    ):
        raise _prov_error("freshness statement subject does not match authenticated artifact")
    _validate_witness(statement["predicate"], expected)
    return _validate_freshness_time(result.tlog_timestamps, _as_utc(now))


def _validate_authenticated_artifact(expected: Optional[AuthenticatedArtifact]) -> None:
    if expected is None:
        raise _prov_error("authenticated artifact is nil")
    if REPO_NAME_RE.fullmatch(expected.repo) is None:
        raise _prov_error("authenticated artifact repository is invalid")
    if expected.tag == "":
        raise _prov_error("authenticated artifact tag is empty")
    if _COMMIT_RE.fullmatch(expected.commit) is None:
        raise _prov_error("authenticated artifact commit is malformed")
    if expected.subject_name == "":
        raise _prov_error("authenticated artifact subject name is empty")
    if _ARTIFACT_DIGEST_RE.fullmatch(expected.digest) is None:
        raise _prov_error("authenticated artifact digest is malformed")


def _validate_freshness_time(timestamps: list[datetime], now: datetime) -> datetime:
    """Appraise the earliest verified transparency-log timestamp against the
    pinned appraisal time."""
    logged_at: Optional[datetime] = None
    for timestamp in timestamps:
        if logged_at is None or timestamp < logged_at:
            logged_at = timestamp
    if logged_at is None:
        raise _prov_error("freshness witness has no verified transparency-log timestamp")
    if logged_at > now + MAX_FRESHNESS_FUTURE_SKEW:
        raise _prov_error("freshness witness timestamp is in the future")
    if now - logged_at > MAX_FRESHNESS_AGE:
        raise _prov_error("freshness witness is stale")
    return logged_at


def _parse_freshness_statement(bundle_json: bytes) -> dict[str, Any]:
    wire = parse_bundle(bundle_json)
    envelope = wire.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        raise _prov_error("freshness bundle has no DSSE envelope")
    payload_b64 = envelope.get("payload")
    try:
        payload = decode_base64(payload_b64 if isinstance(payload_b64, str) else "")
    except ValueError as e:
        raise _prov_error(f"parsing freshness bundle: {e}") from None
    try:
        return strictjson.unmarshal(payload, _FRESHNESS_STATEMENT_SCHEMA)
    except ValueError as e:
        raise _prov_error(f"parsing freshness statement: {e}") from None


def _validate_witness(witness: dict[str, Any], expected: AuthenticatedArtifact) -> None:
    endorses = witness["endorses"]
    subject = endorses["subject"]
    if (
        endorses["repo"] != expected.repo
        or endorses["tag"] != expected.tag
        or endorses["commit"] != expected.commit
        or subject["name"] != expected.subject_name
        or subject["digest"] != "sha256:" + expected.digest
    ):
        raise _prov_error("freshness witness does not match authenticated artifact")
    if _SHA256_DIGEST_RE.fullmatch(subject["digest"]) is None:
        raise _prov_error("freshness witness subject digest is malformed")
