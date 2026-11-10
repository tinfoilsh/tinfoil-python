"""Freshness witnesses: an independently signed statement that a reference-values artifact was recently
republished, whose transparency-log time bounds the artifact's age."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._endorsement._common import ProvenanceError, freshness_witness_identity
from tinfoil._v3.verifier._endorsement.reference import (
    AuthenticatedArtifact,
    ReferenceError,
    validate_authenticated_artifact,
)
from tinfoil._v3.verifier._endorsement.time import (
    DEFAULT_FUTURE_SKEW,
    DEFAULT_MAX_AGE,
    TimePolicy,
    TimePolicyError,
    new_time_policy,
)
from tinfoil._v3.verifier._sigstore.bundle import Subject

if TYPE_CHECKING:
    from tinfoil._v3.verifier._endorsement.provenance import ProvenanceClient

FRESHNESS_PREDICATE_FORMAT = "https://tinfoil.sh/predicate/freshness-witness/v1"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
SHA256_DIGEST_PREFIX = "sha256:"
MAX_FRESHNESS_AGE = DEFAULT_MAX_AGE
MAX_FRESHNESS_FUTURE_SKEW = DEFAULT_FUTURE_SKEW

_STATEMENT_MEMBERS = ("_type", "subject", "predicateType", "predicate")
_SUBJECT_MEMBERS = ("name", "digest")
_WITNESS_MEMBERS = ("format", "endorses")
_ENDORSEMENT_MEMBERS = ("repo", "tag", "commit", "subject")
_WITNESS_SUBJECT_MEMBERS = ("name", "digest")


class FreshnessError(ValueError):
    """A freshness witness that does not verify, does not match the artifact or is stale."""


@dataclass(frozen=True, slots=True)
class WitnessSubject:
    name: str
    digest: str
    """``sha256:`` plus lowercase hex."""


@dataclass(frozen=True, slots=True)
class WitnessEndorsement:
    repo: str
    tag: str
    commit: str
    subject: WitnessSubject


@dataclass(frozen=True, slots=True)
class FreshnessWitness:
    format: str
    endorses: WitnessEndorsement


@dataclass(frozen=True, slots=True)
class FreshnessStatement:
    type: str
    subjects: tuple[Subject, ...]
    """The in-toto subjects: each a name and an algorithm-to-hex digest map."""
    predicate_type: str
    predicate: FreshnessWitness


def authenticate_freshness(
    client: ProvenanceClient,
    bundle: _json.JsonValue,
    expected: AuthenticatedArtifact,
    now: datetime,
    max_age: timedelta | None = None,
) -> datetime:
    """Verify a freshness witness for ``expected`` and return its transparency-log time.

    In order: the window is built with ``time.new_time_policy`` (None
    selects the default age, a negative one rejects, the default skew
    applies); ``expected`` is well formed; the bundle verifies
    as a Fulcio bundle signed by the freshness-witness workflow over
    ``expected.digest``; the statement is an in-toto v1 statement with the
    witness predicate whose one subject and endorsement match
    ``expected``; the log time lies within the window.
    """
    if max_age is not None and max_age < timedelta(0):
        raise FreshnessError("freshness maximum age must not be negative")
    try:
        policy = new_time_policy(now, max_age)
    except TimePolicyError as err:
        raise FreshnessError(str(err)) from err
    try:
        validate_authenticated_artifact(expected)
    except ReferenceError as err:
        raise FreshnessError(str(err)) from err
    try:
        verified, _ = client.verify_bundle_with_identity(bundle, freshness_witness_identity(), expected.digest)
    except ProvenanceError as err:
        raise FreshnessError(f"verifying freshness witness bundle: {err}") from err
    statement = parse_freshness_statement(verified.payload)
    if statement.type != IN_TOTO_STATEMENT_V1:
        raise FreshnessError(f"unexpected freshness statement type {statement.type!r}")
    if (
        statement.predicate_type != FRESHNESS_PREDICATE_FORMAT
        or statement.predicate.format != FRESHNESS_PREDICATE_FORMAT
    ):
        raise FreshnessError("unexpected freshness predicate format")
    if (
        len(statement.subjects) != 1
        or statement.subjects[0].name != expected.subject_name
        or statement.subjects[0].digest.get("sha256") != expected.digest
    ):
        raise FreshnessError("freshness statement subject does not match authenticated artifact")
    validate_witness(statement.predicate, expected)
    logged_at = [verified.logged_at] if verified.logged_at is not None else []
    return validate_freshness_time(logged_at, policy)


def parse_freshness_statement(payload: bytes) -> FreshnessStatement:
    """Strictly decode the witness statement; unknown members reject."""
    try:
        value = _json.strict_parse(payload)
        record = _json.object_(value, "freshness statement", _STATEMENT_MEMBERS)
        subjects: list[Subject] = []
        for index, item in enumerate(_json.array(record, "subject") or ()):
            subject = _json.object_(item, f"subject[{index}]", _SUBJECT_MEMBERS)
            subjects.append(
                Subject(name=_json.string(subject, "name"), digest=_json.mapping(subject, "digest", _digest_value))
            )
        witness = _json.struct(record, "predicate", _WITNESS_MEMBERS)
        endorses = _json.struct(witness, "endorses", _ENDORSEMENT_MEMBERS)
        witness_subject = _json.struct(endorses, "subject", _WITNESS_SUBJECT_MEMBERS)
        return FreshnessStatement(
            type=_json.string(record, "_type"),
            subjects=tuple(subjects),
            predicate_type=_json.string(record, "predicateType"),
            predicate=FreshnessWitness(
                format=_json.string(witness, "format"),
                endorses=WitnessEndorsement(
                    repo=_json.string(endorses, "repo"),
                    tag=_json.string(endorses, "tag"),
                    commit=_json.string(endorses, "commit"),
                    subject=WitnessSubject(
                        name=_json.string(witness_subject, "name"), digest=_json.string(witness_subject, "digest")
                    ),
                ),
            ),
        )
    except _json.JsonError as err:
        raise FreshnessError(f"parsing freshness statement: {err}") from err


def _digest_value(value: _json.JsonValue, algorithm: str) -> str:
    # A null digest value decodes as the empty string, like any null string member.
    if value is None:
        return ""
    if not isinstance(value, str):
        raise _json.JsonError(f"cannot unmarshal JSON value into string within digest {algorithm!r}")
    return value


def validate_witness(witness: FreshnessWitness, expected: AuthenticatedArtifact) -> None:
    """Check that the witness endorses exactly ``expected``: repo, tag, commit, subject name and ``sha256:`` digest."""
    endorses = witness.endorses
    if (
        endorses.repo != expected.repo
        or endorses.tag != expected.tag
        or endorses.commit != expected.commit
        or endorses.subject.name != expected.subject_name
        or endorses.subject.digest != SHA256_DIGEST_PREFIX + expected.digest
    ):
        raise FreshnessError("freshness witness does not match authenticated artifact")


def validate_freshness_time(logged_at: Sequence[datetime], policy: TimePolicy) -> datetime:
    """Pick the earliest verified log time and check it against the window. No verified log time is an error."""
    if not logged_at:
        raise FreshnessError("freshness witness has no verified transparency-log timestamp")
    earliest = min(logged_at)
    if earliest > policy.latest:
        raise FreshnessError("freshness witness timestamp is in the future")
    if earliest < policy.earliest:
        raise FreshnessError("freshness witness is stale")
    return earliest
