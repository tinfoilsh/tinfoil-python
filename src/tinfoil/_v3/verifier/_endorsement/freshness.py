"""Freshness witnesses: an independently signed statement that a reference-values artifact was recently
republished, whose transparency-log time bounds the artifact's age."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._endorsement.reference import AuthenticatedArtifact
from tinfoil._v3.verifier._endorsement.time import DEFAULT_FUTURE_SKEW, DEFAULT_MAX_AGE, TimePolicy

if TYPE_CHECKING:
    from tinfoil._v3.verifier._endorsement.provenance import ProvenanceClient

FRESHNESS_PREDICATE_FORMAT = "https://tinfoil.sh/predicate/freshness-witness/v1"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
SHA256_DIGEST_PREFIX = "sha256:"
MAX_FRESHNESS_AGE = DEFAULT_MAX_AGE
MAX_FRESHNESS_FUTURE_SKEW = DEFAULT_FUTURE_SKEW


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
    subjects: tuple[tuple[str, dict[str, str]], ...]
    """Each subject's name and digest map."""
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
    raise NotImplementedError


def parse_freshness_statement(payload: bytes) -> FreshnessStatement:
    """Strictly decode the witness statement; unknown members reject."""
    raise NotImplementedError


def validate_witness(witness: FreshnessWitness, expected: AuthenticatedArtifact) -> None:
    """Check that the witness endorses exactly ``expected``: repo, tag, commit, subject name and ``sha256:`` digest."""
    raise NotImplementedError


def validate_freshness_time(logged_at: Sequence[datetime], policy: TimePolicy) -> datetime:
    """Pick the earliest verified log time and check it against the window. No verified log time is an error."""
    raise NotImplementedError
