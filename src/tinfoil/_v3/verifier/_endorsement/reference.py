"""Release references and the identity that a verified bundle recovers."""

from __future__ import annotations

import re
from dataclasses import dataclass

# The patterns are ASCII-only so that the character classes match the same
# characters on every interpreter; they are applied with ``fullmatch`` so that
# a trailing newline never slips past the end anchor.
REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", re.ASCII)
"""A GitHub ``owner/name`` repository slug."""
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
SHA256_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
REF_RE = re.compile(
    r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:@([^@\s~^:?*\[\\]+))??(?:@sha256:([0-9a-f]{64}))?$", re.ASCII
)
"""``owner/name[@tag][@sha256:digest]``; the tag group is lazy so that ``@sha256:`` alone is a digest."""

TINFOIL_ORGANIZATION_ID = "168487856"
RUNTIME_REPO_ID = "902195777"
FRESHNESS_WITNESS_REPO = "tinfoilsh/freshness-witness"
PLATFORM_ENDORSEMENTS_REPO = "tinfoilsh/cvmimage"


class ReferenceError(ValueError):
    """A release reference or authenticated artifact that is malformed."""


@dataclass(frozen=True, slots=True)
class Reference:
    """A parsed ``owner/name[@tag][@sha256:digest]`` release reference; "" marks an absent part."""

    repo: str
    tag: str = ""
    digest: str = ""


@dataclass(frozen=True, slots=True)
class AuthenticatedArtifact:
    """Release identity recovered from a verified statement and its signing certificate."""

    repo: str
    tag: str
    commit: str
    subject_name: str
    digest: str


def parse_reference(ref: str) -> Reference:
    """Validate ``owner/name[@tag][@sha256:digest]`` and return its parts."""
    match = REF_RE.fullmatch(ref)
    if match is None:
        raise ReferenceError(f"invalid release reference {ref!r}: want owner/name[@tag][@sha256:digest]")
    return Reference(repo=match[1], tag=match[2] or "", digest=match[3] or "")


def validate_authenticated_artifact(artifact: AuthenticatedArtifact) -> None:
    """Check that every field is well formed: a repository slug, a non-empty tag, a lowercase 40-hex commit, a
    non-empty subject name and a lowercase SHA-256 digest."""
    if REPO_NAME_RE.fullmatch(artifact.repo) is None:
        raise ReferenceError("authenticated artifact repository is invalid")
    if artifact.tag == "":
        raise ReferenceError("authenticated artifact tag is empty")
    if GIT_COMMIT_RE.fullmatch(artifact.commit) is None:
        raise ReferenceError("authenticated artifact commit is malformed")
    if artifact.subject_name == "":
        raise ReferenceError("authenticated artifact subject name is empty")
    if SHA256_DIGEST_RE.fullmatch(artifact.digest) is None:
        raise ReferenceError("authenticated artifact digest is malformed")
