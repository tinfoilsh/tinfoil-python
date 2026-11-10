"""Release references and the identity that a verified bundle recovers."""

from __future__ import annotations

import re
from dataclasses import dataclass

REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
"""A GitHub ``owner/name`` repository slug."""
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
REF_RE = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:@([^@\s~^:?*\[\\]+))??(?:@sha256:([0-9a-f]{64}))?$")
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
    raise NotImplementedError


def validate_authenticated_artifact(artifact: AuthenticatedArtifact) -> None:
    """Check that every field is well formed: a repository slug, a non-empty tag, a lowercase 40-hex commit, a
    non-empty subject name and a lowercase SHA-256 digest."""
    raise NotImplementedError
