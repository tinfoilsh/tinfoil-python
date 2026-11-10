"""What the provenance modules share: the provenance error, the workflow signing identities and the release
identity that a verified bundle recovers. It imports none of them, so that each can import it at module scope."""

from __future__ import annotations

import re

from tinfoil._v3.verifier._document.collateral.runtime import RUNTIME_REPO
from tinfoil._v3.verifier._endorsement.reference import (
    FRESHNESS_WITNESS_REPO,
    GIT_COMMIT_RE,
    PLATFORM_ENDORSEMENTS_REPO,
    REPO_NAME_RE,
    RUNTIME_REPO_ID,
    TINFOIL_ORGANIZATION_ID,
    AuthenticatedArtifact,
)
from tinfoil._v3.verifier._sigstore.bundle import Statement
from tinfoil._v3.verifier._sigstore.certificate import (
    GITHUB_OIDC_ISSUER,
    RUNNER_ENVIRONMENT_GITHUB_HOSTED,
    SigningIdentity,
    VerifiedBundle,
    workflow_identity_pattern,
)

_TAG_REF_PREFIX = "refs/tags/"


class ProvenanceError(ValueError):
    """Reference values that fail to authenticate or do not match the requested release."""


def signing_identity(repo: str) -> SigningIdentity:
    """The identity accepted for artifacts signed from ``repo``: any one workflow file directly under
    ``.github/workflows``, run from a tag ref, by GitHub's OIDC issuer on a GitHub-hosted runner."""
    if REPO_NAME_RE.fullmatch(repo) is None:
        raise ProvenanceError(f"invalid repository name {repo!r}")
    return workflow_identity(repo, r"[^/@]+", r"refs/tags/[^@]+")


def platform_endorsements_identity() -> SigningIdentity:
    """The platform-release workflow of the platform-endorsements repository, at a ``platform-v*`` tag."""
    return workflow_identity(PLATFORM_ENDORSEMENTS_REPO, r"platform-release\.yml", r"refs/tags/platform-v[0-9][^@]*")


def freshness_witness_identity() -> SigningIdentity:
    """The freshness workflow of the freshness-witness repository, on ``refs/heads/main``."""
    return workflow_identity(FRESHNESS_WITNESS_REPO, r"freshness\.yml", r"refs/heads/main")


def workflow_identity(repo: str, workflow_pattern: str, ref_pattern: str) -> SigningIdentity:
    """A ``SigningIdentity`` for a GitHub workflow SAN pattern with the GitHub issuer and hosted runner."""
    return SigningIdentity(
        san=workflow_identity_pattern(repo, workflow_pattern, ref_pattern),
        issuer=GITHUB_OIDC_ISSUER,
        runner_environment=RUNNER_ENVIRONMENT_GITHUB_HOSTED,
    )


def authenticated_artifact(
    verified: VerifiedBundle, statement: Statement, repo: str, tag: str, digest: str, label: str
) -> AuthenticatedArtifact:
    """Recover the release identity from a verified bundle.

    For the runtime repository the certificate's repository and owner ids
    must be the pinned ones. The certificate's source ref must be a tag
    ref; when ``tag`` is non-empty it must equal that tag. The commit must
    be a lowercase 40-hex digest and the statement must have a named first
    subject. ``label`` names the artifact in errors.
    """
    extensions = verified.extensions
    if repo == RUNTIME_REPO:
        if extensions.source_repository_identifier != RUNTIME_REPO_ID:
            raise ProvenanceError(f"{label} source repository ID does not match the pinned repository")
        if extensions.source_repository_owner_identifier != TINFOIL_ORGANIZATION_ID:
            raise ProvenanceError(f"{label} source repository owner ID does not match the pinned organization")
    ref = extensions.source_repository_ref
    if not ref.startswith(_TAG_REF_PREFIX):
        raise ProvenanceError(f"{label} source ref {ref!r} is not a tag")
    authenticated_tag = ref[len(_TAG_REF_PREFIX) :]
    if tag != "" and authenticated_tag != tag:
        raise ProvenanceError(f"{label} source ref {ref!r} does not match tag {tag!r}")
    commit = extensions.source_repository_digest
    if GIT_COMMIT_RE.fullmatch(commit) is None:
        raise ProvenanceError(f"{label} source digest is not a lowercase Git commit")
    if not statement.subjects or statement.subjects[0].name == "":
        raise ProvenanceError(f"{label} statement has no named subject")
    return AuthenticatedArtifact(
        repo=repo,
        tag=authenticated_tag,
        commit=commit,
        subject_name=statement.subjects[0].name,
        digest=digest.lower(),
    )


def tag_ref_pattern(tag: str) -> re.Pattern[str]:
    """An anchored pattern for ``refs/tags/<tag>`` with the tag escaped."""
    return re.compile(r"\A" + _TAG_REF_PREFIX + re.escape(tag) + r"\Z")
