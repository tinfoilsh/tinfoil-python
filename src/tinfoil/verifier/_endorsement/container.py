"""Container provenance: the SLSA bundle that attests which GitHub Actions workflow built a container image, checked
against the build that the image's config requires."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tinfoil.verifier import _json
from tinfoil.verifier._endorsement._common import ProvenanceError, workflow_identity
from tinfoil.verifier._endorsement.reference import GIT_COMMIT_RE
from tinfoil.verifier._endorsement.runtime import SLSA_PROVENANCE_V1
from tinfoil.verifier._runtime.container import ContainerProvenance
from tinfoil.verifier._sigstore.bundle import IN_TOTO_STATEMENT_V1

if TYPE_CHECKING:
    from tinfoil.verifier._endorsement.provenance import ProvenanceClient

GITHUB_REPOSITORY_URL_PREFIX = "https://github.com/"
REF_WILDCARD = "*"
"""The pattern character that a container requirement uses for any run of characters within one ref segment."""
_REF_WILDCARD_CHARACTERS = r"[^/@]"


class ContainerProvenanceError(ValueError):
    """Container provenance that does not verify or does not match the build that the config requires."""


@dataclass(frozen=True, slots=True)
class Container:
    """A container image whose build was authenticated against the requirement that its config declares."""

    digest: str
    repository: str
    workflow: str
    ref: str
    """The ref that the build ran from, as the signing certificate states it."""
    commit: str


def authenticate_container(
    client: ProvenanceClient, bundle: _json.JsonValue, required: ContainerProvenance
) -> Container:
    """Verify that ``bundle`` is a SLSA build attestation for the required image digest, signed by the required
    workflow of the required repository on a GitHub-hosted runner.

    In order: the bundle verifies as a Fulcio bundle whose signing identity
    is the required workflow file at a ref that matches the required
    pattern, with the image digest as its first subject; the statement is
    SLSA v1; the signing certificate's source repository, its ID and its
    ref are the required ones and its commit is well formed.
    """
    ref = ref_pattern(required.ref)
    identity = workflow_identity(required.repository, re.escape(required.workflow), ref)
    try:
        verified, statement = client.verify_bundle_with_identity(bundle, identity, required.digest)
    except ProvenanceError as err:
        raise ContainerProvenanceError(f"verifying container provenance: {err}") from err
    if statement.type != IN_TOTO_STATEMENT_V1 or statement.predicate_type != SLSA_PROVENANCE_V1:
        raise ContainerProvenanceError("container provenance must use SLSA v1")
    # The signing identity names the workflow file that ran, which a workflow
    # in another repository can call. The source fields name the repository
    # and ref that triggered the run.
    extensions = verified.extensions
    if extensions.source_repository_uri != GITHUB_REPOSITORY_URL_PREFIX + required.repository:
        raise ContainerProvenanceError(
            f"container provenance source repository {extensions.source_repository_uri!r} "
            f"does not match {required.repository!r}"
        )
    if extensions.source_repository_identifier != required.repository_id:
        raise ContainerProvenanceError(
            "container provenance source repository ID does not match the required repository"
        )
    if re.fullmatch(ref, extensions.source_repository_ref) is None:
        raise ContainerProvenanceError(
            f"container provenance source ref {extensions.source_repository_ref!r} does not match {required.ref!r}"
        )
    if GIT_COMMIT_RE.fullmatch(extensions.source_repository_digest) is None:
        raise ContainerProvenanceError("container provenance source digest is not a lowercase Git commit")
    return Container(
        digest=required.digest,
        repository=required.repository,
        workflow=required.workflow,
        ref=extensions.source_repository_ref,
        commit=extensions.source_repository_digest,
    )


def ref_pattern(ref: str) -> str:
    """A requirement's ref pattern as a regular expression fragment: every ``REF_WILDCARD`` matches any run of
    characters other than ``/`` and ``@``, and every other character matches itself.

    The fragment accepts what a ``[^/@]*`` in place of each wildcard would,
    but commits to the earliest match of the literal that follows each
    wildcard except the last, so that a pattern with many wildcards cannot
    make a ref that does not match slow to reject.
    """
    first, *literals = (re.escape(literal) for literal in ref.split(REF_WILDCARD))
    if not literals:
        return first
    *committed, last = literals
    return (
        first
        + "".join(f"(?>{_REF_WILDCARD_CHARACTERS}*?{literal})" for literal in committed)
        + f"{_REF_WILDCARD_CHARACTERS}*{last}"
    )
