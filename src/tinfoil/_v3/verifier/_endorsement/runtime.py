"""Runtime provenance: the SLSA bundle that signs the IGVM runtime manifest named by a config's runtime pin."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from tinfoil._v3.verifier import _semver
from tinfoil._v3.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference
from tinfoil._v3.verifier._document.collateral.runtime import Runtime as RuntimeCollateral
from tinfoil._v3.verifier._endorsement.reference import AuthenticatedArtifact
from tinfoil._v3.verifier._runtime import Manifest, ManifestError, parse_manifest
from tinfoil._v3.verifier._sigstore.bundle import IN_TOTO_STATEMENT_V1, Subject
from tinfoil._v3.verifier._sigstore.certificate import (
    GITHUB_OIDC_ISSUER,
    RUNNER_ENVIRONMENT_GITHUB_HOSTED,
    SigningIdentity,
    workflow_identity_pattern,
)

if TYPE_CHECKING:
    from tinfoil._v3.verifier._endorsement.provenance import ProvenanceClient

SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
RUNTIME_SUBJECT_PREFIX = "tinfoil-inference-"
RUNTIME_SUBJECT_SUFFIX = "-manifest.json"


class RuntimeProvenanceError(ValueError):
    """Runtime collateral that does not match its pin or whose provenance does not verify."""


@dataclass(frozen=True, slots=True)
class RuntimeArtifact:
    """An authenticated runtime release and its parsed manifest."""

    artifact: AuthenticatedArtifact
    manifest: Manifest


def runtime_subject_name(tag: str) -> str:
    """``tinfoil-inference-<tag>-manifest.json``."""
    return RUNTIME_SUBJECT_PREFIX + tag + RUNTIME_SUBJECT_SUFFIX


def runtime_identity(release_tag: str) -> re.Pattern[str]:
    """The SAN pattern of the runtime release workflow: ``release.yml`` of the runtime repository at
    ``refs/tags/<release_tag>``."""
    return workflow_identity_pattern(RUNTIME_REPO, r"release\.yml", "refs/tags/" + re.escape(release_tag))


def authenticate_runtime(
    client: ProvenanceClient, material: RuntimeCollateral, expected: RuntimeReference
) -> RuntimeArtifact:
    """Authenticate runtime collateral against the config's runtime pin.

    In order: the collateral's reference equals ``expected``; the manifest
    parses against ``expected`` (digest, then version); the bundle verifies
    as a Fulcio bundle signed by the runtime release workflow at the
    canonical form of ``expected.tag``, over ``expected.digest``, with the
    manifest's subject name matching exactly one subject; the statement is
    SLSA v1; the signing certificate's repository and owner ids are the
    pinned runtime repository and organization, its ref is the release tag
    and its commit is well formed.
    """
    from tinfoil._v3.verifier._endorsement.provenance import ProvenanceError, authenticated_artifact

    if material.reference != expected:
        raise RuntimeProvenanceError("runtime collateral does not match the endorsed config's runtime pin")
    try:
        manifest = parse_manifest(material.manifest, expected)
    except ManifestError as err:
        raise RuntimeProvenanceError(str(err)) from err
    subject = runtime_subject_name(expected.tag)
    release_tag = _semver.canonical(expected.tag)
    identity = SigningIdentity(
        san=runtime_identity(release_tag),
        issuer=GITHUB_OIDC_ISSUER,
        runner_environment=RUNNER_ENVIRONMENT_GITHUB_HOSTED,
    )
    try:
        verified, statement = client.verify_bundle_with_identity(material.bundle, identity, expected.digest, subject)
    except ProvenanceError as err:
        raise RuntimeProvenanceError(f"verifying runtime provenance: {err}") from err
    if statement.type != IN_TOTO_STATEMENT_V1 or statement.predicate_type != SLSA_PROVENANCE_V1:
        raise RuntimeProvenanceError("runtime provenance must use SLSA v1")
    try:
        artifact = authenticated_artifact(verified, statement, expected.repo, release_tag, expected.digest, "runtime")
    except ProvenanceError as err:
        raise RuntimeProvenanceError(str(err)) from err
    return RuntimeArtifact(artifact=replace(artifact, subject_name=subject), manifest=manifest)


def enforce_artifact_subject(subjects: Sequence[Subject], name: str, digest: str) -> None:
    """Require exactly one subject named ``name`` whose ``sha256`` digest equals ``digest`` (case-insensitively);
    with an empty ``name``, require the first subject's digest to match instead."""
    if name == "":
        if not subjects:
            raise RuntimeProvenanceError("in-toto statement has no subject")
        got = subjects[0].digest.get("sha256", "")
        if got.lower() != digest.lower():
            raise RuntimeProvenanceError(
                f"subject[0] digest {got!r} does not match expected artifact digest {digest!r}"
            )
        return
    matches = 0
    for subject in subjects:
        if subject.name != name:
            continue
        if subject.digest.get("sha256", "").lower() != digest.lower():
            raise RuntimeProvenanceError("runtime provenance subject digest does not match")
        matches += 1
    if matches != 1:
        raise RuntimeProvenanceError("runtime provenance requires exactly one matching manifest subject")
