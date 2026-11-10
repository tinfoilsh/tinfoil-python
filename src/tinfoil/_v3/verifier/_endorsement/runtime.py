"""Runtime provenance: the SLSA bundle that signs the IGVM runtime manifest named by a config's runtime pin."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tinfoil._v3.verifier._document.collateral.runtime import Runtime as RuntimeCollateral
from tinfoil._v3.verifier._document.collateral.runtime import RuntimeReference
from tinfoil._v3.verifier._endorsement.reference import AuthenticatedArtifact
from tinfoil._v3.verifier._runtime import Manifest
from tinfoil._v3.verifier._sigstore.bundle import Subject

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
    raise NotImplementedError


def runtime_identity(release_tag: str) -> re.Pattern[str]:
    """The SAN pattern of the runtime release workflow: ``release.yml`` of the runtime repository at
    ``refs/tags/<release_tag>``."""
    raise NotImplementedError


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
    raise NotImplementedError


def enforce_artifact_subject(subjects: Sequence[Subject], name: str, digest: str) -> None:
    """Require exactly one subject named ``name`` whose ``sha256`` digest equals ``digest`` (case-insensitively);
    with an empty ``name``, require the first subject's digest to match instead."""
    raise NotImplementedError
