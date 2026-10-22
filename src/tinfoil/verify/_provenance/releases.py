"""Authentication of Fulcio-signed GitHub release artifacts.

Code provenance, the platform-endorsements artifact, runtime manifests and
freshness witnesses are each a Sigstore bundle signed by a pinned GitHub
Actions workflow identity. Verification uses an embedded Sigstore trusted
root and never touches the network.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from importlib import resources
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from .. import _policy, _runtime
from ..collateral import Runtime, RuntimeReference
from ..measurement import Measurement
from .approvals import ArtifactApprovalVerifier, ConfigApprovalVerifier

MAX_FRESHNESS_AGE = timedelta(days=7)
"""The default maximum age of a freshness witness or approval."""


class Reference(NamedTuple):
    """A parsed ``owner/name[@tag][@sha256:digest]`` release reference."""

    repo: str
    tag: str | None
    digest: str | None


def parse_reference(ref: str) -> Reference:
    """Validate ``owner/name[@tag][@sha256:digest]`` and return its parts.

    Raises ValueError for anything else.
    """
    raise NotImplementedError


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthenticatedArtifact:
    """Release identity recovered from a verified statement and its signing certificate."""

    repo: str
    tag: str
    commit: str
    subject_name: str
    digest: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Code:
    """The verified content of a code-provenance bundle."""

    artifact: AuthenticatedArtifact
    measurement: Measurement
    """The release's expected launch measurement."""
    shape: _policy.Shape
    """The VM shape the release requires."""


@dataclass(frozen=True, slots=True, kw_only=True)
class PlatformEndorsements:
    """The verified content of a platform-endorsements bundle."""

    artifact: AuthenticatedArtifact
    policy: _policy.Artifact


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthenticatedRuntime:
    """The verified content of a runtime bundle."""

    artifact: AuthenticatedArtifact
    manifest: _runtime.Manifest


class ReleaseVerifier:
    """Authenticates release artifacts against a Sigstore trusted root."""

    __slots__ = ("_trusted_root",)

    def __init__(self, trusted_root: bytes) -> None:
        """Verify against ``trusted_root``, a Sigstore trusted-root JSON document."""
        self._trusted_root = trusted_root

    @classmethod
    def embedded(cls) -> ReleaseVerifier:
        """Return a verifier for the embedded production trusted root."""
        return cls(resources.files(__package__).joinpath("trusted_root.json").read_bytes())

    def config_approval_verifier(self, keys: Sequence[PublicKeyTypes]) -> ConfigApprovalVerifier:
        """Return a verifier for config approvals signed by one of ``keys``."""
        return ConfigApprovalVerifier(self._trusted_root, keys)

    def artifact_approval_verifier(self, keys: Sequence[PublicKeyTypes]) -> ArtifactApprovalVerifier:
        """Return a verifier for artifact freshness approvals signed by one of ``keys``."""
        return ArtifactApprovalVerifier(self._trusted_root, keys)

    def authenticate_code(self, bundle: bytes, reference: Reference, tag: str | None, digest: str) -> Code:
        """Verify code provenance for the pinned ``reference``.

        Pins in ``reference`` take precedence over the document's ``tag`` and
        ``digest`` hints.
        """
        raise NotImplementedError

    def authenticate_platform_endorsements(
        self, bundle: bytes, repo: str | None, tag: str | None, digest: str, artifact_format: str
    ) -> PlatformEndorsements:
        """Verify a platform-endorsements artifact in ``artifact_format``.

        The format is chosen by the verification flow, never by collateral.
        """
        raise NotImplementedError

    def authenticate_runtime(self, material: Runtime, expected: RuntimeReference) -> AuthenticatedRuntime:
        """Verify runtime manifest provenance for the release ``expected`` pins."""
        raise NotImplementedError

    def authenticate_freshness(
        self, bundle: bytes, expected: AuthenticatedArtifact, now: datetime, max_age: timedelta
    ) -> datetime:
        """Verify a freshness witness for ``expected`` and return when it was logged.

        The witness must be no older than ``max_age`` at ``now``.
        """
        raise NotImplementedError
