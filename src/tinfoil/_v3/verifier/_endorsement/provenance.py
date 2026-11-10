"""Release provenance: Sigstore-signed reference values verified against pinned GitHub workflow identities.

A ``ProvenanceClient`` holds one trusted root. Its methods authenticate
the code bundle, the platform-endorsements bundle, freshness witnesses
and runtime provenance, and build the approval verifiers that use the
same root.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._document.collateral.runtime import Runtime as RuntimeCollateral
from tinfoil._v3.verifier._document.collateral.runtime import RuntimeReference
from tinfoil._v3.verifier._endorsement.approval import ConfigVerifier, FreshnessVerifier
from tinfoil._v3.verifier._endorsement.reference import AuthenticatedArtifact, Reference
from tinfoil._v3.verifier._endorsement.runtime import RuntimeArtifact
from tinfoil._v3.verifier._measurement import ExpectedSEVSNP, ExpectedTDX
from tinfoil._v3.verifier._policy import Artifact, Shape
from tinfoil._v3.verifier._sigstore.bundle import Statement
from tinfoil._v3.verifier._sigstore.certificate import SigningIdentity, VerifiedBundle
from tinfoil._v3.verifier._sigstore.trusted_root import TrustedRoot
from tinfoil._v3.verifier._x509.certificate import PublicKey

MULTI_PLATFORM_PREDICATE_TYPE = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
"""The code-provenance predicate fixing a release's SEV-SNP launch measurement and its TDX RTMR1 and RTMR2."""


class ProvenanceError(ValueError):
    """Reference values that fail to authenticate or do not match the requested release."""


@dataclass(frozen=True, slots=True)
class Code:
    """The verified content of a code-provenance bundle."""

    artifact: AuthenticatedArtifact
    sevsnp: ExpectedSEVSNP
    """The registers the release fixes on SEV-SNP: the launch measurement."""
    tdx: ExpectedTDX
    """The registers the release fixes on TDX: RTMR1 and RTMR2."""
    shape: Shape | None
    """The VM shape the artifact declares."""


@dataclass(frozen=True, slots=True)
class PlatformEndorsements:
    """The verified platform-endorsements artifact."""

    artifact: AuthenticatedArtifact
    endorsements: Artifact


def signing_identity(repo: str) -> SigningIdentity:
    """The identity accepted for artifacts signed from ``repo``: any one workflow file directly under
    ``.github/workflows``, run from a tag ref, by GitHub's OIDC issuer on a GitHub-hosted runner."""
    raise NotImplementedError


def platform_endorsements_identity() -> SigningIdentity:
    """The platform-release workflow of the platform-endorsements repository, at a ``platform-v*`` tag."""
    raise NotImplementedError


def freshness_witness_identity() -> SigningIdentity:
    """The freshness workflow of the freshness-witness repository, on ``refs/heads/main``."""
    raise NotImplementedError


def workflow_identity(repo: str, workflow_pattern: str, ref_pattern: str) -> SigningIdentity:
    """A ``SigningIdentity`` for a GitHub workflow SAN pattern with the GitHub issuer and hosted runner."""
    raise NotImplementedError


class ProvenanceClient:
    """Verifies reference-values bundles against one trusted root."""

    __slots__ = ("_root",)

    def __init__(self, root: TrustedRoot) -> None:
        raise NotImplementedError

    @classmethod
    def default(cls) -> ProvenanceClient:
        """A client over the embedded trusted root."""
        raise NotImplementedError

    @classmethod
    def from_json(cls, trusted_root: bytes) -> ProvenanceClient:
        """A client over a parsed trusted-root document."""
        raise NotImplementedError

    @property
    def root(self) -> TrustedRoot:
        raise NotImplementedError

    def authenticate_code(self, bundle: _json.JsonValue, ref: Reference, tag: str, digest: str) -> Code:
        """Verify code provenance against the pinned reference.

        ``ref.tag`` and ``ref.digest`` take precedence over the document's
        ``tag`` and ``digest`` hints. The bundle must be signed from
        ``ref.repo`` over the digest, carry the multiplatform predicate
        with a ``vm_shape``, and its certificate must name a tag ref that
        equals the tag when one is known.
        """
        raise NotImplementedError

    def authenticate_platform_endorsements(
        self, bundle: _json.JsonValue, repo: str, tag: str, digest: str, artifact_format: str
    ) -> PlatformEndorsements:
        """Verify the platform-endorsements bundle.

        ``artifact_format`` is the artifact format the verification flow selected
        (v1 or v2); ``repo`` must be the platform-endorsements repository.
        The bundle must be signed by the platform-release workflow over
        the digest; the signed predicate must parse as a policy artifact
        whose format, and the statement's predicate type, equal
        ``artifact_format``.
        """
        raise NotImplementedError

    def authenticate_freshness(
        self,
        bundle: _json.JsonValue,
        expected: AuthenticatedArtifact,
        now: datetime,
        max_age: timedelta | None = None,
    ) -> datetime:
        """Verify a freshness witness for ``expected`` and return its log time; see ``freshness``."""
        raise NotImplementedError

    def authenticate_runtime(self, material: RuntimeCollateral, expected: RuntimeReference) -> RuntimeArtifact:
        """Authenticate runtime collateral against a config's runtime pin; see ``runtime``."""
        raise NotImplementedError

    def config_verifier(self, keys: Sequence[PublicKey]) -> ConfigVerifier:
        """A verifier of key-signed config approvals under ``keys``."""
        raise NotImplementedError

    def registry_verifier(self, keys: Sequence[PublicKey]) -> ConfigVerifier:
        """A verifier of config approvals whose root keys are ``keys``: certified (v2) registry endorsements and,
        for the public registry, key-signed ones."""
        raise NotImplementedError

    def freshness_verifier(self, keys: Sequence[PublicKey]) -> FreshnessVerifier:
        """A verifier of artifact freshness approvals signed under ``keys``."""
        raise NotImplementedError

    def verify_bundle(self, bundle: _json.JsonValue, repo: str, digest: str) -> VerifiedBundle:
        """Verify a bundle signed from ``repo`` (see ``signing_identity``) over ``digest``."""
        raise NotImplementedError

    def verify_bundle_with_identity(
        self, bundle: _json.JsonValue, identity: SigningIdentity, digest: str, subject_name: str = ""
    ) -> tuple[VerifiedBundle, Statement]:
        """Verify a bundle against an explicit identity and return it with its parsed statement.

        In order: the bundle parses with the v0.3 layout checks; the
        Fulcio verification runs over the lowercase decoded digest with
        ``identity``; the leaf carries no two SCTs from one CT log; the
        subject check runs (``subject_name`` empty: the first subject's
        digest must equal ``digest`` case-insensitively; otherwise exactly
        one subject with that name and digest).
        """
        raise NotImplementedError


def measurements_from_statement(statement: Statement) -> tuple[ExpectedSEVSNP, ExpectedTDX]:
    """Read the multiplatform predicate: ``snp_measurement`` and ``tdx_measurement.rtmr1``/``rtmr2`` as registers in
    either hex case. A predicate type other than the multiplatform one, or a missing or null member, is an error."""
    raise NotImplementedError


def shape_from_predicate(statement: Statement) -> Shape:
    """Read ``vm_shape``: an object with ``cpus``, ``memory_mb``, ``gpus`` and ``disks``, each a non-negative integer
    number below 2**63; a missing member or a fractional, negative or non-number value is an error."""
    raise NotImplementedError


def signed_predicate(payload: bytes) -> bytes:
    """The ``predicate`` member of a statement payload exactly as signed, which must be an object.

    The strict policy parser reads these bytes so that integer precision
    and literal forms survive.
    """
    raise NotImplementedError


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
    raise NotImplementedError


def tag_ref_pattern(tag: str) -> re.Pattern[str]:
    """An anchored pattern for ``refs/tags/<tag>`` with the tag escaped."""
    raise NotImplementedError
