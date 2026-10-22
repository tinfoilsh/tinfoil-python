"""Reference-value resolution: what the quote is appraised against, and why.

A document's collateral format selects how reference values are
authenticated:

- attestation-collaterals/v2 (legacy): a Sigstore-signed code release from
  the caller's repository and the platform-endorsements artifact, each with a
  freshness witness.
- attestation-collaterals/v3: an approved config, the runtime manifest it
  pins and the platform-endorsements artifact, each with an approval. The
  caller may embed any of them, or authorize configs itself.

The format selects a verification policy, never a trust anchor: each policy
authenticates its required entries before using their claims.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TypeVar

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from . import _formats, _policy, _provenance, _quote, _runtime
from ._errors import Layer, UsageError, VerificationError, as_usage_error, prefixed
from ._verification import ArtifactVerification, ConfigVerification, ReferenceSource
from .collateral import ConfigEndorsement, RuntimeReference
from .document import Document

ConfigAuthorizer = Callable[[ConfigEndorsement], object]
"""Approves untrusted config material by returning, or rejects it by raising."""


@dataclass(frozen=True, slots=True)
class EmbeddedConfig:
    """Exact config bytes authorized without a registry endorsement.

    ``name`` optionally associates them with a trusted
    ``/org/project/revision`` identity.
    """

    data: bytes
    name: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", bytes(self.data))


@dataclass(frozen=True, slots=True, kw_only=True)
class EmbeddedReferences:
    """Caller-trusted reference values for attestation-collaterals/v3.

    Each supplied component replaces endorsement and renewal checks for that
    component only; omitted components keep their normal checks. ``runtime``
    is the exact manifest the config pins and ``platform`` a
    platform-endorsements v2 artifact. Hardware authentication, component
    bindings and register pins still apply. These values must come from
    trusted client configuration.
    """

    config: EmbeddedConfig | None = None
    runtime: bytes | None = None
    platform: bytes | None = None

    def __post_init__(self) -> None:
        for name in ("runtime", "platform"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, bytes(value))


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedReferences:
    """Authenticated reference values and the facts a verification reports about them."""

    quote: _quote.ReferenceValues
    artifact: ArtifactVerification
    """The code (legacy) or runtime (config) release."""
    platform: ArtifactVerification | None = None
    config: ConfigVerification | None = None
    freshness_expires_at: datetime | None = None


class ReferenceResolver:
    """Authenticates a document's reference values under a fixed trust policy."""

    __slots__ = (
        "_artifact_approvals",
        "_config_approvals",
        "_config_authorizer",
        "_embedded",
        "_freshness_max_age",
        "_releases",
        "_requires_config_collateral",
    )

    def __init__(
        self,
        releases: _provenance.ReleaseVerifier,
        *,
        freshness_max_age: timedelta | None = None,
        embedded: EmbeddedReferences | None = None,
        config_authorizer: ConfigAuthorizer | None = None,
        config_signing_keys: Sequence[PublicKeyTypes] | None = None,
        freshness_signing_keys: Sequence[PublicKeyTypes] | None = None,
    ) -> None:
        """Validate the trust policy. Raises ValueError or TypeError when it is invalid."""
        if freshness_max_age is not None and freshness_max_age < timedelta(0):
            raise ValueError("freshness maximum age must not be negative")
        # Zero keeps the default, so an unset policy field never disables the bound.
        self._freshness_max_age = freshness_max_age or _provenance.MAX_FRESHNESS_AGE
        self._embedded = _validate_embedded(embedded) if embedded is not None else EmbeddedReferences()
        if config_authorizer is not None and not callable(config_authorizer):
            raise TypeError("config authorizer must be callable")
        self._config_authorizer = config_authorizer
        if config_signing_keys is not None and not config_signing_keys:
            raise ValueError("config signing keys must not be empty")
        if freshness_signing_keys is not None and not freshness_signing_keys:
            raise ValueError("freshness signing keys must not be empty")

        if self._embedded.config is not None and config_signing_keys is not None:
            raise ValueError("embedded config and config signing keys select conflicting trust sources")
        if config_authorizer is not None and (self._embedded.config is not None or config_signing_keys is not None):
            raise ValueError("config authorizer conflicts with embedded config or config signing keys")
        if (
            self._embedded.runtime is not None
            and self._embedded.platform is not None
            and freshness_signing_keys is not None
        ):
            raise ValueError("freshness signing keys have no endorsed artifact to verify")

        public_keys = _provenance.public_signing_keys()
        self._releases = releases
        self._config_approvals = releases.config_approval_verifier(config_signing_keys or public_keys)
        self._artifact_approvals = releases.artifact_approval_verifier(freshness_signing_keys or public_keys)
        self._requires_config_collateral = (
            self._embedded != EmbeddedReferences()
            or config_signing_keys is not None
            or freshness_signing_keys is not None
            or config_authorizer is not None
        )

    @property
    def freshness_max_age(self) -> timedelta:
        """The maximum age of a freshness witness or approval."""
        return self._freshness_max_age

    def resolve(self, document: Document, repo: str | None, now: datetime) -> ResolvedReferences:
        """Authenticate the reference values ``document`` carries, appraised at ``now``.

        ``repo`` is the caller's ``owner/name[@tag][@sha256:digest]``
        workload constraint, or None when an embedded config or config
        authorizer provides it.
        """
        if document.collateral_format == _formats.COLLATERAL_V3:
            return self._config_references(document, repo, now)
        if document.collateral_format == _formats.COLLATERAL_V2:
            return self._code_references(document, repo, now)
        raise ValueError(f"unsupported collateral format {document.collateral_format!r}")

    def _code_references(self, document: Document, repo: str | None, now: datetime) -> ResolvedReferences:
        if self._requires_config_collateral:
            raise ValueError(f"configured trust requires {_formats.COLLATERAL_V3}")
        code_ref = _require(
            document.sigstore_code, f"document carries no {_formats.SIGSTORE_CODE_V1} reference-values entry"
        )
        if repo is None:
            raise UsageError("a repository reference is required")
        with as_usage_error():
            pin = _provenance.parse_reference(repo)
        code = self._releases.authenticate_code(code_ref.bundle, pin, code_ref.tag, code_ref.digest)
        platform_ref = _require(
            document.sigstore_platform, f"document carries no {_formats.SIGSTORE_PLATFORM_V1} reference-values entry"
        )
        with prefixed("verifying platform endorsements"):
            endorsements = self._releases.authenticate_platform_endorsements(
                platform_ref.bundle, platform_ref.repo, platform_ref.tag, platform_ref.digest, _policy.ARTIFACT_FORMAT
            )
        with prefixed("verifying code freshness"):
            code_witnessed_at = self._authenticate_witness(document, _formats.FRESHNESS_ID_CODE, code.artifact, now)
        with prefixed("verifying platform freshness"):
            platform_witnessed_at = self._authenticate_witness(
                document, _formats.FRESHNESS_ID_PLATFORM, endorsements.artifact, now
            )
        return ResolvedReferences(
            quote=_quote.LegacyReferenceValues(
                endorsements=endorsements.policy, code=code.measurement, shape=code.shape
            ),
            artifact=_artifact_verification(code.artifact),
            freshness_expires_at=_freshness_expiration(
                self._freshness_max_age, code_witnessed_at, platform_witnessed_at
            ),
        )

    def _authenticate_witness(
        self, document: Document, entry_id: str, artifact: _provenance.AuthenticatedArtifact, now: datetime
    ) -> datetime:
        witness = _require(
            document.freshness(entry_id),
            f"document carries no {_formats.SIGSTORE_FRESHNESS_V1} reference-values entry {entry_id!r}",
        )
        if witness.format != _formats.SIGSTORE_FRESHNESS_V1:
            raise ValueError(
                f"legacy verification requires freshness collateral format {_formats.SIGSTORE_FRESHNESS_V1!r}"
            )
        return self._releases.authenticate_freshness(witness.bundle, artifact, now, self._freshness_max_age)

    def _config_references(self, document: Document, repo: str | None, now: datetime) -> ResolvedReferences:
        if self._config_authorizer is not None and repo is not None:
            raise UsageError(
                "config authorizer cannot authenticate repository or revision pins; enforce them in caller policy"
            )
        pins = _provenance.ConfigPolicy(now=now, max_age=self._freshness_max_age)
        if repo is not None or (self._embedded.config is None and self._config_authorizer is None):
            if repo is None:
                raise UsageError("a repository reference is required")
            with as_usage_error():
                reference = _provenance.parse_reference(repo)
                pins = replace(pins, identity="/" + reference.repo, revision=reference.tag, digest=reference.digest)
                pins.validate_pins()
        config, approved = self._resolve_config(document, pins)
        expected_runtime = _runtime.config_runtime(config)
        manifest, runtime_trust = self._resolve_runtime(document, expected_runtime, now)
        platform, platform_trust = self._resolve_platform(document, now)
        return ResolvedReferences(
            quote=_quote.ConfigReferenceValues(
                endorsements=platform, runtime=manifest.measurements, config_hash=hashlib.sha256(config).digest()
            ),
            artifact=runtime_trust,
            platform=platform_trust,
            config=approved,
            freshness_expires_at=_freshness_expiration(
                self._freshness_max_age,
                approved.approval_time,
                platform_trust.approval_time,
                runtime_trust.approval_time,
            ),
        )

    def _resolve_config(self, document: Document, pins: _provenance.ConfigPolicy) -> tuple[bytes, ConfigVerification]:
        embedded = self._embedded.config
        if embedded is not None:
            identity = revision = None
            if embedded.name is not None:
                identity, revision = _provenance.parse_config_name(embedded.name)
            digest = hashlib.sha256(embedded.data).hexdigest()
            if (
                (pins.identity is not None and pins.identity != identity)
                or (pins.revision is not None and pins.revision != revision)
                or (pins.digest is not None and pins.digest != digest)
            ):
                raise UsageError("embedded config does not match the caller's pins")
            return embedded.data, ConfigVerification(source=ReferenceSource.EMBEDDED, name=embedded.name, digest=digest)

        config = _require(
            document.config_endorsement, f"document carries no {_formats.CONFIG_ID!r} reference-values entry"
        )
        if self._config_authorizer is not None:
            if not 0 < len(config.config) <= _provenance.MAX_CONFIG_SIZE:
                raise ValueError("config size is outside allowed bounds")
            # The callback's error is the cause and never decides the error
            # type, even when it is one of this package's own.
            try:
                self._config_authorizer(config)
            except Exception as err:
                raise VerificationError(Layer.PROVENANCE, f"authorizing config: {err}") from err
            return config.config, ConfigVerification(
                source=ReferenceSource.POLICY, digest=hashlib.sha256(config.config).hexdigest()
            )

        if config.bundle is None:
            raise ValueError("unsigned config requires a config authorizer")
        with prefixed("verifying config approval"):
            approved = self._config_approvals.verify(config.config, config.bundle, pins)
        if config.reference != approved.reference:
            raise ValueError("config endorsement reference does not match the verified approval")
        return config.config, ConfigVerification(
            source=ReferenceSource.ENDORSEMENT,
            name=approved.name,
            digest=approved.digest,
            reference=approved.reference,
            signing_key_hint=approved.signing_key_hint,
            approval_time=approved.approval_time,
        )

    def _resolve_runtime(
        self, document: Document, expected: RuntimeReference, now: datetime
    ) -> tuple[_runtime.Manifest, ArtifactVerification]:
        if self._embedded.runtime is not None:
            manifest = _runtime.parse_manifest(self._embedded.runtime, expected)
            return manifest, ArtifactVerification(
                source=ReferenceSource.EMBEDDED, repo=expected.repo, tag=expected.tag, digest=expected.digest
            )
        material = _require(document.runtime, f"document carries no {_formats.RUNTIME_ID!r} reference-values entry")
        authenticated = self._releases.authenticate_runtime(material, expected)
        with prefixed("verifying runtime freshness"):
            approved_at = self._authenticate_approval(
                document, _formats.FRESHNESS_ID_RUNTIME, _provenance.KIND_RUNTIME, authenticated.artifact, now
            )
        return authenticated.manifest, _artifact_verification(authenticated.artifact, approved_at)

    def _resolve_platform(self, document: Document, now: datetime) -> tuple[_policy.Artifact, ArtifactVerification]:
        if self._embedded.platform is not None:
            artifact = _policy.parse(self._embedded.platform)
            return artifact, ArtifactVerification(
                source=ReferenceSource.EMBEDDED, digest=hashlib.sha256(self._embedded.platform).hexdigest()
            )
        material = _require(document.config_platform(), "document carries no platform reference-values entry")
        platform = self._releases.authenticate_platform_endorsements(
            material.bundle, material.repo, material.tag, material.digest, _policy.ARTIFACT_FORMAT_V2
        )
        if platform.artifact.subject_name != _provenance.PLATFORM_NAME:
            raise ValueError("config verification requires its dedicated platform endorsement artifact")
        with prefixed("verifying platform freshness"):
            approved_at = self._authenticate_approval(
                document, _formats.FRESHNESS_ID_PLATFORM, _provenance.KIND_PLATFORM, platform.artifact, now
            )
        return platform.policy, _artifact_verification(platform.artifact, approved_at)

    def _authenticate_approval(
        self,
        document: Document,
        entry_id: str,
        kind: str,
        artifact: _provenance.AuthenticatedArtifact,
        now: datetime,
    ) -> datetime:
        material = _require(
            document.freshness(entry_id),
            f"document carries no {_formats.ARTIFACT_FRESHNESS_V1} reference-values entry {entry_id!r}",
        )
        if material.format != _formats.ARTIFACT_FRESHNESS_V1:
            raise ValueError("config verification requires Tinfoil artifact freshness approvals")
        approved = self._artifact_approvals.verify(
            material.bundle,
            _provenance.ArtifactPolicy(
                artifact=_provenance.ReleaseArtifact(
                    kind=kind,
                    repo=artifact.repo,
                    tag=artifact.tag,
                    name=artifact.subject_name,
                    digest=artifact.digest,
                ),
                now=now,
                max_age=self._freshness_max_age,
            ),
        )
        return approved.approval_time


def _validate_embedded(references: EmbeddedReferences) -> EmbeddedReferences:
    if references == EmbeddedReferences():
        raise ValueError("embedded references must contain at least one component")
    if references.config is not None:
        if not 0 < len(references.config.data) <= _provenance.MAX_CONFIG_SIZE:
            raise ValueError("embedded config size is outside allowed bounds")
        if references.config.name is not None:
            _provenance.parse_config_name(references.config.name)
        expected = _runtime.config_runtime(references.config.data)
        # Both come from the caller, so a manifest the config does not pin is
        # rejected here rather than at verification.
        if references.runtime is not None:
            _runtime.parse_manifest(references.runtime, expected)
    if references.runtime is not None:
        _runtime.decode_manifest(references.runtime)
    if references.platform is not None:
        artifact = _policy.parse(references.platform)
        if artifact.format != _policy.ARTIFACT_FORMAT_V2:
            raise ValueError("embedded platform requires platform-endorsements/v2")
    return references


def _artifact_verification(
    artifact: _provenance.AuthenticatedArtifact, approved_at: datetime | None = None
) -> ArtifactVerification:
    return ArtifactVerification(
        source=ReferenceSource.ENDORSEMENT,
        repo=artifact.repo,
        tag=artifact.tag,
        digest=artifact.digest,
        name=artifact.subject_name,
        commit=artifact.commit,
        approval_time=approved_at,
    )


def _freshness_expiration(max_age: timedelta, *issued: datetime | None) -> datetime | None:
    """Return the earliest deadline among authenticated issue times, never derived from the local clock."""
    times = [at for at in issued if at is not None]
    return min(times) + max_age if times else None


_T = TypeVar("_T")


def _require(value: _T | None, message: str) -> _T:
    if value is None:
        raise ValueError(message)
    return value
