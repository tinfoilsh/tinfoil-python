"""The trust that a verifier was built with, and the reference values that v3 collateral resolves under it: the
config, the runtime that it pins and the platform endorsements, each endorsed, embedded or caller-authorized."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TypeAlias

from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil._v3.verifier import _json, _semver
from tinfoil._v3.verifier._canonical import decode_lower_hex
from tinfoil._v3.verifier._document.collateral.collateral import (
    ARTIFACT_FRESHNESS_V1_FORMAT,
    FRESHNESS_ID_PLATFORM,
    FRESHNESS_ID_RUNTIME,
)
from tinfoil._v3.verifier._document.collateral.config import ConfigEndorsement
from tinfoil._v3.verifier._document.collateral.runtime import RuntimeReference
from tinfoil._v3.verifier._document.document import Document
from tinfoil._v3.verifier._embedded import ResolvedReferences
from tinfoil._v3.verifier._endorsement.approval import (
    KIND_PLATFORM,
    KIND_RUNTIME,
    MAX_CONFIG_SIZE,
    PLATFORM_NAME,
    PUBLIC_REGISTRY_ID,
    ApprovalError,
    ConfigPolicy,
    ConfigVerifier,
    FreshnessArtifact,
    FreshnessPolicy,
    FreshnessVerifier,
    parse_name,
)
from tinfoil._v3.verifier._endorsement.provenance import ProvenanceClient
from tinfoil._v3.verifier._endorsement.reference import AuthenticatedArtifact, ReleaseReferenceError, parse_reference
from tinfoil._v3.verifier._errors import LAYER_PROVENANCE, UsageError, VerificationError
from tinfoil._v3.verifier._measurement import Expected
from tinfoil._v3.verifier._policy import ARTIFACT_FORMAT_V2, Artifact
from tinfoil._v3.verifier._policy import parse as parse_policy_artifact
from tinfoil._v3.verifier._quote import ConfigReferenceValues, QuoteOptions, ReferenceValues
from tinfoil._v3.verifier._runtime import Manifest, parse_manifest, runtime_from_config
from tinfoil._v3.verifier._verification import (
    SOURCE_EMBEDDED,
    SOURCE_ENDORSEMENT,
    SOURCE_POLICY,
    ArtifactVerification,
    ConfigVerification,
)
from tinfoil._v3.verifier._x509.certificate import X509Error, load_public_key_der, load_public_key_pem

PublicKey: TypeAlias = ec.EllipticCurvePublicKey
"""A config or freshness signing key: an ECDSA P-256 public key, the one key type that approvals are signed with.
``load_public_key`` decodes one from PEM or DER."""

ConfigAuthorizer = Callable[[ConfigEndorsement], None]
"""Caller policy over detached, untrusted config material; it must raise for config bytes that it does not
authorize. It may be called concurrently. Runtime, platform and hardware checks still apply; approval does not
authenticate a registry name or timestamp. The decision is about ``config``; ``bundle`` is there for transparency,
not for the authorizer to verify."""

_P256 = ec.SECP256R1.name


def load_public_key(pem_or_der: bytes | str) -> PublicKey:
    """Decode a signing key for ``Verifier(config_signing_keys=...)`` or ``freshness_signing_keys``: a PEM
    ``PUBLIC KEY`` block as text or bytes, or a DER SubjectPublicKeyInfo. Anything that is not an ECDSA P-256
    public key, including a PEM with several blocks or DER that does not re-encode to itself, is a UsageError."""
    try:
        if isinstance(pem_or_der, str):
            key = load_public_key_pem(pem_or_der)
        elif isinstance(pem_or_der, bytes | bytearray | memoryview):
            data = bytes(pem_or_der)
            key = load_public_key_pem(data) if data.lstrip().startswith(b"-----") else load_public_key_der(data)
        else:
            raise UsageError(f"public key must be PEM text or bytes, or DER bytes, not {type(pem_or_der).__name__}")
    except X509Error as err:
        raise UsageError(str(err)) from err
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != _P256:
        raise UsageError("public key must be an ECDSA P-256 key")
    return key


_CONFIG_DIGEST_SIZE = 32


class ReferencesError(ValueError):
    """Reference values that the document carries do not satisfy the configured trust."""


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustPolicy:
    """Everything that a verifier's constructor decided: the pins, the window, the trust anchors and the
    endorsement verifiers built on them. Immutable, so a verifier is safe for concurrent use."""

    embedded: ResolvedReferences
    pinned_registers: Expected | None
    freshness_max_age: timedelta
    config_authorizer: ConfigAuthorizer | None
    endorsements: ProvenanceClient
    """Authenticates reference values against its own copy of the trusted root."""
    config_keys: tuple[PublicKey, ...] | None
    """The caller's config signing keys, or None for the registry trust built on the public keys."""
    config_verifier: ConfigVerifier
    config_registry_ids: tuple[str, ...] | None
    freshness_keys: tuple[PublicKey, ...] | None
    freshness_verifier: FreshnessVerifier
    quote_options: QuoteOptions | None
    """None in production; carries replacement vendor roots down to the CPU evidence layer for conformance."""


@dataclass(frozen=True, slots=True, kw_only=True)
class EndorsementResult:
    """What the reference-values layer resolved for the quote and for the verification record."""

    quote: ReferenceValues
    artifact: ArtifactVerification
    """The code (legacy) or runtime (config) artifact."""
    platform: ArtifactVerification | None = None
    config: ConfigVerification | None = None
    freshness_expires_at: datetime | None = None


def requires_config_collateral(trust: TrustPolicy) -> bool:
    """Whether the configured trust can only be satisfied by v3 collateral."""
    embedded = trust.embedded
    return (
        embedded.config is not None
        or embedded.runtime is not None
        or embedded.platform is not None
        or trust.config_keys is not None
        or trust.freshness_keys is not None
        or trust.config_authorizer is not None
        or trust.config_registry_ids is not None
    )


def freshness_expiration(max_age: timedelta, *approved_at: datetime | None) -> datetime | None:
    """The deadline that the earliest authenticated approval time sets, or None when every component was embedded.
    Uses authenticated witness times, never the local verification time."""
    known = [at for at in approved_at if at is not None]
    if not known:
        return None
    return min(known) + max_age


def reference_pins(trust: TrustPolicy, ref: str) -> ConfigPolicy:
    """The config pins that ``ref`` sets under the policy, or a UsageError when verification rejects ``ref``
    whatever the document. Every check of that kind belongs here, so that ``check_repo_verifiability`` makes it
    too."""
    registry_ids = trust.config_registry_ids
    if registry_ids is None and trust.config_keys is None:
        registry_ids = (PUBLIC_REGISTRY_ID,)
    if trust.config_authorizer is not None and ref != "":
        raise UsageError(
            "config authorizer cannot authenticate repository or revision pins; enforce them in caller policy"
        )
    identity = revision = digest = ""
    if ref != "":
        try:
            parsed = parse_reference(ref)
        except ReleaseReferenceError as err:
            raise UsageError(str(err)) from err
        identity, revision, digest = "/" + parsed.repo, parsed.tag, parsed.digest
    embedded = trust.embedded.config
    if embedded is not None:
        embedded_identity = embedded_revision = ""
        if embedded.name != "":
            try:
                embedded_identity, embedded_revision = parse_name(embedded.name)
            except ApprovalError as err:
                raise UsageError(str(err)) from err
        if (
            (identity != "" and identity != embedded_identity)
            or (revision != "" and revision != embedded_revision)
            or (digest != "" and digest != embedded.digest)
        ):
            raise UsageError("embedded config does not match the caller's pins")
    return ConfigPolicy(identity=identity, revision=revision, digest=digest, registry_ids=registry_ids)


def config_references(trust: TrustPolicy, doc: Document, ref: str, now: datetime) -> EndorsementResult:
    """Resolve v3 collateral: the config, the runtime that it pins and the platform endorsements, with their
    approvals appraised at ``now``.

    A pin that no document can satisfy is a UsageError; everything else is
    the provenance layer's.
    """
    pins = reference_pins(trust, ref)
    # Config identities and revisions are stricter than the repository references that v2 collateral accepts, so
    # only v3 collateral checks them.
    if pins.identity != "":
        try:
            pins.validate_pins()
        except ApprovalError as err:
            raise UsageError(str(err)) from err
    pins = replace(pins, now=now, max_age=trust.freshness_max_age)
    expected_runtime, approved = _resolve_config(trust, doc, pins)
    digest = decode_lower_hex("config digest", approved.digest, _CONFIG_DIGEST_SIZE)
    manifest, runtime_trust = _resolve_runtime(trust, doc, expected_runtime, now)
    platform, platform_trust = _resolve_platform(trust, doc, now)
    return EndorsementResult(
        quote=ConfigReferenceValues(endorsements=platform, runtime=manifest.measurements, hash=digest),
        artifact=runtime_trust,
        platform=platform_trust,
        config=approved,
        freshness_expires_at=freshness_expiration(
            trust.freshness_max_age, approved.approval_time, platform_trust.approval_time, runtime_trust.approval_time
        ),
    )


def _resolve_config(
    trust: TrustPolicy, doc: Document, pins: ConfigPolicy
) -> tuple[RuntimeReference, ConfigVerification]:
    """The runtime that the config pins and the record of how the config was accepted: embedded, authorized by the
    caller's policy, or verified against the configured endorsement trust."""
    embedded = trust.embedded.config
    if embedded is not None:
        # reference_pins matched the pins against it.
        return embedded.runtime, ConfigVerification(source=SOURCE_EMBEDDED, name=embedded.name, digest=embedded.digest)
    config = doc.config_endorsement()
    if trust.config_authorizer is not None:
        data = config.config
        if data is None or not 0 < len(data) <= MAX_CONFIG_SIZE:
            raise ReferencesError("config size is outside allowed bounds")
        try:
            trust.config_authorizer(config)
        except Exception as err:
            # The authorizer's error is the cause and never chooses the error type.
            raise VerificationError(LAYER_PROVENANCE, f"authorizing config: {err}") from err
        digest = hashlib.sha256(data).hexdigest()
        return runtime_from_config(data), ConfigVerification(source=SOURCE_POLICY, digest=digest)
    if config.bundle is None:
        raise ReferencesError("unsigned config requires a config authorizer")
    try:
        bundle = _json.strict_parse(config.bundle)
        if config.issuer is not None and trust.config_keys is None:
            approved = trust.config_verifier.verify_certified(config.config, bundle, config.issuer, pins)
        else:
            approved = trust.config_verifier.verify(config.config, bundle, pins)
    except (_json.JsonError, ApprovalError) as err:
        raise ReferencesError(f"verifying config approval: {err}") from err
    if config.reference != approved.reference:
        raise ReferencesError("config endorsement reference does not match the verified approval")
    expected = approved.runtime if approved.runtime is not None else runtime_from_config(config.config or b"")
    return expected, ConfigVerification(
        source=SOURCE_ENDORSEMENT,
        name=approved.name,
        digest=approved.digest,
        reference=approved.reference,
        signing_key_hint=approved.signing_key_hint,
        approval_time=approved.approval_time,
        registry_id=approved.registry_id,
        signature_time=approved.signature_time,
    )


def _resolve_runtime(
    trust: TrustPolicy, doc: Document, expected: RuntimeReference, now: datetime
) -> tuple[Manifest, ArtifactVerification]:
    """The manifest that the config pins: the embedded one checked against the pin, or the document's authenticated
    with its freshness approval."""
    if trust.embedded.runtime is not None:
        manifest = parse_manifest(trust.embedded.runtime, expected)
        return manifest, ArtifactVerification(
            source=SOURCE_EMBEDDED, repo=expected.repo, tag=_semver.canonical(expected.tag), digest=expected.digest
        )
    material = doc.runtime()
    authenticated = trust.endorsements.authenticate_runtime(material, expected)
    try:
        approved_at = _authenticate_artifact_freshness(
            trust, doc, FRESHNESS_ID_RUNTIME, KIND_RUNTIME, authenticated.artifact, now
        )
    except (LookupError, ValueError) as err:
        raise ReferencesError(f"verifying runtime freshness: {err}") from err
    return authenticated.manifest, _artifact_verification(authenticated.artifact, approved_at)


def _resolve_platform(trust: TrustPolicy, doc: Document, now: datetime) -> tuple[Artifact, ArtifactVerification]:
    """The platform policy artifact: the embedded one parsed, or the document's dedicated platform endorsement
    authenticated with its freshness approval."""
    if trust.embedded.platform is not None:
        artifact = parse_policy_artifact(trust.embedded.platform)
        digest = hashlib.sha256(trust.embedded.platform).hexdigest()
        return artifact, ArtifactVerification(source=SOURCE_EMBEDDED, digest=digest)
    material = doc.config_platform()
    platform = trust.endorsements.authenticate_platform_endorsements(
        material.bundle, material.repo, material.tag, material.digest, ARTIFACT_FORMAT_V2
    )
    if platform.artifact.subject_name != PLATFORM_NAME:
        raise ReferencesError("config verification requires its dedicated platform endorsement artifact")
    try:
        approved_at = _authenticate_artifact_freshness(
            trust, doc, FRESHNESS_ID_PLATFORM, KIND_PLATFORM, platform.artifact, now
        )
    except (LookupError, ValueError) as err:
        raise ReferencesError(f"verifying platform freshness: {err}") from err
    return platform.endorsements, _artifact_verification(platform.artifact, approved_at)


def _artifact_verification(artifact: AuthenticatedArtifact, approved_at: datetime | None) -> ArtifactVerification:
    return ArtifactVerification(
        source=SOURCE_ENDORSEMENT,
        repo=artifact.repo,
        tag=artifact.tag,
        digest=artifact.digest,
        name=artifact.subject_name,
        commit=artifact.commit,
        approval_time=approved_at,
    )


def _authenticate_artifact_freshness(
    trust: TrustPolicy, doc: Document, witness_id: str, kind: str, artifact: AuthenticatedArtifact, now: datetime
) -> datetime:
    """The approval time of the artifact's freshness approval, verified under the freshness keys within the
    window around ``now``."""
    material = doc.freshness(witness_id)
    if material.format != ARTIFACT_FRESHNESS_V1_FORMAT:
        raise ReferencesError("config verification requires Tinfoil artifact freshness approvals")
    approved = trust.freshness_verifier.verify(
        material.bundle,
        FreshnessPolicy(
            artifact=FreshnessArtifact(
                kind=kind, repo=artifact.repo, tag=artifact.tag, name=artifact.subject_name, digest=artifact.digest
            ),
            now=now,
            max_age=trust.freshness_max_age,
        ),
    )
    return approved.approval_time


__all__ = [
    "ConfigAuthorizer",
    "EndorsementResult",
    "PublicKey",
    "ReferencesError",
    "TrustPolicy",
    "config_references",
    "freshness_expiration",
    "load_public_key",
    "reference_pins",
    "requires_config_collateral",
]
