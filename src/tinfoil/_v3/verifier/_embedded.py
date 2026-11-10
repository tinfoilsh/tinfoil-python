"""Caller-trusted reference values that replace endorsement and renewal checks for the components they supply."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from tinfoil._v3.verifier._canonical import EncodingError, decode_lower_hex
from tinfoil._v3.verifier._document.collateral.runtime import RuntimeCollateralError, RuntimeReference
from tinfoil._v3.verifier._endorsement.approval import MAX_CONFIG_SIZE, ApprovalError, parse_name
from tinfoil._v3.verifier._errors import UsageError
from tinfoil._v3.verifier._policy import ARTIFACT_FORMAT_V2, PolicyError
from tinfoil._v3.verifier._policy import parse as parse_policy_artifact
from tinfoil._v3.verifier._runtime import ManifestError, RuntimeConfigError, decode_manifest, parse_manifest
from tinfoil._v3.verifier._runtime import runtime_from_config as _runtime_from_config

_CONFIG_DIGEST_SIZE = 32


@dataclass(frozen=True, slots=True)
class EmbeddedConfig:
    """Exact config bytes that the caller authorizes without a registry endorsement. ``name`` optionally associates
    them with a trusted ``/org/project/revision`` identity."""

    data: bytes
    name: str = ""


@dataclass(frozen=True, slots=True)
class EmbeddedConfigReference:
    """An exact config/runtime pair that the caller authorizes by digest."""

    digest: str
    """SHA-256 of the config bytes, lowercase hex."""
    runtime: RuntimeReference
    """The runtime release that the config pins."""
    name: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class EmbeddedReferences:
    """Replaces endorsement and renewal checks only for the supplied components of v3 collateral; None components
    retain normal checks.

    ``config`` is the config bytes, or a digest and runtime pin for one;
    ``runtime`` is the exact manifest that the config pins; ``platform`` is
    a platform policy artifact. Hardware authentication, component bindings
    and pins remain mandatory. These values must come from trusted client
    configuration.
    """

    config: EmbeddedConfig | EmbeddedConfigReference | None = None
    runtime: bytes | None = None
    platform: bytes | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedReferences:
    """Embedded references after validation, with config bytes reduced to their reference."""

    config: EmbeddedConfigReference | None = None
    runtime: bytes | None = None
    platform: bytes | None = None


def resolve_embedded(refs: EmbeddedReferences) -> ResolvedReferences:
    """Check the caller-trusted values and reduce them to an immutable policy.

    At least one component is required. A config must be an
    ``EmbeddedConfig`` or an ``EmbeddedConfigReference``. Config bytes must
    be within the size bounds and carry a runtime pin; a config reference must have a
    well-formed name when it has one, a lowercase SHA-256 digest and a valid
    runtime pin whose repository, tag and digest are strings, and a
    manifest supplied beside it must be the one the config pins. A manifest must decode; a platform artifact must parse
    with the v2 format. Every field must have its declared type, so that
    a caller's mistake is a UsageError and never an attribute or type
    error. Every failure is a UsageError.

    The manifest and platform bytes are copied, so a caller cannot change
    the policy through a mutable buffer after the verifier is built.
    """
    if refs.config is None and refs.runtime is None and refs.platform is None:
        raise UsageError("embedded references must contain at least one component")
    if refs.config is not None and not isinstance(refs.config, EmbeddedConfig | EmbeddedConfigReference):
        raise UsageError(
            "embedded config must be an EmbeddedConfig or EmbeddedConfigReference value, "
            f"not {type(refs.config).__name__}"
        )
    runtime_bytes = _bytes_or_none("embedded runtime manifest", refs.runtime)
    platform_bytes = _bytes_or_none("embedded platform artifact", refs.platform)
    reference: EmbeddedConfigReference | None = None
    if isinstance(refs.config, EmbeddedConfig):
        if not isinstance(refs.config.data, bytes | bytearray | memoryview):
            raise UsageError("embedded config data must be bytes")
        if not isinstance(refs.config.name, str):
            raise UsageError("embedded config name must be a string")
        data = bytes(refs.config.data)
        if not 0 < len(data) <= MAX_CONFIG_SIZE:
            raise UsageError("embedded config size is outside allowed bounds")
        try:
            runtime = _runtime_from_config(data)
        except RuntimeConfigError as err:
            raise UsageError(str(err)) from err
        reference = EmbeddedConfigReference(
            name=refs.config.name, digest=hashlib.sha256(data).hexdigest(), runtime=runtime
        )
    elif refs.config is not None:
        reference = refs.config
        if not isinstance(reference.name, str):
            raise UsageError("embedded config name must be a string")
        if not isinstance(reference.digest, str):
            raise UsageError("embedded config digest must be a string")
        if not isinstance(reference.runtime, RuntimeReference):
            raise UsageError("embedded config runtime must be a RuntimeReference value")
        for field in ("repo", "tag", "digest"):
            if not isinstance(getattr(reference.runtime, field), str):
                raise UsageError(f"embedded config runtime {field} must be a string")
    if reference is not None:
        try:
            if reference.name != "":
                parse_name(reference.name)
            decode_lower_hex("config digest", reference.digest, _CONFIG_DIGEST_SIZE)
            reference.runtime.validate()
            # Both come from the caller, so a manifest the config does not pin is rejected here rather than at
            # verification.
            if runtime_bytes is not None:
                parse_manifest(runtime_bytes, reference.runtime)
        except (ApprovalError, EncodingError, RuntimeCollateralError, ManifestError) as err:
            raise UsageError(str(err)) from err
    if runtime_bytes is not None:
        try:
            decode_manifest(runtime_bytes)
        except ManifestError as err:
            raise UsageError(str(err)) from err
    if platform_bytes is not None:
        try:
            artifact = parse_policy_artifact(platform_bytes)
        except PolicyError as err:
            raise UsageError(str(err)) from err
        if artifact.format != ARTIFACT_FORMAT_V2:
            raise UsageError("embedded platform requires platform-endorsements/v2")
    return ResolvedReferences(config=reference, runtime=runtime_bytes, platform=platform_bytes)


def _bytes_or_none(what: str, value: object) -> bytes | None:
    """A private copy of a bytes-like value, None for None; anything else is a UsageError."""
    if value is None:
        return None
    if not isinstance(value, bytes | bytearray | memoryview):
        raise UsageError(f"{what} must be bytes")
    return bytes(value)


__all__ = [
    "EmbeddedConfig",
    "EmbeddedConfigReference",
    "EmbeddedReferences",
    "ResolvedReferences",
    "resolve_embedded",
]
