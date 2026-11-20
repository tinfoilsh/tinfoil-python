"""The checks of caller-trusted reference values, which replace endorsement and renewal checks for the components
that they supply."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from tinfoil.verifier._canonical import EncodingError, decode_lower_hex
from tinfoil.verifier._document.collateral.runtime import RuntimeCollateralError, RuntimeReference
from tinfoil.verifier._endorsement.approval import MAX_CONFIG_SIZE, ApprovalError, parse_name
from tinfoil.verifier._errors import UsageError
from tinfoil.verifier._options import EmbeddedArtifacts, EmbeddedConfig, EmbeddedConfigReference
from tinfoil.verifier._policy import ARTIFACT_FORMAT_V2, PolicyError
from tinfoil.verifier._policy import parse as parse_policy_artifact
from tinfoil.verifier._runtime import ManifestError, RuntimeConfigError, decode_manifest, parse_manifest
from tinfoil.verifier._runtime import runtime_from_config as _runtime_from_config

_CONFIG_DIGEST_SIZE = 32


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedReferences:
    """Embedded references after validation, with config bytes reduced to their reference."""

    config: EmbeddedConfigReference | None = None
    runtime: bytes | None = None
    platform: bytes | None = None


def resolve_artifacts(artifacts: EmbeddedArtifacts) -> ResolvedReferences:
    """Check the caller-trusted runtime manifest and platform artifact and copy them.

    At least one is required. A manifest must decode, and a platform artifact
    must parse with the v2 format. Every field must have its declared type, so
    that a caller's mistake is a UsageError and never an attribute or type
    error. The bytes are copied, so that a caller cannot change the policy
    through a mutable buffer after the verifier is built.
    """
    runtime_bytes = _bytes_or_none("embedded runtime manifest", artifacts.runtime)
    platform_bytes = _bytes_or_none("embedded platform artifact", artifacts.platform)
    if runtime_bytes is None and platform_bytes is None:
        raise UsageError("embedded artifacts must contain a runtime or a platform")
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
    return ResolvedReferences(runtime=runtime_bytes, platform=platform_bytes)


def resolve_config(config: EmbeddedConfig | EmbeddedConfigReference, runtime: bytes | None) -> EmbeddedConfigReference:
    """Check a caller-trusted config, and reduce config bytes to their reference.

    Config bytes must be within the size bounds and carry a runtime pin; a
    config reference must have a well-formed name when it has one, a
    lowercase SHA-256 digest and a valid runtime pin whose repository, tag and
    digest are strings. ``runtime``, an embedded manifest that ``resolve_artifacts``
    checked, must be the one that the config pins. Every failure is a
    UsageError.
    """
    if isinstance(config, EmbeddedConfig):
        if not isinstance(config.data, bytes | bytearray | memoryview):
            raise UsageError("embedded config data must be bytes")
        if not isinstance(config.name, str):
            raise UsageError("embedded config name must be a string")
        data = bytes(config.data)
        if not 0 < len(data) <= MAX_CONFIG_SIZE:
            raise UsageError("embedded config size is outside allowed bounds")
        try:
            pinned = _runtime_from_config(data)
        except RuntimeConfigError as err:
            raise UsageError(str(err)) from err
        reference = EmbeddedConfigReference(name=config.name, digest=hashlib.sha256(data).hexdigest(), runtime=pinned)
    else:
        reference = config
        if not isinstance(reference.name, str):
            raise UsageError("embedded config name must be a string")
        if not isinstance(reference.digest, str):
            raise UsageError("embedded config digest must be a string")
        if not isinstance(reference.runtime, RuntimeReference):
            raise UsageError("embedded config runtime must be a RuntimeReference value")
        for field in ("repo", "tag", "digest"):
            if not isinstance(getattr(reference.runtime, field), str):
                raise UsageError(f"embedded config runtime {field} must be a string")
    try:
        if reference.name != "":
            parse_name(reference.name)
        decode_lower_hex("config digest", reference.digest, _CONFIG_DIGEST_SIZE)
        reference.runtime.validate()
        # Both come from the caller, so a manifest that the config does not pin is rejected here rather than at
        # verification.
        if runtime is not None:
            parse_manifest(runtime, reference.runtime)
    except (ApprovalError, EncodingError, RuntimeCollateralError, ManifestError) as err:
        raise UsageError(str(err)) from err
    return reference


def _bytes_or_none(what: str, value: object) -> bytes | None:
    """A private copy of a bytes-like value, None for None; anything else is a UsageError."""
    if value is None:
        return None
    if not isinstance(value, bytes | bytearray | memoryview):
        raise UsageError(f"{what} must be bytes")
    return bytes(value)


__all__ = ["ResolvedReferences", "resolve_artifacts", "resolve_config"]
