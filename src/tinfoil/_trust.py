"""The trust argument of the explicit-enclave clients: who vouches for the config that the enclave runs.

Each variant is a frozen dataclass and ``Trust`` is their union. A client converts the variant into the verifier's
config trust and the pin that each verification is made against, so the verifier's own split between the two is not
visible to the caller.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, TypeAlias, final

from tinfoil._errors import ConfigurationError
from tinfoil.verifier import (
    ConfigAuthorizer,
    ConfigEndorsement,
    ConfigSigningKeys,
    ConfigTrust,
    Pin,
    PublicKey,
    Registries,
)
from tinfoil.verifier import EmbeddedConfig as _VerifierEmbeddedConfig


@final
@dataclass(frozen=True, slots=True)
class RepoPin:
    """Trusts ``attestation-collaterals/v2`` collateral for ``repo``, a GitHub repository
    ``owner/name[@tag][@sha256:digest]``. ``repo`` must not be empty."""

    repo: str


@final
@dataclass(frozen=True, slots=True)
class ProjectPin:
    """Trusts ``attestation-collaterals/v3`` collateral for ``project``, a config registry project
    ``org/project[@revision][@sha256:digest]``, that one of the trusted registries endorses. ``project`` must not be
    empty.

    ``registry_ids`` selects the trusted registries, and None and empty differ:

    - None trusts Tinfoil's public registry, ``PUBLIC_REGISTRY_ID``, alone.
    - A non-empty sequence trusts exactly the registries that it names, in
      place of the public registry. To trust a private registry alongside
      the public one, list ``PUBLIC_REGISTRY_ID`` too.
    - An empty sequence is a ConfigurationError, so that an empty list that
      the application computed fails closed rather than silently widening
      trust to the public registry.
    """

    project: str
    registry_ids: Sequence[str] | None = None


@final
@dataclass(frozen=True, slots=True)
class SignedBy:
    """Trusts ``attestation-collaterals/v3`` configs whose endorsements the caller's ECDSA P-256 ``keys``
    (``load_public_key``) sign, in place of Tinfoil's registry root. ``keys`` must not be empty. ``project``, a
    config registry project ``org/project[@revision][@sha256:digest]``, optionally restricts the configs that are
    accepted; None accepts any config that ``keys`` sign."""

    keys: Sequence[PublicKey]
    project: str | None = None


@final
@dataclass(frozen=True, slots=True)
class AuthorizedBy:
    """Trusts ``attestation-collaterals/v3`` configs that ``authorize`` accepts, in place of a registry
    endorsement. ``authorize`` receives detached, untrusted material and must raise for config bytes that it does
    not authorize; it may be called concurrently. Runtime, platform and hardware checks still apply. Approval
    authenticates no registry name or timestamp, so ``AuthorizedBy`` has no pin. ``authorize`` must be callable."""

    authorize: Callable[[ConfigEndorsement], None]


@final
@dataclass(frozen=True, slots=True)
class EmbeddedConfig:
    """Trusts ``attestation-collaterals/v3`` collateral for exactly the config bytes ``data`` that the caller
    supplies, which must come from trusted client configuration and be a JSON config, as ``cvm-version``
    0.15.5-rc.1 and later measure. ``name`` optionally associates them with a ``/org/project/revision`` identity. It
    has no pin, because a pin would only compare the caller's input against the caller's input."""

    data: bytes
    name: str = ""


@final
@dataclass(frozen=True, slots=True)
class EitherPin:
    """Trusts ``attestation-collaterals/v2`` collateral for ``repo`` or ``attestation-collaterals/v3`` collateral
    for ``project``, as ``RepoPin`` and ``ProjectPin`` do. Both must be set. It exists for the migration from v2 to
    v3 collateral and will be removed with v2."""

    repo: str
    project: str


Trust: TypeAlias = RepoPin | ProjectPin | SignedBy | AuthorizedBy | EmbeddedConfig | EitherPin
"""Who vouches for the config that an enclave runs: the required trust argument of the explicit-enclave clients.
Only ``RepoPin`` and ``EitherPin`` accept ``attestation-collaterals/v2``; every other variant requires
``attestation-collaterals/v3``."""


@dataclass(frozen=True, slots=True)
class VerifierInputs:
    """What a trust argument converts to: the verifier's config trust, the pin of each verification, and a copy of
    the trust argument that shares no mutable value with the caller's."""

    config: ConfigTrust | None
    pin: Pin
    trust: Trust


def verifier_inputs(trust: object) -> VerifierInputs:
    """Convert ``trust`` into the verifier's config trust and pin. It checks only what the variant itself requires;
    the verifier and its pin check reject the values, which the client reports as ConfigurationError. Anything but
    a ``Trust`` variant, None included, is a ConfigurationError."""
    if isinstance(trust, RepoPin):
        if not trust.repo:
            raise ConfigurationError("RepoPin requires repo")
        return VerifierInputs(None, Pin(repo=trust.repo), trust)
    if isinstance(trust, ProjectPin):
        if not trust.project:
            raise ConfigurationError("ProjectPin requires project")
        pin = Pin(project=trust.project)
        if trust.registry_ids is None:
            return VerifierInputs(None, pin, trust)
        if isinstance(trust.registry_ids, str) or not isinstance(trust.registry_ids, Sequence):
            raise ConfigurationError("ProjectPin registry_ids must be a sequence of registry IDs")
        ids = tuple(trust.registry_ids)
        if not ids:
            raise ConfigurationError(
                "ProjectPin registry_ids must not be empty; leave it None to trust the public registry"
            )
        return VerifierInputs(Registries(ids), pin, dataclasses.replace(trust, registry_ids=ids))
    if isinstance(trust, SignedBy):
        if isinstance(trust.keys, str | bytes | bytearray | memoryview) or not isinstance(trust.keys, Sequence):
            raise ConfigurationError("SignedBy keys must be a sequence of public keys")
        signed = dataclasses.replace(trust, keys=tuple(trust.keys))
        return VerifierInputs(ConfigSigningKeys(signed.keys), Pin(project=trust.project), signed)
    if isinstance(trust, AuthorizedBy):
        return VerifierInputs(ConfigAuthorizer(trust.authorize), Pin(), trust)
    if isinstance(trust, EmbeddedConfig):
        embedded = dataclasses.replace(trust, data=_frozen(trust.data))
        return VerifierInputs(_VerifierEmbeddedConfig(embedded.data, embedded.name), Pin(), embedded)
    if isinstance(trust, EitherPin):
        if not trust.repo or not trust.project:
            raise ConfigurationError("EitherPin requires both repo and project")
        return VerifierInputs(None, Pin(repo=trust.repo, project=trust.project), trust)
    raise ConfigurationError(
        "trust must be a RepoPin, ProjectPin, SignedBy, AuthorizedBy, EmbeddedConfig or EitherPin value, "
        f"not {type(trust).__name__}"
    )


def _frozen(value: Any) -> Any:
    """``value`` as an immutable copy when it is a mutable buffer, so that a client's copy of the trust argument
    shares nothing that the caller can change; any other value is returned for the verifier to check."""
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    return value


__all__ = [
    "AuthorizedBy",
    "EitherPin",
    "EmbeddedConfig",
    "ProjectPin",
    "RepoPin",
    "SignedBy",
    "Trust",
    "VerifierInputs",
    "verifier_inputs",
]
