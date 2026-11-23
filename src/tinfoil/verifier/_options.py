"""What a ``Verifier`` is built from: the config trust, which names who vouches for the config that an enclave runs,
and the ``Policy``, which holds the checks that apply on top of it.

Each trust choice is one value of a closed union of frozen dataclasses, so that two choices that exclude each other
cannot be written together. The values are plain data: the ``Verifier`` constructor checks them and copies what it
keeps, and raises a UsageError for a value that it cannot use.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import TypeAlias, final

from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil.verifier._document.collateral.config import ConfigEndorsement
from tinfoil.verifier._document.collateral.runtime import RuntimeReference
from tinfoil.verifier._measurement import Expected

AuthorizeConfig: TypeAlias = Callable[[ConfigEndorsement], None]
"""The ``authorize`` callable of a ``ConfigAuthorizer``."""

PublicKey: TypeAlias = ec.EllipticCurvePublicKey
"""A config or freshness signing key: an ECDSA P-256 public key, the one key type that approvals are signed with.
``load_public_key`` decodes one from PEM or DER."""


@final
@dataclass(frozen=True, slots=True)
class Registries:
    """Trusts configs that exactly these registries endorse, under Tinfoil's registry root, in place of the public
    registry alone. To keep the public registry, list ``PUBLIC_REGISTRY_ID``. An empty sequence, a string in place
    of a sequence, or a malformed ID is a UsageError."""

    ids: Sequence[str]


@final
@dataclass(frozen=True, slots=True)
class ConfigSigningKeys:
    """Trusts configs whose endorsements these ECDSA P-256 keys (``load_public_key``) sign, in place of Tinfoil's
    registry root. This explicit trust path uses no registry IDs and authorizes no artifact freshness. An empty
    sequence is a UsageError."""

    keys: Sequence[PublicKey]


@final
@dataclass(frozen=True, slots=True)
class ConfigAuthorizer:
    """Replaces config endorsement verification with the caller's policy. ``authorize`` receives detached,
    untrusted material and must raise for config bytes that it does not authorize; it may be called concurrently.
    Runtime, platform and hardware checks still apply. Approval authenticates no registry name or timestamp, so a
    ``project`` pin is a UsageError. The decision is about ``config``; ``bundle`` is there for transparency, not for
    the authorizer to verify. An ``authorize`` that is not callable is a UsageError."""

    authorize: AuthorizeConfig


@final
@dataclass(frozen=True, slots=True)
class EmbeddedConfig:
    """Trusts exact config bytes that the caller supplies, in place of a registry endorsement. ``name`` optionally
    associates them with a trusted ``/org/project/revision`` identity, which a ``project`` pin must then match. The
    config must come from trusted client configuration, and requires ``attestation-collaterals/v3``. The
    attestation must still prove every container build that the config requires."""

    data: bytes
    name: str = ""


@final
@dataclass(frozen=True, slots=True)
class EmbeddedConfigReference:
    """Trusts an exact config, identified by the SHA-256 ``digest`` of its bytes, and the runtime that it pins, in
    place of a registry endorsement. Otherwise it is ``EmbeddedConfig``, except that the container builds that the
    config requires are checked only when the attestation carries the config bytes."""

    digest: str
    """SHA-256 of the config bytes, lowercase hex."""
    runtime: RuntimeReference
    """The runtime release that the config pins."""
    name: str = ""


ConfigTrust: TypeAlias = Registries | ConfigSigningKeys | ConfigAuthorizer | EmbeddedConfig | EmbeddedConfigReference
"""Who vouches for the config that an enclave runs. None, where a ``ConfigTrust`` is optional, selects the public
registry; every other choice requires ``attestation-collaterals/v3``."""


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class EndorsedArtifacts:
    """Trusts runtime and platform artifacts that the document's endorsements authenticate and whose freshness
    approvals ``freshness_keys`` sign.

    None selects Tinfoil's public keys. Keys set here approve platform and
    runtime freshness only; they authorize no config, which the config trust
    decides. An explicit key set requires ``attestation-collaterals/v3``, and
    an empty one is a UsageError.
    """

    freshness_keys: Sequence[PublicKey] | None = None


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class EmbeddedArtifacts:
    """Trusts caller-supplied runtime and platform artifacts in place of their endorsements, and requires
    ``attestation-collaterals/v3``.

    ``runtime`` is the exact runtime manifest that the config pins, and
    ``platform`` is a ``platform-endorsements/v2`` policy artifact. No
    endorsement is consulted for a supplied artifact, even if the document
    carries one. An artifact left None is still endorsed, with its freshness
    approval signed by ``freshness_keys``, as ``EndorsedArtifacts``
    describes. At least one artifact must be supplied, and ``freshness_keys``
    must be None when both are, since nothing is left for them to verify.
    Hardware authentication, component bindings and pins remain mandatory.
    These values must come from trusted client configuration.
    """

    runtime: bytes | None = None
    platform: bytes | None = None
    freshness_keys: Sequence[PublicKey] | None = None


ArtifactTrust: TypeAlias = EndorsedArtifacts | EmbeddedArtifacts
"""How the runtime and platform artifacts are trusted. None, where an ``ArtifactTrust`` is optional, selects
``EndorsedArtifacts()``."""


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """The checks that a verifier applies on top of its config trust. ``Policy()`` keeps every default: no register
    pins, the seven-day freshness bound, and runtime and platform artifacts that Tinfoil's public keys approve."""

    pinned_registers: Expected | None = None
    """Register checks on top of the release's. Each set register must match the enclave: it fills a register that
    the release leaves open and must equal one that the release fixes. Pins for one platform reject every enclave on
    the other. It must be an ``ExpectedSEVSNP`` or ``ExpectedTDX`` value."""

    freshness_max_age: timedelta | None = None
    """How old an authenticated witness or approval may be at the verification instant. None keeps the seven-day
    default; a positive ``timedelta`` is honored as given. Zero, including a ``timedelta`` that rounds to zero
    microseconds, is a UsageError rather than a bound that would reject every witness, and so is a negative age or
    one longer than the span between the earliest and the latest representable ``datetime``."""

    artifacts: ArtifactTrust | None = None
    """How the runtime and platform artifacts are trusted; None selects ``EndorsedArtifacts()``."""


__all__ = [
    "ArtifactTrust",
    "AuthorizeConfig",
    "ConfigAuthorizer",
    "ConfigSigningKeys",
    "ConfigTrust",
    "EmbeddedArtifacts",
    "EmbeddedConfig",
    "EmbeddedConfigReference",
    "EndorsedArtifacts",
    "Policy",
    "PublicKey",
    "Registries",
]
