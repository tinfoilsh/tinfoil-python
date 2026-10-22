"""Authentication of key-signed Tinfoil approvals.

Config approvals and artifact freshness approvals are DSSE bundles signed by
a pinned key rather than a Fulcio certificate. Each carries Rekor v2
inclusion proofs and an RFC 3161 timestamp inside the signed statement,
which dates the approval.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from .. import _formats

MAX_CONFIG_SIZE = 1 << 20
"""The largest config, in bytes, an approval may cover."""

KIND_PLATFORM = "platform"
KIND_RUNTIME = "runtime"
PLATFORM_REPO = _formats.RUNTIME_REPO
PLATFORM_NAME = "platform-endorsements.json"

_PUBLIC_SIGNING_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcadRPBdmNf1LPWYcY9AZ2Crrqxsy
nqzLE7k3kahjPxIM42bgZbze0GnT/EmGqe1w6So5AhmXci8By8Azt8gAhw==
-----END PUBLIC KEY-----
"""


def public_signing_keys() -> tuple[PublicKeyTypes, ...]:
    """Return Tinfoil's public config and artifact approval signing keys."""
    return (serialization.load_pem_public_key(_PUBLIC_SIGNING_KEY_PEM),)


def parse_config_name(name: str) -> tuple[str, str]:
    """Split a canonical ``/org/project/revision`` config name into identity and revision."""
    raise NotImplementedError


@dataclass(frozen=True, slots=True, kw_only=True)
class ReleaseArtifact:
    """Exact release bytes an artifact approval must name."""

    kind: str
    repo: str
    tag: str
    name: str
    digest: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigPolicy:
    """What a config approval must match: the caller's pins and the appraisal time."""

    identity: str | None = None
    """The ``/org/project`` identity."""
    revision: str | None = None
    digest: str | None = None
    now: datetime
    max_age: timedelta

    def validate_pins(self) -> None:
        """Raise ValueError unless the pins are well formed."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigApproval:
    """A verified config approval."""

    name: str
    digest: str
    reference: str
    signing_key_hint: str
    approval_time: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactPolicy:
    """What an artifact approval must match, and the appraisal time."""

    artifact: ReleaseArtifact
    now: datetime
    max_age: timedelta


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactApproval:
    """A verified artifact freshness approval."""

    artifact: ReleaseArtifact
    reference: str
    signing_key_hint: str
    approval_time: datetime


class ConfigApprovalVerifier:
    """Authenticates config approvals signed by a pinned key set."""

    __slots__ = ("_keys", "_trusted_root")

    def __init__(self, trusted_root: bytes, keys: Sequence[PublicKeyTypes]) -> None:
        self._trusted_root = trusted_root
        self._keys = tuple(keys)

    def verify(self, config: bytes, bundle: bytes, policy: ConfigPolicy) -> ConfigApproval:
        """Authenticate the approval of exact ``config`` bytes."""
        raise NotImplementedError


class ArtifactApprovalVerifier:
    """Authenticates artifact freshness approvals signed by a pinned key set."""

    __slots__ = ("_keys", "_trusted_root")

    def __init__(self, trusted_root: bytes, keys: Sequence[PublicKeyTypes]) -> None:
        self._trusted_root = trusted_root
        self._keys = tuple(keys)

    def verify(self, bundle: bytes, policy: ArtifactPolicy) -> ArtifactApproval:
        """Authenticate an approval of the artifact ``policy`` names."""
        raise NotImplementedError
