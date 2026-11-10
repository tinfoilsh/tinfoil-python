"""Approvals: config endorsements and artifact freshness statements signed under pinned keys, timestamped by a
trusted authority and logged in Rekor v2.

A config approval binds a config digest (and optionally its runtime pin)
to a registry; an artifact freshness approval binds a platform or runtime
release to a recent time. Both carry an inner RFC 3161 timestamp over the
canonical statement core, which establishes the approval time
independently of the signature.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._document.collateral.runtime import RuntimeReference
from tinfoil._v3.verifier._endorsement.time import TimePolicy
from tinfoil._v3.verifier._sigstore.bundle import Bundle
from tinfoil._v3.verifier._sigstore.keyed import PinnedKey
from tinfoil._v3.verifier._sigstore.keyed import key_hint as key_hint
from tinfoil._v3.verifier._sigstore.trusted_root import TrustedRoot
from tinfoil._v3.verifier._x509.certificate import Certificate, PublicKey

IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
CONFIG_PREDICATE_TYPE = "https://tinfoil.sh/predicate/config-endorsement/v1"
CONFIG_PREDICATE_TYPE_V2 = "https://tinfoil.sh/predicate/config-endorsement/v2"
ARTIFACT_FRESHNESS_PREDICATE_TYPE = "https://tinfoil.sh/predicate/artifact-freshness/v1"

MAX_CONFIG_SIZE = 1 << 20
MAX_CERTIFICATE_SIZE = 16 << 10
CERTIFICATE_VALIDITY = timedelta(minutes=10)
"""The longest validity a registry signing certificate may have."""
CERTIFICATE_CLOCK_SKEW = timedelta(minutes=1)
"""How far the inner approval time may follow the signature timestamp."""

REGISTRY_ID_PREFIX = "https://registry.tinfoil.sh/scopes/"
PUBLIC_REGISTRY_ID = REGISTRY_ID_PREFIX + "public"
REGISTRY_ID_SIZE = 16
MAX_SLUG_LENGTH = 63
MAX_REVISION_LENGTH = 128

CONFIG_FRESHNESS_DOMAIN = b"tinfoil-config-freshness/v1\x00"
CONFIG_FRESHNESS_DOMAIN_V2 = b"tinfoil-config-freshness/v2\x00"
ARTIFACT_FRESHNESS_DOMAIN = b"tinfoil-artifact-freshness/v1\x00"

KIND_PLATFORM = "platform"
KIND_RUNTIME = "runtime"
PLATFORM_REPO = "tinfoilsh/cvmimage"
RUNTIME_REPO = "tinfoilsh/cvmimage"
PLATFORM_NAME = "platform-endorsements.json"
PLATFORM_TAG_PREFIX = "platform-"


class ApprovalError(ValueError):
    """An approval that does not verify, does not match the expected artifact or is outside the time window."""


# --- Statements -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StatementSubject:
    name: str
    digest: dict[str, str]


@dataclass(frozen=True, slots=True)
class Freshness:
    rfc3161_timestamp: bytes


@dataclass(frozen=True, slots=True)
class ConfigPredicate:
    registry_id: str
    """The ``scope`` member; "" in a v1 statement."""
    runtime: RuntimeReference | None
    freshness: Freshness | None


@dataclass(frozen=True, slots=True)
class ConfigStatement:
    type: str
    subjects: tuple[StatementSubject, ...]
    predicate_type: str
    predicate: ConfigPredicate
    core: _json.JsonValue
    """The statement without its freshness member, as the JSON value that is timestamped."""

    @property
    def name(self) -> str:
        """The one subject's name: a versioned config name ``/org/project/revision``."""
        raise NotImplementedError

    @property
    def digest(self) -> str:
        """The one subject's lowercase SHA-256 digest."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class FreshnessArtifact:
    """Exact release bytes that a freshness approval covers; the caller authenticates the artifact separately."""

    kind: str
    repo: str
    tag: str
    name: str
    digest: str

    def validate(self) -> None:
        """A platform artifact is ``platform-endorsements.json`` of the platform repository at a ``platform-<semver>``
        tag; a runtime artifact is the versioned manifest of the runtime repository. The version must be canonical
        semver and the digest lowercase SHA-256."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class FreshnessPredicate:
    kind: str
    repo: str
    tag: str
    freshness: Freshness | None


@dataclass(frozen=True, slots=True)
class ArtifactFreshnessStatement:
    type: str
    subjects: tuple[StatementSubject, ...]
    predicate_type: str
    predicate: FreshnessPredicate
    core: _json.JsonValue

    @property
    def artifact(self) -> FreshnessArtifact:
        raise NotImplementedError


def validate_registry_id(registry_id: str) -> None:
    """Accept the public registry id or ``REGISTRY_ID_PREFIX`` plus 32 lowercase hex characters."""
    raise NotImplementedError


def validate_identity(identity: str) -> None:
    """Accept a canonical ``/org/project`` identity of two slug components."""
    raise NotImplementedError


def validate_identity_component(part: str) -> None:
    """Accept a lowercase slug of at most MAX_SLUG_LENGTH characters."""
    raise NotImplementedError


def validate_revision(revision: str) -> None:
    """Accept ``[A-Za-z0-9][A-Za-z0-9._-]*`` of at most MAX_REVISION_LENGTH characters."""
    raise NotImplementedError


def parse_name(name: str) -> tuple[str, str]:
    """Split a versioned config name into identity and revision, validating both; a NUL byte is an error."""
    raise NotImplementedError


def runtime_name(tag: str) -> str:
    """``tinfoil-inference-<tag>-manifest.json``."""
    raise NotImplementedError


def is_runtime_name(tag: str, name: str) -> bool:
    """Whether ``name`` is the runtime manifest name for ``tag`` (build metadata allowed in the name's version)."""
    raise NotImplementedError


def parse_config_statement(payload: bytes) -> ConfigStatement:
    """Strictly decode a config endorsement statement.

    Requires a size within MAX_STATEMENT_SIZE, the v1 statement type, a
    v1 or v2 predicate type, exactly one subject with a parseable name and
    one lowercase SHA-256 digest, and an inner timestamp within
    MAX_TIMESTAMP_SIZE. A v2 statement requires a valid registry id and
    runtime reference; a v1 statement must carry neither. Unknown members
    reject.
    """
    raise NotImplementedError


def config_timestamp_input(statement: ConfigStatement) -> bytes:
    """The bytes the inner timestamp covers: the v1 or v2 domain plus the canonical statement core."""
    raise NotImplementedError


def parse_artifact_freshness_statement(payload: bytes) -> ArtifactFreshnessStatement:
    """Strictly decode an artifact freshness statement: v1 statement type, the artifact-freshness predicate type,
    exactly one subject with one digest, a valid artifact and an inner timestamp within bounds."""
    raise NotImplementedError


def artifact_freshness_timestamp_input(statement: ArtifactFreshnessStatement) -> bytes:
    """The bytes the inner timestamp covers: the artifact-freshness domain plus the canonical statement core."""
    raise NotImplementedError


# --- Signing keys -----------------------------------------------------------


def public_signing_keys() -> tuple[PublicKey, ...]:
    """The embedded keys that authenticate registry issuers, legacy public configs and artifact approvals."""
    raise NotImplementedError


# --- Registry certificates --------------------------------------------------


def verify_signing_certificate(
    certificate_der: bytes, issuer_der: bytes, roots: Sequence[PublicKey], at: datetime
) -> tuple[Certificate, Certificate]:
    """Authenticate a registry signing certificate at ``at`` and return it with its issuer.

    The issuer's key must be one of ``roots`` and the issuer self-signed.
    The certificate must be a non-CA with valid basic constraints, key
    usage exactly digitalSignature, extended key usage exactly code
    signing, ECDSA with SHA-256, a validity no longer than
    CERTIFICATE_VALIDITY and within the issuer's, an empty subject, exactly
    one URI SAN that is a valid registry id in a critical SAN extension and
    no other names, a key that is not a root key, and it must chain to the
    issuer at ``at``.
    """
    raise NotImplementedError


# --- Verifiers --------------------------------------------------------------


class ApprovalVerifier:
    """Verifies key-signed approval bundles and inner timestamps against one trusted root and a pinned key set."""

    __slots__ = ("_keys", "_root")

    def __init__(self, root: TrustedRoot, keys: Sequence[PublicKey]) -> None:
        """Requires a root with at least one transparency log and at least one key; duplicate keys reject."""
        raise NotImplementedError

    @property
    def keys(self) -> tuple[PinnedKey, ...]:
        raise NotImplementedError

    def verify(self, bundle: Bundle, digest: bytes) -> str:
        """Verify a key-signed bundle over ``digest`` and return the signing key's hint."""
        raise NotImplementedError

    def verify_timestamp(self, response: bytes, data: bytes, policy: TimePolicy) -> datetime:
        """Verify an inner RFC 3161 timestamp over ``data`` (within MAX_STATEMENT_SIZE) with the Sigstore
        timestamp policy OID, then check the genTime against ``policy``."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class ConfigPolicy:
    """What a config approval must match, plus the clock and window; None age and skew select the defaults."""

    identity: str = ""
    revision: str = ""
    digest: str = ""
    now: datetime | None = None
    max_age: timedelta | None = None
    future_skew: timedelta | None = None
    registry_ids: tuple[str, ...] | None = (PUBLIC_REGISTRY_ID,)
    """The registries whose approvals are accepted; the public registry by default. None accepts any registry and is
    meant only for a verifier whose caller supplied its own config signing keys, where the registry is not what
    authorizes the config; an empty tuple is an error."""

    def validate_pins(self) -> None:
        """Check the identity, revision, lowercase digest and registry ids (valid, no duplicates) independently of
        the clock."""
        raise NotImplementedError

    def time_policy(self) -> TimePolicy:
        """The pins validated, then the window around ``now``."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class ConfigVerified:
    name: str
    digest: str
    reference: str
    """The endorsement reference ``sha256:...`` of the signed statement."""
    signing_key_hint: str
    approval_time: datetime
    """The inner timestamp's genTime."""
    runtime: RuntimeReference | None
    registry_id: str
    signature_time: datetime | None
    """The signature timestamp of a certified endorsement; None for a key-signed one."""


class ConfigVerifier:
    """Verifies config approvals offline; only ``keys`` can authorize one."""

    __slots__ = ("_approvals", "_root_keys")

    def __init__(self, root: TrustedRoot, keys: Sequence[PublicKey], *, root_keys: Sequence[PublicKey] = ()) -> None:
        """``root_keys`` non-empty makes this a registry verifier: certified endorsements chain to those keys and
        key-signed ones are attributed to the public registry."""
        raise NotImplementedError

    def verify(self, config: bytes | None, bundle: _json.JsonValue, policy: ConfigPolicy) -> ConfigVerified:
        """Verify a key-signed config approval.

        In order: ``config`` when given is within MAX_CONFIG_SIZE; the
        pins and window; the bundle layout; the statement parses; the
        identity, revision and digest pins match; without ``config`` the
        statement must be v2, with it the bytes must hash to the endorsed
        digest and, when the statement names a runtime, the config's
        ``cvm-version`` must equal it; a registry verifier rejects a v2
        statement here; the key-signed bundle verifies; the registry id is
        accepted; the inner timestamp verifies within the window.
        """
        raise NotImplementedError

    def verify_certified(
        self, config: bytes | None, bundle: _json.JsonValue, issuer_der: bytes, policy: ConfigPolicy
    ) -> ConfigVerified:
        """Verify a certified (v2) registry endorsement.

        Requires root keys and an issuer certificate. After the shared
        checks: the bundle's one signature timestamp verifies and falls
        within the window; the signing certificate verifies against the
        issuer at that time; its registry id equals the signed one; the
        certified bundle verifies; the inner timestamp verifies and does
        not follow the signature timestamp by more than
        CERTIFICATE_CLOCK_SKEW.
        """
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class FreshnessPolicy:
    artifact: FreshnessArtifact
    now: datetime
    max_age: timedelta | None = None
    future_skew: timedelta | None = None

    def time_policy(self) -> TimePolicy:
        """The artifact validated, then the window around ``now``."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class FreshnessVerified:
    artifact: FreshnessArtifact
    reference: str
    signing_key_hint: str
    approval_time: datetime


class FreshnessVerifier:
    """Verifies artifact freshness approvals signed under pinned keys."""

    __slots__ = ("_approvals",)

    def __init__(self, root: TrustedRoot, keys: Sequence[PublicKey]) -> None:
        raise NotImplementedError

    def verify(self, bundle: _json.JsonValue, policy: FreshnessPolicy) -> FreshnessVerified:
        """Verify an artifact freshness approval.

        In order: the window; the bundle layout; the statement parses and
        its artifact equals ``policy.artifact``; the key-signed bundle
        verifies over the artifact digest; the inner timestamp verifies
        within the window.
        """
        raise NotImplementedError
