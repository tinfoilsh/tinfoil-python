"""Approvals: config endorsements and artifact freshness statements signed under pinned keys, timestamped by a
trusted authority and logged in Rekor v2.

A config approval binds a config digest (and optionally its runtime pin)
to a registry; an artifact freshness approval binds a platform or runtime
release to a recent time. Both carry an inner RFC 3161 timestamp over the
canonical statement core, which establishes the approval time
independently of the signature.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil.verifier import _json, _semver
from tinfoil.verifier._canonical import EncodingError, decode_base64, decode_lower_hex
from tinfoil.verifier._document.collateral.runtime import RuntimeReference
from tinfoil.verifier._endorsement.reference import SHA256_DIGEST_RE
from tinfoil.verifier._endorsement.time import TimePolicy, TimePolicyError, new_time_policy
from tinfoil.verifier._runtime.config import RuntimeConfigError, runtime_from_config
from tinfoil.verifier._sigstore.bundle import (
    IN_TOTO_STATEMENT_V1,
    MAX_STATEMENT_SIZE,
    MAX_TIMESTAMP_SIZE,
    Bundle,
    BundleError,
    CertificateMaterial,
    endorsement_reference,
    parse_bundle,
)
from tinfoil.verifier._sigstore.certificate import (
    CertificateBundleError,
    signed_timestamp,
    verify_certified_bundle,
)
from tinfoil.verifier._sigstore.keyed import (
    KeyedBundleError,
    PinnedKey,
    check_layout,
    pinned_keys,
    verify_keyed_bundle,
)
from tinfoil.verifier._sigstore.keyed import key_hint as key_hint
from tinfoil.verifier._sigstore.timestamp import TimestampError, timestamp_input, verify_timestamp
from tinfoil.verifier._sigstore.trusted_root import TrustedRoot
from tinfoil.verifier._trust import PUBLIC_SIGNING_KEYS_PEM
from tinfoil.verifier._x509 import der
from tinfoil.verifier._x509.certificate import (
    OID_ECDSA_SHA256,
    OID_EKU_CODE_SIGNING,
    OID_SUBJECT_ALT_NAME,
    AnyPublicKey,
    Certificate,
    X509Error,
    basic_constraints,
    can_issue_certificates,
    certificate_public_key,
    extended_key_usage,
    extension,
    key_usage,
    load_public_key_pem,
    parse_certificate,
    signature_algorithm,
    subject_name,
    uri_sans,
    verify_certificate_signature,
    verify_chain,
)

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
RUNTIME_NAME_PREFIX = "tinfoil-inference-"
RUNTIME_NAME_SUFFIX = "-manifest.json"

_SLUG_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
_REVISION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*", re.ASCII)
_REGISTRY_HEX_RE = re.compile(rf"[0-9a-f]{{{2 * REGISTRY_ID_SIZE}}}", re.ASCII)
_DIGEST_ALGORITHM = "sha256"
_EMPTY_NAME_DER = b"\x30\x00"
_GENERAL_NAME_URI = 6

_STATEMENT_MEMBERS = ("_type", "subject", "predicateType", "predicate")
_SUBJECT_MEMBERS = ("name", "digest")
_CONFIG_PREDICATE_MEMBERS = ("scope", "runtime", "freshness")
_RUNTIME_MEMBERS = ("repo", "tag", "digest")
_FRESHNESS_MEMBERS = ("rfc3161Timestamp",)
_ARTIFACT_PREDICATE_MEMBERS = ("kind", "repo", "tag", "freshness")


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
        return self.subjects[0].name

    @property
    def digest(self) -> str:
        """The one subject's lowercase SHA-256 digest."""
        return self.subjects[0].digest[_DIGEST_ALGORITHM]


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
        version = self.tag
        if self.kind == KIND_PLATFORM:
            version = self.tag.removeprefix(PLATFORM_TAG_PREFIX)
            if version == self.tag or self.repo != PLATFORM_REPO or self.name != PLATFORM_NAME:
                raise ApprovalError("platform freshness requires the cvmimage platform artifact")
        elif self.kind == KIND_RUNTIME:
            if self.repo != RUNTIME_REPO or not is_runtime_name(self.tag, self.name):
                raise ApprovalError("runtime freshness requires the versioned runtime manifest")
        else:
            raise ApprovalError(f"unsupported freshness artifact kind {self.kind!r}")
        if not _semver.is_valid(version) or _semver.canonical(version) != version:
            raise ApprovalError("artifact tag must be a canonical semantic version")
        try:
            decode_lower_hex("artifact digest", self.digest, hashlib.sha256().digest_size)
        except EncodingError as err:
            raise ApprovalError(str(err)) from err


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
        subject = self.subjects[0]
        return FreshnessArtifact(
            kind=self.predicate.kind,
            repo=self.predicate.repo,
            tag=self.predicate.tag,
            name=subject.name,
            digest=subject.digest.get(_DIGEST_ALGORITHM, ""),
        )


def validate_registry_id(registry_id: str) -> None:
    """Accept the public registry id or ``REGISTRY_ID_PREFIX`` plus 32 lowercase hex characters."""
    if registry_id == PUBLIC_REGISTRY_ID:
        return
    if registry_id.startswith(REGISTRY_ID_PREFIX):
        identifier = registry_id[len(REGISTRY_ID_PREFIX) :]
        if _REGISTRY_HEX_RE.fullmatch(identifier) is not None:
            return
    raise ApprovalError("registry ID must be a canonical registry URI")


def validate_identity(identity: str) -> None:
    """Accept a canonical ``/org/project`` identity of two slug components."""
    parts = identity.split("/")
    if len(parts) != 3 or parts[0] != "":
        raise ApprovalError(f"invalid config identity {identity!r}")
    for part in parts[1:]:
        validate_identity_component(part)


def validate_identity_component(part: str) -> None:
    """Accept a lowercase slug of at most MAX_SLUG_LENGTH characters."""
    if len(part) > MAX_SLUG_LENGTH or _SLUG_RE.fullmatch(part) is None:
        raise ApprovalError(f"invalid config identity component {part!r}")


def validate_revision(revision: str) -> None:
    """Accept ``[A-Za-z0-9][A-Za-z0-9._-]*`` of at most MAX_REVISION_LENGTH characters."""
    if len(revision) > MAX_REVISION_LENGTH or _REVISION_RE.fullmatch(revision) is None:
        raise ApprovalError(f"invalid config revision {revision!r}")


def parse_name(name: str) -> tuple[str, str]:
    """Split a versioned config name into identity and revision, validating both; a NUL byte is an error."""
    if "\x00" in name:
        raise ApprovalError("invalid config name")
    last = name.rfind("/")
    if last < 0:
        raise ApprovalError("config name has no revision")
    identity, revision = name[:last], name[last + 1 :]
    validate_identity(identity)
    validate_revision(revision)
    return identity, revision


def runtime_name(tag: str) -> str:
    """``tinfoil-inference-<tag>-manifest.json``."""
    return RUNTIME_NAME_PREFIX + tag + RUNTIME_NAME_SUFFIX


def is_runtime_name(tag: str, name: str) -> bool:
    """Whether ``name`` is the runtime manifest name for ``tag`` (build metadata allowed in the name's version)."""
    version = name.removeprefix(RUNTIME_NAME_PREFIX).removesuffix(RUNTIME_NAME_SUFFIX)
    return _semver.is_valid(version) and version == tag + _semver.build(version) and name == runtime_name(version)


def parse_config_statement(payload: bytes) -> ConfigStatement:
    """Strictly decode a config endorsement statement.

    Requires a size within MAX_STATEMENT_SIZE, the v1 statement type, a
    v1 or v2 predicate type, exactly one subject with a parseable name and
    one lowercase SHA-256 digest, and an inner timestamp within
    MAX_TIMESTAMP_SIZE. A v2 statement requires a valid registry id and
    runtime reference; a v1 statement must carry neither. Unknown members
    reject.
    """
    _check_statement_size(payload)
    try:
        record = _statement_record(payload)
        predicate_record = _json.struct(record, "predicate", _CONFIG_PREDICATE_MEMBERS)
        runtime_record = _json.opt_struct(predicate_record, "runtime", _RUNTIME_MEMBERS)
        runtime = (
            None
            if runtime_record is None
            else RuntimeReference(
                repo=_json.string(runtime_record, "repo"),
                tag=_json.string(runtime_record, "tag"),
                digest=_json.string(runtime_record, "digest"),
            )
        )
        predicate = ConfigPredicate(
            registry_id=_json.string(predicate_record, "scope"),
            runtime=runtime,
            freshness=_freshness(predicate_record),
        )
        subjects = _subjects(record)
        statement_type = _json.string(record, "_type")
        predicate_type = _json.string(record, "predicateType")
    except (_json.JsonError, EncodingError) as err:
        raise ApprovalError(f"decoding config endorsement: {err}") from err

    if statement_type != IN_TOTO_STATEMENT_V1 or predicate_type not in (
        CONFIG_PREDICATE_TYPE,
        CONFIG_PREDICATE_TYPE_V2,
    ):
        raise ApprovalError("unsupported config endorsement statement type")
    if predicate_type == CONFIG_PREDICATE_TYPE_V2:
        validate_registry_id(predicate.registry_id)
        if predicate.runtime is None:
            raise ApprovalError("config endorsement requires a runtime reference")
        try:
            predicate.runtime.validate()
        except ValueError as err:
            raise ApprovalError(str(err)) from err
    elif predicate.runtime is not None or predicate.registry_id != "":
        raise ApprovalError("v1 config endorsement cannot contain a runtime reference")
    if len(subjects) != 1:
        raise ApprovalError("config endorsement requires exactly one subject")
    parse_name(subjects[0].name)
    digest = subjects[0].digest
    if len(digest) != 1 or SHA256_DIGEST_RE.fullmatch(digest.get(_DIGEST_ALGORITHM, "")) is None:
        raise ApprovalError("subject requires one lowercase SHA-256 digest")
    _check_inner_timestamp(predicate.freshness, "config endorsement requires an inner timestamp")

    predicate_core: dict[str, _json.JsonValue] = {}
    if predicate.registry_id != "":
        predicate_core["scope"] = predicate.registry_id
    if predicate.runtime is not None:
        predicate_core["runtime"] = _json.JsonObject(
            {"repo": predicate.runtime.repo, "tag": predicate.runtime.tag, "digest": predicate.runtime.digest}
        )
    core = _core(statement_type, subjects, predicate_type, _json.JsonObject(predicate_core))
    return ConfigStatement(
        type=statement_type, subjects=subjects, predicate_type=predicate_type, predicate=predicate, core=core
    )


def config_timestamp_input(statement: ConfigStatement) -> bytes:
    """The bytes the inner timestamp covers: the v1 or v2 domain plus the canonical statement core."""
    domain = (
        CONFIG_FRESHNESS_DOMAIN_V2 if statement.predicate_type == CONFIG_PREDICATE_TYPE_V2 else CONFIG_FRESHNESS_DOMAIN
    )
    return timestamp_input(domain, statement.core)


def parse_artifact_freshness_statement(payload: bytes) -> ArtifactFreshnessStatement:
    """Strictly decode an artifact freshness statement: v1 statement type, the artifact-freshness predicate type,
    exactly one subject with one digest, a valid artifact and an inner timestamp within bounds."""
    _check_statement_size(payload)
    try:
        record = _statement_record(payload)
        predicate_record = _json.struct(record, "predicate", _ARTIFACT_PREDICATE_MEMBERS)
        predicate = FreshnessPredicate(
            kind=_json.string(predicate_record, "kind"),
            repo=_json.string(predicate_record, "repo"),
            tag=_json.string(predicate_record, "tag"),
            freshness=_freshness(predicate_record),
        )
        subjects = _subjects(record)
        statement_type = _json.string(record, "_type")
        predicate_type = _json.string(record, "predicateType")
    except (_json.JsonError, EncodingError) as err:
        raise ApprovalError(f"decoding artifact freshness statement: {err}") from err

    if (
        statement_type != IN_TOTO_STATEMENT_V1
        or predicate_type != ARTIFACT_FRESHNESS_PREDICATE_TYPE
        or len(subjects) != 1
        or len(subjects[0].digest) != 1
    ):
        raise ApprovalError("unsupported artifact freshness statement")
    statement = ArtifactFreshnessStatement(
        type=statement_type,
        subjects=subjects,
        predicate_type=predicate_type,
        predicate=predicate,
        core=_core(
            statement_type,
            subjects,
            predicate_type,
            _json.JsonObject({"kind": predicate.kind, "repo": predicate.repo, "tag": predicate.tag}),
        ),
    )
    statement.artifact.validate()
    _check_inner_timestamp(predicate.freshness, "artifact freshness requires an inner timestamp")
    return statement


def artifact_freshness_timestamp_input(statement: ArtifactFreshnessStatement) -> bytes:
    """The bytes the inner timestamp covers: the artifact-freshness domain plus the canonical statement core."""
    return timestamp_input(ARTIFACT_FRESHNESS_DOMAIN, statement.core)


def _check_statement_size(payload: bytes) -> None:
    if not 0 < len(payload) <= MAX_STATEMENT_SIZE:
        raise ApprovalError("statement size is outside allowed bounds")


def _statement_record(payload: bytes) -> _json.JsonObject:
    value = _json.strict_parse(payload)
    if value is None:
        raise ApprovalError("statement is null")
    return _json.object_(value, "statement", _STATEMENT_MEMBERS)


def _subjects(record: _json.JsonObject) -> tuple[StatementSubject, ...]:
    out: list[StatementSubject] = []
    for index, item in enumerate(_json.array(record, "subject") or ()):
        subject = _json.object_(item, f"subject[{index}]", _SUBJECT_MEMBERS)
        digest = _json.mapping(subject, "digest", _digest_value)
        out.append(StatementSubject(name=_json.string(subject, "name"), digest=digest))
    return tuple(out)


def _digest_value(value: _json.JsonValue, algorithm: str) -> str:
    # A null digest value decodes as the empty string, like any null string member.
    if value is None:
        return ""
    if not isinstance(value, str):
        raise _json.JsonError(f"cannot unmarshal JSON value into string within digest {algorithm!r}")
    return value


def _freshness(predicate_record: _json.JsonObject) -> Freshness | None:
    freshness_record = _json.opt_struct(predicate_record, "freshness", _FRESHNESS_MEMBERS)
    if freshness_record is None:
        return None
    encoded = _json.string(freshness_record, "rfc3161Timestamp")
    return Freshness(rfc3161_timestamp=decode_base64("rfc3161Timestamp", encoded))


def _check_inner_timestamp(freshness: Freshness | None, missing: str) -> None:
    if freshness is None or len(freshness.rfc3161_timestamp) == 0:
        raise ApprovalError(missing)
    if len(freshness.rfc3161_timestamp) > MAX_TIMESTAMP_SIZE:
        raise ApprovalError("inner timestamp exceeds size limit")


def _core(
    statement_type: str, subjects: tuple[StatementSubject, ...], predicate_type: str, predicate: _json.JsonObject
) -> _json.JsonValue:
    """The statement rebuilt from its decoded members without the freshness member, in the member order of the
    signed form; canonicalization orders the members when the core is timestamped."""
    return _json.JsonObject(
        {
            "_type": statement_type,
            "subject": tuple(
                _json.JsonObject({"name": subject.name, "digest": _json.JsonObject(dict(subject.digest))})
                for subject in subjects
            ),
            "predicateType": predicate_type,
            "predicate": predicate,
        }
    )


# --- Signing keys -----------------------------------------------------------


def public_signing_keys() -> tuple[ec.EllipticCurvePublicKey, ...]:
    """The embedded keys that authenticate registry issuers, legacy public configs and artifact approvals: ECDSA
    P-256 keys, the one type that key hints are computed over."""
    keys = []
    for pem in PUBLIC_SIGNING_KEYS_PEM:
        key = load_public_key_pem(pem)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise X509Error("public signing key is not an ECDSA key")
        keys.append(key)
    return tuple(keys)


# --- Registry certificates --------------------------------------------------


def verify_signing_certificate(
    certificate_der: bytes, issuer_der: bytes, roots: Sequence[AnyPublicKey], at: datetime
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
    if (
        not isinstance(at, datetime)
        or at.tzinfo is None
        or at.utcoffset() is None
        or not 0 < len(certificate_der) <= MAX_CERTIFICATE_SIZE
        or not 0 < len(issuer_der) <= MAX_CERTIFICATE_SIZE
    ):
        raise ApprovalError("signing certificate requires a time and bounded certificate bytes")
    try:
        certificate = parse_certificate(certificate_der)
        issuer = parse_certificate(issuer_der)
        issuer_hint = key_hint(certificate_public_key(issuer))
        trusted = [key_hint(root) for root in roots]
    except (X509Error, KeyedBundleError) as err:
        raise ApprovalError(str(err)) from err
    if issuer_hint not in trusted:
        raise ApprovalError("untrusted registry root")
    try:
        if not can_issue_certificates(issuer):
            raise X509Error("issuer is not a certificate authority")
        verify_certificate_signature(issuer, issuer)
    except X509Error as err:
        raise ApprovalError(f"invalid registry root certificate: {err}") from err
    try:
        if not _signing_certificate_profile(certificate, issuer):
            raise ApprovalError("invalid config signing certificate profile")
        sans = uri_sans(certificate)
    except X509Error as err:
        raise ApprovalError(f"invalid config signing certificate profile: {err}") from err
    if len(sans) != 1:
        raise ApprovalError("invalid config signing certificate profile")
    validate_registry_id(sans[0])
    if not _single_critical_uri_san(certificate, sans[0]):
        raise ApprovalError("registry identity requires exactly one critical URI SAN")
    try:
        hint = key_hint(certificate_public_key(certificate))
    except (X509Error, KeyedBundleError) as err:
        raise ApprovalError(str(err)) from err
    if hint in trusted:
        raise ApprovalError("registry root cannot serve as a config signing key")
    try:
        verify_chain(certificate, [], [issuer], at, extended_key_usage=OID_EKU_CODE_SIGNING)
    except X509Error as err:
        raise ApprovalError(f"verifying config signing certificate: {err}") from err
    return certificate, issuer


def _signing_certificate_profile(certificate: Certificate, issuer: Certificate) -> bool:
    """Whether the certificate's constraints, usages, algorithm, validity and subject fit the registry profile."""
    constraints = basic_constraints(certificate)
    if constraints is None or constraints[0]:
        return False
    usage = key_usage(certificate)
    if usage is None or not usage[0] or any(usage[1:]):
        return False
    if extended_key_usage(certificate) != (OID_EKU_CODE_SIGNING,):
        return False
    outer = der.children(der.decode(certificate.public_bytes(serialization.Encoding.DER)))
    try:
        algorithm = signature_algorithm(outer[1])
    except X509Error:
        return False
    if algorithm.oid != OID_ECDSA_SHA256:
        return False
    not_before, not_after = certificate.not_valid_before_utc, certificate.not_valid_after_utc
    if not_after - not_before > CERTIFICATE_VALIDITY:
        return False
    if not_before < issuer.not_valid_before_utc or not_after > issuer.not_valid_after_utc:
        return False
    return subject_name(certificate) == _EMPTY_NAME_DER


def _single_critical_uri_san(certificate: Certificate, uri: str) -> bool:
    """Whether the subjectAltName extension is critical and holds exactly one primitive URI name equal to ``uri``."""
    ext = extension(certificate, OID_SUBJECT_ALT_NAME)
    if ext is None or not ext.critical:
        return False
    try:
        names = der.expect_sequence(der.decode(ext.value), "GeneralNames")
    except der.DerError:
        return False
    if len(names) != 1:
        return False
    name = names[0]
    return (
        name.tag_class == der.CLASS_CONTEXT
        and name.tag == _GENERAL_NAME_URI
        and not name.constructed
        and name.content == uri.encode("ascii")
    )


# --- Verifiers --------------------------------------------------------------


class ApprovalVerifier:
    """Verifies key-signed approval bundles and inner timestamps against one trusted root and a pinned key set."""

    __slots__ = ("_keys", "_root")

    def __init__(self, root: TrustedRoot, keys: Sequence[AnyPublicKey]) -> None:
        """Requires a root with at least one transparency log and at least one key; duplicate keys reject."""
        if not root.tlogs:
            raise ApprovalError("Rekor trust is required")
        try:
            self._keys = pinned_keys(keys)
        except KeyedBundleError as err:
            raise ApprovalError(str(err)) from err
        self._root = root

    @property
    def keys(self) -> tuple[PinnedKey, ...]:
        return self._keys

    @property
    def root(self) -> TrustedRoot:
        return self._root

    def verify(self, bundle: Bundle, digest: bytes) -> str:
        """Verify a key-signed bundle over ``digest`` and return the signing key's hint."""
        try:
            return verify_keyed_bundle(self._root, bundle, self._keys, digest)
        except (KeyedBundleError, BundleError) as err:
            raise ApprovalError(f"verifying endorsement bundle: {err}") from err

    def verify_timestamp(self, response: bytes, data: bytes, policy: TimePolicy) -> datetime:
        """Verify an inner RFC 3161 timestamp over ``data`` (within MAX_STATEMENT_SIZE) with the Sigstore
        timestamp policy OID, then check the genTime against ``policy``."""
        try:
            at = verify_timestamp(self._root, response, data)
            policy.verify(at)
        except (TimestampError, TimePolicyError) as err:
            raise ApprovalError(str(err)) from err
        return at


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
        if self.identity != "":
            validate_identity(self.identity)
        if self.revision != "":
            validate_revision(self.revision)
        if self.digest != "" and SHA256_DIGEST_RE.fullmatch(self.digest) is None:
            raise ApprovalError("digest pin must be lowercase SHA-256")
        if self.registry_ids is not None and len(self.registry_ids) == 0:
            raise ApprovalError("config registry IDs must not be empty")
        registry_ids = self.registry_ids or ()
        for index, registry_id in enumerate(registry_ids):
            validate_registry_id(registry_id)
            if registry_id in registry_ids[:index]:
                raise ApprovalError("duplicate config registry ID")

    def time_policy(self) -> TimePolicy:
        """The pins validated, then the window around ``now``."""
        self.validate_pins()
        if self.now is None:
            raise TimePolicyError("clock and nonnegative age and skew are required")
        return new_time_policy(self.now, self.max_age, self.future_skew)


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

    def __init__(
        self, root: TrustedRoot, keys: Sequence[AnyPublicKey], *, root_keys: Sequence[AnyPublicKey] = ()
    ) -> None:
        """``root_keys`` non-empty makes this a registry verifier: certified endorsements chain to those keys and
        key-signed ones are attributed to the public registry."""
        self._approvals = ApprovalVerifier(root, keys)
        self._root_keys = tuple(root_keys)

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
        return self._verify(config, bundle, None, policy)

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
        if not self._root_keys:
            raise ApprovalError("registry root trust is not configured")
        if not issuer_der:
            raise ApprovalError("certified registry verification requires an issuer certificate")
        return self._verify(config, bundle, issuer_der, policy)

    def _verify(
        self, config: bytes | None, bundle: _json.JsonValue, issuer_der: bytes | None, policy: ConfigPolicy
    ) -> ConfigVerified:
        if config is not None and not 0 < len(config) <= MAX_CONFIG_SIZE:
            raise ApprovalError("config size is outside allowed bounds")
        try:
            time_policy = policy.time_policy()
        except TimePolicyError as err:
            raise ApprovalError(str(err)) from err
        parsed = _parse_approval_bundle(bundle)
        payload = parsed.envelope.payload
        statement = parse_config_statement(payload)
        identity, revision = parse_name(statement.name)
        if (policy.identity != "" and identity != policy.identity) or (
            policy.revision != "" and revision != policy.revision
        ):
            raise ApprovalError("config endorsement does not match the pinned identity or revision")
        hex_digest = statement.digest
        if policy.digest != "" and policy.digest != hex_digest:
            raise ApprovalError("config endorsement does not match the pinned digest")
        if config is None:
            if statement.predicate_type != CONFIG_PREDICATE_TYPE_V2:
                raise ApprovalError("digest verification requires a v2 config endorsement")
        else:
            if hashlib.sha256(config).hexdigest() != hex_digest:
                raise ApprovalError("config bytes do not match the endorsed digest")
            if statement.predicate.runtime is not None:
                try:
                    runtime = runtime_from_config(config)
                except RuntimeConfigError as err:
                    raise ApprovalError(str(err)) from err
                if runtime != statement.predicate.runtime:
                    raise ApprovalError("config runtime does not match the endorsed runtime")
        digest = bytes.fromhex(hex_digest)
        signed_at: datetime | None = None
        if issuer_der is not None:
            if statement.predicate_type != CONFIG_PREDICATE_TYPE_V2:
                raise ApprovalError("certified registry endorsement requires a v2 statement")
            signed_at = self._signature_time(parsed)
            try:
                time_policy.verify(signed_at)
            except TimePolicyError as err:
                raise ApprovalError(str(err)) from err
            material = parsed.material
            certificate_der = material.certificate if isinstance(material, CertificateMaterial) else b""
            certificate, issuer = verify_signing_certificate(certificate_der, issuer_der, self._root_keys, signed_at)
            registry_id = uri_sans(certificate)[0]
            if registry_id != statement.predicate.registry_id:
                raise ApprovalError("certificate registry ID does not match signed registry ID")
            try:
                verify_certified_bundle(self._approvals.root, parsed, issuer, registry_id, digest, signed_at)
                hint = key_hint(certificate_public_key(certificate))
            except (CertificateBundleError, KeyedBundleError, X509Error) as err:
                raise ApprovalError(str(err)) from err
        else:
            if self._root_keys and statement.predicate_type == CONFIG_PREDICATE_TYPE_V2:
                raise ApprovalError("v2 registry endorsement requires an issuer certificate")
            hint = self._approvals.verify(parsed, digest)
            registry_id = PUBLIC_REGISTRY_ID if self._root_keys else ""
        if policy.registry_ids is not None and registry_id not in policy.registry_ids:
            raise ApprovalError("config registry ID is not accepted by the caller")
        freshness = statement.predicate.freshness
        if freshness is None:  # parse_config_statement requires one; this narrows the type
            raise ApprovalError("config endorsement requires an inner timestamp")
        try:
            inner = self._approvals.verify_timestamp(
                freshness.rfc3161_timestamp, config_timestamp_input(statement), time_policy
            )
        except ApprovalError as err:
            raise ApprovalError(f"inner timestamp: {err}") from err
        if signed_at is not None and inner > signed_at + CERTIFICATE_CLOCK_SKEW:
            raise ApprovalError("approval timestamp follows signature timestamp")
        return ConfigVerified(
            name=statement.name,
            digest=hex_digest,
            reference=endorsement_reference(payload),
            signing_key_hint=hint,
            approval_time=inner,
            runtime=statement.predicate.runtime,
            registry_id=registry_id,
            signature_time=signed_at,
        )

    def _signature_time(self, bundle: Bundle) -> datetime:
        """The verified genTime of the bundle's one signature timestamp."""
        try:
            return signed_timestamp(self._approvals.root, bundle)
        except CertificateBundleError as err:
            raise ApprovalError(f"signature timestamp: {err}") from err


@dataclass(frozen=True, slots=True)
class FreshnessPolicy:
    artifact: FreshnessArtifact
    now: datetime
    max_age: timedelta | None = None
    future_skew: timedelta | None = None

    def time_policy(self) -> TimePolicy:
        """The artifact validated, then the window around ``now``."""
        self.artifact.validate()
        return new_time_policy(self.now, self.max_age, self.future_skew)


@dataclass(frozen=True, slots=True)
class FreshnessVerified:
    artifact: FreshnessArtifact
    reference: str
    signing_key_hint: str
    approval_time: datetime


class FreshnessVerifier:
    """Verifies artifact freshness approvals signed under pinned keys."""

    __slots__ = ("_approvals",)

    def __init__(self, root: TrustedRoot, keys: Sequence[AnyPublicKey]) -> None:
        self._approvals = ApprovalVerifier(root, keys)

    def verify(self, bundle: _json.JsonValue, policy: FreshnessPolicy) -> FreshnessVerified:
        """Verify an artifact freshness approval.

        In order: the window; the bundle layout; the statement parses and
        its artifact equals ``policy.artifact``; the key-signed bundle
        verifies over the artifact digest; the inner timestamp verifies
        within the window.
        """
        try:
            time_policy = policy.time_policy()
        except TimePolicyError as err:
            raise ApprovalError(str(err)) from err
        parsed = _parse_approval_bundle(bundle)
        payload = parsed.envelope.payload
        statement = parse_artifact_freshness_statement(payload)
        if statement.artifact != policy.artifact:
            raise ApprovalError("freshness approval does not match the expected artifact")
        hint = self._approvals.verify(parsed, bytes.fromhex(policy.artifact.digest))
        freshness = statement.predicate.freshness
        if freshness is None:  # parse_artifact_freshness_statement requires one; this narrows the type
            raise ApprovalError("artifact freshness requires an inner timestamp")
        try:
            at = self._approvals.verify_timestamp(
                freshness.rfc3161_timestamp, artifact_freshness_timestamp_input(statement), time_policy
            )
        except ApprovalError as err:
            raise ApprovalError(f"inner timestamp: {err}") from err
        return FreshnessVerified(
            artifact=policy.artifact, reference=endorsement_reference(payload), signing_key_hint=hint, approval_time=at
        )


def _parse_approval_bundle(bundle: _json.JsonValue) -> Bundle:
    """Decode an approval bundle and check its layout: a certified bundle carries one signature timestamp, a
    key-signed one none."""
    try:
        parsed = parse_bundle(bundle)
    except BundleError as err:
        raise ApprovalError(f"parsing endorsement bundle: {err}") from err
    try:
        check_layout(parsed, timestamps="one" if isinstance(parsed.material, CertificateMaterial) else "none")
    except KeyedBundleError as err:
        raise ApprovalError(str(err)) from err
    return parsed
