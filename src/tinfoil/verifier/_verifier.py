"""Appraisal of attestation documents.

Given a document, the nonce the caller bound it to and the repository or
registry project the caller trusts, a ``Verifier`` decides what the document
proves. It opens no
connections and keeps no state between calls, so fetching documents, caching
a verification and enforcing its expiry all belong to the caller.

It raises two error types: a ``UsageError`` when the verifier is built or
called with invalid inputs, and a ``VerificationError`` when the document
must not be trusted.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from tinfoil._sdkinfo import SDK_NAME, sdk_version
from tinfoil.verifier._config import (
    EndorsementResult,
    ReferencesError,
    TrustPolicy,
    config_references,
    freshness_expiration,
    reference_pins,
    requires_config_collateral,
)
from tinfoil.verifier._document.collateral.collateral import (
    FORMAT_V2,
    FORMAT_V3,
    FRESHNESS_ID_CODE,
    FRESHNESS_ID_PLATFORM,
    SIGSTORE_FRESHNESS_V1_FORMAT,
)
from tinfoil.verifier._document.document import Document, InvalidInputError, parse
from tinfoil.verifier._embedded import ResolvedReferences, resolve_artifacts, resolve_config
from tinfoil.verifier._endorsement.approval import ApprovalError, ConfigPolicy, public_signing_keys
from tinfoil.verifier._endorsement.provenance import ProvenanceClient, ProvenanceError
from tinfoil.verifier._endorsement.reference import AuthenticatedArtifact, Reference, ReleaseReferenceError
from tinfoil.verifier._endorsement.reference import parse_reference as _parse_reference
from tinfoil.verifier._endorsement.time import DEFAULT_MAX_AGE, MAX_AGE_SPAN
from tinfoil.verifier._errors import (
    LAYER_ENVELOPE,
    LAYER_POLICY,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    UsageError,
    VerificationError,
    VerifyError,
)
from tinfoil.verifier._measurement import Expected, ExpectedSEVSNP, ExpectedTDX
from tinfoil.verifier._options import (
    ConfigAuthorizer,
    ConfigSigningKeys,
    ConfigTrust,
    EmbeddedArtifacts,
    EmbeddedConfig,
    EmbeddedConfigReference,
    EndorsedArtifacts,
    Policy,
    PublicKey,
    Registries,
)
from tinfoil.verifier._policy import ARTIFACT_FORMAT
from tinfoil.verifier._quote import LegacyReferenceValues, QuoteOptions, TestOnlyRoots, assemble, authenticate
from tinfoil.verifier._verification import (
    SOURCE_ENDORSEMENT,
    ArtifactVerification,
    SoftwareIdentity,
    Verification,
    VerificationMetadata,
)
from tinfoil.verifier._x509.certificate import X509Error

REGISTRY_COLLATERAL_NEEDS_PROJECT = (
    "document carries config registry collateral, but only a GitHub repository is pinned"
)
REPOSITORY_COLLATERAL_NEEDS_REPO = (
    "document carries GitHub repository collateral, but only a registry project is pinned"
)
PIN_REQUIRED = (
    "pin must be a Pin: pass Pin(repo=...) for a GitHub repository or Pin(project=...) for a registry project"
)


@dataclass(frozen=True, slots=True, kw_only=True)
class Pin:
    """What an enclave must be running. ``repo`` and ``project`` are separate namespaces with unrelated owners,
    so neither is satisfied by the other's collateral. Setting both accepts either; ``Pin()`` accepts any config
    the verifier's trust authorizes, and is a UsageError under default config trust. None and "" both leave a part
    unset."""

    repo: str | None = None
    """A GitHub repository, ``owner/name[@tag][@sha256:digest]``."""
    project: str | None = None
    """A config registry project, ``org/project[@revision][@sha256:digest]``."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Overrides:
    """Replacement trust anchors for the conformance harness; a None entry keeps the embedded anchor.

    A supplied Sigstore root destroys the guarantee that reference values
    came from Tinfoil's release workflows, and a supplied vendor root the
    guarantee that evidence chains to AMD or Intel. Only ``_build`` accepts
    them; the public constructor never does.
    """

    sigstore_root: bytes | None = None
    """A Sigstore trusted-root document (JSON bytes)."""
    amd_root_pem: bytes | None = None
    """An AMD KDS ``cert_chain`` PEM (ASK then ARK)."""
    intel_root_pem: bytes | None = None
    """An Intel SGX root certificate PEM."""


class Verifier:
    """Appraises attestation documents against a fixed policy.

    A Verifier is immutable once built and safe for concurrent use. It
    performs no I/O: the document arrives as an argument, and every trust
    anchor it needs is embedded in this package or carried by the document
    itself. It holds no cache, so it never decides that an earlier answer is
    still good enough; that judgment belongs to whatever fetches documents.

    It does read the clock. ``verify_v3`` samples it once and judges
    everything time-bound against that instant: the freshness witnesses and
    approvals, and the vendor certificate and CRL validity windows of the
    CPU evidence. The same instant is reported as ``metadata.verified_at``.
    ``verify_v3_at`` takes that instant from the caller instead. So the same
    document is accepted today and rejected once its witnesses go stale.
    """

    __slots__ = ("_trust",)

    _trust: TrustPolicy

    def __init__(self, config: ConfigTrust | None = None, policy: Policy | None = None) -> None:
        """Build a verifier that trusts configs as ``config`` selects and applies ``policy``.

        ``config`` is one of ``Registries``, ``ConfigSigningKeys``,
        ``ConfigAuthorizer``, ``EmbeddedConfig`` or ``EmbeddedConfigReference``;
        None selects the public registry. ``policy`` is a ``Policy``; None
        keeps every default: no register pins, the seven-day freshness bound,
        and runtime and platform artifacts that Tinfoil's public keys approve.
        The constructor copies what it keeps, so that later changes by the
        caller have no effect, and raises a UsageError for a value of another
        type or an invalid field.

        Any config trust other than None, and any artifact trust other than
        the default, requires ``attestation-collaterals/v3`` collateral; a v2
        document is then rejected at the provenance layer.
        """
        self._trust = _trust_policy(config, policy, overrides=None)

    @property
    def freshness_max_age(self) -> timedelta:
        """The configured witness age bound."""
        return self._trust.freshness_max_age

    @property
    def pinned_registers(self) -> Expected | None:
        """The configured register pins, or None."""
        return self._trust.pinned_registers

    @property
    def caller_authorizes_config(self) -> bool:
        """Whether the caller supplies the config, with an embedded config, or authorizes it, with a config
        authorizer, instead of a pin authenticating it."""
        return self._trust.embedded.config is not None or self._trust.config_authorizer is not None

    def __repr__(self) -> str:
        return f"Verifier(pinned_registers={self.pinned_registers!r}, freshness_max_age={self.freshness_max_age!r})"

    def check_pin_verifiability(self, pin: Pin) -> None:
        """Raise UsageError, without a document or network I/O, for a pin that ``verify_v3`` rejects whatever the
        document: one that is not a ``Pin``, one that names nothing under default config trust, a malformed
        reference, a ``repo`` set alone when this verifier verifies registry collateral only, or a ``project`` that
        its config authorizer or embedded config cannot match. A pin that passes can still be rejected once the
        document shows the project is not a valid config identity."""
        repo, project = _pin_parts(pin)
        _require_pin(self._trust, repo, project)
        if repo != "":
            _repository_pin(repo)
            if project == "" and requires_config_collateral(self._trust):
                raise UsageError(
                    "configured trust verifies registry collateral only, which a GitHub repository pin cannot match"
                )
        reference_pins(self._trust, project)

    def verify_v3(self, doc: bytes, nonce: bytes, pin: Pin) -> Verification:
        """Appraise a nonce-bound v3 attestation document, with whichever collateral format (v2 or v3) the document
        carries, at the current time.

        The document's collateral decides which part of ``pin`` applies.
        Anything but a ``Pin``, such as a bare reference string, is a
        UsageError.

        The caller owns both expectations that cannot come from the
        document: the nonce it generated, and any additional workload
        constraints. On success it must bind traffic to the returned keys
        and enforce ``freshness_expires_at``. Hardware collateral bounds
        the result even when every reference is embedded.
        """
        # The only clock read.
        return self.verify_v3_at(doc, nonce, pin, datetime.now(UTC))

    def verify_v3_at(self, doc: bytes, nonce: bytes, pin: Pin, verification_time: datetime) -> Verification:
        """``verify_v3`` for an archived document. ``verification_time`` replaces the current time in every
        time-bound check: the freshness witnesses and approvals, and the vendor certificate and CRL validity windows
        of the CPU evidence. ``metadata.verified_at`` reports it, and a naive or missing time is a UsageError.
        ``pin`` means what it means to ``verify_v3``.

        The caller must authenticate ``verification_time`` independently,
        for example from a trusted timestamp recorded when the document was
        received. An earlier time accepts collateral that has since expired
        or been revoked, so live clients use ``verify_v3``.
        """
        trust = getattr(self, "_trust", None)
        if trust is None:
            raise UsageError("verifier must be built by its constructor")
        if not isinstance(verification_time, datetime):
            raise UsageError("verification time is required")
        if verification_time.tzinfo is None or verification_time.utcoffset() is None:
            raise UsageError("verification time must be timezone-aware")
        if not isinstance(doc, bytes | bytearray | memoryview):
            raise UsageError("document must be bytes")
        if not isinstance(nonce, bytes | bytearray | memoryview):
            raise UsageError("nonce must be bytes")
        repo, project = _pin_parts(pin)
        _require_pin(trust, repo, project)
        return _verify_v3(trust, bytes(doc), bytes(nonce), repo, project, verification_time)


def _pin_parts(pin: Pin) -> tuple[str, str]:
    """The parts of ``pin``, "" when unset. A bare string is a UsageError, not an empty pin."""
    if not isinstance(pin, Pin):
        raise UsageError(PIN_REQUIRED)
    return _reference("repository", pin.repo), _reference("project", pin.project)


def _require_pin(trust: TrustPolicy, repo: str, project: str) -> None:
    """Refuse a pin that names nothing under default config trust, which would accept any config in the public
    registry."""
    if repo or project or trust.embedded.config is not None or trust.config_authorizer is not None:
        return
    if trust.config_keys is not None or trust.config_registry_ids is not None:
        return
    raise UsageError("pin names nothing: set repo or project, or configure the verifier's config trust")


def _reference(what: str, ref: str | None) -> str:
    """A part of a pin as a string: None means unset, like ``""``; anything but a string is a UsageError."""
    if ref is None:
        return ""
    if not isinstance(ref, str):
        raise UsageError(f"pin {what} must be a string or None: pass Pin(repo=...) or Pin(project=...)")
    return ref


def _repository_pin(repo: str) -> Reference:
    """The parts of a GitHub repository pin; a string that is not a reference is a UsageError."""
    try:
        return _parse_reference(repo)
    except ReleaseReferenceError as err:
        raise UsageError(str(err)) from err


def _key_tuple(what: str, keys: object) -> tuple[PublicKey, ...]:
    """The keys as a tuple; a value that is not a sequence of keys, or an empty one, is a UsageError."""
    if isinstance(keys, str | bytes | bytearray | memoryview) or not isinstance(keys, Iterable):
        raise UsageError(f"{what} must be a sequence of keys")
    out: tuple[PublicKey, ...] = tuple(keys)
    if len(out) == 0:
        raise UsageError(f"{what} must not be empty")
    return out


def _freshness_keys(keys: object) -> tuple[PublicKey, ...] | None:
    """An explicit freshness key set as a tuple; None selects Tinfoil's public keys and stays None."""
    if keys is None:
        return None
    return _key_tuple("freshness signing keys", keys)


def _build(
    config: ConfigTrust | None = None, policy: Policy | None = None, *, overrides: Overrides | None = None
) -> Verifier:
    """``Verifier(config, policy)`` with replacement trust anchors, for the conformance harness only. A Sigstore
    root that is not a trusted-root document is a UsageError; the vendor roots are checked when evidence selects
    them."""
    verifier = object.__new__(Verifier)
    verifier._trust = _trust_policy(config, policy, overrides=overrides)
    return verifier


@dataclass(frozen=True, slots=True, kw_only=True)
class _ConfigChoice:
    """What a config trust selects, checked and copied."""

    config_keys: tuple[PublicKey, ...] | None = None
    registry_ids: tuple[str, ...] | None = None
    authorizer: Callable[..., None] | None = None
    embedded: EmbeddedConfigReference | None = None


def _config_choice(config: object, runtime: bytes | None) -> _ConfigChoice:
    """Check ``config`` and copy what it selects. It runs after the artifact trust, so that an embedded config can
    check an embedded runtime."""
    if config is None:
        return _ConfigChoice()
    if isinstance(config, Registries):
        ids = config.ids
        if isinstance(ids, str) or not isinstance(ids, Sequence):
            raise UsageError("config registry IDs must be a sequence of strings")
        registry_ids = tuple(ids)
        if len(registry_ids) == 0:
            raise UsageError("config registry IDs must not be empty")
        if not all(isinstance(registry_id, str) for registry_id in registry_ids):
            raise UsageError("config registry IDs must be strings")
        try:
            ConfigPolicy(registry_ids=registry_ids).validate_pins()
        except ApprovalError as err:
            raise UsageError(str(err)) from err
        return _ConfigChoice(registry_ids=registry_ids)
    if isinstance(config, ConfigSigningKeys):
        return _ConfigChoice(config_keys=_key_tuple("config signing keys", config.keys))
    if isinstance(config, ConfigAuthorizer):
        if not callable(config.authorize):
            raise UsageError("config authorizer must be callable")
        return _ConfigChoice(authorizer=config.authorize)
    if isinstance(config, EmbeddedConfig | EmbeddedConfigReference):
        return _ConfigChoice(embedded=resolve_config(config, runtime))
    raise UsageError(
        "config trust must be a Registries, ConfigSigningKeys, ConfigAuthorizer, EmbeddedConfig or "
        f"EmbeddedConfigReference value, not {type(config).__name__}"
    )


def _artifact_choice(artifacts: object) -> tuple[ResolvedReferences, tuple[PublicKey, ...] | None]:
    """Check ``artifacts`` and copy the embedded artifacts and the freshness keys that it selects."""
    if artifacts is None:
        return ResolvedReferences(), None
    if isinstance(artifacts, EndorsedArtifacts):
        return ResolvedReferences(), _freshness_keys(artifacts.freshness_keys)
    if isinstance(artifacts, EmbeddedArtifacts):
        if artifacts.runtime is not None and artifacts.platform is not None and artifacts.freshness_keys is not None:
            raise UsageError("freshness signing keys have no endorsed artifact to verify")
        keys = _freshness_keys(artifacts.freshness_keys)
        return resolve_artifacts(artifacts), keys
    raise UsageError(
        f"artifact trust must be an EndorsedArtifacts or EmbeddedArtifacts value, not {type(artifacts).__name__}"
    )


def _trust_policy(config: object, policy: object, *, overrides: Overrides | None) -> TrustPolicy:
    """Check the policy, then the config trust, then build the endorsement verifiers. Every failure is a
    UsageError."""
    if policy is None:
        policy = Policy()
    if not isinstance(policy, Policy):
        raise UsageError(f"policy must be a Policy value, not {type(policy).__name__}")
    pinned_registers = policy.pinned_registers
    if pinned_registers is not None and not isinstance(pinned_registers, ExpectedSEVSNP | ExpectedTDX):
        raise UsageError(
            f"pinned registers must be an ExpectedSEVSNP or ExpectedTDX value, not {type(pinned_registers).__name__}"
        )
    max_age = DEFAULT_MAX_AGE
    freshness_max_age = policy.freshness_max_age
    if freshness_max_age is not None:
        if not isinstance(freshness_max_age, timedelta):
            raise UsageError(f"freshness maximum age must be a timedelta, not {type(freshness_max_age).__name__}")
        if freshness_max_age < timedelta(0):
            raise UsageError("freshness maximum age must not be negative")
        if freshness_max_age > MAX_AGE_SPAN:
            raise UsageError("freshness maximum age is longer than any representable window")
        max_age = freshness_max_age
    artifacts, freshness_keys = _artifact_choice(policy.artifacts)
    choice = _config_choice(config, artifacts.runtime)
    embedded = ResolvedReferences(config=choice.embedded, runtime=artifacts.runtime, platform=artifacts.platform)

    try:
        if overrides is None or overrides.sigstore_root is None:
            endorsements = ProvenanceClient.default()
        else:
            endorsements = ProvenanceClient.from_json(overrides.sigstore_root)
        public_keys = public_signing_keys()
        if choice.config_keys is None:
            config_verifier = endorsements.registry_verifier(public_keys)
        else:
            config_verifier = endorsements.config_verifier(choice.config_keys)
        freshness_verifier = endorsements.freshness_verifier(freshness_keys or public_keys)
    except (ProvenanceError, ApprovalError, X509Error) as err:
        raise UsageError(str(err)) from err

    quote_options: QuoteOptions | None = None
    if overrides is not None and (overrides.amd_root_pem is not None or overrides.intel_root_pem is not None):
        quote_options = QuoteOptions(
            test_only_roots=TestOnlyRoots(amd=overrides.amd_root_pem, intel=overrides.intel_root_pem)
        )
    return TrustPolicy(
        embedded=embedded,
        pinned_registers=pinned_registers,
        freshness_max_age=max_age,
        config_authorizer=choice.authorizer,
        endorsements=endorsements,
        config_keys=choice.config_keys,
        config_verifier=config_verifier,
        config_registry_ids=choice.registry_ids,
        freshness_keys=freshness_keys,
        freshness_verifier=freshness_verifier,
        quote_options=quote_options,
    )


@contextmanager
def _layer(layer: str) -> Iterator[None]:
    """Attribute any failure inside to ``layer``: an error that already carries a verify type, such as the UsageError
    for a caller's mistake, passes through; anything else becomes a VerificationError for the layer that rejected
    the document, with the failure as its cause."""
    try:
        yield
    except VerifyError:
        raise
    except Exception as err:
        raise VerificationError(layer, str(err)) from err


def _verify_v3(
    trust: TrustPolicy, doc_bytes: bytes, nonce: bytes, repo: str, project: str, now: datetime
) -> Verification:
    """The pipeline: envelope, reference values, CPU evidence, policy; then the record."""
    # A malformed pin is a usage error for any document.
    code_pin = _repository_pin(repo) if repo != "" else None
    reference_pins(trust, project)

    with _layer(LAYER_ENVELOPE):
        try:
            doc = parse(doc_bytes, nonce)
        except InvalidInputError as err:
            raise UsageError(str(err)) from err

    # Reference values and CPU evidence are appraised against the same instant.
    with _layer(LAYER_PROVENANCE):
        collateral_format = doc.collateral_format()
        if collateral_format == FORMAT_V3:
            if project == "" and code_pin is not None:
                raise ReferencesError(REGISTRY_COLLATERAL_NEEDS_PROJECT)
            refs = config_references(trust, doc, project, now)
        elif collateral_format == FORMAT_V2:
            if requires_config_collateral(trust):
                raise ReferencesError(f"configured trust requires {FORMAT_V3}")
            if code_pin is None:
                if project != "":
                    raise ReferencesError(REPOSITORY_COLLATERAL_NEEDS_REPO)
                code_pin = _repository_pin(repo)
            refs = _code_references(trust, doc, code_pin, now)
        else:
            raise ReferencesError(f"unsupported collateral format {collateral_format!r}")

    with _layer(LAYER_QUOTE):
        authenticated = authenticate(doc.cpu_evidence(), doc.cpu_endorsements(), now, trust.quote_options)

    with _layer(LAYER_POLICY):
        assembled = assemble(doc, refs.quote, trust.pinned_registers, authenticated)
        assembled.validate()

    return Verification(
        code_digest=refs.artifact.digest,
        code_tag=refs.artifact.tag,
        config_repo=refs.artifact.repo,
        code_measurement=assembled.code_measurement,
        enclave_measurement=authenticated.measurement,
        crypto_material=doc.crypto_material_items(),
        freshness_expires_at=min(refs.freshness_expires_at, authenticated.quote.expires_at)
        if refs.freshness_expires_at is not None
        else authenticated.quote.expires_at,
        config=refs.config,
        runtime=refs.artifact if refs.config is not None else None,
        platform=refs.platform,
        metadata=VerificationMetadata(
            verifier=SoftwareIdentity(name=SDK_NAME, version=sdk_version()), verified_at=now.astimezone(UTC)
        ),
    )


def _code_references(trust: TrustPolicy, doc: Document, pin: Reference, now: datetime) -> EndorsementResult:
    """Resolve v2 collateral against the repository ``pin``: the code release and the platform endorsements, each
    with its freshness witness appraised at ``now``."""
    code_ref = doc.sigstore_code()
    code = trust.endorsements.authenticate_code(code_ref.bundle, pin, code_ref.tag, code_ref.digest)
    platform_ref = doc.sigstore_platform()
    try:
        endorsements = trust.endorsements.authenticate_platform_endorsements(
            platform_ref.bundle, platform_ref.repo, platform_ref.tag, platform_ref.digest, ARTIFACT_FORMAT
        )
    except ValueError as err:
        raise ReferencesError(f"verifying platform endorsements: {err}") from err
    try:
        code_witnessed_at = _authenticate_freshness(trust, doc, FRESHNESS_ID_CODE, code.artifact, now)
    except (LookupError, ValueError) as err:
        raise ReferencesError(f"verifying code freshness: {err}") from err
    try:
        platform_witnessed_at = _authenticate_freshness(trust, doc, FRESHNESS_ID_PLATFORM, endorsements.artifact, now)
    except (LookupError, ValueError) as err:
        raise ReferencesError(f"verifying platform freshness: {err}") from err
    return EndorsementResult(
        quote=LegacyReferenceValues(
            endorsements=endorsements.endorsements, sevsnp=code.sevsnp, tdx=code.tdx, shape=code.shape
        ),
        artifact=ArtifactVerification(
            source=SOURCE_ENDORSEMENT,
            repo=code.artifact.repo,
            tag=code.artifact.tag,
            digest=code.artifact.digest,
            name=code.artifact.subject_name,
            commit=code.artifact.commit,
        ),
        freshness_expires_at=freshness_expiration(trust.freshness_max_age, code_witnessed_at, platform_witnessed_at),
    )


def _authenticate_freshness(
    trust: TrustPolicy, doc: Document, witness_id: str, artifact: AuthenticatedArtifact, now: datetime
) -> datetime:
    """The log time of the freshness witness for ``artifact``, within the window around ``now``."""
    witness = doc.freshness(witness_id)
    if witness.format != SIGSTORE_FRESHNESS_V1_FORMAT:
        raise ReferencesError(
            f"legacy verification requires freshness collateral format {SIGSTORE_FRESHNESS_V1_FORMAT!r}"
        )
    return trust.endorsements.authenticate_freshness(witness.bundle, artifact, now, trust.freshness_max_age)


def parse_reference(ref: str) -> Reference:
    """Validate ``owner/name[@tag][@sha256:digest]`` and return its parts. A string that is not a reference, or a
    value that is not a string, is a UsageError."""
    if not isinstance(ref, str):
        raise UsageError(f"release reference must be a string, not {type(ref).__name__}")
    try:
        return _parse_reference(ref)
    except ReleaseReferenceError as err:
        raise UsageError(str(err)) from err


__all__ = ["Overrides", "Reference", "Verifier", "parse_reference"]
