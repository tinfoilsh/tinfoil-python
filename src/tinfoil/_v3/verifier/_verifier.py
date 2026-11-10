"""Appraisal of attestation documents.

Given a document, the nonce the caller bound it to and the repository the
caller trusts, a ``Verifier`` decides what the document proves. It opens no
connections and keeps no state between calls, so fetching documents, caching
a verification and enforcing its expiry all belong to the caller.

It raises two error types: a ``UsageError`` when the verifier is built or
called with invalid inputs, and a ``VerificationError`` when the document
must not be trusted.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from tinfoil._sdkinfo import SDK_NAME, sdk_version
from tinfoil._v3.verifier._config import (
    ConfigAuthorizer,
    EndorsementResult,
    PublicKey,
    ReferencesError,
    TrustPolicy,
    config_references,
    freshness_expiration,
    reference_pins,
    requires_config_collateral,
)
from tinfoil._v3.verifier._document.collateral.collateral import (
    FORMAT_V2,
    FORMAT_V3,
    FRESHNESS_ID_CODE,
    FRESHNESS_ID_PLATFORM,
    SIGSTORE_FRESHNESS_V1_FORMAT,
)
from tinfoil._v3.verifier._document.document import Document, InvalidInputError, parse
from tinfoil._v3.verifier._embedded import EmbeddedReferences, ResolvedReferences, resolve_embedded
from tinfoil._v3.verifier._endorsement.approval import ApprovalError, ConfigPolicy, public_signing_keys
from tinfoil._v3.verifier._endorsement.provenance import ProvenanceClient, ProvenanceError
from tinfoil._v3.verifier._endorsement.reference import AuthenticatedArtifact, Reference, ReleaseReferenceError
from tinfoil._v3.verifier._endorsement.reference import parse_reference as _parse_reference
from tinfoil._v3.verifier._endorsement.time import DEFAULT_MAX_AGE
from tinfoil._v3.verifier._errors import (
    LAYER_ENVELOPE,
    LAYER_POLICY,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    UsageError,
    VerificationError,
    VerifyError,
)
from tinfoil._v3.verifier._measurement import Expected, ExpectedSEVSNP, ExpectedTDX
from tinfoil._v3.verifier._policy import ARTIFACT_FORMAT
from tinfoil._v3.verifier._quote import LegacyReferenceValues, QuoteOptions, TestOnlyRoots, assemble, authenticate
from tinfoil._v3.verifier._verification import (
    SOURCE_ENDORSEMENT,
    ArtifactVerification,
    SoftwareIdentity,
    Verification,
    VerificationMetadata,
)
from tinfoil._v3.verifier._x509.certificate import X509Error


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

    def __init__(
        self,
        *,
        pinned_registers: Expected | None = None,
        freshness_max_age: timedelta | None = None,
        config_signing_keys: Sequence[PublicKey] | None = None,
        freshness_signing_keys: Sequence[PublicKey] | None = None,
        config_registry_ids: Sequence[str] | None = None,
        config_authorizer: ConfigAuthorizer | None = None,
        embedded_references: EmbeddedReferences | None = None,
    ) -> None:
        """Build a verifier. The defaults use the embedded production trust roots, Tinfoil's public config and
        artifact signing keys, and a seven-day freshness bound. An invalid option or a conflicting combination is a
        UsageError.

        ``pinned_registers``: register checks on top of the release's. Each
        set register must match the enclave: it fills a register that the
        release leaves open and must equal one that the release fixes. Pins
        for one platform reject every enclave on the other. None adds no
        checks.

        ``freshness_max_age``: how old an authenticated witness or approval
        may be at the verification instant. None keeps the seven-day
        default. Any non-negative ``timedelta`` is honored as given: zero
        means zero, so every witness is stale, and a negative age is a
        UsageError.

        ``config_signing_keys``: ECDSA P-256 keys (``load_public_key``)
        that replace the public config trust. Configs must be key-signed by
        one of them; registry ids do not apply and these keys authorize no
        artifact freshness. An empty sequence is a UsageError.

        ``freshness_signing_keys``: ECDSA P-256 keys that replace the public
        keys for the platform and runtime freshness approvals. An empty
        sequence is a UsageError.

        ``config_registry_ids``: the registries whose certified approvals
        are accepted, in place of the public registry alone. An empty
        sequence or a malformed id is a UsageError.

        ``config_authorizer``: caller policy that replaces config
        endorsement verification; it decides on the config bytes and the
        verifier still authenticates the runtime, the platform and the
        hardware. ``verify_v3`` then requires an empty ``repo``.

        ``embedded_references``: caller-trusted config, runtime manifest
        or platform artifact that replace endorsement and renewal checks
        for the components supplied; the others keep their checks.

        Conflicts, each a UsageError: an embedded config with
        ``config_signing_keys``; ``config_authorizer`` with an embedded
        config or ``config_signing_keys``; ``config_registry_ids`` with an
        embedded config, ``config_authorizer`` or ``config_signing_keys``;
        ``freshness_signing_keys`` when both the runtime and the platform
        are embedded, so that no endorsed artifact remains to verify.

        Any explicit key set, registry list, authorizer or embedded
        reference requires ``attestation-collaterals/v3`` collateral; a v2
        document is then rejected at the provenance layer.
        """
        self._trust = _trust_policy(
            overrides=None,
            pinned_registers=pinned_registers,
            freshness_max_age=freshness_max_age,
            config_signing_keys=config_signing_keys,
            freshness_signing_keys=freshness_signing_keys,
            config_registry_ids=config_registry_ids,
            config_authorizer=config_authorizer,
            embedded_references=embedded_references,
        )

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
        authorizer, instead of a repository pin authenticating it."""
        return self._trust.embedded.config is not None or self._trust.config_authorizer is not None

    def __repr__(self) -> str:
        return (
            f"Verifier(pinned_registers={self.pinned_registers!r}, freshness_max_age={self.freshness_max_age!r}, "
            f"caller_authorizes_config={self.caller_authorizes_config!r})"
        )

    def check_repo_verifiability(self, repo: str | None) -> None:
        """Check that this verifier can verify an enclave against the repository pin ``repo``, without a document or
        network I/O, so that a caller can reject a pin before fetching a document.

        Raises UsageError when ``repo`` is non-empty and is not an
        ``org/project[@revision][@sha256:digest]`` reference; when ``repo``
        is set and this verifier has a config authorizer, which cannot
        authenticate a repository pin; or when this verifier has an embedded
        config whose name or digest ``repo`` does not match. An empty
        ``repo``, or None, which means the same, accepts configs authorized
        by the configured registry trust. ``verify_v3`` rejects every such
        ``repo``, whatever the document. It can still reject a ``repo``
        that passes: v3 collateral also requires the repo and revision to be
        valid config identity components, such as lowercase slugs, and v2
        collateral does not, so that check waits for the document.
        """
        reference_pins(self._trust, _repo(repo))

    def verify_v3(self, doc: bytes, nonce: bytes, repo: str | None) -> Verification:
        """Appraise a nonce-bound v3 attestation document, with whichever collateral format (v2 or v3) the document
        carries, at the current time.

        ``repo`` pins the expected repository or registry project as
        ``org/project[@revision][@sha256:digest]``; an empty ``repo``, or
        None, which means the same, accepts authorized registry ids. An
        embedded config instead authorizes its exact caller-supplied bytes.
        A config authorizer requires an empty ``repo`` and owns config
        authorization.

        The caller owns both expectations that cannot come from the
        document: the nonce it generated, and any additional workload
        constraints. On success it must bind traffic to the returned keys
        and enforce a non-None ``freshness_expires_at``. With all references
        embedded, the caller owns renewal and cache lifetime; None is not a
        guarantee of unlimited evidence validity.
        """
        # The only clock read.
        return self.verify_v3_at(doc, nonce, repo, datetime.now(UTC))

    def verify_v3_at(self, doc: bytes, nonce: bytes, repo: str | None, verification_time: datetime) -> Verification:
        """``verify_v3`` for an archived document. ``verification_time`` replaces the current time in every
        time-bound check: the freshness witnesses and approvals, and the vendor certificate and CRL validity windows
        of the CPU evidence. ``metadata.verified_at`` reports it, and a naive or missing time is a UsageError.

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
        return _verify_v3(trust, bytes(doc), bytes(nonce), _repo(repo), verification_time)


def _repo(repo: str | None) -> str:
    """The repository pin as a string: None means no pin, like ``""``; anything but a string is a UsageError."""
    if repo is None:
        return ""
    if not isinstance(repo, str):
        raise UsageError("repository reference must be a string or None")
    return repo


def _build(
    *,
    overrides: Overrides | None = None,
    pinned_registers: Expected | None = None,
    freshness_max_age: timedelta | None = None,
    config_signing_keys: Sequence[PublicKey] | None = None,
    freshness_signing_keys: Sequence[PublicKey] | None = None,
    config_registry_ids: Sequence[str] | None = None,
    config_authorizer: ConfigAuthorizer | None = None,
    embedded_references: EmbeddedReferences | None = None,
) -> Verifier:
    """``Verifier(...)`` with replacement trust anchors, for the conformance harness only. A Sigstore root that is
    not a trusted-root document is a UsageError; the vendor roots are checked when evidence selects them."""
    verifier = object.__new__(Verifier)
    verifier._trust = _trust_policy(
        overrides=overrides,
        pinned_registers=pinned_registers,
        freshness_max_age=freshness_max_age,
        config_signing_keys=config_signing_keys,
        freshness_signing_keys=freshness_signing_keys,
        config_registry_ids=config_registry_ids,
        config_authorizer=config_authorizer,
        embedded_references=embedded_references,
    )
    return verifier


def _trust_policy(
    *,
    overrides: Overrides | None,
    pinned_registers: Expected | None,
    freshness_max_age: timedelta | None,
    config_signing_keys: Sequence[PublicKey] | None,
    freshness_signing_keys: Sequence[PublicKey] | None,
    config_registry_ids: Sequence[str] | None,
    config_authorizer: ConfigAuthorizer | None,
    embedded_references: EmbeddedReferences | None,
) -> TrustPolicy:
    """Check each option, then the combinations, then build the endorsement verifiers. Every failure is a
    UsageError."""
    if pinned_registers is not None and not isinstance(pinned_registers, ExpectedSEVSNP | ExpectedTDX):
        raise UsageError(
            f"pinned registers must be an ExpectedSEVSNP or ExpectedTDX value, not {type(pinned_registers).__name__}"
        )
    max_age = DEFAULT_MAX_AGE
    if freshness_max_age is not None:
        if not isinstance(freshness_max_age, timedelta):
            raise UsageError(f"freshness maximum age must be a timedelta, not {type(freshness_max_age).__name__}")
        if freshness_max_age < timedelta(0):
            raise UsageError("freshness maximum age must not be negative")
        max_age = freshness_max_age
    config_keys = None if config_signing_keys is None else tuple(config_signing_keys)
    if config_keys is not None and len(config_keys) == 0:
        raise UsageError("config signing keys must not be empty")
    freshness_keys = None if freshness_signing_keys is None else tuple(freshness_signing_keys)
    if freshness_keys is not None and len(freshness_keys) == 0:
        raise UsageError("freshness signing keys must not be empty")
    registry_ids: tuple[str, ...] | None = None
    if config_registry_ids is not None:
        try:
            registry_ids = tuple(config_registry_ids)
        except TypeError as err:
            raise UsageError("config registry IDs must be a sequence of strings") from err
        if len(registry_ids) == 0:
            raise UsageError("config registry IDs must not be empty")
        if not all(isinstance(registry_id, str) for registry_id in registry_ids):
            raise UsageError("config registry IDs must be strings")
        try:
            ConfigPolicy(registry_ids=registry_ids).validate_pins()
        except ApprovalError as err:
            raise UsageError(str(err)) from err
    if config_authorizer is not None and not callable(config_authorizer):
        raise UsageError("config authorizer must be callable")
    embedded = ResolvedReferences() if embedded_references is None else resolve_embedded(embedded_references)

    if embedded.config is not None and config_keys is not None:
        raise UsageError("embedded config and config signing keys select conflicting trust sources")
    if config_authorizer is not None and (embedded.config is not None or config_keys is not None):
        raise UsageError("config authorizer conflicts with embedded config or config signing keys")
    if registry_ids is not None and (embedded.config is not None or config_authorizer is not None):
        raise UsageError("config authority pins require endorsement verification")
    if registry_ids is not None and config_keys is not None:
        raise UsageError("config registry ID policy requires Tinfoil registry root verification")
    if embedded.runtime is not None and embedded.platform is not None and freshness_keys is not None:
        raise UsageError("freshness signing keys have no endorsed artifact to verify")

    try:
        if overrides is None or overrides.sigstore_root is None:
            endorsements = ProvenanceClient.default()
        else:
            endorsements = ProvenanceClient.from_json(overrides.sigstore_root)
        public_keys = public_signing_keys()
        if config_keys is None:
            config_verifier = endorsements.registry_verifier(public_keys)
        else:
            config_verifier = endorsements.config_verifier(config_keys)
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
        config_authorizer=config_authorizer,
        endorsements=endorsements,
        config_keys=config_keys,
        config_verifier=config_verifier,
        config_registry_ids=registry_ids,
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


def _verify_v3(trust: TrustPolicy, doc_bytes: bytes, nonce: bytes, repo: str, now: datetime) -> Verification:
    """The pipeline: envelope, reference values, CPU evidence, policy; then the record."""
    with _layer(LAYER_ENVELOPE):
        try:
            doc = parse(doc_bytes, nonce)
        except InvalidInputError as err:
            raise UsageError(str(err)) from err

    # Reference values and CPU evidence are appraised against the same instant.
    with _layer(LAYER_PROVENANCE):
        collateral_format = doc.collateral_format()
        if collateral_format == FORMAT_V3:
            refs = config_references(trust, doc, repo, now)
        elif collateral_format == FORMAT_V2:
            refs = _code_references(trust, doc, repo, now)
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
        freshness_expires_at=refs.freshness_expires_at,
        config=refs.config,
        runtime=refs.artifact if refs.config is not None else None,
        platform=refs.platform,
        metadata=VerificationMetadata(
            verifier=SoftwareIdentity(name=SDK_NAME, version=sdk_version()), verified_at=now.astimezone(UTC)
        ),
    )


def _code_references(trust: TrustPolicy, doc: Document, repo: str, now: datetime) -> EndorsementResult:
    """Resolve v2 collateral: the code release and the platform endorsements, each with its freshness witness
    appraised at ``now``. An invalid repository reference is a UsageError."""
    if requires_config_collateral(trust):
        raise ReferencesError(f"configured trust requires {FORMAT_V3}")
    code_ref = doc.sigstore_code()
    try:
        pin = _parse_reference(repo)
    except ReleaseReferenceError as err:
        raise UsageError(str(err)) from err
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
