"""The verifier: appraises a document against the caller's nonce and workload."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from .. import _sdkinfo
from . import _provenance, _quote
from . import document as _document
from ._errors import Layer, UsageError, as_rejection, as_usage_error
from ._references import ConfigAuthorizer, EmbeddedReferences, ReferenceResolver
from ._verification import SoftwareIdentity, Verification, VerificationMetadata
from .measurement import Measurement

Reference = _provenance.Reference


def parse_reference(ref: str) -> Reference:
    """Validate ``owner/name[@tag][@sha256:digest]`` and return its parts.

    Raises UsageError for anything else.
    """
    with as_usage_error():
        return _provenance.parse_reference(ref)


class Verifier:
    """Appraises attestation documents against a fixed policy.

    A verifier is immutable once built and safe to share between threads.
    Verification performs no I/O: the document arrives as an argument, and
    every trust anchor is embedded in this package or carried by the
    document. It holds no cache, so deciding whether an earlier verification
    is still good enough belongs to whatever fetches documents.

    It does read the clock: ``verify`` samples it once and judges everything
    time-bound against that instant, so the same document is accepted today
    and rejected once its witnesses go stale.
    """

    __slots__ = ("_pinned_registers", "_references", "_vendor_roots")

    _pinned_registers: Measurement | None
    _references: ReferenceResolver
    _vendor_roots: _quote.VendorRoots

    def __init__(
        self,
        *,
        pinned_registers: Measurement | None = None,
        freshness_max_age: timedelta | None = None,
        embedded_references: EmbeddedReferences | None = None,
        config_authorizer: ConfigAuthorizer | None = None,
        config_signing_keys: Sequence[PublicKeyTypes] | None = None,
        freshness_signing_keys: Sequence[PublicKeyTypes] | None = None,
    ) -> None:
        """Build a verifier. The defaults trust Tinfoil's public releases.

        Args:
            pinned_registers: Register values the enclave must also attest.
                Empty entries keep the release and platform expectations.
                TDX order is MRTD, RTMR0, RTMR1, RTMR2, RTMR3. Pins add
                constraints; they never replace release or platform values.
            freshness_max_age: How old an authenticated freshness witness or
                approval may be. None or zero selects seven days.
            embedded_references: Caller-trusted reference values that replace
                endorsement checks for attestation-collaterals/v3.
            config_authorizer: Approves config material in place of config
                endorsements, by returning, or rejects it by raising. It
                receives untrusted material and may be called from several
                threads at once. Runtime, platform and hardware checks still
                apply.
            config_signing_keys: Replace Tinfoil's public config approval
                keys. They do not authorize artifact freshness.
            freshness_signing_keys: Replace Tinfoil's platform and runtime
                approval keys. They do not authorize configs.

        Raises:
            UsageError: The options are invalid or conflict.
        """
        with as_usage_error():
            releases = _provenance.ReleaseVerifier.embedded()
        self._configure(
            releases,
            _quote.VendorRoots(),
            pinned_registers=pinned_registers,
            freshness_max_age=freshness_max_age,
            embedded_references=embedded_references,
            config_authorizer=config_authorizer,
            config_signing_keys=config_signing_keys,
            freshness_signing_keys=freshness_signing_keys,
        )

    def _configure(
        self,
        releases: _provenance.ReleaseVerifier,
        vendor_roots: _quote.VendorRoots,
        *,
        pinned_registers: Measurement | None = None,
        freshness_max_age: timedelta | None = None,
        embedded_references: EmbeddedReferences | None = None,
        config_authorizer: ConfigAuthorizer | None = None,
        config_signing_keys: Sequence[PublicKeyTypes] | None = None,
        freshness_signing_keys: Sequence[PublicKeyTypes] | None = None,
    ) -> None:
        if pinned_registers is not None and not isinstance(pinned_registers, Measurement):
            raise UsageError("pinned registers must be a Measurement")
        with as_usage_error():
            if pinned_registers is not None:
                _quote.validate_pins(pinned_registers)
            self._references = ReferenceResolver(
                releases,
                freshness_max_age=freshness_max_age,
                embedded=embedded_references,
                config_authorizer=config_authorizer,
                config_signing_keys=config_signing_keys,
                freshness_signing_keys=freshness_signing_keys,
            )
        self._pinned_registers = pinned_registers
        self._vendor_roots = vendor_roots

    @property
    def freshness_max_age(self) -> timedelta:
        """The maximum age of a freshness witness or approval."""
        return self._references.freshness_max_age

    @property
    def pinned_registers(self) -> Measurement | None:
        """The caller's register pins, if any."""
        return self._pinned_registers

    def verify(self, document: bytes, nonce: bytes, repo: str | None, *, at: datetime | None = None) -> Verification:
        """Appraise a nonce-bound v3 attestation document.

        The caller owns the two expectations the document cannot supply: the
        nonce it generated, and its workload constraint. On success, bind
        traffic only to the returned keys, and stop authorizing new requests
        at ``freshness_expires_at`` when it is set.

        Args:
            document: The attestation document, as fetched.
            nonce: The NONCE_SIZE-byte nonce the caller sent with its request.
            repo: The expected repository as
                ``owner/name[@tag][@sha256:digest]``. None only with an
                embedded config, which then provides the workload constraint,
                or with a config authorizer, which owns config authorization.
            at: Appraise an archived document as of this instant instead of
                now: freshness witnesses and approvals, and the vendor
                certificate and CRL validity windows, are all judged at it.
                It must come from a trusted record, such as a timestamp taken
                when the document was received; an earlier instant accepts
                collateral that has since expired or been revoked.

        Raises:
            UsageError: An argument is invalid or conflicts with the
                verifier's configuration.
            VerificationError: The document must not be trusted.
        """
        if at is None:
            # The only clock read.
            at = datetime.now(timezone.utc)
        elif at.utcoffset() is None:
            raise UsageError("verification time must be timezone-aware")
        at = at.astimezone(timezone.utc)

        with as_rejection(Layer.ENVELOPE):
            try:
                parsed = _document.parse(document, nonce)
            except _document.InvalidInputError as err:
                raise UsageError(str(err)) from err
        with as_rejection(Layer.PROVENANCE):
            references = self._references.resolve(parsed, repo, at)
        with as_rejection(Layer.QUOTE):
            authenticated = _quote.authenticate(parsed.cpu_evidence, parsed.cpu_endorsements, at, self._vendor_roots)
        with as_rejection(Layer.POLICY):
            assembled = _quote.assemble(parsed, references.quote, self._pinned_registers, authenticated)
            assembled.validate()

        return Verification(
            config_repo=references.artifact.repo,
            code_digest=references.artifact.digest,
            code_tag=references.artifact.tag,
            code_measurement=assembled.code_measurement,
            enclave_measurement=authenticated.measurement,
            crypto_material=parsed.crypto_material,
            freshness_expires_at=references.freshness_expires_at,
            metadata=VerificationMetadata(
                verifier=SoftwareIdentity(_sdkinfo.SDK_NAME, _sdkinfo.sdk_version()),
                verified_at=at,
            ),
            config=references.config,
            runtime=references.artifact if references.config is not None else None,
            platform=references.platform,
        )
