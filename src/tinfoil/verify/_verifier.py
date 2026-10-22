"""The verifier: appraises a document against the caller's nonce and workload."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .. import _sdkinfo
from . import _provenance, _quote
from . import document as _document
from ._errors import Layer, UsageError, as_rejection, as_usage_error
from ._references import ReferenceResolver
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

    It does read the clock: verify() samples it once and judges everything
    time-bound against that instant, so the same document is accepted today
    and rejected once its witnesses go stale. verify_at() takes that instant
    from the caller instead.
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
    ) -> None:
        """Build a verifier. The defaults trust Tinfoil's public releases.

        Args:
            pinned_registers: Register values the enclave must also attest.
                Empty entries keep the release and platform expectations.
                TDX order is MRTD, RTMR0, RTMR1, RTMR2, RTMR3. Pins add
                constraints; they never replace release or platform values.
            freshness_max_age: How old an authenticated freshness witness may
                be. None or zero selects seven days.

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
        )

    def _configure(
        self,
        releases: _provenance.ReleaseVerifier,
        vendor_roots: _quote.VendorRoots,
        *,
        pinned_registers: Measurement | None = None,
        freshness_max_age: timedelta | None = None,
    ) -> None:
        if pinned_registers is not None and not isinstance(pinned_registers, Measurement):
            raise UsageError("pinned registers must be a Measurement")
        with as_usage_error():
            if pinned_registers is not None:
                _quote.validate_pins(pinned_registers)
            references = ReferenceResolver(releases, freshness_max_age=freshness_max_age)
        object.__setattr__(self, "_references", references)
        object.__setattr__(self, "_pinned_registers", pinned_registers)
        object.__setattr__(self, "_vendor_roots", vendor_roots)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"cannot assign to {name!r}: verifiers are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"cannot delete {name!r}: verifiers are immutable")

    @property
    def freshness_max_age(self) -> timedelta:
        """The maximum age of a freshness witness."""
        return self._references.freshness_max_age

    @property
    def pinned_registers(self) -> Measurement | None:
        """The caller's register pins, if any."""
        return self._pinned_registers

    def verify(self, document: bytes, nonce: bytes, repo: str) -> Verification:
        """Appraise a nonce-bound v3 attestation document as of now.

        The caller owns the two expectations the document cannot supply: the
        nonce it generated, and its workload constraint. On success, bind
        traffic only to the returned keys, and stop authorizing new requests
        at ``freshness_expires_at``.

        Args:
            document: The attestation document, as fetched.
            nonce: The NONCE_SIZE-byte nonce the caller sent with its request.
            repo: The expected repository as
                ``owner/name[@tag][@sha256:digest]``.

        Raises:
            UsageError: An argument is invalid.
            VerificationError: The document must not be trusted.
        """
        # The only clock read.
        return self.verify_at(document, nonce, repo, datetime.now(timezone.utc))

    def verify_at(self, document: bytes, nonce: bytes, repo: str, verification_time: datetime) -> Verification:
        """Appraise an archived document as of ``verification_time``.

        Like verify(), but ``verification_time`` replaces the current time in
        every time-bound check: the freshness witnesses, and the vendor
        certificate and CRL validity windows of the CPU evidence. The
        result reports it as ``metadata.verified_at``.

        The caller must authenticate ``verification_time`` independently, for
        example from a trusted timestamp recorded when the document was
        received. An earlier time accepts collateral that has since expired or
        been revoked, so live clients use verify().

        Raises:
            UsageError: An argument is invalid, including a
                ``verification_time`` that is not a timezone-aware datetime.
            VerificationError: The document must not be trusted.
        """
        if not isinstance(verification_time, datetime) or verification_time.utcoffset() is None:
            raise UsageError("verification time must be a timezone-aware datetime")
        at = verification_time.astimezone(timezone.utc)

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
        )
