"""VerifiedFacts of one attested enclave. An ``Enclave`` names the enclave and the policy it is verified against,
and keeps no state; the attested transport caches what it verifies and ties HTTP traffic to the keys it
endorses."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime

from tinfoil._errors import (
    AttestationError,
    ConfigurationError,
    NetworkError,
    TinfoilError,
    attestation_error,
    from_verify,
)
from tinfoil._fetch import fetch_document, fetch_document_async, is_authority
from tinfoil._types import DEFAULT_HTTP_TIMEOUT, OnVerificationAttempt, TimeoutTypes, VerificationCheck
from tinfoil.verifier import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    ConfigTrust,
    Pin,
    Policy,
    VerificationError,
    VerificationReport,
    VerifiedFacts,
    Verifier,
    VerifyError,
    random_nonce,
)

FRESHNESS_EXPIRED = "attestation freshness witnesses have expired; retry verification with fresh evidence"
"""The message of the AttestationError for a verification whose witnesses no longer authorize requests."""
NO_FRESHNESS_DEADLINE = (
    "verification carries no freshness deadline; the client needs an endorsed deadline to bound requests "
    "(use the verifier directly when no reference endorses a deadline)"
)
"""The message of the AttestationError for a verification without a freshness deadline: no endorsed reference
supplied an approval time, whether every reference is embedded or a caller-authorized config is combined with
embedded runtime and platform references, so nothing bounds the time the enclave's keys may be used for."""
DEADLINE_EXCEEDED = "verification did not complete before its deadline"
"""The message of the NetworkError for a verification that ran past the deadline it was given."""
NO_VERIFIED_FACTS = "verification passed without verified facts"
"""The message of the AttestationError for a report that claims a pass but holds no verified facts, which the
verifier never returns."""

_LOG = logging.getLogger("tinfoil")

VERIFICATION_RETRIES = 1
CANDIDATE_VERIFICATION_RETRIES = 0
VERIFICATION_RETRY_DELAY = 1.0

Fetch = Callable[[], VerificationReport]
"""A test seam: replaces fetching and verifying a document."""
AsyncFetch = Callable[[], Awaitable[VerificationReport]]
Retried = Callable[[TinfoilError], None]
"""Called with each failed attempt that a verification retries, before the retry starts."""

DocumentFetch = Callable[[str, bytes, TimeoutTypes, "float | None"], bytes]
"""How an enclave obtains its raw attestation document: ``(host, nonce, timeout, deadline)`` to the document, where
``deadline`` is a ``time.monotonic`` instant or None. Errors are client errors already."""
AsyncDocumentFetch = Callable[[str, bytes, TimeoutTypes, "float | None"], Awaitable[bytes]]


def new_verifier(config: ConfigTrust | None, policy: Policy | None) -> Verifier:
    """The verifier that ``config`` and ``policy`` describe. A verifier UsageError, such as an invalid policy field
    or a value of another type, is a ConfigurationError with the UsageError as its cause."""
    try:
        return Verifier(config, policy)
    except VerifyError as err:
        raise from_verify(err) from err


class VerificationRejected(Exception):
    """A verification check's rejection: a decision about the evidence, so an Enclave does not retry it."""

    def __init__(self, host: str, cause: BaseException) -> None:
        super().__init__(f"verification check rejected {host}: {cause}")
        self.__cause__ = cause


class Enclave:
    """One enclave and the policy its attestation is verified against.

    ``host`` is the enclave, a host with an optional port. ``relay``, when
    set, is a host that fetches attestation from the enclave on the
    client's behalf. ``pin`` is the ``Pin`` it is verified against. ``verifier``
    is the policy, which several enclaves can share; None selects the defaults.
    ``verification_check``, when set, is called with the verified facts of
    each verification that passes the verifier; raising rejects it without
    a retry. ``on_verification_attempt``, when set, is what ``notify``
    reports each attempt to.
    ``fetch_document`` and ``fetch_document_async``, when set, obtain the
    raw document in place of a direct fetch from ``host`` or ``relay``.

    Construction checks ``pin`` against the verifier's rules and does no
    network I/O.
    """

    __slots__ = (
        "_check",
        "_fetch",
        "_fetch_async",
        "_on_verification_attempt",
        "fetch_document",
        "fetch_document_async",
        "host",
        "pin",
        "relay",
        "verifier",
    )

    def __init__(
        self,
        host: str,
        pin: Pin,
        *,
        relay: str = "",
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        on_verification_attempt: OnVerificationAttempt | None = None,
        fetch_document: DocumentFetch | None = None,
        fetch_document_async: AsyncDocumentFetch | None = None,
        _fetch: Fetch | None = None,
        _fetch_async: AsyncFetch | None = None,
    ) -> None:
        if not host:
            raise ConfigurationError("enclave host is required")
        if relay and (fetch_document is not None or fetch_document_async is not None):
            raise ConfigurationError("an enclave fetches through a relay host or a document fetcher, not both")
        for authority in (host, relay):
            if authority and not is_authority(authority):
                raise ConfigurationError(f"invalid host {authority!r}: want a host with an optional port")
        if verifier is None:
            verifier = Verifier()
        try:
            verifier.check_pin_verifiability(pin)
        except VerifyError as err:
            raise from_verify(err) from err
        self.host = host
        self.relay = relay
        self.pin = pin
        self.verifier = verifier
        self._check = verification_check
        self._on_verification_attempt = on_verification_attempt
        self.fetch_document = fetch_document
        self.fetch_document_async = fetch_document_async
        self._fetch = _fetch
        self._fetch_async = _fetch_async

    def verify(
        self,
        *,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        deadline: float | None = None,
        retried: Retried | None = None,
    ) -> VerificationReport:
        """Fetch and verify the enclave's attestation, retrying once after a network or attestation failure. The
        report it returns is fresh, and its verified facts have passed the verification check. ``timeout`` bounds
        each network operation of the fetch; ``deadline``, a ``time.monotonic`` instant, bounds the whole of each
        attempt, the fetch, the verification and the check included, and no retry starts once it has passed: an
        attempt that completes after it is a NetworkError. Each attempt that fails and is retried is passed to
        ``retried`` before the retry starts; the outcome of the last attempt is the result."""
        return self._verify(VERIFICATION_RETRIES, timeout, deadline, retried)

    def verify_once(
        self,
        *,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        deadline: float | None = None,
        retried: Retried | None = None,
    ) -> VerificationReport:
        """``verify`` without the retry, so a caller trying several enclaves moves on quickly. It never calls
        ``retried``."""
        return self._verify(CANDIDATE_VERIFICATION_RETRIES, timeout, deadline, retried)

    async def verify_async(
        self,
        *,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        deadline: float | None = None,
        retried: Retried | None = None,
    ) -> VerificationReport:
        """``verify`` on the event loop."""
        return await self._verify_async(VERIFICATION_RETRIES, timeout, deadline, retried)

    async def verify_once_async(
        self,
        *,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        deadline: float | None = None,
        retried: Retried | None = None,
    ) -> VerificationReport:
        """``verify_once`` on the event loop."""
        return await self._verify_async(CANDIDATE_VERIFICATION_RETRIES, timeout, deadline, retried)

    def notify(self, report: VerificationReport | None, error: TinfoilError | None) -> None:
        """Reports the outcome of an attempt to verify the enclave to the ``on_verification_attempt`` callback, if
        there is one. The caller must hold no lock that the callback could need. The callback cannot change the
        outcome, so an exception that it raises is logged rather than raised: raised, a client error from it would
        read as a failed verification to router discovery and the gateway's replica fallback."""
        if self._on_verification_attempt is None:
            return
        try:
            self._on_verification_attempt(self.host, report, error)
        except Exception:
            _LOG.exception("on_verification_attempt callback for %s raised", self.host)

    def _verify(
        self, retries: int, timeout: TimeoutTypes, deadline: float | None, retried: Retried | None
    ) -> VerificationReport:
        first: TinfoilError | None = None
        for attempt in range(retries + 1):
            try:
                check_deadline(deadline)
                verified = self._fetch() if self._fetch is not None else self._fetch_verification(timeout, deadline)
                verified = self._name_host(verified)
                self._admit(verified)
                # The verification and the check are not bounded by the fetch's timeouts, so the deadline is
                # checked again before the result is accepted.
                check_deadline(deadline)
                return verified
            except TinfoilError as err:
                self._name_rejected_host(err)
                if attempt == retries or not retryable(err) or not _retry_fits(deadline):
                    if first is not None:
                        err.__context__ = first
                    raise
                first = err
                if retried is not None:
                    retried(err)
            time.sleep(VERIFICATION_RETRY_DELAY)
        raise AssertionError("unreachable")  # pragma: no cover - the loop returns or raises

    async def _verify_async(
        self, retries: int, timeout: TimeoutTypes, deadline: float | None, retried: Retried | None
    ) -> VerificationReport:
        first: TinfoilError | None = None
        for attempt in range(retries + 1):
            try:
                check_deadline(deadline)
                if self._fetch_async is not None:
                    verified = await self._fetch_async()
                else:
                    verified = await self._fetch_verification_async(timeout, deadline)
                verified = self._name_host(verified)
                self._admit(verified)
                check_deadline(deadline)
                return verified
            except TinfoilError as err:
                self._name_rejected_host(err)
                if attempt == retries or not retryable(err) or not _retry_fits(deadline):
                    if first is not None:
                        err.__context__ = first
                    raise
                first = err
                if retried is not None:
                    retried(err)
            await asyncio.sleep(VERIFICATION_RETRY_DELAY)
        raise AssertionError("unreachable")  # pragma: no cover - the loop returns or raises

    def _name_host(self, report: VerificationReport) -> VerificationReport:
        """``report`` with the enclave's host in its metadata, since the verifier doesn't know which host the
        document came from. Every report that a client hands out passes through here or through
        ``_name_rejected_host``. Reports are immutable, so this builds a copy."""
        if report.metadata.host == self.host:
            return report
        return replace(report, metadata=replace(report.metadata, host=self.host))

    def _name_rejected_host(self, err: TinfoilError) -> None:
        """Names the enclave's host in the report of the verifier's ``VerificationError`` that ``err`` was raised
        from, when the verifier rejected the document."""
        rejected = err.__cause__
        if isinstance(rejected, VerificationError) and rejected.report is not None:
            rejected.report = self._name_host(rejected.report)
            # The error is rebuilt from its arguments when it is copied or pickled.
            rejected.args = (rejected.layer, rejected.message, rejected.report)

    def _admit(self, report: VerificationReport) -> None:
        """Checks that a fetched verification is fresh and that its verified facts pass the verification check. The
        check can run past the deadline, so freshness is checked again after it; a retry then fetches fresh
        evidence."""
        verified = report.verified_facts
        if verified is None:
            raise AttestationError(NO_VERIFIED_FACTS)
        check_freshness(verified)
        if self._check is not None:
            try:
                self._check(verified)
            except Exception as err:
                raise attestation_error(VerificationRejected(self.host, err))  # noqa: B904 - the cause is set
        check_freshness(verified)

    def _fetch_verification(self, timeout: TimeoutTypes, deadline: float | None) -> VerificationReport:
        nonce = random_nonce()
        if self.fetch_document is not None:
            doc = self.fetch_document(self.host, nonce, timeout, deadline)
        elif self.fetch_document_async is not None:
            raise ConfigurationError("the enclave's document fetcher is asynchronous; verify it on the event loop")
        else:
            doc = fetch_document(self.host, self.relay, nonce, timeout=timeout, deadline=deadline)
        return self._verify_document(doc, nonce)

    async def _fetch_verification_async(self, timeout: TimeoutTypes, deadline: float | None) -> VerificationReport:
        nonce = random_nonce()
        if self.fetch_document_async is not None:
            doc = await self.fetch_document_async(self.host, nonce, timeout, deadline)
        elif self.fetch_document is not None:
            raise ConfigurationError("the enclave's document fetcher is synchronous; verify it with verify")
        else:
            doc = await fetch_document_async(self.host, self.relay, nonce, timeout=timeout, deadline=deadline)
        # VerifiedFacts is CPU-bound, so it runs off the event loop.
        return await asyncio.to_thread(self._verify_document, doc, nonce)

    def _verify_document(self, doc: bytes, nonce: bytes) -> VerificationReport:
        """The report of ``doc``'s verification. A rejection is an AttestationError caused by the verifier's
        VerificationError, which carries the report; a document whose keys a transport cannot use is an
        AttestationError of the client's own, with no report."""
        try:
            report = self.verifier.verify_v3(doc, nonce, self.pin)
        except VerifyError as err:
            raise from_verify(err) from err
        if report.verified_facts is None:
            raise AttestationError(NO_VERIFIED_FACTS)
        validate_transport_keys(report.verified_facts)
        return report


def check_deadline(deadline: float | None) -> None:
    """Raises NetworkError once ``deadline``, a ``time.monotonic`` instant, has passed; None is no deadline."""
    if deadline is not None and time.monotonic() > deadline:
        raise NetworkError(DEADLINE_EXCEEDED)


def _retry_fits(deadline: float | None) -> bool:
    """Whether the retry delay and another attempt can start before ``deadline``."""
    return deadline is None or time.monotonic() + VERIFICATION_RETRY_DELAY < deadline


def check_freshness(verified: VerifiedFacts) -> None:
    """Rejects a verification whose witnesses no longer authorize requests. A verification without a deadline,
    which no endorsed reference supplied, has nothing that bounds requests, so it is rejected as well, with a
    message of its own."""
    if verified.freshness_expires_at is None:
        raise AttestationError(NO_FRESHNESS_DEADLINE)
    if not is_fresh(verified):
        raise AttestationError(FRESHNESS_EXPIRED)


def is_fresh(verified: VerifiedFacts) -> bool:
    """Whether ``verified``'s witnesses authorize requests now."""
    return verified.freshness_expires_at is not None and datetime.now(UTC) < verified.freshness_expires_at


def validate_transport_keys(verified: VerifiedFacts) -> None:
    """Requires the keys a transport binds traffic to: the TLS key, and the HPKE key when the document endorses
    one."""
    _key_format(verified, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT)
    if verified.tls_public_key_fp is None:
        raise AttestationError(f'document endorses no "{CRYPTO_MATERIAL_ID_TLS}" key')
    _key_format(verified, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT)


def _key_format(verified: VerifiedFacts, item_id: str, item_format: str) -> None:
    for item in verified.crypto_material:
        if item.id == item_id and item.format != item_format:
            raise AttestationError(f'crypto_material item "{item_id}" has format "{item.format}", want "{item_format}"')


def retryable(err: TinfoilError) -> bool:
    """Whether a failed verification attempt is worth one more: a network or attestation failure, but not a
    configuration error or a verification check's rejection."""
    if isinstance(err, ConfigurationError) or isinstance(err.__cause__, VerificationRejected):
        return False
    return isinstance(err, NetworkError | AttestationError)


__all__ = [
    "DEADLINE_EXCEEDED",
    "FRESHNESS_EXPIRED",
    "NO_FRESHNESS_DEADLINE",
    "NO_VERIFIED_FACTS",
    "VERIFICATION_RETRY_DELAY",
    "AsyncDocumentFetch",
    "DocumentFetch",
    "Enclave",
    "Retried",
    "VerificationRejected",
    "check_deadline",
    "check_freshness",
    "is_fresh",
    "new_verifier",
    "retryable",
    "validate_transport_keys",
]
