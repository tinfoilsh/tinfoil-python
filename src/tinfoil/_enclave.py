"""Verification of one attested enclave. An ``Enclave`` names the enclave and the policy it is verified against,
and keeps no state; the attested transport caches what it verifies and ties HTTP traffic to the keys it
endorses."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
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
from tinfoil._types import DEFAULT_HTTP_TIMEOUT, TimeoutTypes, VerificationCheck
from tinfoil.verifier import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    Verification,
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

VERIFICATION_RETRIES = 1
CANDIDATE_VERIFICATION_RETRIES = 0
VERIFICATION_RETRY_DELAY = 1.0

Fetch = Callable[[], Verification]
"""A test seam: replaces fetching and verifying a document."""
AsyncFetch = Callable[[], Awaitable[Verification]]


class VerificationRejected(Exception):
    """A verification check's rejection: a decision about the evidence, so an Enclave does not retry it."""

    def __init__(self, host: str, cause: BaseException) -> None:
        super().__init__(f"verification check rejected {host}: {cause}")
        self.__cause__ = cause


class Enclave:
    """One enclave and the policy its attestation is verified against.

    ``host`` is the enclave, a host with an optional port. ``relay``, when
    set, is a host that fetches attestation from the enclave on the
    client's behalf. ``repo`` pins a GitHub repository,
    ``owner/name[@tag][@sha256:digest]``, and ``project`` a config registry
    project, ``org/project[@revision][@sha256:digest]``; both empty accepts
    the configs that the verifier's configured config trust authorizes: the public or
    the caller's registry, the caller's signing keys, a config authorizer
    or an embedded config. ``verifier`` is the policy, which several
    enclaves can share; None selects the defaults.
    ``verification_check``, when set, is called with each verification
    that passes the verifier; raising rejects it without a retry.

    Construction checks ``repo`` and ``project`` against the verifier's
    rules for a pin and does no network I/O.
    """

    __slots__ = ("_check", "_fetch", "_fetch_async", "host", "project", "relay", "repo", "verifier")

    def __init__(
        self,
        host: str,
        repo: str | None = None,
        *,
        project: str | None = None,
        relay: str = "",
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        _fetch: Fetch | None = None,
        _fetch_async: AsyncFetch | None = None,
    ) -> None:
        if not host:
            raise ConfigurationError("enclave host is required")
        for authority in (host, relay):
            if authority and not is_authority(authority):
                raise ConfigurationError(f"invalid host {authority!r}: want a host with an optional port")
        if verifier is None:
            verifier = Verifier()
        repo = repo or ""
        project = project or ""
        try:
            verifier.check_pin_verifiability(repo, project=project)
        except VerifyError as err:
            raise from_verify(err) from err
        self.host = host
        self.relay = relay
        self.repo = repo
        self.project = project
        self.verifier = verifier
        self._check = verification_check
        self._fetch = _fetch
        self._fetch_async = _fetch_async

    def verify(self, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None) -> Verification:
        """Fetch and verify the enclave's attestation, retrying once after a network or attestation failure. The
        verification it returns is fresh and has passed the verification check. ``timeout`` bounds each network
        operation of the fetch; ``deadline``, a ``time.monotonic`` instant, bounds the whole of each attempt,
        the fetch, the verification and the check included, and no retry starts once it has passed: an attempt
        that completes after it is a NetworkError."""
        return self._verify(VERIFICATION_RETRIES, timeout, deadline)

    def verify_once(
        self, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
    ) -> Verification:
        """``verify`` without the retry, so a caller trying several enclaves moves on quickly."""
        return self._verify(CANDIDATE_VERIFICATION_RETRIES, timeout, deadline)

    async def verify_async(
        self, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
    ) -> Verification:
        """``verify`` on the event loop."""
        return await self._verify_async(VERIFICATION_RETRIES, timeout, deadline)

    async def verify_once_async(
        self, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT, deadline: float | None = None
    ) -> Verification:
        """``verify_once`` on the event loop."""
        return await self._verify_async(CANDIDATE_VERIFICATION_RETRIES, timeout, deadline)

    def _verify(self, retries: int, timeout: TimeoutTypes, deadline: float | None) -> Verification:
        first: TinfoilError | None = None
        for attempt in range(retries + 1):
            try:
                check_deadline(deadline)
                verified = self._fetch() if self._fetch is not None else self._fetch_verification(timeout, deadline)
                self._admit(verified)
                # The verification and the check are not bounded by the fetch's timeouts, so the deadline is
                # checked again before the result is accepted.
                check_deadline(deadline)
                return verified
            except TinfoilError as err:
                if attempt == retries or not retryable(err) or not _retry_fits(deadline):
                    if first is not None:
                        err.__context__ = first
                    raise
                first = err
            time.sleep(VERIFICATION_RETRY_DELAY)
        raise AssertionError("unreachable")  # pragma: no cover - the loop returns or raises

    async def _verify_async(self, retries: int, timeout: TimeoutTypes, deadline: float | None) -> Verification:
        first: TinfoilError | None = None
        for attempt in range(retries + 1):
            try:
                check_deadline(deadline)
                if self._fetch_async is not None:
                    verified = await self._fetch_async()
                else:
                    verified = await self._fetch_verification_async(timeout, deadline)
                self._admit(verified)
                check_deadline(deadline)
                return verified
            except TinfoilError as err:
                if attempt == retries or not retryable(err) or not _retry_fits(deadline):
                    if first is not None:
                        err.__context__ = first
                    raise
                first = err
            await asyncio.sleep(VERIFICATION_RETRY_DELAY)
        raise AssertionError("unreachable")  # pragma: no cover - the loop returns or raises

    def _admit(self, verified: Verification) -> None:
        """Checks that a fetched verification is fresh and passes the verification check. The check can run past
        the deadline, so freshness is checked again after it; a retry then fetches fresh evidence."""
        check_freshness(verified)
        if self._check is not None:
            try:
                self._check(verified)
            except Exception as err:
                raise attestation_error(VerificationRejected(self.host, err))  # noqa: B904 - the cause is set
        check_freshness(verified)

    def _fetch_verification(self, timeout: TimeoutTypes, deadline: float | None) -> Verification:
        nonce = random_nonce()
        doc = fetch_document(self.host, self.relay, nonce, timeout=timeout, deadline=deadline)
        return self._verify_document(doc, nonce)

    async def _fetch_verification_async(self, timeout: TimeoutTypes, deadline: float | None) -> Verification:
        nonce = random_nonce()
        doc = await fetch_document_async(self.host, self.relay, nonce, timeout=timeout, deadline=deadline)
        # Verification is CPU-bound, so it runs off the event loop.
        return await asyncio.to_thread(self._verify_document, doc, nonce)

    def _verify_document(self, doc: bytes, nonce: bytes) -> Verification:
        try:
            verified = self.verifier.verify_v3(doc, nonce, self.repo, project=self.project)
        except VerifyError as err:
            raise from_verify(err) from err
        validate_transport_keys(verified)
        return verified


def check_deadline(deadline: float | None) -> None:
    """Raises NetworkError once ``deadline``, a ``time.monotonic`` instant, has passed; None is no deadline."""
    if deadline is not None and time.monotonic() > deadline:
        raise NetworkError(DEADLINE_EXCEEDED)


def _retry_fits(deadline: float | None) -> bool:
    """Whether the retry delay and another attempt can start before ``deadline``."""
    return deadline is None or time.monotonic() + VERIFICATION_RETRY_DELAY < deadline


def check_freshness(verified: Verification) -> None:
    """Rejects a verification whose witnesses no longer authorize requests. A verification without a deadline,
    which no endorsed reference supplied, has nothing that bounds requests, so it is rejected as well, with a
    message of its own."""
    if verified.freshness_expires_at is None:
        raise AttestationError(NO_FRESHNESS_DEADLINE)
    if not is_fresh(verified):
        raise AttestationError(FRESHNESS_EXPIRED)


def is_fresh(verified: Verification) -> bool:
    """Whether ``verified``'s witnesses authorize requests now."""
    return verified.freshness_expires_at is not None and datetime.now(UTC) < verified.freshness_expires_at


def validate_transport_keys(verified: Verification) -> None:
    """Requires the keys a transport binds traffic to: the TLS key, and the HPKE key when the document endorses
    one."""
    _key_format(verified, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT)
    if verified.tls_public_key_fp is None:
        raise AttestationError(f'document endorses no "{CRYPTO_MATERIAL_ID_TLS}" key')
    _key_format(verified, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT)


def _key_format(verified: Verification, item_id: str, item_format: str) -> None:
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
    "VERIFICATION_RETRY_DELAY",
    "Enclave",
    "VerificationRejected",
    "check_deadline",
    "check_freshness",
    "is_fresh",
    "retryable",
    "validate_transport_keys",
]
