"""Reference-value resolution: what the quote is appraised against, and why.

A document's collateral format selects how its reference values are
authenticated. The legacy format, attestation-collaterals/v2, carries a
Sigstore-signed code release from the caller's repository and the
platform-endorsements artifact, each with a freshness witness. The format
selects a verification policy, never a trust anchor: each policy
authenticates its required entries before using their claims.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TypeVar

from . import _formats, _policy, _provenance, _quote
from ._errors import as_usage_error, prefixed
from .document import Document


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedReferences:
    """Authenticated reference values and the release they came from."""

    quote: _quote.LegacyReferenceValues
    # The authenticated code release.
    artifact: _provenance.AuthenticatedArtifact
    # The earlier of the code and platform freshness witness deadlines.
    freshness_expires_at: datetime


class ReferenceResolver:
    """Authenticates a document's reference values under a fixed trust policy."""

    __slots__ = ("_freshness_max_age", "_releases")

    def __init__(self, releases: _provenance.ReleaseVerifier, *, freshness_max_age: timedelta | None = None) -> None:
        """Validate the trust policy. Raises ValueError when it is invalid."""
        if freshness_max_age is not None and freshness_max_age < timedelta(0):
            raise ValueError("freshness maximum age must not be negative")
        # Zero keeps the default, so an unset policy field never disables the bound.
        self._freshness_max_age = freshness_max_age or _provenance.MAX_FRESHNESS_AGE
        self._releases = releases

    @property
    def freshness_max_age(self) -> timedelta:
        """The maximum age of a freshness witness."""
        return self._freshness_max_age

    def resolve(self, document: Document, repo: str, now: datetime) -> ResolvedReferences:
        """Authenticate the reference values ``document`` carries, appraised at ``now``.

        ``repo`` is the caller's ``owner/name[@tag][@sha256:digest]`` workload
        constraint.
        """
        if document.collateral_format == _formats.COLLATERAL_V3:
            # Config, runtime and platform collateral are not supported yet.
            raise NotImplementedError
        if document.collateral_format != _formats.COLLATERAL_V2:
            raise ValueError(f"unsupported collateral format {document.collateral_format!r}")

        code_ref = _require(
            document.sigstore_code, f"document carries no {_formats.SIGSTORE_CODE_V1} reference-values entry"
        )
        with as_usage_error():
            pin = _provenance.parse_reference(repo)
        code = self._releases.authenticate_code(code_ref.bundle, pin, code_ref.tag, code_ref.digest)
        platform_ref = _require(
            document.sigstore_platform, f"document carries no {_formats.SIGSTORE_PLATFORM_V1} reference-values entry"
        )
        with prefixed("verifying platform endorsements"):
            endorsements = self._releases.authenticate_platform_endorsements(
                platform_ref.bundle, platform_ref.repo, platform_ref.tag, platform_ref.digest, _policy.ARTIFACT_FORMAT
            )
        with prefixed("verifying code freshness"):
            code_witnessed_at = self._authenticate_witness(document, _formats.FRESHNESS_ID_CODE, code.artifact, now)
        with prefixed("verifying platform freshness"):
            platform_witnessed_at = self._authenticate_witness(
                document, _formats.FRESHNESS_ID_PLATFORM, endorsements.artifact, now
            )
        return ResolvedReferences(
            quote=_quote.LegacyReferenceValues(
                endorsements=endorsements.policy, code=code.measurement, shape=code.shape
            ),
            artifact=code.artifact,
            # Deadlines come from authenticated witness times, never the local clock.
            freshness_expires_at=min(code_witnessed_at, platform_witnessed_at) + self._freshness_max_age,
        )

    def _authenticate_witness(
        self, document: Document, entry_id: str, artifact: _provenance.AuthenticatedArtifact, now: datetime
    ) -> datetime:
        witness = _require(
            document.freshness(entry_id),
            f"document carries no {_formats.SIGSTORE_FRESHNESS_V1} reference-values entry {entry_id!r}",
        )
        if witness.format != _formats.SIGSTORE_FRESHNESS_V1:
            raise ValueError(
                f"legacy verification requires freshness collateral format {_formats.SIGSTORE_FRESHNESS_V1!r}"
            )
        return self._releases.authenticate_freshness(witness.bundle, artifact, now, self._freshness_max_age)


_T = TypeVar("_T")


def _require(value: _T | None, message: str) -> _T:
    if value is None:
        raise ValueError(message)
    return value
