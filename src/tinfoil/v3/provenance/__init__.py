"""Sigstore provenance verification (Go: verifier/provenance): authenticates
the code, platform-endorsements, and freshness-witness bundles against the
pinned Tinfoil workflow identities and a caller-supplied (or embedded)
Sigstore trusted root. All failures raise VerificationError with the
PROVENANCE_REJECTED layer."""

from .freshness import (
    FRESHNESS_PREDICATE_FORMAT,
    MAX_FRESHNESS_AGE,
    MAX_FRESHNESS_FUTURE_SKEW,
    authenticate_freshness,
)
from .provenance import (
    FRESHNESS_WITNESS_IDENTITY,
    FRESHNESS_WITNESS_REPO,
    PLATFORM_ENDORSEMENTS_IDENTITY,
    PLATFORM_ENDORSEMENTS_REPO,
    AuthenticatedArtifact,
    Code,
    PlatformEndorsements,
    authenticate_code,
    authenticate_platform_endorsements,
    check_trust_root,
)

__all__ = [
    "FRESHNESS_PREDICATE_FORMAT",
    "FRESHNESS_WITNESS_IDENTITY",
    "FRESHNESS_WITNESS_REPO",
    "MAX_FRESHNESS_AGE",
    "MAX_FRESHNESS_FUTURE_SKEW",
    "PLATFORM_ENDORSEMENTS_IDENTITY",
    "PLATFORM_ENDORSEMENTS_REPO",
    "AuthenticatedArtifact",
    "Code",
    "PlatformEndorsements",
    "authenticate_code",
    "authenticate_freshness",
    "authenticate_platform_endorsements",
    "check_trust_root",
]
