"""Reference-value provenance (block B2): who released what, and how recently."""

from .releases import (
    MAX_FRESHNESS_AGE,
    AuthenticatedArtifact,
    Code,
    PlatformEndorsements,
    Reference,
    ReleaseVerifier,
    parse_reference,
)

__all__ = [
    "MAX_FRESHNESS_AGE",
    "AuthenticatedArtifact",
    "Code",
    "PlatformEndorsements",
    "Reference",
    "ReleaseVerifier",
    "parse_reference",
]
