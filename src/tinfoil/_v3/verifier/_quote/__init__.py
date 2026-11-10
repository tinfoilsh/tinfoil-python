"""Verification of a document's CPU evidence: authenticate, assemble, validate."""

from tinfoil._v3.verifier._quote.config import ConfigReferenceValues
from tinfoil._v3.verifier._quote.legacy import LegacyReferenceValues
from tinfoil._v3.verifier._quote.quote import (
    AssembledPolicy,
    AssemblyError,
    Authenticated,
    QuoteError,
    QuoteOptions,
    ReferenceValues,
    TestOnlyRoots,
    assemble,
    assemble_with,
    authenticate,
)

__all__ = [
    "AssembledPolicy",
    "AssemblyError",
    "Authenticated",
    "ConfigReferenceValues",
    "LegacyReferenceValues",
    "QuoteError",
    "QuoteOptions",
    "ReferenceValues",
    "TestOnlyRoots",
    "assemble",
    "assemble_with",
    "authenticate",
]
