"""Verification of a document's CPU evidence: authenticate, assemble, validate."""

from tinfoil.verifier._quote.config import ConfigReferenceValues
from tinfoil.verifier._quote.legacy import LegacyReferenceValues
from tinfoil.verifier._quote.quote import (
    AssembledPolicy,
    AssembledSEVSNP,
    AssembledTDX,
    AssemblyError,
    Authenticated,
    AuthenticatedSEVSNP,
    AuthenticatedTDX,
    QuoteError,
    QuoteOptions,
    ReferenceValues,
    SevPolicyError,
    TdxPolicyError,
    TestOnlyRoots,
    assemble,
    assemble_with,
    authenticate,
)

__all__ = [
    "AssembledPolicy",
    "AssembledSEVSNP",
    "AssembledTDX",
    "AssemblyError",
    "Authenticated",
    "AuthenticatedSEVSNP",
    "AuthenticatedTDX",
    "ConfigReferenceValues",
    "LegacyReferenceValues",
    "QuoteError",
    "QuoteOptions",
    "ReferenceValues",
    "SevPolicyError",
    "TdxPolicyError",
    "TestOnlyRoots",
    "assemble",
    "assemble_with",
    "authenticate",
]
