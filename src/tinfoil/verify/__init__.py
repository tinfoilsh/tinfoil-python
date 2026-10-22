"""Verification of Tinfoil v3 attestation documents.

A Verifier appraises a document offline: given the document, the nonce the
caller bound it to, and the workload the caller trusts, it decides what the
document proves. It opens no connections and keeps no state between calls,
so fetching documents, caching a verification and enforcing its expiry
belong to the caller.

Verification raises two error types. UsageError means the verifier was built
or called with invalid inputs; fix the caller. VerificationError means the
document must not be trusted; its ``layer`` names the layer that rejected it.

The ``document``, ``collateral`` and ``measurement`` modules hold the types
these results and options refer to.
"""

from ._errors import Error, Layer, UsageError, VerificationError
from ._references import EmbeddedConfig, EmbeddedReferences
from ._verification import (
    ArtifactVerification,
    ConfigVerification,
    ReferenceSource,
    SoftwareIdentity,
    Verification,
    VerificationMetadata,
    crypto_material_data,
)
from ._verifier import Reference, Verifier, parse_reference
from .collateral import ConfigEndorsement

__all__ = [
    "ArtifactVerification",
    "ConfigEndorsement",
    "ConfigVerification",
    "EmbeddedConfig",
    "EmbeddedReferences",
    "Error",
    "Layer",
    "Reference",
    "ReferenceSource",
    "SoftwareIdentity",
    "UsageError",
    "Verification",
    "VerificationError",
    "VerificationMetadata",
    "Verifier",
    "crypto_material_data",
    "parse_reference",
]
