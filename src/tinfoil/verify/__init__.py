"""Verification of Tinfoil v3 attestation documents.

Verification raises two error types. UsageError means the verifier was built
or called with invalid inputs; fix the caller. VerificationError means the
document must not be trusted; its ``layer`` names the layer that rejected it.

The ``document``, ``collateral`` and ``measurement`` modules hold the types
results refer to.
"""

from ._errors import Error, Layer, UsageError, VerificationError
from ._verification import SoftwareIdentity, Verification, VerificationMetadata, crypto_material_data

__all__ = [
    "Error",
    "Layer",
    "SoftwareIdentity",
    "UsageError",
    "Verification",
    "VerificationError",
    "VerificationMetadata",
    "crypto_material_data",
]
