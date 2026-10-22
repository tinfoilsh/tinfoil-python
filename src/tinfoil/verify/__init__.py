"""Verification of Tinfoil v3 attestation documents.

Verification raises two error types. UsageError means the verifier was built
or called with invalid inputs; fix the caller. VerificationError means the
document must not be trusted; its ``layer`` names the layer that rejected it.
"""

from ._errors import Error, Layer, UsageError, VerificationError

__all__ = [
    "Error",
    "Layer",
    "UsageError",
    "VerificationError",
]
