"""The errors that verification reports."""

from __future__ import annotations

# The verification layer that rejected a document. More layers may be added,
# so a caller must tolerate values that it does not recognize.
LAYER_ENVELOPE = "envelope"
"""A document that can't be parsed, isn't bound to the caller's nonce, or contradicts itself."""
LAYER_PROVENANCE = "provenance"
"""Reference values that fail to authenticate or don't match the requested workload."""
LAYER_QUOTE = "quote"
"""Hardware evidence that isn't authentic."""
LAYER_POLICY = "policy"
"""Authentic evidence that doesn't satisfy the policy."""


class VerifyError(Exception):
    """An error raised by the verifier: a UsageError or a VerificationError."""


class UsageError(VerifyError):
    """A verifier built or called with invalid inputs. Fix the caller; retrying will not help."""

    def __init__(self, message: str) -> None:
        super().__init__(f"usage error: {message}")
        self.message = message


class VerificationError(VerifyError):
    """A document that must not be trusted, and the layer that rejected it."""

    def __init__(self, layer: str, message: str) -> None:
        super().__init__(f"verification error: {layer}: {message}")
        self.layer = layer
        self.message = message
