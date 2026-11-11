"""The errors that verification reports."""

from __future__ import annotations

from typing import Final, TypeAlias

Layer: TypeAlias = str
"""The verification layer that rejected a document. The ``LAYER_*`` constants name the layers that exist today;
more may be added, so a caller must tolerate values that it does not recognize."""

LAYER_ENVELOPE: Final[Layer] = "envelope"
"""A document that can't be parsed, isn't bound to the caller's nonce, or contradicts itself."""
LAYER_PROVENANCE: Final[Layer] = "provenance"
"""Reference values that fail to authenticate or don't match the requested workload."""
LAYER_QUOTE: Final[Layer] = "quote"
"""Hardware evidence that isn't authentic."""
LAYER_POLICY: Final[Layer] = "policy"
"""Authentic evidence that doesn't satisfy the policy."""


class VerifyError(Exception):
    """An error raised by the verifier: a UsageError or a VerificationError."""


class UsageError(VerifyError, ValueError):
    """A verifier built or called with invalid inputs. Fix the caller; retrying will not help.

    ``str(err)`` is the bare message, which ``message`` also carries. It is a
    ``ValueError`` as well, so code that treats invalid arguments generically
    catches it; code that tells a caller's mistake from a rejected document
    catches ``UsageError`` and ``VerificationError`` separately.
    """

    message: str

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class VerificationError(VerifyError):
    """A document that must not be trusted, and the layer that rejected it.

    ``layer`` names the layer that rejected the document and ``message``
    says why; ``str(err)`` is ``"<layer>: <message>"``. A failure inside a
    layer that is not itself a ``VerifyError`` is reported as a rejection
    at that layer with the underlying exception as ``__cause__``, so an
    unfamiliar message may mean that the verifier failed rather than that
    the document was forged; a ``UsageError`` raised inside the pipeline
    passes through unwrapped.

    A rejection at the provenance layer may be transient: a freshness
    witness that has gone stale is reported the same way as a forged one,
    and a fresh document from the enclave may verify. The message is the
    only distinction today; there is no code to test.
    """

    layer: Layer
    message: str

    def __init__(self, layer: Layer, message: str) -> None:
        super().__init__(f"{layer}: {message}")
        self.layer = layer
        self.message = message


__all__ = [
    "LAYER_ENVELOPE",
    "LAYER_POLICY",
    "LAYER_PROVENANCE",
    "LAYER_QUOTE",
    "Layer",
    "UsageError",
    "VerificationError",
    "VerifyError",
]
