"""The verify error contract (sdk-flywheel ERROR_ARCHITECTURE.md).

Verification raises only UsageError and VerificationError. The type tells the
caller what to do; the layer of a VerificationError is for diagnostics,
telemetry and conformance, and messages and causes may change in any release.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum


class Layer(StrEnum):
    """The verification layer that rejected a document.

    More layers may be added, so callers must tolerate values they don't
    recognize.
    """

    ENVELOPE = "envelope"
    """The document can't be parsed, isn't bound to the caller's nonce, or contradicts itself."""
    PROVENANCE = "provenance"
    """Reference values fail to authenticate or don't match the requested workload."""
    QUOTE = "quote"
    """The hardware evidence isn't authentic."""
    POLICY = "policy"
    """The evidence is authentic but doesn't satisfy the policy."""


class Error(Exception):
    """An error raised by tinfoil.verify: a UsageError or a VerificationError."""


class UsageError(Error):
    """The verifier was built or called with invalid inputs.

    Fix the caller; retrying won't help.
    """

    def __str__(self) -> str:
        return f"usage error: {super().__str__()}"


class VerificationError(Error):
    """The document must not be trusted.

    ``layer`` names the layer that rejected it. The underlying error, when
    there is one, is the exception's ``__cause__``.
    """

    def __init__(self, layer: Layer, message: str) -> None:
        super().__init__(layer, message)
        self.layer = layer

    def __str__(self) -> str:
        return f"verification error: {self.layer}: {self.args[1]}"


@contextmanager
def as_rejection(layer: Layer) -> Iterator[None]:
    """Report a failure inside the block as a rejection by ``layer``.

    Errors that already carry a verify type pass through, so a caller's
    mistake found mid-verification stays a UsageError. NotImplementedError
    also passes through: an unimplemented step is never a verdict.
    """
    try:
        yield
    except (Error, NotImplementedError):
        raise
    except Exception as err:
        raise VerificationError(layer, str(err)) from err


@contextmanager
def as_usage_error() -> Iterator[None]:
    """Report a failure inside the block as a UsageError."""
    try:
        yield
    except (Error, NotImplementedError):
        raise
    except Exception as err:
        raise UsageError(str(err)) from err


@contextmanager
def prefixed(context: str) -> Iterator[None]:
    """Prefix the message of a failure inside the block with ``context``."""
    try:
        yield
    except (Error, NotImplementedError):
        raise
    except Exception as err:
        raise ValueError(f"{context}: {err}") from err
