"""The client's errors: one base type and three categories.

The category alone tells a caller what to do: fix the code
(``ConfigurationError``), retry later (``NetworkError``) or not proceed
(``AttestationError``). Finer detail is in the message; there are no further
subclasses. A verifier error that caused a client error is its ``__cause__``.
"""

from __future__ import annotations

from typing import ClassVar, TypeVar

from tinfoil._v3.verifier import UsageError, VerifyError

_E = TypeVar("_E", bound="TinfoilError")


class TinfoilError(Exception):
    """A client error: one of the three categories and the message that explains it.

    ``str(err)`` is the category, " error: " and the message, as in
    ``"attestation error: <message>"``. Upstream API errors, such as the
    ``openai`` package's, keep their own types and are never wrapped.
    """

    category: ClassVar[str] = ""
    """The category name: ``"configuration"``, ``"network"`` or ``"attestation"``."""

    def __init__(self, message: str) -> None:
        super().__init__(f"{self.category} error: {message}")
        self.message = message
        """The message without the category prefix."""


class ConfigurationError(TinfoilError):
    """Invalid caller arguments or client configuration. Retrying will not help."""

    category = "configuration"


class NetworkError(TinfoilError):
    """The client could not reach what it needed: a network failure, a timeout or an HTTP error status while
    fetching attestation material, the router list or the gateway catalog, or a gateway that keeps routing a
    request away from its enclave. Retry later."""

    category = "network"


class AttestationError(TinfoilError):
    """Rejected evidence, policy or channel binding: the enclave could not be trusted. Do not proceed."""

    category = "attestation"


def configuration_error(cause: BaseException | str) -> ConfigurationError:
    """A ConfigurationError with ``cause`` as its message and, when it is an exception, its ``__cause__``."""
    return _with_cause(ConfigurationError, cause)


def network_error(cause: BaseException | str) -> NetworkError:
    """A NetworkError with ``cause`` as its message and, when it is an exception, its ``__cause__``."""
    return _with_cause(NetworkError, cause)


def attestation_error(cause: BaseException | str) -> AttestationError:
    """An AttestationError with ``cause`` as its message and, when it is an exception, its ``__cause__``."""
    return _with_cause(AttestationError, cause)


def wrap_network(err: BaseException) -> BaseException:
    """``err`` itself when it already carries a client error, otherwise a NetworkError caused by it."""
    return err if tinfoil_error(err) is not None else network_error(err)


def wrap_attestation(err: BaseException) -> BaseException:
    """``err`` itself when it already carries a client error, otherwise an AttestationError caused by it."""
    return err if tinfoil_error(err) is not None else attestation_error(err)


def from_verify(err: VerifyError) -> TinfoilError:
    """A verifier error in the client's categories, by its type: a UsageError is the caller's configuration error,
    and anything else the verifier rejects is an attestation failure. The verifier error remains the cause."""
    if isinstance(err, UsageError):
        return configuration_error(err)
    return attestation_error(err)


def tinfoil_error(err: BaseException) -> TinfoilError | None:
    """The client error in ``err``'s cause chain, or None when there is none.

    A client error raised from the transport reaches a caller of the
    ``openai`` package wrapped in that package's ``APIConnectionError`` or
    ``APITimeoutError``; this follows ``__cause__`` and ``__context__``
    to find it.
    """
    current: BaseException | None = err
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, TinfoilError):
            return current
        current = current.__cause__ or current.__context__
    return None


def _with_cause(cls: type[_E], cause: BaseException | str) -> _E:
    if isinstance(cause, str):
        return cls(cause)
    err = cls(str(cause))
    err.__cause__ = cause
    return err


__all__ = [
    "AttestationError",
    "ConfigurationError",
    "NetworkError",
    "TinfoilError",
    "attestation_error",
    "configuration_error",
    "from_verify",
    "network_error",
    "tinfoil_error",
    "wrap_attestation",
    "wrap_network",
]
