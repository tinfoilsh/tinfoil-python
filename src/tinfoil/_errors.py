"""The client's errors: one base type and three categories.

The category alone tells a caller what to do: fix the code
(``ConfigurationError``), retry later (``NetworkError``) or not proceed
(``AttestationError``). Finer detail is in the message; there are no further
subclasses. A verifier error that caused a client error is its ``__cause__``.
"""

from __future__ import annotations

from typing import ClassVar, TypeVar

from tinfoil.verifier import UsageError, VerifyError

_E = TypeVar("_E", bound="TinfoilError")


class TinfoilError(Exception):
    """A client error: one of the three categories and the message that explains it.

    ``str(err)`` is the message alone; the category is ``err.category`` and
    the class. The message is the exception's only argument, so an error
    pickles and unpickles unchanged. The class is abstract: only the three
    categories are raised, and constructing it directly is a TypeError.
    Upstream API errors, such as the ``openai`` package's, keep their own
    types and are never wrapped.
    """

    category: ClassVar[str]
    """The category name: ``"configuration"``, ``"network"`` or ``"attestation"``."""

    def __init__(self, message: str) -> None:
        if type(self) is TinfoilError:
            raise TypeError("TinfoilError is abstract; raise ConfigurationError, NetworkError or AttestationError")
        super().__init__(message)
        self.message = message
        """The message, as ``str(err)`` renders it."""


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
    """The client error that ``err`` is or was raised from, or None when there is none.

    A client error raised in the transport reaches a caller of the
    ``openai`` package as itself, not wrapped in that package's connection
    error, and the package does not retry it: it wraps and retries only
    the errors of its own HTTP stack. This helper is for a caller whose
    own code wraps the error, such as ``raise MyError(...) from err``: it
    follows the chain that the traceback shows, ``__cause__`` when it is
    set and otherwise ``__context__`` unless ``from None`` suppressed it.
    """
    current: BaseException | None = err
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, TinfoilError):
            return current
        if current.__cause__ is not None:
            current = current.__cause__
        elif not current.__suppress_context__:
            current = current.__context__
        else:
            current = None
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
