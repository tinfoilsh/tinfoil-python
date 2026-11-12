"""The signals by which a bound transport reports that the peer no longer holds the attested keys, and by which
the attested transport reports that it has invalidated the verification a request was sent under."""

from __future__ import annotations

from tinfoil._errors import AttestationError, attestation_error


class PeerLacksKeyError(Exception):
    """A bound transport's report that the peer does not hold the keys the transport was created for, detected
    before the application processed the request. ``__cause__`` is the underlying failure.

    It is distinct from a key rejection because a bound transport used on
    its own has not invalidated anything, so its errors must not make a
    caller replay.
    """

    def __init__(self, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.__cause__ = cause


class KeyRejectedError(Exception):
    """The attested transport's report of a key rejection: the verification the request was sent under has been
    invalidated, so a replay goes out under a fresh one. ``__cause__`` is the underlying failure, and the message
    is that failure's own."""

    def __init__(self, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.__cause__ = cause


def key_rejection(err: PeerLacksKeyError) -> AttestationError:
    """The AttestationError that reports a key rejection, carrying the underlying failure's message once, with
    the ``KeyRejectedError`` marker as its cause and the failure behind that."""
    return attestation_error(KeyRejectedError(err.__cause__ or err))


def is_key_rejection(err: BaseException) -> bool:
    """Whether ``err`` reports a key rejection before application processing. The affected verification has
    already been invalidated, so a caller may replay the request once if its body can be read again."""
    return isinstance(err, AttestationError) and isinstance(err.__cause__, KeyRejectedError)


__all__ = ["KeyRejectedError", "PeerLacksKeyError", "is_key_rejection", "key_rejection"]
