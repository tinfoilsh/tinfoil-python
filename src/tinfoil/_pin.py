"""Checks that bind a TLS connection to the key fingerprint that an attestation document endorses.

The verifier reports the fingerprint (``Verification.tls_public_key_fp``) and computes it from certificate bytes
(``cert_pubkey_fp``); reading the peer certificate off a connection and building the check on it is the
transport's job, so that the verifier never takes a socket or a connection object.
"""

from __future__ import annotations

import hashlib
import ssl
from collections.abc import Callable

from tinfoil.verifier import LAYER_POLICY, UsageError, VerificationError, cert_pubkey_fp

_FINGERPRINT_SIZE = hashlib.sha256().digest_size
_LOWER_HEX = "0123456789abcdef"


def connection_cert_fp(connection: ssl.SSLSocket | ssl.SSLObject) -> str:
    """``cert_pubkey_fp`` of the leaf certificate that a TLS connection presented. A connection without a peer
    certificate is a UsageError."""
    leaf = connection.getpeercert(binary_form=True)
    if not leaf:
        raise UsageError("no peer certificates")
    return cert_pubkey_fp(leaf)


def pin_tls_key(fp: str) -> Callable[[ssl.SSLSocket | ssl.SSLObject], None]:
    """A check that accepts only a connection whose leaf certificate carries the public key fingerprint ``fp``, in
    the form ``Verification.tls_public_key_fp`` reports. It adds to the certificate checks that the TLS context
    performs; it does not replace them. A mismatch, or a peer certificate that does not parse, is a
    VerificationError of the policy layer; a connection without a peer certificate is a UsageError.


    Call the returned check on the ``ssl.SSLSocket`` or ``ssl.SSLObject``
    immediately after ``do_handshake()`` returns and before the first byte
    is written, so that nothing reaches a peer that holds the wrong key.
    The SDK's HTTP clients do this in their transport; a caller that opens
    its own connection does it like this::

        fp = verified.tls_public_key_fp
        if fp is None:  # a valid verification may endorse no TLS key
            raise RuntimeError("the document endorses no TLS key")
        check = pin_tls_key(fp)
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                check(tls)  # do_handshake() ran inside wrap_socket()
                tls.sendall(request)

    ``fp`` must be a SHA-256 digest as lowercase hex; anything else, such as the None that
    ``Verification.tls_public_key_fp`` reports when the document endorses no TLS key, is a UsageError here rather
    than a mismatch on every connection."""
    if not isinstance(fp, str):
        raise UsageError(f"TLS key fingerprint must be a lowercase hex string, not {type(fp).__name__}")
    if len(fp) != _FINGERPRINT_SIZE * 2 or fp.strip(_LOWER_HEX) != "":
        raise UsageError(f"TLS key fingerprint must be {_FINGERPRINT_SIZE} bytes as lowercase hex")

    def check(connection: ssl.SSLSocket | ssl.SSLObject) -> None:
        leaf = connection.getpeercert(binary_form=True)
        if not leaf:
            raise UsageError("no peer certificates")
        try:
            got = cert_pubkey_fp(leaf)
        except UsageError as err:
            # The leaf is the peer's evidence, not the caller's input: one that does not parse is a rejection.
            raise VerificationError(LAYER_POLICY, f"peer certificate: {err.message}") from err
        if got != fp:
            raise VerificationError(LAYER_POLICY, f"TLS key {got} does not match the attested key {fp}")

    return check


__all__ = ["connection_cert_fp", "pin_tls_key"]
