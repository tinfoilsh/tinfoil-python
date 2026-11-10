"""SPKI fingerprints of TLS certificates, in the form that attestation documents endorse."""

from __future__ import annotations

import hashlib
import ssl
from collections.abc import Callable

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from tinfoil._v3.verifier._errors import LAYER_POLICY, UsageError, VerificationError

_FINGERPRINT_SIZE = hashlib.sha256().digest_size
_LOWER_HEX = "0123456789abcdef"


def cert_pubkey_fp(cert_der: bytes) -> str:
    """The SPKI SHA-256 fingerprint of a DER certificate's public key (any key type), lowercase hex: the form that
    ``Verification.tls_public_key_fp`` reports. A certificate that does not parse is a UsageError."""
    if not cert_der:
        raise UsageError("no certificate")
    try:
        certificate = x509.load_der_x509_certificate(bytes(cert_der))
    except ValueError as err:
        raise UsageError(f"parsing certificate: {err}") from err
    try:
        spki = certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except (ValueError, UnsupportedAlgorithm) as err:
        raise UsageError(f"marshaling public key: {err}") from err
    return hashlib.sha256(spki).hexdigest()


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
    performs; it does not replace them. A mismatch is a VerificationError of the policy layer.

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
        got = connection_cert_fp(connection)
        if got != fp:
            raise VerificationError(LAYER_POLICY, f"TLS key {got} does not match the attested key {fp}")

    return check


__all__ = ["cert_pubkey_fp", "connection_cert_fp", "pin_tls_key"]
