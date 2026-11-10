"""SPKI fingerprints of TLS certificates, in the form that attestation documents endorse."""

from __future__ import annotations

import hashlib
import ssl
from collections.abc import Callable

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from tinfoil._v3.verifier._errors import LAYER_POLICY, UsageError, VerificationError


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
    performs; it does not replace them. A mismatch is a VerificationError of the policy layer."""

    def check(connection: ssl.SSLSocket | ssl.SSLObject) -> None:
        got = connection_cert_fp(connection)
        if got != fp:
            raise VerificationError(LAYER_POLICY, f"TLS key {got} does not match the attested key {fp}")

    return check


__all__ = ["cert_pubkey_fp", "connection_cert_fp", "pin_tls_key"]
