"""SPKI fingerprints of TLS certificates, in the form that attestation documents endorse."""

from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from tinfoil.verifier._errors import UsageError


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


__all__ = ["cert_pubkey_fp"]
