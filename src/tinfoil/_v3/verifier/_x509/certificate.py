"""Certificate parsing, accessors and chain verification at an appraisal time.

``cryptography`` parses and checks signatures; the functions here add the
pre-checks on the DER that make parsing strict, read the extensions that
the verifier needs by OID, and build chains against caller-supplied roots
at the instant the caller supplies, never the wall clock.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TypeAlias

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

Certificate: TypeAlias = x509.Certificate
PublicKey: TypeAlias = ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey
"""The key types that the verifier accepts for signatures: ECDSA (P-256, P-384), RSA and Ed25519."""

OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2"
"""The embedded Signed Certificate Timestamp list (RFC 6962)."""
OID_EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

MAX_CHAIN_LENGTH = 6
"""The most certificates a verified path may hold, counting the leaf and the root."""


class X509Error(ValueError):
    """A certificate that fails to parse, violates its profile or does not chain to a trusted root."""


@dataclass(frozen=True, slots=True)
class Extension:
    """One certificate extension, with its value as the raw DER inside the OCTET STRING."""

    oid: str
    critical: bool
    value: bytes


def parse_certificate(der: bytes) -> Certificate:
    """Parse one DER certificate.

    Before handing the bytes to the library, the outer structure is
    tokenized so that trailing bytes, indefinite lengths and non-minimal
    encodings are rejected, and the result must re-encode to the same
    bytes.
    """
    raise NotImplementedError


def parse_certificate_pem(pem: str | bytes) -> Certificate:
    """Parse exactly one PEM CERTIFICATE block."""
    raise NotImplementedError


def parse_certificates_pem(pem: str | bytes) -> tuple[Certificate, ...]:
    """Parse every PEM CERTIFICATE block, in order, requiring at least one and nothing but certificates."""
    raise NotImplementedError


def load_public_key_pem(pem: str | bytes) -> PublicKey:
    """Load a PEM PUBLIC KEY of an accepted type."""
    raise NotImplementedError


def extensions(certificate: Certificate) -> tuple[Extension, ...]:
    """Every extension in certificate order, with duplicate OIDs rejected."""
    raise NotImplementedError


def extension(certificate: Certificate, oid: str) -> Extension | None:
    """The extension with ``oid``, or None when absent."""
    raise NotImplementedError


def public_key_spki(key: PublicKey) -> bytes:
    """The DER SubjectPublicKeyInfo of a key."""
    raise NotImplementedError


def spki_fingerprint(spki: bytes) -> bytes:
    """SHA-256 over a DER SubjectPublicKeyInfo: the standard key-pinning computation."""
    raise NotImplementedError


def uri_sans(certificate: Certificate) -> tuple[str, ...]:
    """The URI entries of the subjectAltName extension, in order; empty when there is none."""
    raise NotImplementedError


def can_issue_certificates(certificate: Certificate) -> bool:
    """Whether basicConstraints marks a CA and keyUsage, when present, allows keyCertSign."""
    raise NotImplementedError


def can_sign_revocation_lists(certificate: Certificate) -> bool:
    """Whether keyUsage, when present, allows cRLSign."""
    raise NotImplementedError


def can_sign_data(certificate: Certificate) -> bool:
    """Whether keyUsage, when present, allows digitalSignature."""
    raise NotImplementedError


def unsupported_critical_extension(certificate: Certificate) -> str | None:
    """The OID of the first critical extension that the verifier does not understand, or None.

    Understood: basicConstraints, keyUsage, extendedKeyUsage,
    subjectAltName and the SCT list.
    """
    raise NotImplementedError


def valid_at(certificate: Certificate, at: datetime) -> bool:
    """Whether ``at`` falls within notBefore and notAfter, inclusive."""
    raise NotImplementedError


def verify_certificate_signature(certificate: Certificate, issuer: Certificate) -> None:
    """Check that ``issuer``'s key signed ``certificate`` with an accepted algorithm.

    Accepted: ECDSA with SHA-256 or SHA-384, RSA PKCS#1 v1.5 with
    SHA-256, RSA-PSS with SHA-384 and Ed25519; the algorithm in the
    signed TBSCertificate must equal the outer one.
    """
    raise NotImplementedError


def verify_chain(
    leaf: Certificate,
    intermediates: Sequence[Certificate],
    roots: Sequence[Certificate],
    at: datetime,
    *,
    extended_key_usage: str | None = None,
) -> tuple[Certificate, ...]:
    """Build and verify a path from ``leaf`` through ``intermediates`` to one of ``roots`` at ``at``.

    Every certificate on the path must be valid at ``at``, each must be
    signed by the next, each non-leaf must be able to issue certificates,
    the path (leaf and root included) may hold at most MAX_CHAIN_LENGTH
    certificates, no certificate may carry an
    unsupported critical extension, and when ``extended_key_usage`` is
    given the leaf and every intermediate that lists extendedKeyUsage must
    include it. Returns the path from the leaf to the matched root.
    """
    raise NotImplementedError
