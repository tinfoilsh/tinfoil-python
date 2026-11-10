"""Verification of certificate-signed bundles: the Fulcio path for release provenance and the registry-issuer path
for certified config approvals.

Both paths establish a signing time from verified material (a transparency
log receipt or an RFC 3161 timestamp, never the wall clock), build the
signing certificate's chain at that time, check the certificate's identity
and check the DSSE signature over the artifact digest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from tinfoil._v3.verifier._sigstore.bundle import Bundle
from tinfoil._v3.verifier._sigstore.trusted_root import CertificateAuthority, TrustedRoot
from tinfoil._v3.verifier._x509.certificate import Certificate

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
RUNNER_ENVIRONMENT_GITHUB_HOSTED = "github-hosted"

# Fulcio certificate extensions (1.3.6.1.4.1.57264.1.x).
OID_FULCIO_ISSUER = "1.3.6.1.4.1.57264.1.8"
OID_FULCIO_BUILD_SIGNER_URI = "1.3.6.1.4.1.57264.1.9"
OID_FULCIO_RUNNER_ENVIRONMENT = "1.3.6.1.4.1.57264.1.11"
OID_FULCIO_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12"
OID_FULCIO_SOURCE_REPOSITORY_DIGEST = "1.3.6.1.4.1.57264.1.13"
OID_FULCIO_SOURCE_REPOSITORY_REF = "1.3.6.1.4.1.57264.1.14"
OID_FULCIO_SOURCE_REPOSITORY_IDENTIFIER = "1.3.6.1.4.1.57264.1.15"
OID_FULCIO_SOURCE_REPOSITORY_OWNER_URI = "1.3.6.1.4.1.57264.1.16"
OID_FULCIO_SOURCE_REPOSITORY_OWNER_IDENTIFIER = "1.3.6.1.4.1.57264.1.17"

SCT_VERSION_V1 = 0
SCT_LOG_ID_SIZE = 32


class CertificateBundleError(ValueError):
    """A certificate-signed bundle that does not verify."""


@dataclass(frozen=True, slots=True)
class SigningIdentity:
    """What the signing certificate must assert: a SAN pattern, the OIDC issuer and the runner environment."""

    san: re.Pattern[str]
    issuer: str
    runner_environment: str


@dataclass(frozen=True, slots=True)
class FulcioExtensions:
    """The Fulcio extensions that the verifier reads from a signing certificate; "" when absent."""

    issuer: str
    source_repository_uri: str
    source_repository_digest: str
    source_repository_ref: str
    source_repository_identifier: str
    source_repository_owner_identifier: str
    runner_environment: str
    build_signer_uri: str


@dataclass(frozen=True, slots=True)
class SignedCertificateTimestamp:
    """One SCT from the leaf's embedded list."""

    log_id: bytes
    timestamp: datetime
    signature_algorithm: tuple[int, int]
    """The TLS HashAlgorithm and SignatureAlgorithm codes."""
    signature: bytes
    extensions: bytes


@dataclass(frozen=True, slots=True)
class VerifiedBundle:
    """The outcome of verifying a certificate-signed bundle."""

    payload: bytes
    leaf: Certificate
    extensions: FulcioExtensions
    signed_at: datetime
    """The instant the chain was verified at: the earliest observer timestamp, or the log integrated time."""
    logged_at: datetime | None
    """The earliest verified transparency-log time, or None when only an RFC 3161 timestamp was verified."""


def workflow_identity_pattern(repo: str, workflow_pattern: str, ref_pattern: str) -> re.Pattern[str]:
    """An anchored SAN regex for a GitHub workflow of ``repo``.

    ``repo`` is escaped; ``workflow_pattern`` matches the workflow file
    name under ``.github/workflows/`` and ``ref_pattern`` the ref after
    ``@``.
    """
    raise NotImplementedError


def fulcio_extensions(leaf: Certificate) -> FulcioExtensions:
    """Read the Fulcio extensions, each a DER UTF8String; a malformed value is an error, an absent one is ""."""
    raise NotImplementedError


def signed_certificate_timestamps(leaf: Certificate) -> tuple[SignedCertificateTimestamp, ...]:
    """Decode the leaf's embedded SCT list (RFC 6962 SignedCertificateTimestampList), in order."""
    raise NotImplementedError


def check_duplicate_sct_logs(scts: tuple[SignedCertificateTimestamp, ...]) -> None:
    """Reject a list in which two SCTs name the same CT log."""
    raise NotImplementedError


def verify_scts(root: TrustedRoot, leaf: Certificate, issuer: Certificate, at: datetime) -> int:
    """Verify every embedded SCT against the CT logs valid at its timestamp and return how many verified.

    The signed input is the precertificate: the leaf's TBSCertificate
    with the SCT extension removed, prefixed by the issuer key hash. An SCT
    from an unknown log is an error, not a skip.
    """
    raise NotImplementedError


def verify_certificate_chain_at(
    leaf: Certificate,
    authorities: tuple[CertificateAuthority, ...],
    at: datetime,
    *,
    extended_key_usage: str,
) -> CertificateAuthority:
    """Build the leaf's chain to one of ``authorities`` at ``at`` and return the authority that anchored it.

    Each authority's chain supplies the intermediates; the authority
    itself must be valid at ``at``.
    """
    raise NotImplementedError


def check_identity(leaf: Certificate, extensions: FulcioExtensions, identity: SigningIdentity) -> None:
    """Check that exactly one URI SAN matches ``identity.san`` and the issuer and runner-environment extensions equal
    the expected values."""
    raise NotImplementedError


def verify_dsse_signature(leaf: Certificate, bundle: Bundle) -> None:
    """Check the envelope's one signature over the PAE with the leaf's key."""
    raise NotImplementedError


def verify_fulcio_bundle(root: TrustedRoot, bundle: Bundle, identity: SigningIdentity, digest: bytes) -> VerifiedBundle:
    """Verify a Fulcio-signed DSSE bundle: the production path for release provenance.

    In order: the bundle's material is a ``CertificateMaterial``; its SCTs verify (at least
    one, no duplicate logs); the signing time is established from at least
    one verified observer timestamp or transparency-log receipt (the log
    entries are verified against the trusted logs, including inclusion
    proofs and the entry body's binding to the signature); the chain
    verifies to a Fulcio authority at that time with the code-signing EKU;
    the identity matches; the DSSE signature verifies; the statement names
    ``digest`` as a subject.
    """
    raise NotImplementedError


def signed_timestamp(root: TrustedRoot, bundle: Bundle) -> datetime:
    """Verify the bundle's one RFC 3161 timestamp over the DSSE signature and return its genTime.

    Requires exactly one timestamp within MAX_TIMESTAMP_SIZE, verified by
    a timestamp authority whose window contains the genTime.
    """
    raise NotImplementedError


def verify_certified_bundle(
    root: TrustedRoot, bundle: Bundle, issuer: Certificate, san_uri: str, digest: bytes, at: datetime
) -> VerifiedBundle:
    """Verify a bundle signed with a short-lived certificate issued by a registry issuer.

    ``at`` is the independently verified signing time (from
    ``signed_timestamp``). The leaf must chain directly to ``issuer`` at
    ``at``, carry exactly ``san_uri`` as its one URI SAN and no OIDC
    issuer, the transparency-log receipt (exactly one, Rekor v2) must
    verify, and the DSSE signature must verify over ``digest``.
    """
    raise NotImplementedError
