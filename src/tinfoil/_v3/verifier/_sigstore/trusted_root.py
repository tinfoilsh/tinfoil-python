"""The Sigstore trusted root: the transparency logs, CT logs, certificate authorities and timestamp authorities
that bundle verification trusts, each with its validity window.

The records here hold exactly the members that verification reads. They
are decoded from the JSON wire form with the strict parser and reject
unknown members at every depth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tinfoil._v3.verifier._x509.certificate import Certificate, PublicKey

TRUSTED_ROOT_MEDIA_TYPE = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

HASH_ALGORITHM_SHA2_256 = "SHA2_256"
KEY_DETAILS_P256 = "PKIX_ECDSA_P256_SHA_256"
KEY_DETAILS_P384 = "PKIX_ECDSA_P384_SHA_384"
KEY_DETAILS_ED25519 = "PKIX_ED25519"
SUPPORTED_KEY_DETAILS = (KEY_DETAILS_P256, KEY_DETAILS_P384, KEY_DETAILS_ED25519)


class TrustedRootError(ValueError):
    """A trusted root that fails to parse or names material that the verifier cannot use."""


@dataclass(frozen=True, slots=True)
class ValidFor:
    """A half-open validity window; ``end`` None means still valid."""

    start: datetime
    end: datetime | None = None

    def contains(self, at: datetime) -> bool:
        """Whether ``at`` is within the window, start and end inclusive."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class KeyedAuthority:
    """A transparency log or CT log: one public key identified by a log id."""

    base_url: str
    log_id: bytes
    """The 32-byte key id that bundles name the log by."""
    public_key: PublicKey
    key_details: str
    hash_algorithm: str
    valid_for: ValidFor
    checkpoint_key_id: bytes | None = None
    """The key id that signed checkpoints name (Rekor v2); None when the log uses ``log_id``."""


@dataclass(frozen=True, slots=True)
class CertificateAuthority:
    """A Fulcio or timestamp authority: a chain from the issuing certificate up to its self-signed root."""

    uri: str
    subject: str
    chain: tuple[Certificate, ...]
    """Leaf-first; the last entry is the root."""
    valid_for: ValidFor

    @property
    def root(self) -> Certificate:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class TrustedRoot:
    """The parsed trusted root."""

    tlogs: tuple[KeyedAuthority, ...]
    ctlogs: tuple[KeyedAuthority, ...]
    certificate_authorities: tuple[CertificateAuthority, ...]
    timestamp_authorities: tuple[CertificateAuthority, ...]

    def tlog(self, log_id: bytes) -> KeyedAuthority | None:
        """The transparency log with ``log_id``, or None."""
        raise NotImplementedError

    def tlog_by_checkpoint_key_id(self, key_id: bytes) -> KeyedAuthority | None:
        """The transparency log whose checkpoints are signed under ``key_id``, or None."""
        raise NotImplementedError

    def ctlog(self, log_id: bytes) -> KeyedAuthority | None:
        """The CT log with ``log_id``, or None."""
        raise NotImplementedError

    def certificate_authorities_at(self, at: datetime) -> tuple[CertificateAuthority, ...]:
        """The certificate authorities whose window contains ``at``."""
        raise NotImplementedError

    def timestamp_authorities_at(self, at: datetime) -> tuple[CertificateAuthority, ...]:
        """The timestamp authorities whose window contains ``at``."""
        raise NotImplementedError


def parse_trusted_root(data: bytes) -> TrustedRoot:
    """Decode a trusted-root document.

    Requires the v0.1 media type, at least one transparency log, keys of
    a supported type with a 32-byte log id, RFC 3339 times, and every
    certificate chain to parse and end in a self-signed root. Unknown
    members reject at every depth.
    """
    raise NotImplementedError


def embedded_trusted_root() -> TrustedRoot:
    """The trusted root that the verifier ships, parsed on each call."""
    raise NotImplementedError
