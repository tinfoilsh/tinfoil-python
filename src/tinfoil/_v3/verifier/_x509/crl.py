"""Certificate revocation lists: strict parsing, issuer signature and validity window at an appraisal time."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509

from tinfoil._v3.verifier._x509.certificate import Certificate


class CRLError(ValueError):
    """A revocation list that fails to parse, is not signed by its issuer or is outside its window."""


@dataclass(frozen=True, slots=True)
class RevocationList:
    """A parsed CRL, not yet checked against its issuer."""

    raw: bytes
    crl: x509.CertificateRevocationList
    """The library object; the properties below read from it."""

    @property
    def issuer(self) -> x509.Name:
        raise NotImplementedError

    @property
    def this_update(self) -> datetime:
        raise NotImplementedError

    @property
    def next_update(self) -> datetime:
        """Required: a CRL without nextUpdate is rejected at parse time."""
        raise NotImplementedError

    @property
    def revoked_serials(self) -> frozenset[int]:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class VerifiedRevocationList:
    """A CRL whose issuer signature and validity window were checked; the only type that ``is_revoked`` accepts."""

    crl: RevocationList
    issuer: Certificate
    verified_at: datetime


def parse_revocation_list(der: bytes) -> RevocationList:
    """Parse one DER CRL.

    The outer structure is tokenized first so that trailing bytes and
    non-minimal encodings are rejected. Requires version 2, a nextUpdate,
    times with ``Z``, no unsupported critical CRL extensions and no
    critical CRL entry extensions.
    """
    raise NotImplementedError


def verify_revocation_list(crl: RevocationList, issuer: Certificate, at: datetime) -> VerifiedRevocationList:
    """Check that ``issuer`` signed the CRL, may sign CRLs, and that ``at`` lies within thisUpdate and nextUpdate.

    The issuer's name must equal the CRL's issuer name.
    """
    raise NotImplementedError


def is_revoked(crl: VerifiedRevocationList, serial: int) -> bool:
    """Whether a certificate serial number is listed by a verified CRL."""
    raise NotImplementedError
