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
    """A parsed CRL."""

    raw: bytes
    issuer: x509.Name
    this_update: datetime
    next_update: datetime
    """Required: a CRL without nextUpdate is rejected at parse time."""
    revoked_serials: frozenset[int]
    crl: x509.CertificateRevocationList
    """The library object, for the signature check."""


def parse_revocation_list(der: bytes) -> RevocationList:
    """Parse one DER CRL.

    The outer structure is tokenized first so that trailing bytes and
    non-minimal encodings are rejected. Requires version 2, a nextUpdate,
    times with ``Z``, no unsupported critical CRL extensions and no
    critical CRL entry extensions.
    """
    raise NotImplementedError


def verify_revocation_list(crl: RevocationList, issuer: Certificate, at: datetime) -> None:
    """Check that ``issuer`` signed the CRL, may sign CRLs, and that ``at`` lies within thisUpdate and nextUpdate.

    The issuer's name must equal the CRL's issuer name.
    """
    raise NotImplementedError


def is_revoked(crl: RevocationList, serial: int) -> bool:
    """Whether a certificate serial number is listed."""
    raise NotImplementedError
