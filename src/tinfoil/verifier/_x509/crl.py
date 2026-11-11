"""Certificate revocation lists: strict parsing, issuer signature and validity window at an appraisal time.

A list is read as a complete revocation set: no CRL or entry extension is
processed, so a critical one, or one that changes what the serial list
means (a delta CRL indicator, an issuing distribution point, a certificate
issuer on an entry), is rejected rather than silently honored.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from tinfoil.verifier._x509 import der
from tinfoil.verifier._x509.certificate import (
    Certificate,
    X509Error,
    can_sign_revocation_lists,
    certificate_public_key,
    parse_extension_list,
    signature_algorithm,
    subject_name,
    verify_signature,
)

OID_DELTA_CRL_INDICATOR = "2.5.29.27"
OID_ISSUING_DISTRIBUTION_POINT = "2.5.29.28"
OID_CERTIFICATE_ISSUER = "2.5.29.29"
_SCOPE_CHANGING = frozenset({OID_DELTA_CRL_INDICATOR, OID_ISSUING_DISTRIBUTION_POINT, OID_CERTIFICATE_ISSUER})
_CRL_VERSION_2 = 1


class CRLError(ValueError):
    """A revocation list that fails to parse, is not signed by its issuer or is outside its window."""


@dataclass(frozen=True, slots=True)
class RevocationList:
    """A parsed CRL, not yet checked against its issuer."""

    raw: bytes
    crl: x509.CertificateRevocationList
    """The library object; the properties below read from it."""
    revoked_serials: frozenset[int]
    """Every listed serial number, collected once at parse time."""

    @property
    def issuer(self) -> x509.Name:
        return self.crl.issuer

    @property
    def this_update(self) -> datetime:
        return self.crl.last_update_utc

    @property
    def next_update(self) -> datetime:
        """Required: a CRL without nextUpdate is rejected at parse time."""
        value = self.crl.next_update_utc
        if value is None:
            raise CRLError("revocation list has no nextUpdate")
        return value


@dataclass(frozen=True, slots=True)
class VerifiedRevocationList:
    """A CRL whose issuer signature and validity window were checked; the only type that ``is_revoked`` accepts."""

    crl: RevocationList
    issuer: Certificate
    verified_at: datetime


def parse_revocation_list(der_bytes: bytes) -> RevocationList:
    """Parse one DER CRL.

    The outer structure is tokenized first so that trailing bytes and
    non-minimal encodings are rejected. Requires version 2, a nextUpdate,
    times with ``Z``, no unsupported critical CRL extensions and no
    critical CRL entry extensions.
    """
    try:
        _check_crl_der(der_bytes)
    except der.DerError as err:
        raise CRLError(f"revocation list: {err}") from err
    except X509Error as err:
        raise CRLError(f"revocation list: {err}") from err
    try:
        crl = x509.load_der_x509_crl(der_bytes)
    except (ValueError, TypeError, UnsupportedAlgorithm) as err:
        raise CRLError(f"revocation list: {err}") from err
    if crl.public_bytes(serialization.Encoding.DER) != der_bytes:
        raise CRLError("revocation list: does not re-encode to its input")
    parsed = RevocationList(raw=der_bytes, crl=crl, revoked_serials=frozenset(entry.serial_number for entry in crl))
    if parsed.this_update > parsed.next_update:
        raise CRLError("revocation list: thisUpdate is after nextUpdate")
    return parsed


def _check_crl_der(der_bytes: bytes) -> None:
    top = der.decode(der_bytes)
    der.validate_tree(top)
    parts = der.expect_sequence(top, "CertificateList")
    if len(parts) != 3:
        raise CRLError("CertificateList must hold tbsCertList, signatureAlgorithm and signatureValue")
    fields = der.expect_sequence(parts[0], "TBSCertList")
    if not fields or not der.is_universal(fields[0], der.TAG_INTEGER):
        raise CRLError("revocation list version is required")
    if der.integer(fields[0]) != _CRL_VERSION_2:
        raise CRLError("unsupported revocation list version")
    if len(fields) < 5:
        raise CRLError("TBSCertList is missing required fields")
    if fields[1].raw != parts[1].raw:
        raise CRLError("inner and outer signature algorithms differ")
    signature_algorithm(parts[1])
    der.expect_sequence(fields[2], "issuer Name")
    der.time(fields[3])
    if not _is_time(fields[4]):
        raise CRLError("nextUpdate is required")
    der.time(fields[4])
    index = 5
    if index < len(fields) and der.is_universal(fields[index], der.TAG_SEQUENCE):
        for entry in der.children(fields[index]):
            entry_fields = der.expect_sequence(entry, "revoked certificate entry")
            if not 2 <= len(entry_fields) <= 3:
                raise CRLError("revoked certificate entry must hold a serial, a date and optional extensions")
            der.integer(entry_fields[0])
            der.time(entry_fields[1])
            if len(entry_fields) == 3:
                _reject_unsupported(entry_fields[2], "CRL entry extension")
        index += 1
    if index < len(fields) and der.is_context(fields[index], 0) and fields[index].constructed:
        inner = der.children(fields[index])
        if len(inner) != 1:
            raise CRLError("CRL extensions must wrap one SEQUENCE")
        _reject_unsupported(inner[0], "CRL extension")
        index += 1
    if index != len(fields):
        raise CRLError("unexpected field in TBSCertList")
    der.bit_string(parts[2])


def _is_time(element: der.Element) -> bool:
    return der.is_universal(element, der.TAG_UTC_TIME) or der.is_universal(element, der.TAG_GENERALIZED_TIME)


def _reject_unsupported(element: der.Element, what: str) -> None:
    for ext in parse_extension_list(element):
        if ext.critical or ext.oid in _SCOPE_CHANGING:
            raise CRLError(f"unsupported {what} {ext.oid}")


def verify_revocation_list(crl: RevocationList, issuer: Certificate, at: datetime) -> VerifiedRevocationList:
    """Check that ``issuer`` signed the CRL, may sign CRLs, and that ``at`` lies within thisUpdate and nextUpdate.

    The issuer's name must equal the CRL's issuer name.
    """
    if at.tzinfo is None or at.utcoffset() is None:
        raise CRLError("verification time must be timezone-aware")
    if crl.issuer.public_bytes() != subject_name(issuer):
        raise CRLError("revocation list issuer does not match the issuing certificate")
    if not can_sign_revocation_lists(issuer):
        raise CRLError("issuing certificate may not sign revocation lists")
    outer = der.children(der.decode(crl.raw))
    try:
        algorithm = signature_algorithm(outer[1])
        verify_signature(
            algorithm, certificate_public_key(issuer), der.bit_string(outer[2]), crl.crl.tbs_certlist_bytes
        )
    except (X509Error, der.DerError) as err:
        raise CRLError(f"revocation list signature does not verify: {err}") from err
    if not crl.this_update <= at <= crl.next_update:
        raise CRLError(
            f"revocation list is not current at {at.isoformat()} "
            f"(thisUpdate {crl.this_update.isoformat()}, nextUpdate {crl.next_update.isoformat()})"
        )
    return VerifiedRevocationList(crl=crl, issuer=issuer, verified_at=at)


def is_revoked(crl: VerifiedRevocationList, serial: int) -> bool:
    """Whether a certificate serial number is listed by a verified CRL."""
    return serial in crl.crl.revoked_serials
