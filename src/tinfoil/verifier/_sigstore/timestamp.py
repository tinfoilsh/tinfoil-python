"""RFC 3161 timestamp responses: decoding, the imprint check and verification against the trusted root's timestamp
authorities at the token's own genTime.

The CMS signature check is delegated to ``rfc3161-client``; the token's
fields are read here from the strict DER tree, and the checks that the
library does not make (status, policy, TSTInfo version, size bounds, the
signer's profile, the chain to the authority, that the token carries no
certificate from outside that chain, and the authority's validity window
at genTime) are made here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from rfc3161_client import TimeStampResponse as WireResponse
from rfc3161_client import VerificationError, VerifierBuilder, decode_timestamp_response

from tinfoil.verifier import _json
from tinfoil.verifier._sigstore.bundle import MAX_STATEMENT_SIZE as MAX_STATEMENT_SIZE
from tinfoil.verifier._sigstore.bundle import MAX_TIMESTAMP_SIZE as MAX_TIMESTAMP_SIZE
from tinfoil.verifier._sigstore.trusted_root import CertificateAuthority, TrustedRoot
from tinfoil.verifier._x509 import der
from tinfoil.verifier._x509.certificate import (
    OID_EKU_TIME_STAMPING,
    OID_EXT_KEY_USAGE,
    Certificate,
    X509Error,
    basic_constraints,
    can_sign_data,
    extended_key_usage,
    extension,
    issuer_name,
    parse_certificate,
    verify_chain,
)

SIGSTORE_TIMESTAMP_POLICY = "1.3.6.1.4.1.57264.2"
STATUS_GRANTED = 0
TST_INFO_VERSION = 1
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"


class TimestampError(ValueError):
    """A timestamp response that fails to decode, does not match its input or no authority authenticated."""


@dataclass(frozen=True, slots=True)
class TimestampResponse:
    """A decoded TimeStampResp."""

    status: int
    policy: str
    gen_time: datetime
    hash_algorithm: str
    """The message imprint's hash algorithm OID."""
    hashed_message: bytes
    tst_info_version: int
    serial_number: int
    nonce: int | None
    token_raw: bytes
    """The DER TimeStampToken that the response carries: the CMS SignedData, not the TimeStampResp around it."""


def timestamp_input(domain: bytes, core: _json.JsonValue) -> bytes:
    """The bytes that an approval timestamps: ``domain`` followed by the RFC 8785 canonical form of ``core``."""
    return domain + _json.canonicalize(core)


def parse_timestamp_response(response: bytes) -> TimestampResponse:
    """Decode a DER TimeStampResp.

    Rejects a response outside (0, MAX_TIMESTAMP_SIZE], a status other
    than STATUS_GRANTED (a token granted with modifications is rejected
    too), a TSTInfo version other than 1, a genTime that is not
    GeneralizedTime with ``Z`` and a message imprint that is not SHA-256.
    """
    if not 0 < len(response) <= MAX_TIMESTAMP_SIZE:
        raise TimestampError("timestamp response size is outside allowed bounds")
    try:
        top = der.decode(response)
        der.validate_tree(top)
        parts = der.expect_sequence(top, "TimeStampResp")
        if not 1 <= len(parts) <= 2:
            raise TimestampError("TimeStampResp must hold a status and an optional token")
        status_info = der.expect_sequence(parts[0], "PKIStatusInfo")
        if not status_info:
            raise TimestampError("PKIStatusInfo has no status")
        status = der.integer(status_info[0])
        if status != STATUS_GRANTED:
            raise TimestampError(f"timestamp request was not granted (status {status})")
        if len(parts) != 2:
            raise TimestampError("granted timestamp response has no token")
        info = _tst_info(parts[1])
    except der.DerError as err:
        raise TimestampError(f"timestamp response: {err}") from err
    # The library's own decoder must agree that this is a granted response.
    wire = _decode(response)
    if wire.status != STATUS_GRANTED:
        raise TimestampError(f"timestamp request was not granted (status {wire.status})")
    if info.tst_info_version != TST_INFO_VERSION:
        raise TimestampError("unsupported TSTInfo version")
    if info.hash_algorithm != OID_SHA256:
        raise TimestampError("timestamp message imprint is not SHA-256")
    return info


def _decode(response: bytes) -> WireResponse:
    try:
        return decode_timestamp_response(response)
    except ValueError as err:
        raise TimestampError(f"timestamp response: {err}") from err


def _tst_info(token: der.Element) -> TimestampResponse:
    """Read the TSTInfo that the TimeStampToken encapsulates."""
    content_info = der.expect_sequence(token, "TimeStampToken")
    if len(content_info) != 2 or der.object_identifier(content_info[0]) != OID_SIGNED_DATA:
        raise TimestampError("TimeStampToken must be a SignedData ContentInfo")
    signed_data = der.expect_sequence(_explicit(content_info[1], 0, "SignedData content"), "SignedData")
    if len(signed_data) < 4:
        raise TimestampError("SignedData is missing required fields")
    encapsulated = der.expect_sequence(signed_data[2], "EncapsulatedContentInfo")
    if len(encapsulated) != 2 or der.object_identifier(encapsulated[0]) != OID_TST_INFO:
        raise TimestampError("SignedData must encapsulate a TSTInfo")
    tst_info = der.decode(der.octet_string(_explicit(encapsulated[1], 0, "eContent")))
    der.validate_tree(tst_info)
    fields = der.expect_sequence(tst_info, "TSTInfo")
    if len(fields) < 5:
        raise TimestampError("TSTInfo is missing required fields")
    imprint = der.expect_sequence(fields[2], "MessageImprint")
    if len(imprint) != 2:
        raise TimestampError("MessageImprint must hold an algorithm and a digest")
    algorithm = der.expect_sequence(imprint[0], "MessageImprint hashAlgorithm")
    if not 1 <= len(algorithm) <= 2 or (len(algorithm) == 2 and not der.is_universal(algorithm[1], der.TAG_NULL)):
        raise TimestampError("hash AlgorithmIdentifier must hold an OID and optional NULL")
    if not der.is_universal(fields[4], der.TAG_GENERALIZED_TIME):
        raise TimestampError("TSTInfo genTime must be a GeneralizedTime")
    nonce: int | None = None
    for field in fields[5:]:
        if der.is_universal(field, der.TAG_INTEGER):
            nonce = der.integer(field)
    return TimestampResponse(
        status=STATUS_GRANTED,
        policy=der.object_identifier(fields[1]),
        gen_time=der.time(fields[4], fractional_seconds=True),
        hash_algorithm=der.object_identifier(algorithm[0]),
        hashed_message=der.octet_string(imprint[1]),
        tst_info_version=der.integer(fields[0]),
        serial_number=der.integer(fields[3]),
        nonce=nonce,
        token_raw=token.raw,
    )


def _explicit(element: der.Element, tag: int, what: str) -> der.Element:
    if not der.is_context(element, tag) or not element.constructed:
        raise TimestampError(f"{what} must be tagged [{tag}]")
    inner = der.children(element)
    if len(inner) != 1:
        raise TimestampError(f"{what} must wrap one element")
    return inner[0]


def check_imprint(response: TimestampResponse, data: bytes) -> None:
    """Check that the response's message imprint is SHA-256 over ``data``, with ``data`` within MAX_STATEMENT_SIZE."""
    if not 0 < len(data) <= MAX_STATEMENT_SIZE:
        raise TimestampError("timestamp input size is outside allowed bounds")
    if response.hash_algorithm != OID_SHA256 or response.hashed_message != hashlib.sha256(data).digest():
        raise TimestampError("timestamp response does not match the input")


def verify_timestamp(
    root: TrustedRoot, response: bytes, data: bytes, *, policy: str = SIGSTORE_TIMESTAMP_POLICY
) -> datetime:
    """Verify a timestamp over ``data`` and return its genTime.

    The response is decoded and its imprint checked; the token's policy
    OID must equal ``policy``. Then each timestamp
    authority whose window contains the genTime is tried: the token's
    signing certificate must chain to the authority at the genTime with
    the time-stamping EKU and the CMS signature must verify. The first
    authority that authenticates the token decides; when none does, the
    timestamp is rejected.
    """
    parsed = parse_timestamp_response(response)
    check_imprint(parsed, data)
    if parsed.policy != policy:
        raise TimestampError(f"unexpected timestamp policy {parsed.policy}")
    wire = _decode(response)
    failures: list[str] = []
    for index, authority in enumerate(root.timestamp_authorities_at(parsed.gen_time)):
        try:
            _verify_under_authority(authority, wire, parsed, hashlib.sha256(data).digest())
        except (TimestampError, X509Error) as err:
            failures.append(f"authority {index}: {err}")
            continue
        return parsed.gen_time
    detail = f" ({'; '.join(failures)})" if failures else ""
    raise TimestampError(f"no trusted timestamp authority authenticated the response{detail}")


def _verify_under_authority(
    authority: CertificateAuthority, wire: WireResponse, parsed: TimestampResponse, hashed_message: bytes
) -> None:
    """Check one authority: the token's signer is an end entity restricted to timestamping that chains to the
    authority at genTime, and the CMS signature verifies under it."""
    signer_infos = list(wire.signed_data.signer_infos)
    if len(signer_infos) != 1:
        raise TimestampError(f"SignedData must have exactly one signer, got {len(signer_infos)}")
    signer_info = signer_infos[0]
    sid_issuer = signer_info.issuer.public_bytes()
    sid_serial = signer_info.serial_number
    # The library trusts every certificate the token carries and may verify the signature under any of them.
    trusted = {certificate.public_bytes(serialization.Encoding.DER) for certificate in authority.chain}
    if not trusted.issuperset(wire.signed_data.certificates):
        raise TimestampError("the token carries a certificate outside the authority's chain")
    embedded = [parse_certificate(raw) for raw in sorted(wire.signed_data.certificates)]
    candidates = embedded if embedded else [authority.chain[0]]
    signer = next((c for c in candidates if issuer_name(c) == sid_issuer and c.serial_number == sid_serial), None)
    if signer is None:
        raise TimestampError("the token's signer certificate was not found")
    constraints = basic_constraints(signer)
    if constraints is not None and constraints[0]:
        raise TimestampError("the signing certificate is a certificate authority")
    if not can_sign_data(signer):
        raise TimestampError("the signing certificate's key usage does not permit signing")
    eku = extension(signer, OID_EXT_KEY_USAGE)
    if eku is None or not eku.critical or extended_key_usage(signer) != (OID_EKU_TIME_STAMPING,):
        raise TimestampError("the signing certificate's extended key usage must be critical and name only timestamping")
    intermediates = _dedupe([*authority.chain[:-1], *(c for c in embedded if c is not signer)], exclude=signer)
    verify_chain(signer, intermediates, [authority.root], parsed.gen_time, extended_key_usage=OID_EKU_TIME_STAMPING)
    builder = VerifierBuilder().add_root_certificate(authority.root).tsa_certificate(signer)
    for certificate in intermediates:
        builder = builder.add_intermediate_certificate(certificate)
    builder = builder.policy_id(x509.ObjectIdentifier(parsed.policy))
    try:
        builder.build().verify(wire, hashed_message)
    except VerificationError as err:
        raise TimestampError(f"the timestamp signature does not verify: {err}") from err


def _dedupe(certificates: list[Certificate], *, exclude: Certificate) -> list[Certificate]:
    """``certificates`` without repeats and without ``exclude``, in order."""
    out: list[Certificate] = []
    seen = {exclude.public_bytes(serialization.Encoding.DER)}
    for certificate in certificates:
        raw = certificate.public_bytes(serialization.Encoding.DER)
        if raw in seen:
            continue
        seen.add(raw)
        out.append(certificate)
    return out
