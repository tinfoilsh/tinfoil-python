"""Certificate parsing, accessors and chain verification at an appraisal time.

``cryptography`` parses and checks signatures; the functions here add the
pre-checks on the DER that make parsing strict, read the extensions that
the verifier needs by OID, and build chains against caller-supplied roots
at the instant the caller supplies, never the wall clock.
"""

from __future__ import annotations

import hashlib
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TypeAlias, TypeVar

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.utils import CryptographyDeprecationWarning

from tinfoil.verifier._x509 import der

T = TypeVar("T")

# Production AMD VCEK certificates carry serial number zero. The library warns
# about it today and will reject it in a future release, which the
# library-claims test pins; the warning is silenced once, here, rather than by
# mutating the process-wide filters around every parse.
warnings.filterwarnings(
    "ignore", message=r"^Parsed a serial number which wasn't positive", category=CryptographyDeprecationWarning
)

Certificate: TypeAlias = x509.Certificate
AnyPublicKey: TypeAlias = ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey
"""The key types that the verifier accepts for signatures: ECDSA (P-256, P-384), RSA and Ed25519."""

OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2"
"""The embedded Signed Certificate Timestamp list (RFC 6962)."""
OID_EKU_ANY = "2.5.29.37.0"
OID_EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_RSA_PKCS1_SHA256 = "1.2.840.113549.1.1.11"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_ED25519 = "1.3.101.112"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"

MAX_CHAIN_LENGTH = 6
"""The most certificates a verified path may hold, counting the leaf and the root."""
MIN_RSA_KEY_BITS = 2048
"""The smallest RSA modulus accepted, in bits; a smaller key is rejected wherever a key is loaded."""

_UNDERSTOOD_CRITICAL = frozenset(
    {OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_EXT_KEY_USAGE, OID_SUBJECT_ALT_NAME, OID_SCT_LIST}
)
_KEY_USAGE_DIGITAL_SIGNATURE = 0
_KEY_USAGE_KEY_CERT_SIGN = 5
_KEY_USAGE_CRL_SIGN = 6
_GENERAL_NAME_URI = 6
_GENERAL_NAME_IP = 7


class X509Error(ValueError):
    """A certificate that fails to parse, violates its profile or does not chain to a trusted root."""


@dataclass(frozen=True, slots=True)
class Extension:
    """One certificate extension, with its value as the raw DER inside the OCTET STRING."""

    oid: str
    critical: bool
    value: bytes


@dataclass(frozen=True, slots=True)
class SignatureAlgorithm:
    """A supported signature AlgorithmIdentifier, as decoded from its DER."""

    oid: str
    """One of the OID_* signature algorithm constants."""


@dataclass(frozen=True, slots=True)
class _Tbs:
    """The fields of a TBSCertificate that the pre-checks and accessors read."""

    version: int
    serial: int
    issuer: bytes
    subject: bytes
    extensions: tuple[Extension, ...]


def parse_certificate(der_bytes: bytes) -> Certificate:
    """Parse one DER certificate.

    Before handing the bytes to the library, the outer structure is
    tokenized so that trailing bytes, indefinite lengths and non-minimal
    encodings are rejected, and the result must re-encode to the same
    bytes.
    """
    _with_context("certificate", lambda: _check_certificate_der(der_bytes))
    try:
        certificate = x509.load_der_x509_certificate(der_bytes)
    except (ValueError, TypeError, UnsupportedAlgorithm) as err:
        raise X509Error(f"certificate: {err}") from err
    if certificate.public_bytes(serialization.Encoding.DER) != der_bytes:
        raise X509Error("certificate: does not re-encode to its input")
    _public_key(certificate)
    return certificate


def parse_certificate_pem(pem: str | bytes) -> Certificate:
    """Parse exactly one PEM CERTIFICATE block."""
    blocks = _pem_blocks(pem)
    if len(blocks) != 1:
        raise X509Error(f"expected exactly one CERTIFICATE block, found {len(blocks)}")
    return parse_certificate(blocks[0])


def parse_certificates_pem(pem: str | bytes) -> tuple[Certificate, ...]:
    """Parse every PEM CERTIFICATE block, in order, requiring at least one and nothing but certificates."""
    blocks = _pem_blocks(pem)
    if not blocks:
        raise X509Error("no CERTIFICATE block")
    return tuple(parse_certificate(block) for block in blocks)


def load_public_key_pem(pem: str | bytes) -> AnyPublicKey:
    """Load a PEM PUBLIC KEY of an accepted type."""
    blocks = _with_context("public key", lambda: der.pem_blocks(_text(pem), "PUBLIC KEY"))
    if len(blocks) != 1:
        raise X509Error(f"expected exactly one PUBLIC KEY block, found {len(blocks)}")
    return load_public_key_der(blocks[0])


def load_public_key_der(spki: bytes) -> AnyPublicKey:
    """Load a DER SubjectPublicKeyInfo of an accepted type; it must re-encode to the same bytes."""
    _with_context("public key", lambda: der.validate_tree(der.decode(spki)))
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, TypeError, UnsupportedAlgorithm) as err:
        raise X509Error(f"public key: {err}") from err
    accepted = _accepted_key(key)
    if public_key_spki(accepted) != spki:
        raise X509Error("public key: does not re-encode to its input")
    return accepted


def extensions(certificate: Certificate) -> tuple[Extension, ...]:
    """Every extension in certificate order, with duplicate OIDs rejected."""
    return _tbs(certificate).extensions


def extension(certificate: Certificate, oid: str) -> Extension | None:
    """The extension with ``oid``, or None when absent."""
    for ext in extensions(certificate):
        if ext.oid == oid:
            return ext
    return None


def public_key_spki(key: AnyPublicKey) -> bytes:
    """The DER SubjectPublicKeyInfo of a key."""
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_fingerprint(spki: bytes) -> bytes:
    """SHA-256 over a DER SubjectPublicKeyInfo: the standard key-pinning computation."""
    return hashlib.sha256(spki).digest()


def certificate_public_key(certificate: Certificate) -> AnyPublicKey:
    """The certificate's key as one of the accepted types."""
    return _public_key(certificate)


def issuer_name(certificate: Certificate) -> bytes:
    """The DER issuer Name."""
    return _tbs(certificate).issuer


def subject_name(certificate: Certificate) -> bytes:
    """The DER subject Name."""
    return _tbs(certificate).subject


def uri_sans(certificate: Certificate) -> tuple[str, ...]:
    """The URI entries of the subjectAltName extension, in order; empty when there is none."""
    ext = extension(certificate, OID_SUBJECT_ALT_NAME)
    if ext is None:
        return ()
    return _with_context("subjectAltName", lambda: _uri_sans(ext.value))


def _uri_sans(value: bytes) -> tuple[str, ...]:
    names = der.expect_sequence(der.decode(value), "GeneralNames")
    out: list[str] = []
    for name in names:
        if name.tag_class != der.CLASS_CONTEXT or name.tag > 8:
            raise X509Error("GeneralName has an unexpected tag")
        if name.tag == _GENERAL_NAME_URI:
            out.append(_uri_general_name(name))
        elif name.tag == _GENERAL_NAME_IP and len(name.content) not in (4, 16):
            raise X509Error("IP GeneralName must be 4 or 16 bytes")
    return tuple(out)


def _uri_general_name(name: der.Element) -> str:
    """Decode a ``uniformResourceIdentifier`` GeneralName: a primitive IA5String that can be a URL.

    A URI with an ASCII control character cannot be a URL, and a percent
    escape must name a byte.
    """
    if name.constructed:
        raise X509Error("URI GeneralName must be primitive")
    text = der.ia5_string(der.Element(der.CLASS_UNIVERSAL, False, der.TAG_IA5_STRING, name.content, b""))
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text) or not _valid_percent_escapes(text):
        raise X509Error("URI GeneralName is not a URL")
    return text


def crl_distribution_point_uris(certificate: Certificate) -> tuple[str, ...]:
    """The URI names of the certificate's CRL distribution points, in order; empty when there is no extension.

    Only a ``fullName`` holding a ``uniformResourceIdentifier`` contributes,
    decoded under the same rules as a subjectAltName URI; a distribution
    point named relative to the CRL issuer and every other GeneralName
    form (including the X.400 and EDI party forms that have no URI) are
    skipped. A structure that is not a well-formed CRLDistributionPoints,
    including a DistributionPoint whose optional fields repeat or are out
    of order, is an X509Error.
    """
    ext = extension(certificate, OID_CRL_DISTRIBUTION_POINTS)
    if ext is None:
        return ()
    return _with_context("cRLDistributionPoints", lambda: _crl_distribution_point_uris(ext.value))


def _crl_distribution_point_uris(value: bytes) -> tuple[str, ...]:
    points = der.expect_sequence(der.decode(value), "CRLDistributionPoints")
    if not points:
        raise X509Error("CRLDistributionPoints must hold at least one DistributionPoint")
    out: list[str] = []
    for point in points:
        previous = -1
        for field in der.expect_sequence(point, "DistributionPoint"):
            if field.tag_class != der.CLASS_CONTEXT or field.tag > 2:
                raise X509Error("DistributionPoint has an unexpected field")
            # The optional fields distributionPoint [0], reasons [1] and cRLIssuer [2] each appear at most once, in
            # that order.
            if field.tag <= previous:
                raise X509Error("DistributionPoint fields are repeated or out of order")
            previous = field.tag
            # distributionPoint [0] is explicit, wrapping the DistributionPointName choice.
            if field.tag != 0:
                continue
            if not field.constructed:
                raise X509Error("distributionPoint must be constructed")
            choice = der.children(field)
            if len(choice) != 1:
                raise X509Error("distributionPoint must wrap one DistributionPointName")
            name = choice[0]
            if name.tag_class != der.CLASS_CONTEXT or name.tag > 1 or not name.constructed:
                raise X509Error("DistributionPointName has an unexpected form")
            # fullName [0] is implicit over GeneralNames, so its children are the GeneralName entries.
            if name.tag != 0:
                continue
            for general_name in der.children(name):
                if general_name.tag_class != der.CLASS_CONTEXT or general_name.tag > 8:
                    raise X509Error("GeneralName has an unexpected tag")
                if general_name.tag == _GENERAL_NAME_URI:
                    out.append(_uri_general_name(general_name))
    return tuple(out)


def _valid_percent_escapes(text: str) -> bool:
    index = text.find("%")
    while index >= 0:
        pair = text[index + 1 : index + 3]
        if len(pair) != 2 or not all(ch in "0123456789abcdefABCDEF" for ch in pair):
            return False
        index = text.find("%", index + 3)
    return True


def basic_constraints(certificate: Certificate) -> tuple[bool, int | None] | None:
    """The basicConstraints extension as ``(cA, pathLenConstraint)``, or None when absent."""
    ext = extension(certificate, OID_BASIC_CONSTRAINTS)
    if ext is None:
        return None
    return _with_context("basicConstraints", lambda: _basic_constraints(ext.value))


def _basic_constraints(value: bytes) -> tuple[bool, int | None]:
    parts = der.expect_sequence(der.decode(value), "BasicConstraints")
    if len(parts) > 2:
        raise X509Error("BasicConstraints holds too many fields")
    ca = False
    index = 0
    if parts and der.is_universal(parts[0], der.TAG_BOOLEAN):
        ca = der.boolean(parts[0])
        if not ca:
            raise X509Error("BasicConstraints encodes the default cA value")
        index = 1
    if index < len(parts):
        if index + 1 != len(parts):
            raise X509Error("BasicConstraints holds an unexpected field")
        path_length = der.integer(parts[index])
        if path_length < 0:
            raise X509Error("BasicConstraints path length is negative")
        return ca, path_length
    return ca, None


def key_usage(certificate: Certificate) -> tuple[bool, ...] | None:
    """The keyUsage bits indexed by bit position, or None when the extension is absent."""
    ext = extension(certificate, OID_KEY_USAGE)
    if ext is None:
        return None
    return _with_context("keyUsage", lambda: der.named_bits(der.decode(ext.value)))


def extended_key_usage(certificate: Certificate) -> tuple[str, ...] | None:
    """The extendedKeyUsage purposes, or None when the extension is absent."""
    ext = extension(certificate, OID_EXT_KEY_USAGE)
    if ext is None:
        return None
    return _with_context(
        "extendedKeyUsage",
        lambda: tuple(der.object_identifier(p) for p in der.expect_sequence(der.decode(ext.value), "ExtKeyUsage")),
    )


def _usage_bit(certificate: Certificate, bit: int) -> bool:
    usage = key_usage(certificate)
    return usage is None or (len(usage) > bit and usage[bit])


def can_issue_certificates(certificate: Certificate) -> bool:
    """Whether basicConstraints marks a CA and keyUsage, when present, allows keyCertSign."""
    constraints = basic_constraints(certificate)
    return constraints is not None and constraints[0] and _usage_bit(certificate, _KEY_USAGE_KEY_CERT_SIGN)


def can_sign_revocation_lists(certificate: Certificate) -> bool:
    """Whether keyUsage, when present, allows cRLSign."""
    return _usage_bit(certificate, _KEY_USAGE_CRL_SIGN)


def can_sign_data(certificate: Certificate) -> bool:
    """Whether keyUsage, when present, allows digitalSignature."""
    return _usage_bit(certificate, _KEY_USAGE_DIGITAL_SIGNATURE)


def unsupported_critical_extension(certificate: Certificate) -> str | None:
    """The OID of the first critical extension that the verifier does not understand, or None.

    Understood: basicConstraints, keyUsage, extendedKeyUsage,
    subjectAltName and the SCT list.
    """
    for ext in extensions(certificate):
        if ext.critical and ext.oid not in _UNDERSTOOD_CRITICAL:
            return ext.oid
    return None


def valid_at(certificate: Certificate, at: datetime) -> bool:
    """Whether ``at`` falls within notBefore and notAfter, inclusive."""
    _require_aware(at)
    return certificate.not_valid_before_utc <= at <= certificate.not_valid_after_utc


def verify_certificate_signature(certificate: Certificate, issuer: Certificate) -> None:
    """Check that ``issuer``'s key signed ``certificate`` with an accepted algorithm.

    Accepted: ECDSA with SHA-256 or SHA-384, RSA PKCS#1 v1.5 with
    SHA-256, RSA-PSS with SHA-384 and Ed25519; the algorithm in the
    signed TBSCertificate must equal the outer one.
    """
    outer = der.children(der.decode(certificate.public_bytes(serialization.Encoding.DER)))
    algorithm = _with_context("signature algorithm", lambda: signature_algorithm(outer[1]))
    signature = _with_context("signature", lambda: der.bit_string(outer[2]))
    verify_signature(algorithm, _public_key(issuer), signature, certificate.tbs_certificate_bytes)


def signature_algorithm(element: der.Element) -> SignatureAlgorithm:
    """Interpret an AlgorithmIdentifier as one of the supported signature algorithms.

    ECDSA and Ed25519 take no parameters; RSA PKCS#1 v1.5 takes NULL or
    none; RSA-PSS must name SHA-384, MGF1 with SHA-384, a 48-byte salt and
    the default trailer field.
    """
    parts = der.expect_sequence(element, "AlgorithmIdentifier")
    if not 1 <= len(parts) <= 2:
        raise X509Error("AlgorithmIdentifier must hold an OID and optional parameters")
    oid = der.object_identifier(parts[0])
    params = parts[1] if len(parts) == 2 else None
    if oid in (OID_ECDSA_SHA256, OID_ECDSA_SHA384, OID_ED25519):
        if params is not None:
            raise X509Error(f"signature algorithm {oid} takes no parameters")
    elif oid == OID_RSA_PKCS1_SHA256:
        if params is not None and not der.is_universal(params, der.TAG_NULL):
            raise X509Error("RSA PKCS#1 signature algorithm parameters must be NULL")
    elif oid == OID_RSA_PSS:
        if params is None:
            raise X509Error("RSA-PSS signature algorithm requires parameters")
        _check_pss_parameters(params)
    else:
        raise X509Error(f"unsupported signature algorithm {oid}")
    return SignatureAlgorithm(oid)


def _check_pss_parameters(params: der.Element) -> None:
    fields = der.expect_sequence(params, "RSA-PSS parameters")
    hash_oid = mgf_hash = None
    salt = trailer = None
    for field in fields:
        if field.tag_class != der.CLASS_CONTEXT or not field.constructed:
            raise X509Error("RSA-PSS parameter is not tagged")
        inner = der.children(field)
        if len(inner) != 1:
            raise X509Error("RSA-PSS parameter must wrap one value")
        if field.tag == 0:
            hash_oid = _hash_algorithm_oid(inner[0])
        elif field.tag == 1:
            mgf = der.expect_sequence(inner[0], "RSA-PSS mask generation function")
            if len(mgf) != 2 or der.object_identifier(mgf[0]) != OID_MGF1:
                raise X509Error("RSA-PSS mask generation function must be MGF1")
            mgf_hash = _hash_algorithm_oid(mgf[1])
        elif field.tag == 2:
            salt = der.integer(inner[0])
        elif field.tag == 3:
            trailer = der.integer(inner[0])
        else:
            raise X509Error("unknown RSA-PSS parameter")
    if hash_oid != OID_SHA384 or mgf_hash != OID_SHA384 or salt != 48:
        raise X509Error("RSA-PSS is supported only with SHA-384, MGF1-SHA-384 and a 48-byte salt")
    if trailer is not None and trailer != 1:
        raise X509Error("RSA-PSS trailer field must be 1")


def _hash_algorithm_oid(element: der.Element) -> str:
    parts = der.expect_sequence(element, "hash AlgorithmIdentifier")
    if not 1 <= len(parts) <= 2 or (len(parts) == 2 and not der.is_universal(parts[1], der.TAG_NULL)):
        raise X509Error("hash AlgorithmIdentifier must hold an OID and optional NULL")
    return der.object_identifier(parts[0])


def verify_signature(algorithm: SignatureAlgorithm, key: AnyPublicKey, signature: bytes, data: bytes) -> None:
    """Verify ``signature`` over ``data`` under ``key`` with ``algorithm``.

    The key type must suit the algorithm: an ECDSA signature's hash must
    match the key's curve (SHA-256 with P-256, SHA-384 with P-384), RSA
    algorithms need an RSA key and Ed25519 an Ed25519 key. An ECDSA
    signature must be minimal DER.
    """
    try:
        if algorithm.oid in (OID_ECDSA_SHA256, OID_ECDSA_SHA384):
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise X509Error("ECDSA signature under a non-EC key")
            size, hash_algorithm = _curve_parameters(key)
            if (algorithm.oid == OID_ECDSA_SHA256) != isinstance(hash_algorithm, hashes.SHA256):
                raise X509Error("ECDSA signature hash does not match the key's curve")
            raw = der.ecdsa_signature_to_raw(signature, size)
            if der.raw_signature_to_der(raw, size) != signature:
                raise X509Error("ECDSA signature is not minimal DER")
            key.verify(signature, data, ec.ECDSA(hash_algorithm))
        elif algorithm.oid == OID_RSA_PKCS1_SHA256:
            if not isinstance(key, rsa.RSAPublicKey):
                raise X509Error("RSA signature under a non-RSA key")
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm.oid == OID_RSA_PSS:
            if not isinstance(key, rsa.RSAPublicKey):
                raise X509Error("RSA signature under a non-RSA key")
            key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())
        elif algorithm.oid == OID_ED25519:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise X509Error("Ed25519 signature under a non-Ed25519 key")
            key.verify(signature, data)
        else:
            raise X509Error(f"unsupported signature algorithm {algorithm.oid}")
    except InvalidSignature as err:
        raise X509Error("signature does not verify") from err
    except der.DerError as err:
        raise X509Error(f"signature: {err}") from err


def _curve_parameters(key: ec.EllipticCurvePublicKey) -> tuple[int, hashes.HashAlgorithm]:
    if isinstance(key.curve, ec.SECP256R1):
        return 32, hashes.SHA256()
    if isinstance(key.curve, ec.SECP384R1):
        return 48, hashes.SHA384()
    raise X509Error(f"unsupported EC curve {key.curve.name}")


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
    given every certificate on the path that lists extendedKeyUsage must
    include it or anyExtendedKeyUsage. When the usage is code signing, the
    leaf's keyUsage, when present, must also allow digitalSignature.
    Returns the path from the leaf to the matched root.
    """
    _require_aware(at)
    if not roots:
        raise X509Error("no trusted roots")
    root_set = {r.public_bytes(serialization.Encoding.DER) for r in roots}
    failures: list[str] = []

    def accept(path: tuple[Certificate, ...]) -> bool:
        try:
            _check_path(path, at, extended_key_usage)
        except X509Error as err:
            failures.append(str(err))
            return False
        return True

    if leaf.public_bytes(serialization.Encoding.DER) in root_set and accept((leaf,)):
        return (leaf,)

    def extend(path: tuple[Certificate, ...]) -> tuple[Certificate, ...] | None:
        if len(path) >= MAX_CHAIN_LENGTH:
            failures.append(f"path longer than {MAX_CHAIN_LENGTH}")
            return None
        current = path[-1]
        seen = {c.public_bytes(serialization.Encoding.DER) for c in path}
        for candidate in [*roots, *intermediates]:
            raw = candidate.public_bytes(serialization.Encoding.DER)
            if raw in seen or subject_name(candidate) != issuer_name(current):
                continue
            try:
                verify_certificate_signature(current, candidate)
            except X509Error as err:
                failures.append(f"{_describe(current)} under {_describe(candidate)}: {err}")
                continue
            extended = (*path, candidate)
            if raw in root_set:
                if accept(extended):
                    return extended
                continue
            found = extend(extended)
            if found is not None:
                return found
        return None

    found = extend((leaf,))
    if found is None:
        detail = f" ({'; '.join(failures)})" if failures else ""
        raise X509Error(f"no verified path from {_describe(leaf)} to a trusted root{detail}")
    return found


def _check_path(path: tuple[Certificate, ...], at: datetime, extended_key_usage: str | None) -> None:
    for index, certificate in enumerate(path):
        if not valid_at(certificate, at):
            raise X509Error(f"{_describe(certificate)} is not valid at {at.isoformat()}")
        unsupported = unsupported_critical_extension(certificate)
        if unsupported is not None:
            raise X509Error(f"{_describe(certificate)} carries unsupported critical extension {unsupported}")
        if extended_key_usage is not None:
            usages = extended_key_usage_of(certificate)
            if usages is not None and extended_key_usage not in usages and OID_EKU_ANY not in usages:
                raise X509Error(f"{_describe(certificate)} does not allow extended key usage {extended_key_usage}")
        if index == 0:
            if extended_key_usage == OID_EKU_CODE_SIGNING and not can_sign_data(certificate):
                raise X509Error(f"{_describe(certificate)} does not allow digitalSignature")
            continue
        if not can_issue_certificates(certificate):
            raise X509Error(f"{_describe(certificate)} is not a certificate authority")
        constraints = basic_constraints(certificate)
        if constraints is not None and constraints[1] is not None and index - 1 > constraints[1]:
            raise X509Error(f"{_describe(certificate)} path length constraint exceeded")


extended_key_usage_of = extended_key_usage
"""Alias used where the ``extended_key_usage`` name is taken by a keyword argument."""


def _describe(certificate: Certificate) -> str:
    try:
        attributes = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    except ValueError:
        attributes = []
    if attributes:
        value = attributes[0].value
        name = value if isinstance(value, str) else value.hex()
        return f"certificate {name!r}"
    return f"certificate serial {certificate.serial_number}"


# --- pre-checks on the DER ---------------------------------------------------


def _check_certificate_der(der_bytes: bytes) -> None:
    """Check the structure that ``x509.load_der_x509_certificate`` is looser about.

    Rejected here: anything the strict tokenizer rejects anywhere in the
    tree; a negative serial number; an explicit version 1; extensions in a
    certificate below version 3; a duplicate extension; an inner signature
    algorithm that differs from the outer one; a signature BIT STRING with
    unused bits.
    """
    top = der.decode(der_bytes)
    der.validate_tree(top)
    parts = der.expect_sequence(top, "Certificate")
    if len(parts) != 3:
        raise X509Error("Certificate must hold tbsCertificate, signatureAlgorithm and signatureValue")
    tbs = _parse_tbs(parts[0], parts[1])
    if tbs.serial < 0:
        raise X509Error("negative serial number")
    der.bit_string(parts[2])


def _parse_tbs(tbs_element: der.Element, outer_algorithm: der.Element) -> _Tbs:
    fields = der.expect_sequence(tbs_element, "TBSCertificate")
    index = 0
    version = 0
    if fields and der.is_context(fields[0], 0):
        if not fields[0].constructed:
            raise X509Error("version must be explicitly tagged")
        inner = der.children(fields[0])
        if len(inner) != 1:
            raise X509Error("version must wrap one INTEGER")
        version = der.integer(inner[0])
        if version == 0:
            raise X509Error("version 1 must be encoded by omitting the version field")
        if version not in (1, 2):
            raise X509Error(f"unsupported certificate version {version + 1}")
        index = 1
    if len(fields) < index + 6:
        raise X509Error("TBSCertificate is missing required fields")
    serial = der.integer(fields[index])
    if fields[index + 1].raw != outer_algorithm.raw:
        raise X509Error("inner and outer signature algorithms differ")
    issuer = fields[index + 2]
    der.expect_sequence(issuer, "issuer Name")
    validity = der.expect_sequence(fields[index + 3], "Validity")
    if len(validity) != 2:
        raise X509Error("Validity must hold notBefore and notAfter")
    der.time(validity[0])
    der.time(validity[1])
    subject = fields[index + 4]
    der.expect_sequence(subject, "subject Name")
    der.expect_sequence(fields[index + 5], "SubjectPublicKeyInfo")
    exts: tuple[Extension, ...] = ()
    for position in range(index + 6, len(fields)):
        field = fields[position]
        if der.is_context(field, 1) or der.is_context(field, 2):
            if version < 1:
                raise X509Error("unique identifiers require version 2 or 3")
            continue
        if der.is_context(field, 3) and field.constructed and position == len(fields) - 1:
            if version != 2:
                raise X509Error("extensions require version 3")
            inner = der.children(field)
            if len(inner) != 1:
                raise X509Error("extensions must wrap one SEQUENCE")
            exts = parse_extension_list(inner[0])
            continue
        raise X509Error("unexpected field in TBSCertificate")
    for ext in exts:
        _check_known_extension(ext)
    return _Tbs(version=version, serial=serial, issuer=issuer.raw, subject=subject.raw, extensions=exts)


def _check_known_extension(ext: Extension) -> None:
    """Decode the extensions that the verifier reads, so that a malformed one rejects the certificate at parse."""
    if ext.oid == OID_BASIC_CONSTRAINTS:
        _with_context("basicConstraints", lambda: _basic_constraints(ext.value))
    elif ext.oid == OID_KEY_USAGE:
        _with_context("keyUsage", lambda: der.named_bits(der.decode(ext.value)))
    elif ext.oid == OID_EXT_KEY_USAGE:
        _with_context(
            "extendedKeyUsage",
            lambda: [der.object_identifier(p) for p in der.expect_sequence(der.decode(ext.value), "ExtKeyUsage")],
        )
    elif ext.oid == OID_SUBJECT_ALT_NAME:
        _with_context("subjectAltName", lambda: _uri_sans(ext.value))


def parse_extension_list(element: der.Element) -> tuple[Extension, ...]:
    """Parse a SEQUENCE OF Extension: OID, optional critical flag (an explicit FALSE is not DER), OCTET STRING value;
    no duplicates."""
    out: list[Extension] = []
    seen: set[str] = set()
    for ext in der.expect_sequence(element, "extensions"):
        parts = der.expect_sequence(ext, "extension")
        if not 2 <= len(parts) <= 3:
            raise X509Error("extension must hold an OID, optional critical flag and value")
        oid = der.object_identifier(parts[0])
        critical = False
        if len(parts) == 3:
            critical = der.boolean(parts[1])
            if not critical:
                raise X509Error("extension encodes the default critical value")
        value = der.octet_string(parts[-1])
        if oid in seen:
            raise X509Error(f"duplicate extension {oid}")
        seen.add(oid)
        out.append(Extension(oid=oid, critical=critical, value=value))
    return tuple(out)


def _tbs(certificate: Certificate) -> _Tbs:
    parts = der.children(der.decode(certificate.public_bytes(serialization.Encoding.DER)))
    return _with_context("certificate", lambda: _parse_tbs(parts[0], parts[1]))


def _public_key(certificate: Certificate) -> AnyPublicKey:
    try:
        key = certificate.public_key()
    except (ValueError, UnsupportedAlgorithm) as err:
        raise X509Error(f"certificate: unsupported public key: {err}") from err
    return _accepted_key(key)


def _accepted_key(key: object) -> AnyPublicKey:
    if isinstance(key, ec.EllipticCurvePublicKey):
        _curve_parameters(key)
        return key
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < MIN_RSA_KEY_BITS:
            raise X509Error(f"RSA public key of {key.key_size} bits is smaller than {MIN_RSA_KEY_BITS} bits")
        return key
    if isinstance(key, ed25519.Ed25519PublicKey):
        return key
    raise X509Error(f"unsupported public key type {type(key).__name__}")


def _pem_blocks(pem: str | bytes) -> tuple[bytes, ...]:
    return _with_context("certificate PEM", lambda: der.pem_blocks(_text(pem), "CERTIFICATE"))


def _text(pem: str | bytes) -> str:
    if isinstance(pem, bytes):
        try:
            return pem.decode("ascii")
        except UnicodeDecodeError as err:
            raise X509Error("PEM is not ASCII") from err
    return pem


def _require_aware(at: datetime) -> None:
    if at.tzinfo is None or at.utcoffset() is None:
        raise X509Error("verification time must be timezone-aware")


def _with_context(what: str, action: Callable[[], T]) -> T:
    """Run ``action``, re-raising a DER violation as an X509Error that names the structure."""
    try:
        return action()
    except der.DerError as err:
        raise X509Error(f"{what}: {err}") from err
