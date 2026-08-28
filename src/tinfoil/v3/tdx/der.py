"""X.509 and DER helpers for the TDX DCAP core: certificate/CRL wrappers over
`cryptography` exposing the exact fields go-tdx-guest compares,
ECDSA-P256-SHA256 signature checks, and a strict minimal DER (TLV) reader for
the Intel SGX extension. PEM decoding and the extension accessors come from
v3.x509common. All errors are ValueError; callers assign the rejection
layer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from .. import x509common
from ..x509common import (  # noqa: F401 (re-exported for the TDX call sites)
    PEMBlock,
    pem_decode,
)

# Go's zero time.Time; an absent CRL nextUpdate compares as always expired.
ZERO_TIME = datetime(1, 1, 1, tzinfo=timezone.utc)

OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"


def bytes_to_latin1(b: bytes) -> str:
    """One byte per char, so byte-level scanning survives the str round trip."""
    return b.decode("latin-1")


# --- Certificates -------------------------------------------------------------


@dataclass
class Certificate:
    """The go-tdx-guest-relevant view of an X.509 certificate."""

    raw: bytes
    tbs: bytes
    version: int  # 1-based (v3 == 3), like Go
    serial: int
    signature_algorithm_oid: str
    issuer_der: bytes
    issuer_cn: str
    subject_der: bytes
    subject_cn: str
    not_before: datetime
    not_after: datetime
    spki_der: bytes
    signature: bytes  # DER-encoded ECDSA signature
    obj: x509.Certificate


def _name_cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return ""
    value = attrs[0].value
    return value if isinstance(value, str) else bytes_to_latin1(value)


def parse_certificate(der: bytes) -> Certificate:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        raise ValueError(f"x509: malformed certificate: {e}") from None
    try:
        spki_der = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        raise ValueError(f"x509: unsupported public key: {e}") from None
    return Certificate(
        raw=der,
        tbs=cert.tbs_certificate_bytes,
        version=cert.version.value + 1,
        serial=cert.serial_number,
        signature_algorithm_oid=cert.signature_algorithm_oid.dotted_string,
        issuer_der=cert.issuer.public_bytes(),
        issuer_cn=_name_cn(cert.issuer),
        subject_der=cert.subject.public_bytes(),
        subject_cn=_name_cn(cert.subject),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        spki_der=spki_der,
        signature=cert.signature,
        obj=cert,
    )


def basic_constraints(cert: Certificate) -> tuple[bool, bool]:
    """(present, ca) mirroring Go's BasicConstraintsValid / IsCA."""
    bc = x509common.basic_constraints_ext(cert.obj)
    if bc is None:
        return False, False
    return True, bool(bc.ca)


def key_usage(cert: Certificate) -> tuple[bool, bool, bool]:
    """(present, cert_sign, crl_sign) of the KeyUsage extension."""
    ku = x509common.key_usage_ext(cert.obj)
    if ku is None:
        return False, False, False
    return True, bool(ku.key_cert_sign), bool(ku.crl_sign)


def crl_distribution_point_uris(cert: Certificate) -> list[str]:
    """URI GeneralNames of the CRL Distribution Points extension, or []."""
    return x509common.crl_distribution_point_uris(cert.obj)


# --- CRLs ---------------------------------------------------------------------


@dataclass
class CRL:
    raw: bytes
    tbs: bytes
    issuer_der: bytes
    this_update: datetime
    next_update: datetime  # ZERO_TIME when absent (Go's zero time)
    revoked_serials: list[int]
    signature: bytes
    obj: x509.CertificateRevocationList


def parse_crl(der: bytes) -> CRL:
    try:
        crl = x509.load_der_x509_crl(der)
        revoked = [r.serial_number for r in crl]
        this_update = crl.last_update_utc
        next_update = crl.next_update_utc
    except Exception as e:
        raise ValueError(f"x509: malformed CRL: {e}") from None
    return CRL(
        raw=der,
        tbs=crl.tbs_certlist_bytes,
        issuer_der=crl.issuer.public_bytes(),
        this_update=this_update,
        next_update=next_update if next_update is not None else ZERO_TIME,
        revoked_serials=revoked,
        signature=crl.signature,
        obj=crl,
    )


# --- ECDSA-P256-SHA256 signature checks (matching Intel's algorithms) ---------


def _verify_ecdsa_sha256(spki_der: bytes, der_signature: bytes, message: bytes) -> bool:
    try:
        pub = serialization.load_der_public_key(spki_der)
    except (ValueError, UnsupportedAlgorithm):
        return False
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False
    try:
        pub.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except ValueError:
        return False


def verify_der_signature(message: bytes, signature: bytes, signer: Certificate) -> bool:
    """Verify a DER-encoded ECDSA signature made over message."""
    return _verify_ecdsa_sha256(signer.spki_der, signature, message)


def verify_raw_signature(message: bytes, signature: bytes, spki_der: bytes) -> bool:
    """Verify a raw r||s (64-byte) ECDSA-P256 signature (abi.SignatureToDER)."""
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        der_sig = encode_dss_signature(r, s)
    except ValueError:
        return False
    return _verify_ecdsa_sha256(spki_der, der_sig, message)


def ecdsa_p256_public_key(xy: bytes) -> bytes:
    """Build an SPKI from raw X||Y bytes with point validation (Go
    bytesToEcdsaPubKey). Raises ValueError for malformed points."""
    if len(xy) != 64:
        raise ValueError("public key is of unexpected size")
    x = int.from_bytes(xy[:32], "big")
    y = int.from_bytes(xy[32:], "big")
    try:
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as e:
        raise ValueError(f"attestation key is invalid: {e}") from None
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


# --- Strict minimal DER (TLV) reader for the Intel SGX extension --------------

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_SEQUENCE = 0x10


@dataclass
class TLV:
    cls: int  # 0 universal, 2 context
    constructed: bool
    tag: int
    start: int  # offset of the tag byte
    content_start: int
    end: int  # one past the last content byte


def read_tlv(b: bytes, off: int) -> TLV:
    # Sibling: sev/kds.py _read_tlv. Kept separate on purpose — this reader
    # tolerates non-minimal long-form lengths but caps length bytes at 4;
    # kds's rejects non-minimal lengths and returns content, not offsets.
    if off + 2 > len(b):
        raise ValueError("truncated DER element")
    first = b[off]
    cls = first >> 6
    constructed = (first & 0x20) != 0
    tag = first & 0x1F
    if tag == 0x1F:
        raise ValueError("multi-byte DER tags are not supported")
    length = b[off + 1]
    content_start = off + 2
    if length == 0x80:
        raise ValueError("indefinite DER length")
    if length > 0x80:
        n = length & 0x7F
        if n > 4 or off + 2 + n > len(b):
            raise ValueError("invalid DER length")
        length = 0
        for i in range(n):
            length = length * 256 + b[off + 2 + i]
        content_start = off + 2 + n
    end = content_start + length
    if end > len(b):
        raise ValueError("DER element overruns input")
    return TLV(cls, constructed, tag, off, content_start, end)


def tlv_content(b: bytes, t: TLV) -> bytes:
    return b[t.content_start : t.end]


def tlv_children(b: bytes, t: TLV) -> list[TLV]:
    out: list[TLV] = []
    off = t.content_start
    while off < t.end:
        c = read_tlv(b, off)
        out.append(c)
        off = c.end
    return out


def decode_oid(b: bytes) -> str:
    if len(b) == 0:
        raise ValueError("empty OID")
    parts = [b[0] // 40, b[0] % 40]
    v = 0
    for byte in b[1:]:
        v = v * 128 + (byte & 0x7F)
        if (byte & 0x80) == 0:
            parts.append(v)
            v = 0
    return ".".join(str(p) for p in parts)


def decode_uint(b: bytes, what: str) -> int:
    """Parse a DER INTEGER content as an unsigned int, mirroring Go's asn1
    int64 decoding limits (negative and oversized values reject)."""
    if len(b) == 0:
        raise ValueError(f"{what}: empty integer")
    if b[0] & 0x80:
        raise ValueError(f"{what}: negative integer")
    start = 0
    while start < len(b) - 1 and b[start] == 0:
        start += 1
    if len(b) - start > 6:
        raise ValueError(f"{what}: integer too large")
    v = 0
    for byte in b[start:]:
        v = v * 256 + byte
    return v
