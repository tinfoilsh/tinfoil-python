"""X.509 helpers for the SEV slice over `cryptography`: RSASSA-PSS SHA-384
classification/verification (Go x509 SHA384WithRSAPSS: hash == MGF1 hash ==
SHA-384, salt 48), validity windows, CA signer constraints, and CRL fields.
PEM decoding and the extension accessors come from v3.x509common. All errors
are ValueError; the calling module assigns the rejection layer."""

from __future__ import annotations

from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from .. import x509common
from ..x509common import (  # noqa: F401 (re-exported for the SEV call sites)
    PEMBlock,
    crl_distribution_point_uris,
    pem_decode_all,
)

OID_RSASSA_PSS = "1.2.840.113549.1.1.10"


def load_certificate(der: bytes) -> x509.Certificate:
    """Parse a DER certificate; ValueError on failure."""
    try:
        return x509.load_der_x509_certificate(der)
    except Exception as e:  # cryptography raises several parse error types
        raise ValueError(str(e)) from None


def parse_cert(data: bytes) -> x509.Certificate:
    """Parse a PEM[CERTIFICATE]- or DER-encoded certificate (Go trust.ParseCert)."""
    if data.lstrip().startswith(b"-----BEGIN"):
        blocks, rest = pem_decode_all(data.decode("utf-8", errors="replace"))
        if len(blocks) != 1 or blocks[0].type != "CERTIFICATE" or rest.strip() != "":
            raise ValueError(
                "expected a single CERTIFICATE PEM block with no trailing bytes"
            )
        return load_certificate(blocks[0].der)
    return load_certificate(data)


def load_crl(der: bytes) -> x509.CertificateRevocationList:
    """Parse a DER CRL; ValueError on failure."""
    try:
        return x509.load_der_x509_crl(der)
    except Exception as e:
        raise ValueError(str(e)) from None


def is_pss_sha384(obj) -> bool:
    """Whether the declared signature algorithm is what Go x509 classifies as
    SHA384WithRSAPSS. Works on certificates and CRLs."""
    if obj.signature_algorithm_oid.dotted_string != OID_RSASSA_PSS:
        return False
    try:
        params = obj.signature_algorithm_parameters
        hash_alg = obj.signature_hash_algorithm
    except (UnsupportedAlgorithm, ValueError):
        return False
    if not isinstance(params, padding.PSS) or not isinstance(hash_alg, hashes.SHA384):
        return False
    mgf = params.mgf
    if not isinstance(mgf, padding.MGF1) or not isinstance(mgf._algorithm, hashes.SHA384):
        return False
    return params._salt_length == 48


def verify_pss_sha384(signer: x509.Certificate, message: bytes, signature: bytes) -> bool:
    """Verify an RSASSA-PSS SHA-384 signature with salt length 48 (the value
    Go's x509 requires: equal to the hash size)."""
    pub = signer.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        return False
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
            hashes.SHA384(),
        )
        return True
    except InvalidSignature:
        return False


def check_validity(cert: x509.Certificate, now: datetime, role: str) -> None:
    """Mirror Go x509 isValid's window check against opts.Now."""
    if not x509common.check_validity(
        cert.not_valid_before_utc, cert.not_valid_after_utc, now
    ):
        raise ValueError(f"{role} certificate has expired or is not yet valid")


def key_usage_mask(cert: x509.Certificate) -> int:
    """The certificate's KeyUsage as Go's x509.KeyUsage bitmask (0 when the
    extension is absent)."""
    ku = x509common.key_usage_ext(cert)
    if ku is None:
        return 0
    mask = 0
    bits = [
        ku.digital_signature,
        ku.content_commitment,
        ku.key_encipherment,
        ku.data_encipherment,
        ku.key_agreement,
        ku.key_cert_sign,
        ku.crl_sign,
        ku.encipher_only if ku.key_agreement else False,
        ku.decipher_only if ku.key_agreement else False,
    ]
    for i, b in enumerate(bits):
        if b:
            mask |= 1 << i
    return mask


KEY_USAGE_CERT_SIGN = 1 << 5
KEY_USAGE_CRL_SIGN = 1 << 6


def check_ca_signer_constraints(parent: x509.Certificate, usage_bit: int, role: str) -> None:
    """Mirror Go x509 CheckSignatureFrom / isValid CA constraints for a
    signing parent: basic constraints and key usage."""
    bc = x509common.basic_constraints_ext(parent)
    v3 = parent.version == x509.Version.v3
    if (v3 and bc is None) or (bc is not None and not bc.ca):
        raise ValueError(f"{role} certificate is not a certificate authority")
    mask = key_usage_mask(parent)
    if mask != 0 and mask & usage_bit == 0:
        raise ValueError(f"{role} certificate key usage does not permit signing")


def name_raw(name: x509.Name) -> bytes:
    """The DER encoding of a Name for Go-style raw chaining comparisons."""
    return name.public_bytes()


def attr_values(name: x509.Name, oid) -> list[str]:
    return [str(a.value) for a in name.get_attributes_for_oid(oid)]


def common_name(name: x509.Name) -> str:
    values = attr_values(name, NameOID.COMMON_NAME)
    return values[0] if values else ""


def verify_ecdsa_p384_sha384(
    signer: x509.Certificate, message: bytes, r: int, s: int
) -> bool:
    """Verify an ECDSA-P384-SHA384 signature given raw (r, s) integers."""
    pub = signer.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False
    if not isinstance(pub.curve, ec.SECP384R1):
        return False
    if r <= 0 or s <= 0:
        return False
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA384()))
        return True
    except (InvalidSignature, ValueError):
        return False
