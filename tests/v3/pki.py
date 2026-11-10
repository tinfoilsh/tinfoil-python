"""Synthetic certificates, CRLs and keys for the verifier tests.

Everything is generated at test time with ``cryptography``; the helpers
return DER so that tests exercise the strict parsers.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TypeAlias

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.v3 import der_tree

PrivateKey: TypeAlias = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey

NOT_BEFORE = datetime(2024, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime(2034, 1, 1, tzinfo=UTC)
AT = datetime(2025, 6, 1, tzinfo=UTC)

CA_USAGE = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)
SIGNING_USAGE = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)


def name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def p256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def p384() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ed25519_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def _sign(builder: x509.CertificateBuilder, key: PrivateKey, *, pss: bool = False) -> bytes:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        certificate = builder.sign(key, None)
    elif isinstance(key, rsa.RSAPrivateKey) and pss:
        certificate = builder.sign(
            key, hashes.SHA384(), rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
        )
    elif isinstance(key, rsa.RSAPrivateKey):
        certificate = builder.sign(key, hashes.SHA256())
    elif isinstance(key.curve, ec.SECP384R1):
        certificate = builder.sign(key, hashes.SHA384())
    else:
        certificate = builder.sign(key, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.DER)


@dataclass(frozen=True)
class Issued:
    """A certificate with the key behind it."""

    der: bytes
    key: PrivateKey


def certificate(
    subject: str,
    key: PrivateKey,
    issuer: Issued | None = None,
    *,
    ca: bool = False,
    path_length: int | None = None,
    key_usage: x509.KeyUsage | None = None,
    eku: list[x509.ObjectIdentifier] | None = None,
    eku_critical: bool = False,
    sans: list[x509.GeneralName] | None = None,
    san_critical: bool = False,
    extra: list[tuple[x509.ExtensionType, bool]] | None = None,
    not_before: datetime = NOT_BEFORE,
    not_after: datetime = NOT_AFTER,
    serial: int = 1000,
    pss: bool = False,
    subject_name: x509.Name | None = None,
) -> Issued:
    """Issue ``subject``'s certificate, self-signed when ``issuer`` is None."""
    issuer_name = name(subject) if issuer is None else x509.load_der_x509_certificate(issuer.der).subject
    signer = key if issuer is None else issuer.key
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject) if subject_name is None else subject_name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=eku_critical)
    if sans is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=san_critical)
    for extension, critical in extra or []:
        builder = builder.add_extension(extension, critical=critical)
    return Issued(_sign(builder, signer, pss=pss), key)


def chain(key_factory: str = "p256", *, pss: bool = False) -> tuple[Issued, Issued, Issued]:
    """A root, an intermediate and a signing leaf, all with keys of one kind."""
    factories: dict[str, Callable[[], PrivateKey]] = {
        "p256": p256,
        "p384": p384,
        "rsa": rsa_key,
        "ed25519": ed25519_key,
    }
    make = factories[key_factory]
    root = certificate("root", make(), ca=True, key_usage=CA_USAGE, serial=1, pss=pss)
    intermediate = certificate(
        "intermediate", make(), root, ca=True, path_length=0, key_usage=CA_USAGE, serial=2, pss=pss
    )
    leaf = certificate(
        "leaf",
        make(),
        intermediate,
        key_usage=SIGNING_USAGE,
        eku=[ExtendedKeyUsageOID.CODE_SIGNING],
        serial=3,
        pss=pss,
    )
    return root, intermediate, leaf


def crl(
    issuer: Issued,
    *,
    this_update: datetime = NOT_BEFORE,
    next_update: datetime | None = NOT_AFTER,
    revoked: list[int] | None = None,
    extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    entry_extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    pss: bool = False,
) -> bytes:
    """A CRL signed by ``issuer``.

    ``next_update`` None omits the member: the builder requires one, so the
    element is cut from the TBSCertList afterwards, which leaves the
    signature covering the original TBS; such a CRL is for parse-time
    probes only.
    """
    builder = x509.CertificateRevocationListBuilder().issuer_name(x509.load_der_x509_certificate(issuer.der).subject)
    builder = builder.last_update(this_update).next_update(NOT_AFTER if next_update is None else next_update)
    for serial in revoked or []:
        entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(this_update)
        for extension, critical in entry_extensions or []:
            entry = entry.add_extension(extension, critical=critical)
        builder = builder.add_revoked_certificate(entry.build())
    for extension, critical in extensions or []:
        builder = builder.add_extension(extension, critical=critical)
    key = issuer.key
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signed = builder.sign(key, None)
    elif isinstance(key, rsa.RSAPrivateKey) and pss:
        signed = builder.sign(
            key, hashes.SHA384(), rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
        )
    elif isinstance(key, rsa.RSAPrivateKey):
        signed = builder.sign(key, hashes.SHA256())
    elif isinstance(key.curve, ec.SECP384R1):
        signed = builder.sign(key, hashes.SHA384())
    else:
        signed = builder.sign(key, hashes.SHA256())
    encoded = signed.public_bytes(serialization.Encoding.DER)
    if next_update is None:
        encoded = der_tree.mutate(encoded, _drop_next_update)
    return encoded


def _drop_next_update(tree: der_tree.Node) -> None:
    """Remove nextUpdate, the fifth TBSCertList field after version, signature, issuer and thisUpdate."""
    der_tree.children(der_tree.children(tree)[0]).pop(4)


def load(der: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der)


def public_pem(key: PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )


def spki(key: PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def one_day() -> timedelta:
    return timedelta(days=1)
