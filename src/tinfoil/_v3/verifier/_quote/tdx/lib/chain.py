"""The PCK certificate chain that a TDX quote carries, the profile each certificate must meet, and the signatures
that bind the quote to the chain.

A quote carries three concatenated PEM certificates: the PCK leaf, the
Intel SGX PCK Platform CA and the Intel SGX Root CA. Every certificate is
version 3, ECDSA with SHA-256 over P-256, and named by its role. The leaf
chains to the trusted root that the caller supplies; the root inside the
quote is checked for self-consistency and used to validate the root CRL.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from tinfoil._v3.verifier._quote.tdx.lib.abi import (
    ATTESTATION_KEY_SIZE,
    ECDSA_P256_COMPONENT_SIZE,
    PCK_CERT_CHAIN_COUNT,
    QUOTE_BODY_END,
    QUOTE_HEADER_START,
    SHA256_HASH_SIZE,
    SIGNATURE_SIZE,
    QuoteV4,
)
from tinfoil._v3.verifier._x509 import der
from tinfoil._v3.verifier._x509.certificate import (
    OID_ECDSA_SHA256,
    Certificate,
    X509Error,
    basic_constraints,
    can_issue_certificates,
    issuer_name,
    parse_certificate,
    signature_algorithm,
    subject_name,
    verify_certificate_signature,
    verify_chain,
)
from tinfoil._v3.verifier._x509.crl import CRLError, RevocationList, VerifiedRevocationList, verify_revocation_list

ROOT_CERT_PHRASE = "Intel SGX Root CA"
INTERMEDIATE_CERT_PHRASE = "Intel SGX PCK Platform CA"
PCK_CERT_PHRASE = "Intel SGX PCK Certificate"
PROCESSOR_ISSUER = "Intel SGX PCK Processor CA"
PLATFORM_ISSUER = "Intel SGX PCK Platform CA"
PROCESSOR_ISSUER_ID = "processor"
PLATFORM_ISSUER_ID = "platform"

# Chain building applies the TLS server-authentication purpose: a certificate
# on the path that lists extended key usages must include it or
# anyExtendedKeyUsage. Intel's certificates list none.
OID_EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

_PEM_END = "-----END CERTIFICATE-----"


class TdxVerificationError(ValueError):
    """A quote whose chain, certificate profile or signatures do not check out."""


@dataclass(frozen=True, slots=True)
class PCKCertificateChain:
    """The three certificates of a quote: the PCK leaf, the issuing CA and the root."""

    pck_cert: Certificate
    intermediate_cert: Certificate
    root_cert: Certificate


# --- PEM chains ---------------------------------------------------------------


def pem_certificates(data: bytes, count: int, what: str, *, allow_trailing_nul: bool = False) -> list[Certificate]:
    """Parse exactly ``count`` concatenated PEM certificates.

    Nothing may follow the last END line except, when ``allow_trailing_nul``
    is set, one NUL byte: the quote's chain is read from a fixed buffer
    that may end with one. Text outside the blocks and blank lines after
    the last block are errors.
    """
    if allow_trailing_nul and data.endswith(b"\x00"):
        data = data[:-1]
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as err:
        raise TdxVerificationError(f"{what} is not ASCII PEM") from err
    try:
        blocks = der.pem_blocks(text, "CERTIFICATE")
    except der.DerError as err:
        raise TdxVerificationError(f"could not parse PEM formatted certificates in {what}: {err}") from err
    if len(blocks) != count:
        raise TdxVerificationError(f"{what} should contain {count} PEM certificates, found {len(blocks)}")
    if _after_last_block(text):
        raise TdxVerificationError(f"unexpected trailing bytes were found in {what}")
    certs = []
    for index, block in enumerate(blocks):
        try:
            certs.append(parse_certificate(block))
        except X509Error as err:
            raise TdxVerificationError(f"could not interpret certificate {index} DER bytes in {what}: {err}") from err
    return certs


def _after_last_block(text: str) -> str:
    """The text after the line terminator that ends the last END line."""
    index = text.rfind(_PEM_END)
    tail = text[index + len(_PEM_END) :]
    newline = tail.find("\n")
    return "" if newline < 0 else tail[newline + 1 :]


def extract_pck_cert_chain(quote: QuoteV4) -> PCKCertificateChain:
    """The PCK chain of a quote: leaf, intermediate and root, in that order."""
    chain = quote.signed_data.certification_data.get_pck_chain().cert_data
    if not chain:
        raise TdxVerificationError("PCK certificate chain is empty")
    certs = pem_certificates(chain, PCK_CERT_CHAIN_COUNT, "PCK certificate chain", allow_trailing_nul=True)
    return PCKCertificateChain(pck_cert=certs[0], intermediate_cert=certs[1], root_cert=certs[2])


# --- certificate profile -----------------------------------------------------------


def common_name(name: x509.Name) -> str:
    """The last string-valued commonName attribute of a name, or "" without one."""
    value = ""
    for attribute in name.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        if isinstance(attribute.value, str):
            value = attribute.value
    return value


def extract_ca_from_pck_cert(pck_cert: Certificate) -> str:
    """Which Intel CA issued the PCK certificate, by the issuer's commonName: "platform" or "processor"."""
    issuer = common_name(pck_cert.issuer)
    if issuer == PLATFORM_ISSUER:
        return PLATFORM_ISSUER_ID
    if issuer == PROCESSOR_ISSUER:
        return PROCESSOR_ISSUER_ID
    raise TdxVerificationError("could not find CA from PCK certificate")


def validate_certificate(cert: Certificate, parent: Certificate, phrase: str) -> None:
    """Check one certificate of the Intel profile against its parent.

    Version 3, signed with ECDSA and SHA-256, a P-256 public key, a
    subject commonName of ``phrase``, an issuer name equal to the parent's
    subject name, and a signature that the parent, a certificate authority,
    made.
    """
    if cert.version != x509.Version.v3:
        raise TdxVerificationError(f"certificate's version found {cert.version.value + 1}. Expected 3")
    outer = der.children(der.decode(cert.public_bytes(serialization.Encoding.DER)))
    try:
        algorithm = signature_algorithm(outer[1])
    except (X509Error, der.DerError) as err:
        raise TdxVerificationError(f"certificate's signature algorithm: {err}") from err
    if algorithm.oid != OID_ECDSA_SHA256:
        raise TdxVerificationError(f"certificate's signature algorithm found {algorithm.oid}. Expected ECDSA-SHA256")
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TdxVerificationError("certificate public key is not of type ecdsa public key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise TdxVerificationError(f"certificate's public key curve is {key.curve.name!r}. Expected P-256")
    subject = common_name(cert.subject)
    if subject != phrase:
        raise TdxVerificationError(f"{subject!r} is not expected in certificate's subject name. Expected {phrase!r}")
    if issuer_name(cert) != subject_name(parent):
        raise TdxVerificationError(
            f"certificate's issuer name ({cert.issuer.rfc4514_string()!r}) does not match with parent certificate's "
            f"subject name ({parent.subject.rfc4514_string()!r})"
        )
    if not can_issue_certificates(parent):
        raise TdxVerificationError("parent certificate is not a certificate authority that may sign certificates")
    try:
        verify_certificate_signature(cert, parent)
    except X509Error as err:
        raise TdxVerificationError(
            f"certificate signature verification using parent certificate failed: {err}"
        ) from err


def validate_crl(crl: RevocationList, trusted: Certificate, now: datetime) -> VerifiedRevocationList:
    """Check that ``trusted``, a certificate authority, issued and signed the CRL, and that it is current at ``now``."""
    constraints = basic_constraints(trusted)
    if constraints is None or not constraints[0]:
        raise TdxVerificationError("CRL issuing certificate is not a certificate authority")
    if crl.issuer.public_bytes() != subject_name(trusted):
        raise TdxVerificationError(
            f"CRL issuer's name {crl.issuer.rfc4514_string()!r} does not match with expected name "
            f"{trusted.subject.rfc4514_string()!r}"
        )
    try:
        return verify_revocation_list(crl, trusted, now)
    except CRLError as err:
        raise TdxVerificationError(f"CRL signature verification failed using trusted certificate: {err}") from err


def verify_pck_certificate_chain(
    chain: PCKCertificateChain,
    trusted_roots: Sequence[Certificate],
    root_crl: RevocationList,
    pck_crl: RevocationList,
    now: datetime,
) -> None:
    """Verify the quote's chain: each certificate's profile, the path from the leaf to a trusted root at ``now``,
    both CRLs, and that neither the intermediate nor the leaf is revoked."""
    root, intermediate, pck = chain.root_cert, chain.intermediate_cert, chain.pck_cert
    try:
        validate_certificate(root, root, ROOT_CERT_PHRASE)
    except TdxVerificationError as err:
        raise TdxVerificationError(f"unable to validate root cert: {err}") from err
    try:
        validate_certificate(intermediate, root, INTERMEDIATE_CERT_PHRASE)
    except TdxVerificationError as err:
        raise TdxVerificationError(f"unable to validate Intermediate CA certificate: {err}") from err
    try:
        validate_certificate(pck, intermediate, PCK_CERT_PHRASE)
    except TdxVerificationError as err:
        raise TdxVerificationError(f"unable to validate PCK leaf certificate: {err}") from err
    try:
        verify_chain(pck, [intermediate], trusted_roots, now, extended_key_usage=OID_EKU_SERVER_AUTH)
    except X509Error as err:
        raise TdxVerificationError(f"error verifying PCK Certificate: {err}") from err

    try:
        verified_root_crl = validate_crl(root_crl, root, now)
    except TdxVerificationError as err:
        raise TdxVerificationError(
            f"root CA CRL verification failed using root certificate in PCK Certificate chain: {err}"
        ) from err
    try:
        verified_pck_crl = validate_crl(pck_crl, intermediate, now)
    except TdxVerificationError as err:
        raise TdxVerificationError(
            f"PCK CRL verification failed using intermediate certificate in PCK Certificate chain: {err}"
        ) from err
    if pck_crl.issuer.public_bytes() != issuer_name(pck):
        raise TdxVerificationError(
            f"issuer's name ({pck_crl.issuer.rfc4514_string()!r}) in PCK CRL does not match with PCK Leaf "
            f"Certificate's issuer name ({pck.issuer.rfc4514_string()!r})"
        )
    if intermediate.serial_number in verified_root_crl.crl.revoked_serials:
        raise TdxVerificationError("intermediate certificate in PCK certificate chain was revoked")
    if pck.serial_number in verified_pck_crl.crl.revoked_serials:
        raise TdxVerificationError("PCK Leaf certificate in PCK certificate chain was revoked")

    if now > root.not_valid_after_utc:
        raise TdxVerificationError("root CA certificate in PCK certificate chain has expired")
    if now > intermediate.not_valid_after_utc:
        raise TdxVerificationError("intermediate CA certificate in PCK certificate chain has expired")
    if now > pck.not_valid_after_utc:
        raise TdxVerificationError("PCK leaf certificate in PCK certificate chain has expired")


# --- quote signatures ---------------------------------------------------------


def verify_quote_signature(quote: QuoteV4, raw_quote: bytes) -> None:
    """Verify the ECDSA P-256 signature over SHA-256(header || TD quote body) with the quote's attestation key."""
    public_key = bytes_to_p256_public_key(quote.signed_data.attestation_key)
    signature_der = signature_to_der(quote.signed_data.signature)
    message_hash = hashlib.sha256(raw_quote[QUOTE_HEADER_START:QUOTE_BODY_END]).digest()
    try:
        public_key.verify(signature_der, message_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        raise TdxVerificationError(
            "unable to verify message digest using quote's signature and ecdsa attestation key"
        ) from None


def verify_qe_report_signature(quote: QuoteV4, pck_cert: Certificate) -> None:
    """Verify the QE report's ECDSA signature with the PCK leaf certificate's key."""
    qe_report_data = quote.signed_data.certification_data.qe_report_data
    signature_der = signature_to_der(qe_report_data.qe_report_signature)
    key = pck_cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TdxVerificationError("PCK certificate public key is not of type ecdsa public key")
    try:
        key.verify(signature_der, qe_report_data.qe_report, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise TdxVerificationError("QE report's signature verification using PCK Leaf Certificate failed") from None


def verify_qe_report_data_binding(quote: QuoteV4) -> None:
    """Check that the QE report's REPORT_DATA is SHA-256(attestation key || QE auth data), zero-padded to 64 bytes.

    This binds the attestation key that signed the quote to the QE report
    that the PCK certificate signed.
    """
    qe_report_data = quote.signed_data.certification_data.qe_report_data
    digest = hashlib.sha256(quote.signed_data.attestation_key + qe_report_data.qe_auth_data).digest()
    expected = digest + b"\x00" * SHA256_HASH_SIZE
    if qe_report_data.qe_report_parsed.report_data != expected:
        raise TdxVerificationError(
            "QE Report Data does not match with value of SHA 256 calculated over the concatenation of ECDSA "
            "Attestation Key and QE Authenticated Data"
        )


def verify_quote_signatures(quote: QuoteV4, raw_quote: bytes, pck_cert: Certificate) -> None:
    """The three signature checks in order: the quote signature, the QE report signature, the report data binding."""
    verify_quote_signature(quote, raw_quote)
    try:
        verify_qe_report_signature(quote, pck_cert)
    except TdxVerificationError as err:
        raise TdxVerificationError(f"error verifying QE report signature: {err}") from err
    try:
        verify_qe_report_data_binding(quote)
    except TdxVerificationError as err:
        raise TdxVerificationError(f"error verifying QE report data: {err}") from err


def bytes_to_p256_public_key(key_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """A raw ``X || Y`` P-256 public key (64 bytes); a point off the curve is an error."""
    if len(key_bytes) != ATTESTATION_KEY_SIZE:
        raise TdxVerificationError(
            f"public key is of unexpected size {len(key_bytes)}, expected {ATTESTATION_KEY_SIZE}"
        )
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + key_bytes)
    except ValueError as err:
        raise TdxVerificationError(f"attestation key in the quote is invalid: {err}") from err


def signature_to_der(sig_bytes: bytes) -> bytes:
    """A raw ``r || s`` P-256 signature (64 bytes) as a DER ECDSA-Sig-Value."""
    if len(sig_bytes) != SIGNATURE_SIZE:
        raise TdxVerificationError(f"signature size is {len(sig_bytes)} bytes. Expected {SIGNATURE_SIZE} bytes")
    r = int.from_bytes(sig_bytes[0:ECDSA_P256_COMPONENT_SIZE], byteorder="big")
    s = int.from_bytes(sig_bytes[ECDSA_P256_COMPONENT_SIZE:SIGNATURE_SIZE], byteorder="big")
    return encode_dss_signature(r, s)
