"""
TDX Quote cryptographic verification.

This module implements the cryptographic verification of TDX attestation quotes,
including signature verification and certificate chain validation.

Verification flow:
1. Extract PCK certificate chain from quote
2. Verify PCK chain against Intel SGX Root CA
3. Verify quote signature (ECDSA P-256 over Header || TdQuoteBody)
4. Verify QE report signature using PCK leaf certificate
5. Verify QE report data binding (attestation key hash)
"""

import hashlib
from dataclasses import dataclass
from typing import List

from cryptography import x509
from cryptography.x509 import verification
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from .abi_tdx import (
    QuoteV4,
    QUOTE_HEADER_START,
    QUOTE_BODY_END,
    SIGNATURE_SIZE,
)
from .intel_root_ca import get_intel_root_ca


class TdxVerificationError(Exception):
    """Raised when TDX quote verification fails."""
    pass


@dataclass
class PCKCertificateChain:
    """
    PCK Certificate Chain extracted from the quote.

    Contains three certificates:
    - PCK leaf certificate (signs the QE report)
    - Intermediate CA certificate
    - Root CA certificate (should match Intel SGX Root CA)
    """
    pck_cert: x509.Certificate  # PCK Leaf certificate
    intermediate_cert: x509.Certificate  # Intermediate CA certificate
    root_cert: x509.Certificate  # Root CA certificate


def extract_pck_cert_chain(quote: QuoteV4) -> PCKCertificateChain:
    """
    Extract the PCK certificate chain from the quote.

    The certificate chain is embedded in the quote's certification data
    as concatenated PEM certificates: PCK Leaf || Intermediate CA || Root CA.

    Args:
        quote: Parsed TDX QuoteV4

    Returns:
        PCKCertificateChain with three certificates

    Raises:
        TdxVerificationError: If certificate chain is missing or malformed
    """
    pck_chain_data = quote.signed_data.certification_data.get_pck_chain()
    cert_pem = pck_chain_data.cert_data
    if not cert_pem:
        raise TdxVerificationError("PCK certificate chain is empty")

    # Parse concatenated PEM certificates
    certs = _parse_pem_chain(cert_pem)
    if len(certs) != 3:
        raise TdxVerificationError(
            f"PCK certificate chain should contain 3 certificates, got {len(certs)}"
        )

    return PCKCertificateChain(
        pck_cert=certs[0],
        intermediate_cert=certs[1],
        root_cert=certs[2],
    )


def _parse_pem_chain(pem_data: bytes) -> List[x509.Certificate]:
    """
    Parse concatenated PEM certificates.

    Handles:
    - Concatenated PEM certificates
    - Leading/trailing whitespace and null bytes
    - Trailing null bytes between certificates (common in TDX quotes)

    Args:
        pem_data: PEM-encoded certificate chain

    Returns:
        List of parsed certificates in order
    """
    certs = []
    remaining = pem_data

    while remaining:
        # Strip leading whitespace and null bytes
        remaining = remaining.lstrip(b'\x00\n\r\t ')
        if not remaining:
            break

        # Check if remaining data is just null bytes or whitespace
        stripped = remaining.rstrip(b'\x00\n\r\t ')
        if not stripped:
            break

        try:
            cert = x509.load_pem_x509_certificate(remaining)
            certs.append(cert)

            # Find end of this certificate and move to next
            end_marker = b'-----END CERTIFICATE-----'
            end_pos = remaining.find(end_marker)
            if end_pos == -1:
                break
            remaining = remaining[end_pos + len(end_marker):]
        except Exception as e:
            # If we already got certs and remaining is just nulls/whitespace, that's OK
            if certs:
                remaining_stripped = remaining.rstrip(b'\x00\n\r\t ')
                if not remaining_stripped:
                    break
            raise TdxVerificationError(f"Failed to parse PEM certificate: {e}")

    return certs


def verify_pck_chain(chain: PCKCertificateChain) -> None:
    """
    Verify the PCK certificate chain against Intel SGX Root CA.

    Verification steps:
    1. Verify root cert matches embedded Intel SGX Root CA
    2. Verify certificate chain (validity + signatures) using cryptography library

    Args:
        chain: PCK certificate chain from quote

    Raises:
        TdxVerificationError: If chain verification fails
    """
    intel_root = get_intel_root_ca()

    # Step 1: Verify root certificate matches Intel SGX Root CA
    chain_root_pubkey = chain.root_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    intel_root_pubkey = intel_root.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if chain_root_pubkey != intel_root_pubkey:
        raise TdxVerificationError(
            "Root certificate public key does not match Intel SGX Root CA"
        )

    # Step 2: Verify certificate chain (validity periods + signatures)
    store = verification.Store([intel_root])
    builder = verification.PolicyBuilder().store(store)
    verifier = builder.build_client_verifier()

    try:
        verifier.verify(chain.pck_cert, [chain.intermediate_cert])
    except verification.VerificationError as e:
        raise TdxVerificationError(f"PCK certificate chain verification failed: {e}")


def verify_quote_signature(quote: QuoteV4, raw_quote: bytes) -> None:
    """
    Verify the quote signature using the attestation key.

    The signature covers SHA256(Header || TdQuoteBody).

    Args:
        quote: Parsed QuoteV4
        raw_quote: Original raw quote bytes

    Raises:
        TdxVerificationError: If signature verification fails
    """
    # Get attestation key (64 bytes = raw P-256 point)
    attestation_key_bytes = quote.signed_data.attestation_key
    public_key = _bytes_to_p256_pubkey(attestation_key_bytes)

    # Get signature (64 bytes = R || S)
    signature_bytes = quote.signed_data.signature
    signature_der = _signature_to_der(signature_bytes)

    # Message = Header || TdQuoteBody (bytes 0x00 to 0x278)
    message = raw_quote[QUOTE_HEADER_START:QUOTE_BODY_END]
    message_hash = hashlib.sha256(message).digest()

    # Verify ECDSA signature over pre-hashed message
    # Use Prehashed to avoid double-hashing (we already computed SHA256)
    try:
        public_key.verify(
            signature_der,
            message_hash,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )
    except InvalidSignature:
        raise TdxVerificationError(
            "Quote signature verification failed: signature does not match"
        )


def verify_qe_report_signature(quote: QuoteV4, pck_cert: x509.Certificate) -> None:
    """
    Verify the QE report signature using the PCK leaf certificate.

    Args:
        quote: Parsed QuoteV4
        pck_cert: PCK leaf certificate from the chain

    Raises:
        TdxVerificationError: If signature verification fails
    """
    qe_report_data = quote.signed_data.certification_data.qe_report_data
    if qe_report_data is None:
        raise TdxVerificationError("QE report data is missing")

    # Get QE report and signature
    qe_report = qe_report_data.qe_report  # 384 bytes
    qe_signature = qe_report_data.qe_report_signature  # 64 bytes

    # Convert signature to DER format
    signature_der = _signature_to_der(qe_signature)

    # Verify using PCK certificate's public key
    pck_public_key = pck_cert.public_key()
    try:
        pck_public_key.verify(signature_der, qe_report, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise TdxVerificationError(
            "QE report signature verification failed using PCK certificate"
        )


def verify_qe_report_data_binding(quote: QuoteV4) -> None:
    """
    Verify that the QE report data binds to the attestation key.

    This is a CRITICAL security check. The QE report's report_data field
    must contain SHA256(attestation_key || qe_auth_data) padded to 64 bytes.
    Without this check, an attacker could substitute a different attestation key.

    Args:
        quote: Parsed QuoteV4

    Raises:
        TdxVerificationError: If binding verification fails
    """
    qe_report_data = quote.signed_data.certification_data.qe_report_data
    if qe_report_data is None:
        raise TdxVerificationError("QE report data is missing")

    # Get components
    attestation_key = quote.signed_data.attestation_key  # 64 bytes
    qe_auth_data = qe_report_data.qe_auth_data  # Variable
    qe_report_data_field = qe_report_data.qe_report_parsed.report_data  # 64 bytes

    # Compute expected: SHA256(attestation_key || qe_auth_data) || zeros
    data_to_hash = attestation_key + qe_auth_data
    expected_hash = hashlib.sha256(data_to_hash).digest()
    expected_report_data = expected_hash + b'\x00' * 32  # Pad to 64 bytes

    # Compare the full 64 bytes
    if qe_report_data_field != expected_report_data:
        raise TdxVerificationError(
            "QE report data binding verification failed: "
            "SHA256(attestation_key || auth_data) does not match QE report data. "
            "The attestation key may have been tampered with."
        )


def _bytes_to_p256_pubkey(key_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """
    Convert raw 64-byte P-256 public key to cryptography public key object.

    The raw format is X || Y (32 bytes each).

    Args:
        key_bytes: 64 bytes representing X || Y coordinates

    Returns:
        EllipticCurvePublicKey object

    Raises:
        TdxVerificationError: If key format is invalid
    """
    if len(key_bytes) != 64:
        raise TdxVerificationError(
            f"Attestation key is {len(key_bytes)} bytes, expected 64"
        )

    # Convert to uncompressed point format (0x04 || X || Y)
    uncompressed = b'\x04' + key_bytes

    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), uncompressed
        )
    except Exception as e:
        raise TdxVerificationError(f"Invalid attestation key: {e}")


def _signature_to_der(sig_bytes: bytes) -> bytes:
    """
    Convert raw R||S signature to DER format.

    TDX signatures are 64 bytes: R (32 bytes) || S (32 bytes).
    DER format is required by cryptography library.

    Args:
        sig_bytes: 64-byte raw signature

    Returns:
        DER-encoded signature

    Raises:
        TdxVerificationError: If signature format is invalid
    """
    if len(sig_bytes) != SIGNATURE_SIZE:
        raise TdxVerificationError(
            f"Signature is {len(sig_bytes)} bytes, expected {SIGNATURE_SIZE}"
        )

    r = int.from_bytes(sig_bytes[0:32], byteorder='big')
    s = int.from_bytes(sig_bytes[32:64], byteorder='big')

    return encode_dss_signature(r, s)


def verify_tdx_quote(quote: QuoteV4, raw_quote: bytes) -> PCKCertificateChain:
    """
    Perform full cryptographic verification of a TDX quote.

    This is the main entry point for TDX verification. It performs all
    security-critical checks in order:

    1. Extract and verify PCK certificate chain
    2. Verify quote signature using attestation key
    3. Verify QE report signature using PCK certificate
    4. Verify QE report data binding (critical security check)

    Args:
        quote: Parsed QuoteV4 structure
        raw_quote: Original raw quote bytes (needed for signature verification)

    Returns:
        PCKCertificateChain on success (for further use in TCB checks)

    Raises:
        TdxVerificationError: If any verification step fails
    """
    # Step 1: Extract and verify PCK certificate chain
    chain = extract_pck_cert_chain(quote)
    verify_pck_chain(chain)

    # Step 2: Verify quote signature
    verify_quote_signature(quote, raw_quote)

    # Step 3: Verify QE report signature
    verify_qe_report_signature(quote, chain.pck_cert)

    # Step 4: Verify QE report data binding (CRITICAL)
    verify_qe_report_data_binding(quote)

    return chain
