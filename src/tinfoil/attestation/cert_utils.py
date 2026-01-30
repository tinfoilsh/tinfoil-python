"""
Shared certificate utilities for TDX attestation verification.

This module provides common certificate parsing and chain verification
functions used by both verify_tdx.py and collateral_tdx.py.
"""

from datetime import datetime, timezone
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .intel_root_ca import get_intel_root_ca


class CertificateChainError(Exception):
    """Raised when certificate chain verification fails."""
    pass


def parse_pem_chain(pem_data: bytes) -> List[x509.Certificate]:
    """
    Parse concatenated PEM certificates.

    Handles:
    - Concatenated PEM certificates
    - Leading/trailing whitespace and null bytes
    - Trailing null bytes between certificates (common in TDX quotes)

    Args:
        pem_data: PEM-encoded certificate chain (bytes)

    Returns:
        List of parsed certificates in order

    Raises:
        CertificateChainError: If parsing fails
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
            # If we got some certs and remaining is just whitespace/nulls, we're done
            if certs:
                remaining_stripped = remaining.strip(b'\x00\n\r\t ')
                if not remaining_stripped:
                    break
            raise CertificateChainError(f"Failed to parse PEM certificate: {e}")

    return certs


def certs_to_pem(certs: List[x509.Certificate]) -> str:
    """
    Convert list of certificates to concatenated PEM string.

    Args:
        certs: List of certificates

    Returns:
        Concatenated PEM string
    """
    pem_parts = []
    for cert in certs:
        pem_parts.append(cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    return "".join(pem_parts)


def verify_intel_chain(
    certs: List[x509.Certificate],
    chain_name: str = "Certificate chain",
) -> None:
    """
    Verify a certificate chain against Intel SGX Root CA.

    Performs manual chain verification without requiring TLS extensions (SAN).
    Intel PCK certificates don't have SAN extension, so we can't use
    PolicyBuilder.build_client_verifier().

    Verification steps:
    1. Verify root cert matches embedded Intel SGX Root CA (by public key)
    2. Verify each certificate's validity period
    3. Verify each certificate was issued by the next cert in chain

    Args:
        certs: Certificate chain [leaf, intermediate(s)..., root]
        chain_name: Human-readable name for error messages

    Raises:
        CertificateChainError: If chain verification fails
    """
    if len(certs) < 2:
        raise CertificateChainError(
            f"{chain_name} must contain at least 2 certificates (leaf and root)"
        )

    intel_root = get_intel_root_ca()

    # Step 1: Verify root certificate matches Intel SGX Root CA by public key
    chain_root = certs[-1]
    chain_root_pubkey = chain_root.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    intel_root_pubkey = intel_root.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if chain_root_pubkey != intel_root_pubkey:
        raise CertificateChainError(
            f"{chain_name} root certificate does not match Intel SGX Root CA"
        )

    # Step 2: Verify each certificate's validity period
    now = datetime.now(timezone.utc)
    for cert in certs:
        if now < cert.not_valid_before_utc:
            raise CertificateChainError(
                f"{chain_name}: certificate not yet valid (not before {cert.not_valid_before_utc})"
            )
        if now > cert.not_valid_after_utc:
            raise CertificateChainError(
                f"{chain_name}: certificate expired (not after {cert.not_valid_after_utc})"
            )

    # Step 3: Verify certificate chain signatures using verify_directly_issued_by
    # Each cert[i] should be signed by cert[i+1]
    for i in range(len(certs) - 1):
        cert = certs[i]
        issuer = certs[i + 1]
        try:
            cert.verify_directly_issued_by(issuer)
        except Exception as e:
            raise CertificateChainError(
                f"{chain_name}: certificate chain signature verification failed: {e}"
            )

    # Verify the chain's root is signed by the trusted Intel root
    try:
        chain_root.verify_directly_issued_by(intel_root)
    except Exception as e:
        raise CertificateChainError(
            f"{chain_name}: root certificate verification against Intel SGX Root CA failed: {e}"
        )
