"""
Unit tests for TDX quote verification (verify_tdx.py).
"""

import hashlib
import pytest
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed

from tinfoil.attestation.abi_tdx import (
    parse_quote,
    QUOTE_HEADER_START,
    QUOTE_BODY_END,
    QE_REPORT_SIZE,
    HEADER_SIZE,
    TD_QUOTE_BODY_SIZE,
    CERT_DATA_TYPE_QE_REPORT,
    CERT_DATA_TYPE_PCK_CERT_CHAIN,
)
from tinfoil.attestation.verify_tdx import (
    TdxVerificationError,
    PCKCertificateChain,
    extract_pck_cert_chain,
    verify_pck_chain,
    verify_quote_signature,
    verify_qe_report_signature,
    verify_qe_report_data_binding,
    verify_tdx_quote,
    _bytes_to_p256_pubkey,
    _signature_to_der,
    _parse_pem_chain,
)
from tinfoil.attestation.intel_root_ca import get_intel_root_ca, INTEL_SGX_ROOT_CA_PEM


# =============================================================================
# Test Fixtures - Cryptographic Key Generation
# =============================================================================

def generate_p256_keypair():
    """Generate a P-256 key pair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_raw_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Convert P-256 public key to raw 64-byte format (X || Y)."""
    # Get uncompressed point (0x04 || X || Y)
    uncompressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    # Strip the 0x04 prefix
    return uncompressed[1:]


def sign_message(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign a message and return raw R||S signature (64 bytes).

    This hashes the message with SHA256 before signing.
    """
    # Sign with SHA256
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    # Convert DER to raw R||S
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')


def sign_prehashed(private_key: ec.EllipticCurvePrivateKey, digest: bytes) -> bytes:
    """Sign a pre-hashed digest and return raw R||S signature (64 bytes).

    Use this when the message has already been hashed with SHA256.
    """
    # Sign the pre-hashed digest
    der_signature = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    # Convert DER to raw R||S
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')


# =============================================================================
# Test Fixtures - Quote Building with Real Signatures
# =============================================================================

def build_header_bytes() -> bytes:
    """Build a valid TDX header."""
    header = b''
    header += struct.pack('<H', 4)  # version
    header += struct.pack('<H', 2)  # attestation_key_type
    header += struct.pack('<I', 0x81)  # tee_type
    header += struct.pack('<H', 13)  # pce_svn
    header += struct.pack('<H', 8)   # qe_svn
    header += bytes.fromhex('939a7233f79c4ca9940a0db3957f0607')  # qe_vendor_id
    header += b'\x00' * 20  # user_data
    assert len(header) == HEADER_SIZE
    return header


def build_body_bytes() -> bytes:
    """Build a valid TdQuoteBody."""
    body = b''
    body += b'\x03' + b'\x00' * 15  # tee_tcb_svn
    body += b'\xaa' * 48  # mr_seam
    body += b'\x00' * 48  # mr_signer_seam
    body += b'\x00' * 8   # seam_attributes
    body += b'\x00\x00\x00\x10\x00\x00\x00\x00'  # td_attributes
    body += b'\xe7\x02\x06\x00\x00\x00\x00\x00'  # xfam
    body += b'\x11' * 48  # mr_td
    body += b'\x00' * 48  # mr_config_id
    body += b'\x00' * 48  # mr_owner
    body += b'\x00' * 48  # mr_owner_config
    body += b'\x22' * 48  # rtmr0
    body += b'\x33' * 48  # rtmr1
    body += b'\x44' * 48  # rtmr2
    body += b'\x00' * 48  # rtmr3
    body += b'\xab' * 32 + b'\xcd' * 32  # report_data
    assert len(body) == TD_QUOTE_BODY_SIZE
    return body


def build_qe_report_bytes(report_data: bytes = None) -> bytes:
    """Build a QE report with specified report_data."""
    if report_data is None:
        report_data = b'\x00' * 64

    report = b''
    report += b'\x00' * 16   # cpu_svn
    report += struct.pack('<I', 0)  # misc_select
    report += b'\x00' * 28   # reserved
    report += b'\x00' * 16   # attributes
    report += b'\xee' * 32   # mr_enclave
    report += b'\x00' * 32   # reserved
    report += b'\xff' * 32   # mr_signer
    report += b'\x00' * 96   # reserved
    report += struct.pack('<H', 1)  # isv_prod_id
    report += struct.pack('<H', 2)  # isv_svn
    report += b'\x00' * 60   # reserved
    report += report_data[:64].ljust(64, b'\x00')  # report_data
    assert len(report) == QE_REPORT_SIZE
    return report


def build_signed_quote_with_keys():
    """
    Build a quote with real cryptographic signatures.

    Returns:
        tuple: (raw_quote_bytes, attestation_private_key, qe_private_key)
    """
    # Generate key pairs
    attest_priv, attest_pub = generate_p256_keypair()
    qe_priv, qe_pub = generate_p256_keypair()

    # Build header and body
    header = build_header_bytes()
    body = build_body_bytes()

    # Sign header || body with attestation key (signature is over the hash)
    message = header + body
    message_hash = hashlib.sha256(message).digest()
    quote_signature = sign_prehashed(attest_priv, message_hash)

    # Build QE auth data
    qe_auth_data = b'\x88' * 32

    # Compute expected QE report data: SHA256(attestation_key || auth_data)
    attestation_key_raw = public_key_to_raw_bytes(attest_pub)
    qe_report_data_hash = hashlib.sha256(attestation_key_raw + qe_auth_data).digest()
    qe_report_data = qe_report_data_hash + b'\x00' * 32  # Pad to 64 bytes

    # Build QE report
    qe_report = build_qe_report_bytes(qe_report_data)

    # Sign QE report with QE key
    qe_signature = sign_message(qe_priv, qe_report)

    # Build PCK cert chain (using self-signed certs for testing)
    pck_cert_pem = _generate_self_signed_cert_pem("PCK Leaf")
    intermediate_cert_pem = _generate_self_signed_cert_pem("Intermediate CA")
    root_cert_pem = INTEL_SGX_ROOT_CA_PEM  # Use real Intel root for chain validation tests

    cert_chain_pem = pck_cert_pem + intermediate_cert_pem + root_cert_pem

    # Build signed data
    signed_data = _build_signed_data_bytes(
        signature=quote_signature,
        attestation_key=attestation_key_raw,
        qe_report=qe_report,
        qe_signature=qe_signature,
        qe_auth_data=qe_auth_data,
        cert_chain_pem=cert_chain_pem,
    )

    # Assemble quote
    quote_bytes = header + body + struct.pack('<I', len(signed_data)) + signed_data

    return quote_bytes, attest_priv, qe_priv


def _build_signed_data_bytes(
    signature: bytes,
    attestation_key: bytes,
    qe_report: bytes,
    qe_signature: bytes,
    qe_auth_data: bytes,
    cert_chain_pem: bytes,
) -> bytes:
    """Build the signed data section of the quote."""
    # PCK cert chain (type 5)
    pck_chain = struct.pack('<H', CERT_DATA_TYPE_PCK_CERT_CHAIN)
    pck_chain += struct.pack('<I', len(cert_chain_pem))
    pck_chain += cert_chain_pem

    # QE report certification data content
    qe_cert_content = qe_report
    qe_cert_content += qe_signature
    qe_cert_content += struct.pack('<H', len(qe_auth_data))
    qe_cert_content += qe_auth_data
    qe_cert_content += pck_chain

    # Outer certification data (type 6)
    cert_data = struct.pack('<H', CERT_DATA_TYPE_QE_REPORT)
    cert_data += struct.pack('<I', len(qe_cert_content))
    cert_data += qe_cert_content

    return signature + attestation_key + cert_data


def _generate_self_signed_cert_pem(cn: str) -> bytes:
    """Generate a self-signed certificate for testing."""
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime

    private_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM)


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestBytesToP256PubKey:
    """Test _bytes_to_p256_pubkey helper."""

    def test_valid_key(self):
        """Test converting valid key bytes."""
        _, public_key = generate_p256_keypair()
        raw_bytes = public_key_to_raw_bytes(public_key)

        result = _bytes_to_p256_pubkey(raw_bytes)
        assert isinstance(result, ec.EllipticCurvePublicKey)

    def test_wrong_size(self):
        """Test that wrong size raises error."""
        with pytest.raises(TdxVerificationError, match="expected 64"):
            _bytes_to_p256_pubkey(b'\x00' * 63)


class TestSignatureToDer:
    """Test _signature_to_der helper."""

    def test_valid_signature(self):
        """Test converting valid signature."""
        private_key, _ = generate_p256_keypair()
        raw_sig = sign_message(private_key, b"test message")

        der_sig = _signature_to_der(raw_sig)
        assert isinstance(der_sig, bytes)
        assert len(der_sig) > 64  # DER is longer due to encoding

    def test_wrong_size(self):
        """Test that wrong size raises error."""
        with pytest.raises(TdxVerificationError, match="expected 64"):
            _signature_to_der(b'\x00' * 63)


class TestParsePemChain:
    """Test _parse_pem_chain helper."""

    def test_parse_single_cert(self):
        """Test parsing single certificate."""
        cert_pem = _generate_self_signed_cert_pem("Test")
        certs = _parse_pem_chain(cert_pem)
        assert len(certs) == 1

    def test_parse_multiple_certs(self):
        """Test parsing multiple concatenated certificates."""
        cert1 = _generate_self_signed_cert_pem("Cert1")
        cert2 = _generate_self_signed_cert_pem("Cert2")
        cert3 = _generate_self_signed_cert_pem("Cert3")

        chain = cert1 + cert2 + cert3
        certs = _parse_pem_chain(chain)
        assert len(certs) == 3

    def test_parse_with_whitespace(self):
        """Test parsing with leading/trailing whitespace."""
        cert_pem = b'\n\n' + _generate_self_signed_cert_pem("Test") + b'\n\n'
        certs = _parse_pem_chain(cert_pem)
        assert len(certs) == 1


# =============================================================================
# Quote Signature Verification Tests
# =============================================================================

class TestVerifyQuoteSignature:
    """Test quote signature verification."""

    def test_valid_signature(self):
        """Test verification of valid quote signature."""
        raw_quote, attest_priv, _ = build_signed_quote_with_keys()
        quote = parse_quote(raw_quote)

        # Should not raise
        verify_quote_signature(quote, raw_quote)

    def test_tampered_body(self):
        """Test that tampered body fails verification."""
        raw_quote, _, _ = build_signed_quote_with_keys()

        # Tamper with the body
        tampered = bytearray(raw_quote)
        tampered[100] ^= 0xFF  # Flip a byte in the body
        tampered = bytes(tampered)

        quote = parse_quote(tampered)

        with pytest.raises(TdxVerificationError, match="signature verification failed"):
            verify_quote_signature(quote, tampered)


# =============================================================================
# QE Report Data Binding Tests
# =============================================================================

class TestVerifyQeReportDataBinding:
    """Test QE report data binding verification."""

    def test_valid_binding(self):
        """Test verification of valid binding."""
        raw_quote, _, _ = build_signed_quote_with_keys()
        quote = parse_quote(raw_quote)

        # Should not raise
        verify_qe_report_data_binding(quote)

    def test_tampered_auth_data(self):
        """Test that wrong auth data fails binding check."""
        # Build quote with specific auth data
        attest_priv, attest_pub = generate_p256_keypair()

        header = build_header_bytes()
        body = build_body_bytes()
        message_hash = hashlib.sha256(header + body).digest()
        quote_signature = sign_prehashed(attest_priv, message_hash)

        attestation_key_raw = public_key_to_raw_bytes(attest_pub)

        # Use correct auth data for hash calculation
        correct_auth_data = b'\x88' * 32
        qe_report_data_hash = hashlib.sha256(attestation_key_raw + correct_auth_data).digest()
        qe_report_data = qe_report_data_hash + b'\x00' * 32

        qe_report = build_qe_report_bytes(qe_report_data)
        qe_priv, _ = generate_p256_keypair()
        qe_signature = sign_message(qe_priv, qe_report)

        # But embed WRONG auth data in the quote
        wrong_auth_data = b'\x99' * 32  # Different!

        cert_chain = (
            _generate_self_signed_cert_pem("PCK") +
            _generate_self_signed_cert_pem("Int") +
            INTEL_SGX_ROOT_CA_PEM
        )

        signed_data = _build_signed_data_bytes(
            signature=quote_signature,
            attestation_key=attestation_key_raw,
            qe_report=qe_report,
            qe_signature=qe_signature,
            qe_auth_data=wrong_auth_data,  # Wrong!
            cert_chain_pem=cert_chain,
        )

        raw_quote = header + body + struct.pack('<I', len(signed_data)) + signed_data
        quote = parse_quote(raw_quote)

        with pytest.raises(TdxVerificationError, match="binding verification failed"):
            verify_qe_report_data_binding(quote)


# =============================================================================
# Intel Root CA Tests
# =============================================================================

class TestIntelRootCA:
    """Test Intel Root CA certificate."""

    def test_load_intel_root_ca(self):
        """Test that Intel Root CA loads correctly."""
        cert = get_intel_root_ca()

        assert isinstance(cert, x509.Certificate)
        assert "Intel SGX Root CA" in cert.subject.rfc4514_string()

    def test_intel_root_ca_is_ecdsa(self):
        """Test that Intel Root CA uses ECDSA."""
        cert = get_intel_root_ca()
        public_key = cert.public_key()

        assert isinstance(public_key, ec.EllipticCurvePublicKey)


# =============================================================================
# PCK Chain Extraction Tests
# =============================================================================

class TestExtractPckCertChain:
    """Test PCK certificate chain extraction."""

    def test_extract_chain(self):
        """Test extracting certificate chain from quote."""
        raw_quote, _, _ = build_signed_quote_with_keys()
        quote = parse_quote(raw_quote)

        chain = extract_pck_cert_chain(quote)

        assert isinstance(chain, PCKCertificateChain)
        assert chain.pck_cert is not None
        assert chain.intermediate_cert is not None
        assert chain.root_cert is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
