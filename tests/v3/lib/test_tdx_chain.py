"""The PCK chain of a quote: PEM extraction, the certificate profile, chain verification with CRLs, and the quote
signatures."""

from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from tests.v3 import pki
from tests.v3 import tdx_builders as tb
from tinfoil._v3.verifier._quote.tdx.lib.abi import parse_quote
from tinfoil._v3.verifier._quote.tdx.lib.chain import (
    INTERMEDIATE_CERT_PHRASE,
    PCK_CERT_PHRASE,
    ROOT_CERT_PHRASE,
    PCKCertificateChain,
    TdxVerificationError,
    bytes_to_p256_public_key,
    common_name,
    extract_ca_from_pck_cert,
    extract_pck_cert_chain,
    pem_certificates,
    signature_to_der,
    validate_certificate,
    validate_crl,
    verify_pck_certificate_chain,
    verify_qe_report_data_binding,
    verify_qe_report_signature,
    verify_quote_signature,
)
from tinfoil._v3.verifier._x509.crl import parse_revocation_list

SCENARIO = tb.Scenario()
ROOT = pki.load(SCENARIO.intel.root.der)


def crls(
    scenario: tb.Scenario = SCENARIO, *, pck_revoked: list[int] | None = None, root_revoked: list[int] | None = None
):
    pck = parse_revocation_list(
        pki.crl(
            scenario.intel.platform_ca,
            this_update=tb.NOW - timedelta(days=1),
            next_update=tb.NOW + timedelta(days=1),
            revoked=pck_revoked,
        )
    )
    root = parse_revocation_list(
        pki.crl(
            scenario.intel.root,
            this_update=tb.NOW - timedelta(days=1),
            next_update=tb.NOW + timedelta(days=1),
            revoked=root_revoked,
        )
    )
    return root, pck


# --- PEM chains -----------------------------------------------------------------------


class TestPemCertificates:
    def test_exact_count(self) -> None:
        chain = SCENARIO.chain_pem()
        certs = pem_certificates(chain, 3, "chain")
        assert [common_name(c.subject) for c in certs] == [PCK_CERT_PHRASE, INTERMEDIATE_CERT_PHRASE, ROOT_CERT_PHRASE]
        with pytest.raises(TdxVerificationError, match="should contain 2 PEM certificates, found 3"):
            pem_certificates(chain, 2, "chain")

    def test_trailing_nul(self) -> None:
        chain = SCENARIO.chain_pem()
        assert len(pem_certificates(chain + b"\x00", 3, "chain", allow_trailing_nul=True)) == 3
        with pytest.raises(TdxVerificationError, match="could not parse PEM"):
            pem_certificates(chain + b"\x00", 3, "chain")
        with pytest.raises(TdxVerificationError, match="could not parse PEM"):
            pem_certificates(chain + b"\x00\x00", 3, "chain", allow_trailing_nul=True)

    def test_nothing_may_follow_the_last_end_line(self) -> None:
        chain = SCENARIO.chain_pem()
        assert len(pem_certificates(chain.rstrip(b"\n"), 3, "chain")) == 3
        assert len(pem_certificates(chain.replace(b"\n", b"\r\n"), 3, "chain")) == 3
        for suffix in (b"\n", b"\r\n", b" \n", b"text\n"):
            with pytest.raises(TdxVerificationError):
                pem_certificates(chain + suffix, 3, "chain")

    def test_text_around_the_blocks_rejects(self) -> None:
        chain = SCENARIO.chain_pem()
        with pytest.raises(TdxVerificationError, match="could not parse PEM"):
            pem_certificates(b"prefix\n" + chain, 3, "chain")
        with pytest.raises(TdxVerificationError, match="not ASCII"):
            pem_certificates(b"\xff" + chain, 3, "chain")

    def test_block_of_another_label_rejects(self) -> None:
        chain = SCENARIO.chain_pem().replace(b"CERTIFICATE", b"X509 CRL", 2)
        with pytest.raises(TdxVerificationError, match="could not parse PEM"):
            pem_certificates(chain, 3, "chain")


class TestExtractPckCertChain:
    def test_extracts_three_certificates(self) -> None:
        chain = extract_pck_cert_chain(parse_quote(SCENARIO.quote()))
        assert isinstance(chain, PCKCertificateChain)
        assert common_name(chain.pck_cert.subject) == PCK_CERT_PHRASE
        assert common_name(chain.intermediate_cert.subject) == INTERMEDIATE_CERT_PHRASE
        assert common_name(chain.root_cert.subject) == ROOT_CERT_PHRASE

    def test_empty_chain_rejects(self) -> None:
        with pytest.raises(TdxVerificationError, match="chain is empty"):
            extract_pck_cert_chain(parse_quote(tb.quote_bytes(SCENARIO.pck_key, b"")))

    def test_two_certificates_reject(self) -> None:
        pem = SCENARIO.intel.pem(SCENARIO.pck()) + SCENARIO.intel.pem(SCENARIO.intel.platform_ca)
        with pytest.raises(TdxVerificationError, match="should contain 3"):
            extract_pck_cert_chain(parse_quote(tb.quote_bytes(SCENARIO.pck_key, pem)))


# --- the certificate profile -----------------------------------------------------------


class TestValidateCertificate:
    def test_profile(self) -> None:
        chain = extract_pck_cert_chain(parse_quote(SCENARIO.quote()))
        validate_certificate(chain.root_cert, chain.root_cert, ROOT_CERT_PHRASE)
        validate_certificate(chain.intermediate_cert, chain.root_cert, INTERMEDIATE_CERT_PHRASE)
        validate_certificate(chain.pck_cert, chain.intermediate_cert, PCK_CERT_PHRASE)

    def test_subject_phrase(self) -> None:
        chain = extract_pck_cert_chain(parse_quote(SCENARIO.quote()))
        with pytest.raises(TdxVerificationError, match="not expected in certificate's subject name"):
            validate_certificate(chain.pck_cert, chain.intermediate_cert, INTERMEDIATE_CERT_PHRASE)

    def test_issuer_must_equal_parent_subject(self) -> None:
        chain = extract_pck_cert_chain(parse_quote(SCENARIO.quote()))
        with pytest.raises(TdxVerificationError, match="issuer name"):
            validate_certificate(chain.pck_cert, chain.root_cert, PCK_CERT_PHRASE)

    def test_signature_must_come_from_the_parent(self) -> None:
        other = tb.intel_pki()
        chain = extract_pck_cert_chain(parse_quote(SCENARIO.quote()))
        with pytest.raises(TdxVerificationError, match="signature verification using parent certificate failed"):
            validate_certificate(chain.intermediate_cert, pki.load(other.root.der), INTERMEDIATE_CERT_PHRASE)

    def test_parent_must_be_a_certificate_authority(self) -> None:
        leaf = pki.certificate(ROOT_CERT_PHRASE, pki.p256(), key_usage=pki.SIGNING_USAGE)
        with pytest.raises(TdxVerificationError, match="not a certificate authority"):
            validate_certificate(pki.load(leaf.der), pki.load(leaf.der), ROOT_CERT_PHRASE)

    def test_key_must_be_p256(self) -> None:
        root = pki.certificate(ROOT_CERT_PHRASE, pki.p384(), ca=True, key_usage=pki.CA_USAGE)
        with pytest.raises(TdxVerificationError, match="Expected ECDSA-SHA256"):
            validate_certificate(pki.load(root.der), pki.load(root.der), ROOT_CERT_PHRASE)
        ed = pki.certificate(ROOT_CERT_PHRASE, pki.ed25519_key(), ca=True, key_usage=pki.CA_USAGE)
        with pytest.raises(TdxVerificationError, match="Expected ECDSA-SHA256"):
            validate_certificate(pki.load(ed.der), pki.load(ed.der), ROOT_CERT_PHRASE)


def test_extract_ca_from_pck_cert() -> None:
    chain = extract_pck_cert_chain(parse_quote(SCENARIO.quote()))
    assert extract_ca_from_pck_cert(chain.pck_cert) == "platform"
    processor = tb.Scenario(intel=tb.intel_pki(platform_ca_cn=tb.PROCESSOR_CA_CN))
    assert extract_ca_from_pck_cert(pki.load(processor.pck().der)) == "processor"
    other = tb.Scenario(intel=tb.intel_pki(platform_ca_cn="Intel SGX PCK Platform CA v2"))
    with pytest.raises(TdxVerificationError, match="could not find CA"):
        extract_ca_from_pck_cert(pki.load(other.pck().der))


def test_common_name_is_the_last_string_valued_attribute() -> None:
    assert common_name(ROOT.subject) == ROOT_CERT_PHRASE
    assert common_name(x509.Name([])) == ""
    assert (
        common_name(
            x509.Name(
                [x509.NameAttribute(x509.NameOID.COMMON_NAME, "a"), x509.NameAttribute(x509.NameOID.COMMON_NAME, "b")]
            )
        )
        == "b"
    )


# --- chain verification ----------------------------------------------------------------------


class TestVerifyPckCertificateChain:
    def chain(self, scenario: tb.Scenario = SCENARIO) -> PCKCertificateChain:
        return extract_pck_cert_chain(parse_quote(scenario.quote()))

    def test_verifies(self) -> None:
        root_crl, pck_crl = crls()
        verify_pck_certificate_chain(self.chain(), [ROOT], root_crl, pck_crl, tb.NOW)

    def test_requires_a_trusted_root(self) -> None:
        root_crl, pck_crl = crls()
        other = pki.load(tb.intel_pki().root.der)
        with pytest.raises(TdxVerificationError, match="error verifying PCK Certificate"):
            verify_pck_certificate_chain(self.chain(), [other], root_crl, pck_crl, tb.NOW)
        with pytest.raises(TdxVerificationError, match="no trusted roots"):
            verify_pck_certificate_chain(self.chain(), [], root_crl, pck_crl, tb.NOW)

    def test_validity_at_the_verification_time(self) -> None:
        root_crl, pck_crl = crls()
        with pytest.raises(TdxVerificationError, match="not valid at"):
            verify_pck_certificate_chain(self.chain(), [ROOT], root_crl, pck_crl, tb.NOW + timedelta(days=400))

    def test_leaf_key_usage_must_allow_digital_signatures(self) -> None:
        """A keyUsage extension on the leaf must allow digitalSignature; a leaf without the extension is allowed."""
        root_crl, pck_crl = crls()

        def chain_with(key_usage: x509.KeyUsage | None) -> PCKCertificateChain:
            pck = tb.pck_certificate(SCENARIO.intel.platform_ca, SCENARIO.pck_key, key_usage=key_usage)
            return PCKCertificateChain(
                pck_cert=pki.load(pck.der), intermediate_cert=pki.load(SCENARIO.intel.platform_ca.der), root_cert=ROOT
            )

        with pytest.raises(TdxVerificationError, match="key usage does not allow digital signatures"):
            verify_pck_certificate_chain(chain_with(tb.ENCIPHERMENT_USAGE), [ROOT], root_crl, pck_crl, tb.NOW)
        with pytest.raises(TdxVerificationError, match="key usage does not allow digital signatures"):
            verify_pck_certificate_chain(chain_with(pki.CA_USAGE), [ROOT], root_crl, pck_crl, tb.NOW)
        verify_pck_certificate_chain(chain_with(None), [ROOT], root_crl, pck_crl, tb.NOW)

    def test_revocation(self) -> None:
        root_crl, pck_crl = crls(pck_revoked=[4])
        with pytest.raises(TdxVerificationError, match=r"PCK Leaf certificate .* was revoked"):
            verify_pck_certificate_chain(self.chain(), [ROOT], root_crl, pck_crl, tb.NOW)
        root_crl, pck_crl = crls(root_revoked=[2])
        with pytest.raises(TdxVerificationError, match=r"intermediate certificate .* was revoked"):
            verify_pck_certificate_chain(self.chain(), [ROOT], root_crl, pck_crl, tb.NOW)

    def test_crls_must_be_issued_by_the_chain(self) -> None:
        other = tb.Scenario()
        root_crl, pck_crl = crls()
        other_root, other_pck = crls(other)
        with pytest.raises(TdxVerificationError, match="root CA CRL verification failed"):
            verify_pck_certificate_chain(self.chain(), [ROOT], other_root, pck_crl, tb.NOW)
        with pytest.raises(TdxVerificationError, match="PCK CRL verification failed"):
            verify_pck_certificate_chain(self.chain(), [ROOT], root_crl, other_pck, tb.NOW)

    def test_pck_crl_must_be_the_issuing_cas(self) -> None:
        """A CRL that the root signed but that names the issuing CA's name fails: the issuer is the signer."""
        root_crl, _ = crls()
        with pytest.raises(TdxVerificationError, match="PCK CRL verification failed"):
            verify_pck_certificate_chain(self.chain(), [ROOT], root_crl, root_crl, tb.NOW)

    def test_crl_window(self) -> None:
        _, pck_crl = crls()
        with pytest.raises(TdxVerificationError, match="not current at"):
            validate_crl(pck_crl, pki.load(SCENARIO.intel.platform_ca.der), tb.NOW + timedelta(days=2))
        assert validate_crl(pck_crl, pki.load(SCENARIO.intel.platform_ca.der), tb.NOW).crl is pck_crl

    def test_crl_issuer_must_be_a_certificate_authority(self) -> None:
        signing = pki.load(SCENARIO.intel.tcb_signing.der)
        crl = parse_revocation_list(pki.crl(SCENARIO.intel.tcb_signing))
        with pytest.raises(TdxVerificationError, match="not a certificate authority"):
            validate_crl(crl, signing, tb.NOW)


# --- quote signatures --------------------------------------------------------------------------


class TestQuoteSignatures:
    def test_valid(self) -> None:
        raw = SCENARIO.quote()
        quote = parse_quote(raw)
        verify_quote_signature(quote, raw)
        verify_qe_report_signature(quote, pki.load(SCENARIO.pck().der))
        verify_qe_report_data_binding(quote)

    def test_tampered_body(self) -> None:
        raw = bytearray(SCENARIO.quote())
        raw[100] ^= 0xFF
        with pytest.raises(TdxVerificationError, match="unable to verify message digest"):
            verify_quote_signature(parse_quote(bytes(raw)), bytes(raw))

    def test_qe_report_signed_by_another_key(self) -> None:
        quote = parse_quote(SCENARIO.quote())
        other = pki.load(tb.pck_certificate(SCENARIO.intel.platform_ca).der)
        with pytest.raises(TdxVerificationError, match="QE report's signature verification"):
            verify_qe_report_signature(quote, other)

    def test_qe_report_signature_needs_an_ec_key(self) -> None:
        quote = parse_quote(SCENARIO.quote())
        rsa_cert = pki.load(pki.certificate("rsa", pki.rsa_key()).der)
        with pytest.raises(TdxVerificationError, match="not of type ecdsa"):
            verify_qe_report_signature(quote, rsa_cert)

    def test_binding_covers_the_auth_data(self) -> None:
        attestation = pki.p256()
        bound = hashlib.sha256(tb.raw_public_key(attestation) + b"\x88" * 32).digest() + bytes(32)
        report = tb.qe_report_bytes(bound)
        raw = tb.quote_bytes(
            SCENARIO.pck_key,
            SCENARIO.chain_pem(),
            attestation_key=attestation,
            qe_report=report,
            qe_auth_data=b"\x99" * 32,
        )
        with pytest.raises(TdxVerificationError, match="QE Report Data does not match"):
            verify_qe_report_data_binding(parse_quote(raw))


class TestHelpers:
    def test_bytes_to_p256_public_key(self) -> None:
        key = pki.p256()
        assert isinstance(bytes_to_p256_public_key(tb.raw_public_key(key)), ec.EllipticCurvePublicKey)
        with pytest.raises(TdxVerificationError, match="unexpected size"):
            bytes_to_p256_public_key(bytes(63))
        with pytest.raises(TdxVerificationError, match="attestation key in the quote is invalid"):
            bytes_to_p256_public_key(bytes(64))

    def test_signature_to_der(self) -> None:
        raw = tb.raw_signature(pki.p256(), b"message")
        der = signature_to_der(raw)
        assert der[0] == 0x30
        assert len(der) > 64
        with pytest.raises(TdxVerificationError, match="Expected 64"):
            signature_to_der(bytes(63))
