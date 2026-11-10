"""The AMD endorsement key chain: VCEK extensions and profile, chain verification, ASK revocation and the report
signature, on the synthetic vectors' material and minted certificates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from tests.v3 import pki
from tests.v3 import sev_fixtures as fx
from tinfoil._v3.verifier._quote.sev.lib import chain
from tinfoil._v3.verifier._quote.sev.lib.abi import parse_report
from tinfoil._v3.verifier._x509 import der
from tinfoil._v3.verifier._x509.certificate import parse_certificate
from tinfoil._v3.verifier._x509.crl import parse_revocation_list


@dataclass(frozen=True)
class Material:
    case: fx.VectorCase
    vcek: x509.Certificate
    ask: x509.Certificate
    ark: x509.Certificate
    crl_der: bytes


def material(fixture_id: str = "sev-happy", group: str = "quote-sev") -> Material:
    case = fx.vector_case(group, fixture_id)
    endorsements = case.document.cpu_endorsements()
    assert endorsements.amd_vcek is not None
    assert endorsements.amd_crl is not None
    assert case.chain_pem is not None
    ask_der, ark_der = der.pem_blocks(case.chain_pem.decode(), "CERTIFICATE")
    return Material(
        case=case,
        vcek=parse_certificate(endorsements.amd_vcek.vcek_der),
        ask=parse_certificate(ask_der),
        ark=parse_certificate(ark_der),
        crl_der=endorsements.amd_crl.crl_der,
    )


def amd_name(common: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Santa Clara"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common),
        ]
    )


_ISSUER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def mint_vcek(extensions: list[x509.ExtensionType]) -> x509.Certificate:
    """A VCEK-shaped certificate with exactly ``extensions``, signed with RSA-PSS SHA-384 by a Genoa-named issuer."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(amd_name("SEV-VCEK"))
        .issuer_name(amd_name("SEV-Genoa"))
        .public_key(ec.generate_private_key(ec.SECP384R1()).public_key())
        .serial_number(1)
        .not_valid_before(datetime(2024, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2034, 1, 1, tzinfo=UTC))
    )
    for extension in extensions:
        builder = builder.add_extension(extension, critical=False)
    signed = builder.sign(
        _ISSUER_KEY, hashes.SHA384(), rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    )
    return parse_certificate(signed.public_bytes(serialization.Encoding.DER))


def kds(oid: str, value: bytes) -> x509.ExtensionType:
    return x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value)


INTEGER_ZERO = b"\x02\x01\x00"
LEVEL_OIDS = (
    chain.OID_BL_SPL,
    chain.OID_TEE_SPL,
    chain.OID_SNP_SPL,
    chain.OID_SPL4,
    chain.OID_SPL5,
    chain.OID_SPL6,
    chain.OID_SPL7,
    chain.OID_UCODE_SPL,
)


def genoa_extensions(**overrides: bytes | None) -> list[x509.ExtensionType]:
    """The version 0 KDS extension set, with members replaced (bytes) or removed (None) by OID."""
    values: dict[str, bytes | None] = {
        chain.OID_STRUCT_VERSION: INTEGER_ZERO,
        chain.OID_PRODUCT_NAME_1: b"\x16\x08Genoa-B0",
        chain.OID_HWID: bytes(64),
        **dict.fromkeys(LEVEL_OIDS, INTEGER_ZERO),
    }
    values.update(overrides)
    return [kds(oid, value) for oid, value in values.items() if value is not None]


def test_vcek_extensions_of_the_happy_vector() -> None:
    exts = chain.vcek_certificate_extensions(material().vcek)
    assert exts.struct_version == 0
    assert exts.product_name == "Genoa-B0"
    assert exts.hwid == fx.GENOA_HWID
    assert exts.tcb.tcb == fx.GENOA_TCB
    assert exts.tcb.to_parts().bl_spl == 7
    assert exts.tcb.to_parts().ucode_spl == 72


def test_vcek_profile_checks() -> None:
    m = material()
    exts = chain.validate_vcek_certificate(m.vcek, "Genoa")
    assert exts.tcb.version == 0
    with pytest.raises(chain.ChainError, match="different TCB formats"):
        chain.validate_vcek_certificate(m.vcek, "Turin")
    with pytest.raises(chain.ChainError, match="could not determine TCB format for product 'Unknown'"):
        chain.validate_vcek_certificate(m.vcek, "Unknown")
    chain.validate_vcek_issuer(m.vcek, "Genoa")
    with pytest.raises(chain.ChainError, match=r"issuer common name SEV-Genoa not expected\. Expected SEV-Turin"):
        chain.validate_vcek_issuer(m.vcek, "Turin")
    # The ASK and ARK are not VCEKs: their keys, subjects and extensions all miss the profile.
    with pytest.raises(chain.ChainError, match="public key type is not ECDSA"):
        chain.validate_vcek_certificate(m.ask, "Genoa")
    with pytest.raises(chain.ChainError, match="not an AMD KDS OID"):
        chain.kds_extensions(m.ark)


def test_vcek_profile_rejects_other_keys_and_names() -> None:
    issued = pki.certificate("SEV-VCEK", pki.p384())
    with pytest.raises(chain.ChainError, match="signature algorithm is not SHA-384 with RSASSA-PSS"):
        chain.validate_vcek_certificate(parse_certificate(issued.der), "Genoa")
    root = pki.certificate("root", pki.rsa_key(), ca=True, pss=True)
    p256 = pki.certificate("SEV-VCEK", pki.p256(), root, pss=True)
    with pytest.raises(chain.ChainError, match="curve is secp256r1, expected P-384"):
        chain.validate_vcek_certificate(parse_certificate(p256.der), "Genoa")
    rsa_leaf = pki.certificate("SEV-VCEK", pki.rsa_key(), root, pss=True)
    with pytest.raises(chain.ChainError, match="public key type is not ECDSA"):
        chain.validate_vcek_certificate(parse_certificate(rsa_leaf.der), "Genoa")
    wrong_name = pki.certificate("SEV-VCEK", pki.p384(), root, pss=True)
    with pytest.raises(chain.ChainError, match="VCEK subject has 0 countries, want 1"):
        chain.validate_vcek_certificate(parse_certificate(wrong_name.der), "Genoa")
    wrong_common_name = pki.certificate("x", pki.p384(), root, pss=True, subject_name=amd_name("SEV-VLEK"))
    with pytest.raises(chain.ChainError, match=r"subject common name SEV-VLEK not expected\. Expected SEV-VCEK"):
        chain.validate_vcek_certificate(parse_certificate(wrong_common_name.der), "Genoa")
    # Any extension outside the KDS set, such as basic constraints, is rejected.
    with pytest.raises(chain.ChainError, match=r"not an AMD KDS OID: 2\.5\.29\.19"):
        chain.validate_vcek_certificate(
            parse_certificate(pki.certificate("x", pki.p384(), root, pss=True, subject_name=amd_name("SEV-VCEK")).der),
            "Genoa",
        )


def test_amd_location_and_common_name() -> None:
    chain.validate_amd_location(amd_name("SEV-VCEK"), "subject")
    assert chain.common_name(amd_name("SEV-VCEK")) == "SEV-VCEK"
    assert chain.common_name(x509.Name([])) == ""
    twice = x509.Name([*amd_name("first"), x509.NameAttribute(x509.NameOID.COMMON_NAME, "second")])
    assert chain.common_name(twice) == "second"
    austin = [a if a.oid != x509.NameOID.LOCALITY_NAME else x509.NameAttribute(a.oid, "Austin") for a in amd_name("x")]
    with pytest.raises(chain.ChainError, match="subject locality 'Austin' not expected for AMD"):
        chain.validate_amd_location(x509.Name(austin), "subject")
    doubled = x509.Name([*amd_name("x"), x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US")])
    with pytest.raises(chain.ChainError, match="subject has 2 countries, want 1"):
        chain.validate_amd_location(doubled, "subject")


def test_extension_decoding_rules() -> None:
    assert chain.vcek_certificate_extensions(mint_vcek(genoa_extensions())).hwid == bytes(64)
    # A wrapped hardware id is accepted at the layout's size and rejected at any other.
    wrapped = genoa_extensions(**{chain.OID_HWID: b"\x04\x40" + bytes(64)})
    assert chain.vcek_certificate_extensions(mint_vcek(wrapped)).hwid == bytes(64)
    short = genoa_extensions(**{chain.OID_HWID: b"\x04\x08" + bytes(8)})
    with pytest.raises(chain.ChainError, match="HWID size is 8, expected 64"):
        chain.vcek_certificate_extensions(mint_vcek(short))
    with pytest.raises(chain.ChainError, match="missing HWID extension"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_HWID: None})))
    with pytest.raises(chain.ChainError, match="no extension for field UcodeSpl"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_UCODE_SPL: None})))
    with pytest.raises(chain.ChainError, match="FmcSpl extension is not valid for TCB struct version 0"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_FMC_SPL: INTEGER_ZERO})))
    with pytest.raises(chain.ChainError, match="unexpected CSP_ID in VCEK certificate"):
        chain.vcek_certificate_extensions(
            mint_vcek(genoa_extensions(**{chain.OID_HWID: None, chain.OID_CSP_ID: b"\x16\x01x"}))
        )
    with pytest.raises(chain.ChainError, match="has both HWID"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_CSP_ID: b"\x16\x01x"})))
    with pytest.raises(chain.ChainError, match="not tagged as an IA5String: 12"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_PRODUCT_NAME_1: b"\x0c\x01x"})))
    with pytest.raises(chain.ChainError, match="could not parse extension ProductName1 as an IA5String"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_PRODUCT_NAME_1: b"\x16\x01\x80"})))
    with pytest.raises(chain.ChainError, match="could not parse extension BlSpl as an integer"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_BL_SPL: b"\x02\x02\x00\x01"})))
    with pytest.raises(chain.ChainError, match="could not parse extension BlSpl as an integer"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_BL_SPL: b"\x02\x01\x00\x00"})))
    with pytest.raises(chain.ChainError, match="isn't a uint8: 256"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_BL_SPL: b"\x02\x02\x01\x00"})))
    with pytest.raises(chain.ChainError, match="isn't a uint8: -1"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_BL_SPL: b"\x02\x01\xff"})))
    with pytest.raises(chain.ChainError, match=r"SnpSpl TCB part is 128\. Expect 0-127"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_SNP_SPL: b"\x02\x02\x00\x80"})))
    assert (
        chain.vcek_certificate_extensions(
            mint_vcek(genoa_extensions(**{chain.OID_UCODE_SPL: b"\x02\x02\x00\xff"}))
        ).tcb.tcb
        == 0xFF << 56
    )
    with pytest.raises(chain.ChainError, match="unsupported TCB structVersion 2"):
        chain.vcek_certificate_extensions(mint_vcek(genoa_extensions(**{chain.OID_STRUCT_VERSION: b"\x02\x01\x02"})))
    turin = genoa_extensions(
        **{
            chain.OID_STRUCT_VERSION: b"\x02\x01\x01",
            chain.OID_PRODUCT_NAME_1: b"\x16\x08Turin-B1",
            chain.OID_HWID: bytes(8),
            chain.OID_FMC_SPL: INTEGER_ZERO,
            chain.OID_SPL4: None,
        }
    )
    assert chain.vcek_certificate_extensions(mint_vcek(turin)).tcb.version == 1
    with pytest.raises(chain.ChainError, match="Spl4 extension is not valid for TCB struct version 1"):
        chain.vcek_certificate_extensions(mint_vcek([*turin, kds(chain.OID_SPL4, INTEGER_ZERO)]))
    with pytest.raises(chain.ChainError, match="reserved Turin TCB components must be zero"):
        chain.vcek_certificate_extensions(
            mint_vcek(
                [e for e in turin if e.oid.dotted_string != chain.OID_SPL5] + [kds(chain.OID_SPL5, b"\x02\x01\x01")]
            )
        )
    # The authority key identifier that the issuing ASK imparts is tolerated.
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=b"\x01" * 20, authority_cert_issuer=None, authority_cert_serial_number=None
    )
    assert chain.vcek_certificate_extensions(mint_vcek([*genoa_extensions(), aki])).struct_version == 0


def test_chain_verification_at_the_appraisal_time() -> None:
    m = material()
    chain.verify_vcek_chain(m.vcek, m.ask, m.ark, m.case.now)
    chain.verify_vcek_chain(m.vcek, m.ask, m.ark, m.vcek.not_valid_before_utc)
    chain.verify_vcek_chain(m.vcek, m.ask, m.ark, m.vcek.not_valid_after_utc)
    with pytest.raises(chain.ChainError, match="error verifying VCEK certificate"):
        chain.verify_vcek_chain(m.vcek, m.ask, m.ark, m.vcek.not_valid_before_utc - timedelta(seconds=1))
    with pytest.raises(chain.ChainError, match="error verifying VCEK certificate"):
        chain.verify_vcek_chain(m.vcek, m.ask, m.ark, m.vcek.not_valid_after_utc + timedelta(seconds=1))
    other = material("s26-wrong-root")
    with pytest.raises(chain.ChainError, match="error verifying VCEK certificate"):
        chain.verify_vcek_chain(m.vcek, other.ask, other.ark, m.case.now)
    with pytest.raises(chain.ChainError, match="error verifying VCEK certificate"):
        chain.verify_vcek_chain(m.vcek, m.ask, other.ark, m.case.now)


def test_ask_revocation() -> None:
    m = material()
    verified = chain.check_ask_not_revoked(m.ask, m.ark, parse_revocation_list(m.crl_der), m.case.now)
    assert verified.issuer == m.ark
    revoking = material("s26-revoked-ask").crl_der
    with pytest.raises(chain.ChainError, match="ASK was revoked"):
        chain.check_ask_not_revoked(m.ask, m.ark, parse_revocation_list(revoking), m.case.now)
    other = material("s26-wrong-root")
    with pytest.raises(chain.ChainError, match="CRL is not signed by ARK"):
        chain.check_ask_not_revoked(m.ask, other.ark, parse_revocation_list(m.crl_der), m.case.now)
    outside = datetime(2040, 1, 1, tzinfo=UTC)
    with pytest.raises(chain.ChainError, match="CRL is not signed by ARK: revocation list is not current"):
        chain.check_ask_not_revoked(m.ask, m.ark, parse_revocation_list(m.crl_der), outside)
    assert chain.crl_distribution_points(m.ask) == ("https://kdsintf.amd.com/vcek/v1/Genoa/crl",)
    assert chain.crl_distribution_points(parse_certificate(pki.certificate("x", pki.p256()).der)) == ()
    no_point = parse_certificate(pki.certificate("SEV-Genoa", pki.rsa_key(), ca=True, pss=True).der)
    with pytest.raises(chain.ChainError, match="names no CRL distribution point"):
        chain.check_ask_not_revoked(no_point, m.ark, parse_revocation_list(m.crl_der), m.case.now)
    # A distribution point must name the product revocation list by its path.
    elsewhere = x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain")], None, None, None
            )
        ]
    )
    wrong_path = pki.certificate("SEV-Genoa", pki.rsa_key(), ca=True, pss=True, extra=[(elsewhere, False)])
    with pytest.raises(chain.ChainError, match="names no CRL distribution point"):
        chain.check_ask_not_revoked(
            parse_certificate(wrong_path.der), m.ark, parse_revocation_list(m.crl_der), m.case.now
        )
    leaf_as_root = parse_certificate(pki.certificate("ARK-Genoa", pki.rsa_key(), pss=True).der)
    with pytest.raises(chain.ChainError, match="ARK is not a certificate authority"):
        chain.check_ask_not_revoked(m.ask, leaf_as_root, parse_revocation_list(m.crl_der), m.case.now)


def test_report_signature() -> None:
    m = material()
    raw = m.case.document.cpu_evidence().report
    chain.verify_report_signature(parse_report(raw), m.vcek)
    with pytest.raises(chain.ChainError, match="report signature verification error"):
        chain.verify_report_signature(parse_report(fx.flip(raw, 0x50)), m.vcek)
    with pytest.raises(chain.ChainError, match="report signature verification error"):
        chain.verify_report_signature(parse_report(fx.flip(raw, 0x2A0)), m.vcek)
    unsupported = bytearray(raw)
    unsupported[0] = 6
    with pytest.raises(chain.ChainError, match="attestation report format error: report version is: 6"):
        chain.verify_report_signature(parse_report(bytes(unsupported)), m.vcek)
    zero_signature = bytearray(raw)
    zero_signature[0x2A0:0x330] = bytes(144)
    with pytest.raises(chain.ChainError, match="report signature verification error"):
        chain.verify_report_signature(parse_report(bytes(zero_signature)), m.vcek)
    other_algorithm = bytearray(raw)
    other_algorithm[0x34] = 2
    with pytest.raises(chain.ChainError, match="unknown signature algorithm: 2"):
        chain.verify_report_signature(parse_report(bytes(other_algorithm)), m.vcek)


def test_parse_vcek() -> None:
    with pytest.raises(chain.ChainError, match="missing VCEK certificate"):
        chain.parse_vcek(b"")
    with pytest.raises(chain.ChainError, match="could not interpret VCEK DER bytes"):
        chain.parse_vcek(b"\x30\x00")
