"""The AMD endorsement key chain: VCEK extensions and profile, chain verification, ASK revocation and the report
signature, on the synthetic vectors' material and minted certificates."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from tests import pki
from tests import sev_fixtures as fx
from tinfoil.verifier._quote.sev.lib import chain
from tinfoil.verifier._quote.sev.lib.abi import parse_report
from tinfoil.verifier._x509 import der
from tinfoil.verifier._x509.certificate import parse_certificate
from tinfoil.verifier._x509.crl import parse_revocation_list


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


def turin_extensions(**overrides: bytes | None) -> list[x509.ExtensionType]:
    """The version 1 KDS extension set: the Turin name, an 8-byte hardware id and the FMC level in place of Spl4."""
    return genoa_extensions(
        **{
            chain.OID_STRUCT_VERSION: b"\x02\x01\x01",
            chain.OID_PRODUCT_NAME_1: b"\x16\x08Turin-B1",
            chain.OID_HWID: bytes(8),
            chain.OID_FMC_SPL: INTEGER_ZERO,
            chain.OID_SPL4: None,
            **overrides,
        }
    )


AUTHORITY_KEY_IDENTIFIER = x509.AuthorityKeyIdentifier(
    key_identifier=b"\x01" * 20, authority_cert_issuer=None, authority_cert_serial_number=None
)
"""The one non-KDS extension that an issuing ASK imparts, which decoding tolerates."""

REJECTED_EXTENSION_SETS = [
    pytest.param(
        genoa_extensions(**{chain.OID_HWID: b"\x04\x08" + bytes(8)}),
        "HWID size is 8, expected 64",
        id="wrapped-hwid-of-another-layout-size",
    ),
    pytest.param(genoa_extensions(**{chain.OID_HWID: None}), "missing HWID extension", id="missing-hwid"),
    pytest.param(
        genoa_extensions(**{chain.OID_UCODE_SPL: None}), "no extension for field UcodeSpl", id="missing-level"
    ),
    pytest.param(
        genoa_extensions(**{chain.OID_FMC_SPL: INTEGER_ZERO}),
        "FmcSpl extension is not valid for TCB struct version 0",
        id="fmc-level-in-version-0",
    ),
    pytest.param(
        genoa_extensions(**{chain.OID_HWID: None, chain.OID_CSP_ID: b"\x16\x01x"}),
        "unexpected CSP_ID in VCEK certificate",
        id="csp-id-in-place-of-hwid",
    ),
    pytest.param(genoa_extensions(**{chain.OID_CSP_ID: b"\x16\x01x"}), "has both HWID", id="csp-id-beside-hwid"),
    pytest.param(
        genoa_extensions(**{chain.OID_PRODUCT_NAME_1: b"\x0c\x01x"}),
        "not tagged as an IA5String: 12",
        id="product-name-tagged-utf8string",
    ),
    pytest.param(
        genoa_extensions(**{chain.OID_PRODUCT_NAME_1: b"\x16\x01\x80"}),
        "could not parse extension ProductName1 as an IA5String",
        id="product-name-outside-ascii",
    ),
    pytest.param(
        genoa_extensions(**{chain.OID_BL_SPL: b"\x02\x02\x00\x01"}),
        "could not parse extension BlSpl as an integer",
        id="level-non-minimal-integer",
    ),
    pytest.param(
        genoa_extensions(**{chain.OID_BL_SPL: b"\x02\x01\x00\x00"}),
        "could not parse extension BlSpl as an integer",
        id="level-with-trailing-byte",
    ),
    pytest.param(genoa_extensions(**{chain.OID_BL_SPL: b"\x02\x02\x01\x00"}), "isn't a uint8: 256", id="level-256"),
    pytest.param(genoa_extensions(**{chain.OID_BL_SPL: b"\x02\x01\xff"}), "isn't a uint8: -1", id="level-negative"),
    pytest.param(
        genoa_extensions(**{chain.OID_SNP_SPL: b"\x02\x02\x00\x80"}),
        r"SnpSpl TCB part is 128\. Expect 0-127",
        id="level-above-127",
    ),
    pytest.param(
        genoa_extensions(**{chain.OID_STRUCT_VERSION: b"\x02\x01\x02"}),
        "unsupported TCB structVersion 2",
        id="struct-version-2",
    ),
    pytest.param(
        turin_extensions(**{chain.OID_SPL4: INTEGER_ZERO}),
        "Spl4 extension is not valid for TCB struct version 1",
        id="spl4-in-version-1",
    ),
    pytest.param(
        turin_extensions(**{chain.OID_SPL5: b"\x02\x01\x01"}),
        "reserved Turin TCB components must be zero",
        id="non-zero-reserved-turin-level",
    ),
]
"""One VCEK extension set per decoding rule, with the error that it must produce."""

ACCEPTED_EXTENSION_SETS = [
    pytest.param(genoa_extensions(), lambda e: e.hwid == bytes(64), id="version-0"),
    pytest.param(
        genoa_extensions(**{chain.OID_HWID: b"\x04\x40" + bytes(64)}),
        lambda e: e.hwid == bytes(64),
        id="wrapped-hwid-of-the-layout-size",
    ),
    pytest.param(
        genoa_extensions(**{chain.OID_UCODE_SPL: b"\x02\x02\x00\xff"}),
        lambda e: e.tcb.tcb == 0xFF << 56,
        id="microcode-level-255",
    ),
    pytest.param(turin_extensions(), lambda e: e.tcb.version == 1, id="version-1"),
    pytest.param(
        [*genoa_extensions(), AUTHORITY_KEY_IDENTIFIER],
        lambda e: e.struct_version == 0,
        id="authority-key-identifier-tolerated",
    ),
]
"""VCEK extension sets that decode, each with the fact about the decoding that must hold."""


@pytest.mark.parametrize(("extensions", "message"), REJECTED_EXTENSION_SETS)
def test_extension_decoding_rejects(extensions: list[x509.ExtensionType], message: str) -> None:
    with pytest.raises(chain.ChainError, match=message):
        chain.vcek_certificate_extensions(mint_vcek(extensions))


@pytest.mark.parametrize(("extensions", "holds"), ACCEPTED_EXTENSION_SETS)
def test_extension_decoding_accepts(
    extensions: list[x509.ExtensionType], holds: Callable[[chain.VcekExtensions], bool]
) -> None:
    assert holds(chain.vcek_certificate_extensions(mint_vcek(extensions)))


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


def _context(tag: int, content: bytes, *, constructed: bool = True) -> bytes:
    return bytes([0x80 | (0x20 if constructed else 0) | tag]) + der.encode_length(len(content)) + content


def _sequence(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + der.encode_length(len(body)) + body


def _ask_with_distribution_points(general_names: bytes) -> x509.Certificate:
    """An ASK-shaped certificate whose one distribution point's fullName holds ``general_names`` (raw GeneralName
    elements), built from the DER directly so that name forms the library cannot represent are reachable."""
    value = _sequence(_sequence(_context(0, _context(0, general_names))))
    extra: list[tuple[x509.ExtensionType, bool]] = [
        (x509.UnrecognizedExtension(x509.ObjectIdentifier("2.5.29.31"), value), False)
    ]
    return parse_certificate(pki.certificate("SEV-Genoa", pki.rsa_key(), ca=True, pss=True, extra=extra).der)


def test_crl_distribution_points_skip_name_forms_other_than_uri() -> None:
    """A distribution point that names an x400Address or an ediPartyName beside the URI yields the URI alone, and
    the revocation check still finds the product list; a malformed extension is a ChainError."""
    m = material()
    crl = parse_revocation_list(m.crl_der)
    uri = _context(6, b"https://kdsintf.amd.com/vcek/v1/Genoa/crl", constructed=False)
    x400 = _context(3, _sequence())
    edi_party = _context(5, _context(1, b"\x0c\x01x"))
    for names in (x400 + uri, edi_party + uri, uri + x400 + edi_party):
        ask = _ask_with_distribution_points(names)
        assert chain.crl_distribution_points(ask) == ("https://kdsintf.amd.com/vcek/v1/Genoa/crl",)
        chain.check_ask_not_revoked(ask, m.ark, crl, m.case.now)
    # Without a URI among the names there is no distribution point to match.
    with pytest.raises(chain.ChainError, match="names no CRL distribution point"):
        chain.check_ask_not_revoked(_ask_with_distribution_points(x400 + edi_party), m.ark, crl, m.case.now)
    # A URI that is not IA5, a constructed URI and a GeneralName tag outside the choice are malformed.
    for names in (
        _context(6, "https://kdsintf.amd.com/vcek/v1/Genoa/crlé".encode(), constructed=False),
        _context(6, uri),
        _context(9, b"x", constructed=False),
    ):
        with pytest.raises(chain.ChainError, match="CRL distribution points"):
            chain.crl_distribution_points(_ask_with_distribution_points(names))
    # A URL that the URL parser rejects is no match rather than an error of another type.
    unsplittable = _ask_with_distribution_points(_context(6, b"https://[::1/crl", constructed=False))
    assert chain.crl_distribution_points(unsplittable) == ("https://[::1/crl",)
    with pytest.raises(chain.ChainError, match="names no CRL distribution point"):
        chain.check_ask_not_revoked(unsplittable, m.ark, crl, m.case.now)


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
