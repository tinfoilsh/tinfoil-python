"""Certificates and CRLs: strict parsing, the pre-checks on the DER, chain verification and revocation lists.

The probe table records, for each encoding that a lenient parser might
accept, what ``cryptography`` does with it and what this module does; the
module never accepts an encoding that ``cryptography`` would reject, and
it adds the pre-checks for the encodings that ``cryptography`` accepts.
"""

from __future__ import annotations

import copy
import time
from collections.abc import Callable
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests import der_tree, pki
from tests import tdx_builders as tb
from tinfoil.verifier._trust import (
    AMD_GENOA_CERT_CHAIN_PEM,
    AMD_TURIN_CERT_CHAIN_PEM,
    INTEL_SGX_ROOT_CA_PEM,
    PUBLIC_SIGNING_KEYS_PEM,
)
from tinfoil.verifier._x509 import certificate as c
from tinfoil.verifier._x509 import crl as crl_module
from tinfoil.verifier._x509 import der

Node = der_tree.Node


def tbs(tree: Node) -> list[Node]:
    return der_tree.children(der_tree.children(tree)[0])


def exts(tree: Node) -> list[Node]:
    """The Extension nodes of a v3 certificate tree (the TBS's last field wraps one SEQUENCE)."""
    return der_tree.children(der_tree.children(tbs(tree)[-1])[0])


def ext_value(node: Node, content: bytes) -> None:
    der_tree.children(node)[-1] = (0x04, content)


# --- the probe table ---------------------------------------------------------
#
# Each row: a mutation of a well-formed v3 certificate, whether parse_certificate
# accepts it, and (in the id) what cryptography does with it.

Mutation = Callable[[Node], None]


def set_time(index: int, identifier: int, content: bytes) -> Mutation:
    def change(tree: Node) -> None:
        der_tree.children(tbs(tree)[4])[index] = (identifier, content)

    return change


def set_serial(content: bytes) -> Mutation:
    def change(tree: Node) -> None:
        tbs(tree)[1] = (0x02, content)

    return change


def set_critical(content: bytes) -> Mutation:
    def change(tree: Node) -> None:
        der_tree.children(exts(tree)[0])[1] = (0x01, content)

    return change


def duplicate_extension(tree: Node) -> None:
    exts(tree).append(copy.deepcopy(exts(tree)[0]))


def clear_extensions(tree: Node) -> None:
    exts(tree).clear()


def drop_version(tree: Node) -> None:
    tbs(tree).pop(0)


def set_version(content: bytes) -> Mutation:
    def change(tree: Node) -> None:
        der_tree.children(tbs(tree)[0])[0] = (0x02, content)

    return change


def differing_outer_algorithm(tree: Node) -> None:
    der_tree.children(tree)[1] = (0x30, [(0x06, bytes.fromhex("2a8648ce3d040303"))])


def unused_signature_bit(tree: Node) -> None:
    """One unused bit, with that bit cleared so that the padding itself is DER-valid."""
    signature = der_tree.children(tree)[2][1]
    assert isinstance(signature, bytes)
    der_tree.children(tree)[2] = (0x03, b"\x01" + signature[1:-1] + bytes([signature[-1] & 0xFE]))


def null_ecdsa_parameters(tree: Node) -> None:
    der_tree.children(tbs(tree)[2]).append((0x05, b""))
    der_tree.children(der_tree.children(tree)[1]).append((0x05, b""))


def key_usage_value(content: bytes) -> Mutation:
    def change(tree: Node) -> None:
        ext_value(exts(tree)[1], content)

    return change


def constructed_extension_value(tree: Node) -> None:
    value = der_tree.children(exts(tree)[0])[-1][1]
    assert isinstance(value, bytes)
    der_tree.children(exts(tree)[0])[-1] = (0x24, [(0x04, value)])


PROBES: list[tuple[str, Mutation, bool]] = [
    # id: "<probe> / cryptography <accepts|rejects>", mutation, accepted here
    ("serial non-minimal / cryptography rejects", set_serial(b"\x00\x07"), False),
    ("serial negative / cryptography accepts (deprecation)", set_serial(b"\xf0"), False),
    ("serial zero / cryptography accepts", set_serial(b"\x00"), True),
    ("UTCTime without Z / cryptography rejects", set_time(0, 0x17, b"240101000000"), False),
    ("UTCTime with offset / cryptography rejects", set_time(0, 0x17, b"240101000000+0000"), False),
    ("UTCTime without seconds / cryptography rejects", set_time(0, 0x17, b"2401010000Z"), False),
    ("GeneralizedTime before 2050 / cryptography accepts", set_time(0, 0x18, b"20240101000000Z"), True),
    ("GeneralizedTime fraction / cryptography rejects", set_time(0, 0x18, b"20240101000000.5Z"), False),
    ("GeneralizedTime without Z / cryptography rejects", set_time(0, 0x18, b"20240101000000"), False),
    ("impossible date / cryptography rejects", set_time(0, 0x17, b"240230000000Z"), False),
    ("critical BOOLEAN 0x01 / cryptography rejects", set_critical(b"\x01"), False),
    ("critical explicit FALSE / cryptography rejects", set_critical(b"\x00"), False),
    ("duplicate extension / cryptography accepts at load", duplicate_extension, False),
    ("empty extensions SEQUENCE / cryptography accepts", clear_extensions, True),
    ("v1 with extensions / cryptography accepts", drop_version, False),
    ("explicit version 1 / cryptography rejects", set_version(b"\x00"), False),
    ("version 4 / cryptography rejects", set_version(b"\x03"), False),
    ("inner and outer algorithms differ / cryptography accepts", differing_outer_algorithm, False),
    ("ECDSA algorithm with NULL parameters / cryptography rejects", null_ecdsa_parameters, False),
    ("signature BIT STRING with an unused bit / cryptography accepts", unused_signature_bit, False),
    (
        "constructed OCTET STRING extension value / cryptography rejects",
        constructed_extension_value,
        False,
    ),
    (
        "keyUsage with trailing zero bits / cryptography accepts",
        key_usage_value(bytes.fromhex("0303008600")),
        True,
    ),
    (
        "keyUsage with set unused bits / cryptography accepts at load",
        key_usage_value(bytes.fromhex("03020187")),
        False,
    ),
]


@pytest.fixture(scope="module")
def probe_certificate() -> bytes:
    issued = pki.certificate("probe", pki.p256(), ca=True, key_usage=pki.CA_USAGE, serial=7)
    return issued.der


@pytest.mark.filterwarnings("ignore::cryptography.utils.CryptographyDeprecationWarning")
@pytest.mark.parametrize(("mutation", "accepted"), [(m, a) for _, m, a in PROBES], ids=[p[0] for p in PROBES])
def test_probe_table(probe_certificate: bytes, mutation: Mutation, accepted: bool) -> None:
    mutated = der_tree.mutate(probe_certificate, mutation)
    if accepted:
        assert c.parse_certificate(mutated).public_bytes(serialization.Encoding.DER) == mutated
    else:
        with pytest.raises(c.X509Error):
            c.parse_certificate(mutated)


def test_probe_baseline_parses(probe_certificate: bytes) -> None:
    parsed = c.parse_certificate(probe_certificate)
    assert parsed.serial_number == 7
    assert c.can_issue_certificates(parsed)
    assert c.extended_key_usage(parsed) is None


def test_trailing_bytes_and_indefinite_lengths_reject(probe_certificate: bytes) -> None:
    with pytest.raises(c.X509Error, match="trailing bytes"):
        c.parse_certificate(probe_certificate + b"\x00")
    with pytest.raises(c.X509Error, match="indefinite"):
        c.parse_certificate(b"\x30\x80" + probe_certificate[4:] + b"\x00\x00")
    with pytest.raises(c.X509Error):
        c.parse_certificate(b"")


def corrupt_common_name(name_node: Node) -> None:
    """Make the first byte of the UTF8String commonName in ``name_node`` invalid UTF-8. The strict tokenizer does
    not type Name attribute values, so the pre-checks pass the structure and only the library's decoding of the
    name, which happens on first access, fails."""
    attribute = der_tree.children(der_tree.children(der_tree.children(name_node)[0])[0])
    identifier, value = attribute[1]
    assert identifier == 0x0C
    assert isinstance(value, bytes)
    attribute[1] = (0x0C, b"\xff" + value[1:])


def corrupt_certificate_name(field: int) -> Mutation:
    def change(tree: Node) -> None:
        corrupt_common_name(tbs(tree)[field])

    return change


def corrupt_crl_issuer(tree: Node) -> None:
    corrupt_common_name(der_tree.children(der_tree.children(tree)[0])[2])


def test_names_the_library_cannot_decode_reject_at_parse(probe_certificate: bytes) -> None:
    """An undecodable issuer or subject name is an X509Error from parse_certificate, and an undecodable CRL issuer
    name a CRLError from parse_revocation_list, never a ValueError from the first accessor that reads the name."""
    for field, name in ((3, "issuer"), (5, "subject")):
        mutated = der_tree.mutate(probe_certificate, corrupt_certificate_name(field))
        loaded = x509.load_der_x509_certificate(mutated)  # the library loads it; reading the name raises
        with pytest.raises(ValueError, match="asn1"):
            getattr(loaded, name)
        with pytest.raises(c.X509Error, match=r"^certificate: .*asn1"):
            c.parse_certificate(mutated)
    root, _, _ = pki.chain()
    mutated = der_tree.mutate(pki.crl(root), corrupt_crl_issuer)
    loaded_crl = x509.load_der_x509_crl(mutated)
    with pytest.raises(ValueError, match="asn1"):
        _ = loaded_crl.issuer
    with pytest.raises(crl_module.CRLError, match=r"^revocation list: .*asn1"):
        crl_module.parse_revocation_list(mutated)


def test_version_2_certificate_rejects_at_the_pre_check(probe_certificate: bytes) -> None:
    """The library refuses a version 2 certificate with an error that is not a ValueError, so the pre-check names
    the version first and the library error is caught as well."""

    def to_version_2_without_extensions(tree: Node) -> None:
        tbs(tree)[0] = (0xA0, [(0x02, b"\x01")])
        assert tbs(tree)[-1][0] == 0xA3
        tbs(tree).pop()

    mutated = der_tree.mutate(probe_certificate, to_version_2_without_extensions)
    assert not issubclass(x509.InvalidVersion, ValueError)
    with pytest.raises(x509.InvalidVersion):
        x509.load_der_x509_certificate(mutated)
    with pytest.raises(c.X509Error, match="certificate version 2 is not supported"):
        c.parse_certificate(mutated)


# --- library claims ----------------------------------------------------------


def test_library_claims_about_certificates(probe_certificate: bytes) -> None:
    """What this module relies on cryptography for, pinned so that a library change is noticed."""
    parsed = x509.load_der_x509_certificate(probe_certificate)
    # The DER round-trips byte for byte.
    assert parsed.public_bytes(serialization.Encoding.DER) == probe_certificate
    # The TBS and signature views are the raw elements.
    parts = der.children(der.decode(probe_certificate))
    assert parsed.tbs_certificate_bytes == parts[0].raw
    assert parsed.signature == der.bit_string(parts[2])
    # Validity times are aware.
    assert parsed.not_valid_before_utc.tzinfo is not None
    # The strict framing checks that the pre-tokenizer also makes.
    for bad in (probe_certificate + b"\x00", b"\x30\x83\x00" + probe_certificate[2:]):
        with pytest.raises(ValueError, match="asn1"):
            x509.load_der_x509_certificate(bad)
    # Looser than the pre-checks: these load, which is why the pre-checks exist.
    for loose in (duplicate_extension, differing_outer_algorithm, unused_signature_bit, drop_version):
        x509.load_der_x509_certificate(der_tree.mutate(probe_certificate, loose))
    with pytest.warns(UserWarning, match="serial number"):
        x509.load_der_x509_certificate(der_tree.mutate(probe_certificate, set_serial(b"\xf0")))


def test_library_claims_about_keys() -> None:
    for key in (pki.p256(), pki.p384(), pki.rsa_key(), pki.ed25519_key()):
        loaded = serialization.load_der_public_key(pki.spki(key))
        assert isinstance(loaded, ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey)
        assert c.public_key_spki(c.load_public_key_der(pki.spki(key))) == pki.spki(key)
    with pytest.raises(c.X509Error, match="unsupported EC curve"):
        c.load_public_key_der(pki.spki(ec.generate_private_key(ec.SECP521R1())))


def test_rsa_keys_below_2048_bits_reject() -> None:
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    assert isinstance(serialization.load_der_public_key(pki.spki(small)), rsa.RSAPublicKey)
    with pytest.raises(c.X509Error, match="1024 bits is smaller than 2048"):
        c.load_public_key_der(pki.spki(small))
    with pytest.raises(c.X509Error, match="1024 bits is smaller than 2048"):
        c.load_public_key_pem(pki.public_pem(small))
    # A certificate carrying such a key rejects at parse, before any chain is built.
    with pytest.raises(c.X509Error, match="1024 bits is smaller than 2048"):
        c.parse_certificate(pki.certificate("weak", small).der)
    accepted = c.load_public_key_der(pki.spki(pki.rsa_key()))
    assert isinstance(accepted, rsa.RSAPublicKey)
    assert accepted.key_size == c.MIN_RSA_KEY_BITS


# --- accessors ---------------------------------------------------------------


def test_embedded_material_parses_and_re_encodes() -> None:
    for pem in (AMD_GENOA_CERT_CHAIN_PEM, AMD_TURIN_CERT_CHAIN_PEM):
        ask, ark = c.parse_certificates_pem(pem)
        assert c.can_issue_certificates(ask)
        assert c.can_issue_certificates(ark)
        assert c.can_sign_revocation_lists(ark)
        assert c.issuer_name(ask) == c.subject_name(ark)
    (root,) = c.parse_certificates_pem(INTEL_SGX_ROOT_CA_PEM)
    assert c.issuer_name(root) == c.subject_name(root)
    assert isinstance(c.certificate_public_key(root), ec.EllipticCurvePublicKey)
    for key_pem in PUBLIC_SIGNING_KEYS_PEM:
        assert isinstance(c.load_public_key_pem(key_pem), ec.EllipticCurvePublicKey)


def test_pem_parsers_require_exactly_the_blocks_named() -> None:
    with pytest.raises(c.X509Error, match="exactly one CERTIFICATE"):
        c.parse_certificate_pem(AMD_GENOA_CERT_CHAIN_PEM)
    with pytest.raises(c.X509Error, match="no CERTIFICATE block"):
        c.parse_certificates_pem("")
    with pytest.raises(c.X509Error, match="not a CERTIFICATE"):
        c.parse_certificates_pem(PUBLIC_SIGNING_KEYS_PEM[0])
    with pytest.raises(c.X509Error, match="exactly one PUBLIC KEY"):
        c.load_public_key_pem(PUBLIC_SIGNING_KEYS_PEM[0] + PUBLIC_SIGNING_KEYS_PEM[0])
    with pytest.raises(c.X509Error, match="not ASCII"):
        c.parse_certificates_pem(b"\xff")


def test_extensions_and_usage_predicates() -> None:
    _root, intermediate, leaf = pki.chain()
    parsed = c.parse_certificate(leaf.der)
    oids = [e.oid for e in c.extensions(parsed)]
    assert oids == [c.OID_BASIC_CONSTRAINTS, c.OID_KEY_USAGE, c.OID_EXT_KEY_USAGE]
    assert c.extension(parsed, c.OID_KEY_USAGE) is not None
    assert c.extension(parsed, c.OID_SUBJECT_ALT_NAME) is None
    assert c.basic_constraints(parsed) == (False, None)
    assert c.basic_constraints(c.parse_certificate(intermediate.der)) == (True, 0)
    assert c.key_usage(parsed) == (True,)
    assert c.extended_key_usage(parsed) == (c.OID_EKU_CODE_SIGNING,)
    assert c.can_sign_data(parsed)
    assert not c.can_issue_certificates(parsed)
    assert not c.can_sign_revocation_lists(parsed)
    assert c.unsupported_critical_extension(parsed) is None
    assert c.spki_fingerprint(pki.spki(leaf.key)) == __import__("hashlib").sha256(pki.spki(leaf.key)).digest()


def test_usage_predicates_without_key_usage_are_permissive() -> None:
    no_usage = c.parse_certificate(pki.certificate("plain", pki.p256(), ca=True).der)
    assert c.can_issue_certificates(no_usage)
    assert c.can_sign_revocation_lists(no_usage)
    assert c.can_sign_data(no_usage)
    not_ca = c.parse_certificate(pki.certificate("plain", pki.p256()).der)
    assert not c.can_issue_certificates(not_ca)


def test_unsupported_critical_extension_is_reported() -> None:
    issued = pki.certificate(
        "constrained",
        pki.p256(),
        ca=True,
        extra=[(x509.NameConstraints([x509.DNSName("example.test")], None), True)],
    )
    assert c.unsupported_critical_extension(c.parse_certificate(issued.der)) == "2.5.29.30"
    policy = pki.certificate("policies", pki.p256(), extra=[(x509.CertificatePolicies([]), False)])
    assert c.unsupported_critical_extension(c.parse_certificate(policy.der)) is None


def test_uri_sans() -> None:
    uri = "https://github.com/o/r/.github/workflows/a_b.yml@refs/tags/v1"
    issued = pki.certificate(
        "san", pki.p256(), sans=[x509.UniformResourceIdentifier(uri), x509.DNSName("example.test")], san_critical=True
    )
    parsed = c.parse_certificate(issued.der)
    assert c.uri_sans(parsed) == (uri,)
    assert c.uri_sans(c.parse_certificate(pki.certificate("none", pki.p256()).der)) == ()
    # A control character in the URI is not a URL.
    tampered = issued.der.replace(uri.encode(), uri.replace("_", "\t").encode())
    with pytest.raises(c.X509Error, match="not a URL"):
        c.uri_sans(c.parse_certificate(tampered))
    # A malformed percent escape is not a URL either.
    tampered = issued.der.replace(uri.encode(), uri.replace("a_b", "%zz").encode())
    with pytest.raises(c.X509Error, match="not a URL"):
        c.uri_sans(c.parse_certificate(tampered))


def _context(tag: int, content: bytes, *, constructed: bool = True) -> bytes:
    return bytes([0x80 | (0x20 if constructed else 0) | tag]) + der.encode_length(len(content)) + content


def _sequence(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + der.encode_length(len(body)) + body


def _uri_name(text: bytes) -> bytes:
    return _context(6, text, constructed=False)


def with_distribution_points(*points: bytes) -> x509.Certificate:
    """A certificate whose cRLDistributionPoints extension holds ``points`` (raw DistributionPoint SEQUENCEs),
    built from the DER directly so that malformed layouts are reachable."""
    extra: list[tuple[x509.ExtensionType, bool]] = [
        (x509.UnrecognizedExtension(x509.ObjectIdentifier(c.OID_CRL_DISTRIBUTION_POINTS), _sequence(*points)), False)
    ]
    return c.parse_certificate(pki.certificate("cdp", pki.p256(), extra=extra).der)


def test_crl_distribution_point_fields_are_unique_and_ordered() -> None:
    """The optional fields of a DistributionPoint appear at most once each, as [0] distributionPoint, [1] reasons,
    [2] cRLIssuer in that order; a repeated or reordered field is malformed."""
    uri = "https://crl.example.test/a.crl"
    full_name = _context(0, _context(0, _uri_name(uri.encode())))
    reasons = _context(1, b"\x06\x40", constructed=False)
    issuer = _context(2, _context(4, _sequence()))
    assert c.crl_distribution_point_uris(with_distribution_points(_sequence(full_name))) == (uri,)
    assert c.crl_distribution_point_uris(with_distribution_points(_sequence(full_name, reasons, issuer))) == (uri,)
    assert c.crl_distribution_point_uris(with_distribution_points(_sequence(reasons, issuer))) == ()
    for fields in (
        (full_name, full_name),
        (reasons, reasons),
        (full_name, reasons, reasons),
        (reasons, full_name),
        (issuer, full_name),
        (full_name, issuer, reasons),
    ):
        with pytest.raises(c.X509Error, match="DistributionPoint fields are repeated or out of order"):
            c.crl_distribution_point_uris(with_distribution_points(_sequence(*fields)))
    # A field beyond the three is still an unexpected field.
    with pytest.raises(c.X509Error, match="unexpected field"):
        c.crl_distribution_point_uris(with_distribution_points(_sequence(full_name, _context(3, b""))))


def test_crl_distribution_point_uris_are_decoded_like_subject_alt_name_uris() -> None:
    """A distribution point URI with an ASCII control character or a malformed percent escape is rejected with the
    same error as the subjectAltName URI that carries it, and a constructed or non-IA5 URI is malformed."""
    uri = "https://crl.example.test/a_b.crl"
    assert c.crl_distribution_point_uris(
        with_distribution_points(_sequence(_context(0, _context(0, _uri_name(uri.encode())))))
    ) == (uri,)
    san = pki.certificate("san", pki.p256(), sans=[x509.UniformResourceIdentifier(uri)])
    for bad in (uri.replace("_", "\t"), uri.replace("a_b", "%zz"), uri.replace("_", "\x7f")):
        with pytest.raises(c.X509Error, match="URI GeneralName is not a URL") as from_san:
            c.uri_sans(c.parse_certificate(san.der.replace(uri.encode(), bad.encode())))
        point = _sequence(_context(0, _context(0, _uri_name(bad.encode()))))
        with pytest.raises(c.X509Error, match="URI GeneralName is not a URL") as from_point:
            c.crl_distribution_point_uris(with_distribution_points(point))
        assert str(from_san.value) == str(from_point.value)
    with pytest.raises(c.X509Error, match="URI GeneralName must be primitive"):
        c.crl_distribution_point_uris(
            with_distribution_points(_sequence(_context(0, _context(0, _context(6, _uri_name(uri.encode()))))))
        )
    with pytest.raises(c.X509Error, match="cRLDistributionPoints: IA5String"):
        c.crl_distribution_point_uris(
            with_distribution_points(_sequence(_context(0, _context(0, _uri_name(uri.encode() + b"\xc3\xa9")))))
        )


def test_valid_at_is_inclusive_and_requires_an_aware_time() -> None:
    parsed = c.parse_certificate(pki.certificate("t", pki.p256()).der)
    assert c.valid_at(parsed, pki.NOT_BEFORE)
    assert c.valid_at(parsed, pki.NOT_AFTER)
    assert not c.valid_at(parsed, pki.NOT_BEFORE - timedelta(seconds=1))
    assert not c.valid_at(parsed, pki.NOT_AFTER + timedelta(seconds=1))
    with pytest.raises(c.X509Error, match="timezone-aware"):
        c.valid_at(parsed, datetime(2025, 1, 1))


# --- signatures and chains ---------------------------------------------------


@pytest.mark.parametrize("kind", ["p256", "p384", "rsa", "ed25519"])
def test_verify_chain_for_each_algorithm(kind: str) -> None:
    root, intermediate, leaf = pki.chain(kind, pss=kind == "rsa")
    parsed = [c.parse_certificate(i.der) for i in (leaf, intermediate, root)]
    path = c.verify_chain(parsed[0], [parsed[1]], [parsed[2]], pki.AT, extended_key_usage=c.OID_EKU_CODE_SIGNING)
    assert [p.serial_number for p in path] == [3, 2, 1]


def test_rsa_pkcs1_sha256_signatures_verify() -> None:
    root = pki.certificate("root", pki.rsa_key(), ca=True, key_usage=pki.CA_USAGE)
    leaf = pki.certificate("leaf", pki.rsa_key(), root)
    c.verify_certificate_signature(c.parse_certificate(leaf.der), c.parse_certificate(root.der))


def test_signature_rejects_wrong_key_and_tampering() -> None:
    _root, intermediate, leaf = pki.chain()
    other = c.parse_certificate(pki.certificate("other", pki.p256(), ca=True).der)
    parsed_leaf = c.parse_certificate(leaf.der)
    with pytest.raises(c.X509Error, match="does not verify"):
        c.verify_certificate_signature(parsed_leaf, other)
    rsa_root = c.parse_certificate(pki.certificate("rsa", pki.rsa_key(), ca=True).der)
    with pytest.raises(c.X509Error, match="non-EC key"):
        c.verify_certificate_signature(parsed_leaf, rsa_root)
    tampered = bytearray(leaf.der)
    tampered[-1] ^= 0x01
    with pytest.raises(c.X509Error):
        c.verify_certificate_signature(c.parse_certificate(bytes(tampered)), c.parse_certificate(intermediate.der))


def test_ecdsa_hash_must_match_the_issuer_curve() -> None:
    # A P-256 issuer signing with SHA-384 verifies in a permissive verifier; here the pairing is fixed.
    root = pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE)
    builder = (
        x509.CertificateBuilder()
        .subject_name(pki.name("leaf"))
        .issuer_name(pki.name("root"))
        .public_key(pki.p256().public_key())
        .serial_number(5)
        .not_valid_before(pki.NOT_BEFORE)
        .not_valid_after(pki.NOT_AFTER)
    )
    assert isinstance(root.key, ec.EllipticCurvePrivateKey)
    leaf = builder.sign(root.key, hashes.SHA384()).public_bytes(serialization.Encoding.DER)
    with pytest.raises(c.X509Error, match="does not match the key's curve"):
        c.verify_certificate_signature(c.parse_certificate(leaf), c.parse_certificate(root.der))


def test_rsa_pss_parameters_are_pinned() -> None:
    root = pki.certificate("root", pki.rsa_key(), ca=True, key_usage=pki.CA_USAGE)
    assert isinstance(root.key, rsa.RSAPrivateKey)
    builder = (
        x509.CertificateBuilder()
        .subject_name(pki.name("leaf"))
        .issuer_name(pki.name("root"))
        .public_key(pki.rsa_key().public_key())
        .serial_number(5)
        .not_valid_before(pki.NOT_BEFORE)
        .not_valid_after(pki.NOT_AFTER)
    )
    from cryptography.hazmat.primitives.asymmetric import padding

    sha256_pss = builder.sign(
        root.key, hashes.SHA256(), rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    ).public_bytes(serialization.Encoding.DER)
    with pytest.raises(c.X509Error, match="RSA-PSS is supported only with SHA-384"):
        c.verify_certificate_signature(c.parse_certificate(sha256_pss), c.parse_certificate(root.der))


def _pss_params(*fields: bytes) -> der.Element:
    """An RSA-PSS AlgorithmIdentifier whose parameters hold ``fields`` as given."""
    return der.decode(tb.sequence(tb.oid(c.OID_RSA_PSS), tb.sequence(*fields)))


def _tagged(tag: int, content: bytes) -> bytes:
    return tb.tlv(0xA0 | tag, content)


_PSS_HASH = _tagged(0, tb.sequence(tb.oid(c.OID_SHA384)))
_PSS_MGF = _tagged(1, tb.sequence(tb.oid(c.OID_MGF1), tb.sequence(tb.oid(c.OID_SHA384))))
_PSS_SALT = _tagged(2, tb.integer(48))


def test_rsa_pss_parameters_are_strict_der() -> None:
    assert c.signature_algorithm(_pss_params(_PSS_HASH, _PSS_MGF, _PSS_SALT)).oid == c.OID_RSA_PSS
    # Out of order or repeated fields are not DER; a repeat could also override the field that was checked.
    for fields in (
        (_PSS_MGF, _PSS_HASH, _PSS_SALT),
        (_PSS_HASH, _PSS_SALT, _PSS_MGF),
        (_PSS_HASH, _PSS_HASH, _PSS_MGF, _PSS_SALT),
        (_PSS_HASH, _PSS_MGF, _PSS_SALT, _tagged(2, tb.integer(20))),
    ):
        with pytest.raises(c.X509Error, match="must be in tag order without repeats"):
            c.signature_algorithm(_pss_params(*fields))
    # The trailer field has one legal value. DER would omit it as the default, but the AMD chains encode it, so an
    # explicit 1 is accepted and anything else is not.
    assert (
        c.signature_algorithm(_pss_params(_PSS_HASH, _PSS_MGF, _PSS_SALT, _tagged(3, tb.integer(1)))).oid
        == c.OID_RSA_PSS
    )
    with pytest.raises(c.X509Error, match="RSA-PSS trailer field must be 1"):
        c.signature_algorithm(_pss_params(_PSS_HASH, _PSS_MGF, _PSS_SALT, _tagged(3, tb.integer(2))))
    with pytest.raises(c.X509Error, match="must be in tag order without repeats"):
        c.signature_algorithm(
            _pss_params(_PSS_HASH, _PSS_MGF, _PSS_SALT, _tagged(3, tb.integer(1)), _tagged(3, tb.integer(1)))
        )
    with pytest.raises(c.X509Error, match="unknown RSA-PSS parameter"):
        c.signature_algorithm(_pss_params(_PSS_HASH, _PSS_MGF, _PSS_SALT, _tagged(4, tb.integer(1))))
    with pytest.raises(c.X509Error, match="RSA-PSS is supported only with SHA-384"):
        c.signature_algorithm(_pss_params(_PSS_HASH, _PSS_MGF))


def test_verify_chain_rejections() -> None:
    root, intermediate, leaf = pki.chain()
    parsed_leaf, parsed_mid, parsed_root = (c.parse_certificate(i.der) for i in (leaf, intermediate, root))
    with pytest.raises(c.X509Error, match="not valid at"):
        c.verify_chain(parsed_leaf, [parsed_mid], [parsed_root], pki.NOT_AFTER + timedelta(days=1))
    with pytest.raises(c.X509Error, match="no verified path"):
        c.verify_chain(parsed_leaf, [], [parsed_root], pki.AT)
    other_root = c.parse_certificate(pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE).der)
    with pytest.raises(c.X509Error, match="no verified path"):
        c.verify_chain(parsed_leaf, [parsed_mid], [other_root], pki.AT)
    with pytest.raises(c.X509Error, match="no trusted roots"):
        c.verify_chain(parsed_leaf, [parsed_mid], [], pki.AT)
    with pytest.raises(c.X509Error, match="does not allow extended key usage"):
        c.verify_chain(parsed_leaf, [parsed_mid], [parsed_root], pki.AT, extended_key_usage=c.OID_EKU_TIME_STAMPING)
    with pytest.raises(c.X509Error, match="timezone-aware"):
        c.verify_chain(parsed_leaf, [parsed_mid], [parsed_root], datetime(2025, 6, 1))


def test_verify_chain_self_signed_root_as_leaf() -> None:
    root = c.parse_certificate(pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE).der)
    assert c.verify_chain(root, [], [root], pki.AT) == (root,)


def test_verify_chain_requires_issuers_to_be_authorities() -> None:
    root = pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE)
    not_ca = pki.certificate("mid", pki.p256(), root, key_usage=pki.CA_USAGE)
    leaf = pki.certificate("leaf", pki.p256(), not_ca)
    with pytest.raises(c.X509Error, match="not a certificate authority"):
        c.verify_chain(
            c.parse_certificate(leaf.der), [c.parse_certificate(not_ca.der)], [c.parse_certificate(root.der)], pki.AT
        )
    # A CA whose key usage omits keyCertSign may not issue either.
    no_sign = pki.certificate("mid", pki.p256(), root, ca=True, key_usage=pki.SIGNING_USAGE)
    leaf = pki.certificate("leaf", pki.p256(), no_sign)
    with pytest.raises(c.X509Error, match="not a certificate authority"):
        c.verify_chain(
            c.parse_certificate(leaf.der), [c.parse_certificate(no_sign.der)], [c.parse_certificate(root.der)], pki.AT
        )


def test_verify_chain_path_length_and_depth() -> None:
    root = pki.certificate("root", pki.p256(), ca=True, path_length=0, key_usage=pki.CA_USAGE)
    mid = pki.certificate("mid", pki.p256(), root, ca=True, key_usage=pki.CA_USAGE)
    leaf = pki.certificate("leaf", pki.p256(), mid)
    with pytest.raises(c.X509Error, match="path length constraint"):
        c.verify_chain(
            c.parse_certificate(leaf.der), [c.parse_certificate(mid.der)], [c.parse_certificate(root.der)], pki.AT
        )
    # A path of exactly MAX_CHAIN_LENGTH certificates, leaf and root included, verifies; one more never does.
    issued = [pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE)]
    for index in range(c.MAX_CHAIN_LENGTH - 2):
        issued.append(pki.certificate(f"mid{index}", pki.p256(), issued[-1], ca=True, key_usage=pki.CA_USAGE))
    leaf = pki.certificate("leaf", pki.p256(), issued[-1])
    path = c.verify_chain(
        c.parse_certificate(leaf.der),
        [c.parse_certificate(i.der) for i in issued[1:]],
        [c.parse_certificate(issued[0].der)],
        pki.AT,
    )
    assert len(path) == c.MAX_CHAIN_LENGTH
    issued.append(pki.certificate("mid-extra", pki.p256(), issued[-1], ca=True, key_usage=pki.CA_USAGE))
    long_leaf = pki.certificate("leaf", pki.p256(), issued[-1])
    with pytest.raises(c.X509Error, match=f"path longer than {c.MAX_CHAIN_LENGTH}"):
        c.verify_chain(
            c.parse_certificate(long_leaf.der),
            [c.parse_certificate(i.der) for i in issued[1:]],
            [c.parse_certificate(issued[0].der)],
            pki.AT,
        )


def test_verify_chain_extended_key_usage_rule() -> None:
    root = pki.certificate(
        "root", pki.p256(), ca=True, key_usage=pki.CA_USAGE, eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]
    )
    mid = pki.certificate(
        "mid", pki.p256(), root, ca=True, key_usage=pki.CA_USAGE, eku=[ExtendedKeyUsageOID.TIME_STAMPING]
    )
    leaf = pki.certificate("leaf", pki.p256(), mid, eku=[ExtendedKeyUsageOID.TIME_STAMPING], eku_critical=True)
    parsed = [c.parse_certificate(i.der) for i in (leaf, mid, root)]
    c.verify_chain(parsed[0], [parsed[1]], [parsed[2]], pki.AT, extended_key_usage=c.OID_EKU_TIME_STAMPING)
    with pytest.raises(c.X509Error, match="does not allow extended key usage"):
        c.verify_chain(parsed[0], [parsed[1]], [parsed[2]], pki.AT, extended_key_usage=c.OID_EKU_CODE_SIGNING)
    # A root restricted to another usage fails the chain too.
    restricted_root = pki.certificate(
        "root", pki.p256(), ca=True, key_usage=pki.CA_USAGE, eku=[ExtendedKeyUsageOID.SERVER_AUTH]
    )
    mid = pki.certificate("mid", pki.p256(), restricted_root, ca=True, key_usage=pki.CA_USAGE)
    leaf = pki.certificate("leaf", pki.p256(), mid, eku=[ExtendedKeyUsageOID.TIME_STAMPING])
    with pytest.raises(c.X509Error, match="does not allow extended key usage"):
        c.verify_chain(
            c.parse_certificate(leaf.der),
            [c.parse_certificate(mid.der)],
            [c.parse_certificate(restricted_root.der)],
            pki.AT,
            extended_key_usage=c.OID_EKU_TIME_STAMPING,
        )


def test_code_signing_requires_the_leaf_to_allow_digital_signature() -> None:
    root = pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE)
    # A keyUsage without digitalSignature: the leaf may not sign code, whatever its extendedKeyUsage says.
    leaf = pki.certificate("leaf", pki.p256(), root, key_usage=pki.CA_USAGE, eku=[ExtendedKeyUsageOID.CODE_SIGNING])
    parsed_leaf, parsed_root = c.parse_certificate(leaf.der), c.parse_certificate(root.der)
    with pytest.raises(c.X509Error, match="does not allow digitalSignature"):
        c.verify_chain(parsed_leaf, [], [parsed_root], pki.AT, extended_key_usage=c.OID_EKU_CODE_SIGNING)
    # The rule is tied to the code-signing usage; without a requested usage the chain itself is sound.
    assert len(c.verify_chain(parsed_leaf, [], [parsed_root], pki.AT)) == 2
    # Without a keyUsage extension there is nothing to contradict.
    no_usage = c.parse_certificate(
        pki.certificate("leaf", pki.p256(), root, eku=[ExtendedKeyUsageOID.CODE_SIGNING]).der
    )
    assert len(c.verify_chain(no_usage, [], [parsed_root], pki.AT, extended_key_usage=c.OID_EKU_CODE_SIGNING)) == 2


def test_verify_chain_rejects_unsupported_critical_extensions() -> None:
    root = pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE)
    mid = pki.certificate(
        "mid",
        pki.p256(),
        root,
        ca=True,
        key_usage=pki.CA_USAGE,
        extra=[(x509.NameConstraints([x509.DNSName("a")], None), True)],
    )
    leaf = pki.certificate("leaf", pki.p256(), mid)
    with pytest.raises(c.X509Error, match=r"unsupported critical extension 2\.5\.29\.30"):
        c.verify_chain(
            c.parse_certificate(leaf.der), [c.parse_certificate(mid.der)], [c.parse_certificate(root.der)], pki.AT
        )


def test_verify_chain_tries_every_candidate_issuer() -> None:
    # Two intermediates with the same subject; only one signed the leaf.
    root = pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE)
    mid_a = pki.certificate("mid", pki.p256(), root, ca=True, key_usage=pki.CA_USAGE, serial=10)
    mid_b = pki.certificate("mid", pki.p256(), root, ca=True, key_usage=pki.CA_USAGE, serial=11)
    leaf = pki.certificate("leaf", pki.p256(), mid_b)
    path = c.verify_chain(
        c.parse_certificate(leaf.der),
        [c.parse_certificate(mid_a.der), c.parse_certificate(mid_b.der)],
        [c.parse_certificate(root.der)],
        pki.AT,
    )
    assert path[1].serial_number == 11


# --- revocation lists --------------------------------------------------------


@pytest.mark.parametrize("kind", ["p256", "p384", "rsa", "ed25519"])
def test_crl_round_trip(kind: str) -> None:
    root, _, _ = pki.chain(kind, pss=kind == "rsa")
    der_bytes = pki.crl(root, revoked=[42, 7], pss=kind == "rsa")
    parsed = crl_module.parse_revocation_list(der_bytes)
    assert parsed.revoked_serials == frozenset({7, 42})
    assert parsed.this_update == pki.NOT_BEFORE
    assert parsed.next_update == pki.NOT_AFTER
    verified = crl_module.verify_revocation_list(parsed, c.parse_certificate(root.der), pki.AT)
    assert crl_module.is_revoked(verified, 42)
    assert not crl_module.is_revoked(verified, 43)


def test_verified_revocation_list_is_built_only_by_verification() -> None:
    # The type is what ``is_revoked`` accepts, so a list that skipped the issuer and window checks must not be
    # constructible by hand.
    root, _, _ = pki.chain()
    parsed = crl_module.parse_revocation_list(pki.crl(root, revoked=[42]))
    issuer = c.parse_certificate(root.der)
    with pytest.raises(TypeError, match="_proof"):
        crl_module.VerifiedRevocationList(crl=parsed, issuer=issuer, verified_at=pki.AT)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="built only by verify_revocation_list"):
        crl_module.VerifiedRevocationList(
            crl=parsed,
            issuer=issuer,
            verified_at=pki.AT,
            _proof=object(),  # type: ignore[arg-type]
        )
    verified = crl_module.verify_revocation_list(parsed, issuer, pki.AT)
    assert (verified.crl, verified.issuer, verified.verified_at) == (parsed, issuer, pki.AT)
    assert "_proof" not in repr(verified)


def test_crl_library_claims() -> None:
    """cryptography loads what the pre-checks reject: no nextUpdate, critical CRL extensions, trailing bytes aside."""
    root, _, _ = pki.chain()
    base = pki.crl(root, revoked=[1])
    without_next = pki.crl(root, revoked=[1], next_update=None)
    assert x509.load_der_x509_crl(without_next).next_update_utc is None
    assert len(der_tree.children(der_tree.children(der_tree.parse(without_next)[0])[0])) == 5  # no nextUpdate field
    with pytest.raises(crl_module.CRLError, match="nextUpdate is required"):
        crl_module.parse_revocation_list(without_next)
    delta = pki.crl(root, extensions=[(x509.DeltaCRLIndicator(5), True)])
    assert x509.load_der_x509_crl(delta).extensions.get_extension_for_class(x509.DeltaCRLIndicator).critical
    with pytest.raises(crl_module.CRLError, match=r"unsupported CRL extension 2\.5\.29\.27"):
        crl_module.parse_revocation_list(delta)
    with pytest.raises(ValueError, match="asn1"):
        x509.load_der_x509_crl(base + b"\x00")


def test_crl_parse_rejections() -> None:
    root, _, _ = pki.chain()
    base = pki.crl(root, revoked=[1])
    with pytest.raises(crl_module.CRLError, match="trailing bytes"):
        crl_module.parse_revocation_list(base + b"\x00")

    # A v1 CRL (no version field) carrying extensions, which only v2 may: the CRL number is otherwise accepted.
    numbered = pki.crl(root, revoked=[1], extensions=[(x509.CRLNumber(1), False)])
    assert crl_module.parse_revocation_list(numbered).revoked_serials == frozenset({1})

    def drop_version(tree: Node) -> None:
        tbs_list = der_tree.children(der_tree.children(tree)[0])
        assert tbs_list[-1][0] == 0xA0  # the extensions stay
        tbs_list.pop(0)

    v1_with_extensions = der_tree.mutate(numbered, drop_version)
    assert x509.load_der_x509_crl(v1_with_extensions).extensions.get_extension_for_class(x509.CRLNumber)
    with pytest.raises(crl_module.CRLError, match="version is required"):
        crl_module.parse_revocation_list(v1_with_extensions)
    # Scope-changing extensions reject even when not marked critical.
    idp = pki.crl(
        root, extensions=[(x509.IssuingDistributionPoint(None, None, True, False, None, False, False), False)]
    )
    with pytest.raises(crl_module.CRLError, match=r"2\.5\.29\.28"):
        crl_module.parse_revocation_list(idp)
    issuer_entry = pki.crl(root, revoked=[1], entry_extensions=[(x509.CertificateIssuer([x509.DNSName("a")]), True)])
    with pytest.raises(crl_module.CRLError, match=r"CRL entry extension 2\.5\.29\.29"):
        crl_module.parse_revocation_list(issuer_entry)
    # A reason code is a non-critical entry extension that does not change the scope: accepted.
    reason = pki.crl(root, revoked=[1], entry_extensions=[(x509.CRLReason(x509.ReasonFlags.key_compromise), False)])
    assert crl_module.parse_revocation_list(reason).revoked_serials == frozenset({1})

    def swap_updates(tree: Node) -> None:
        tbs_list = der_tree.children(der_tree.children(tree)[0])
        tbs_list[3], tbs_list[4] = tbs_list[4], tbs_list[3]

    with pytest.raises(crl_module.CRLError, match="thisUpdate is after nextUpdate"):
        crl_module.parse_revocation_list(der_tree.mutate(base, swap_updates))


def test_crl_with_a_huge_object_identifier_rejects_quickly() -> None:
    """A 1 MiB CRL whose only content is one OBJECT IDENTIFIER is rejected at the identifier's length check,
    not after its sub-identifiers are accumulated."""
    content = b"\xff" * ((1 << 20) - 1) + b"\x7f"
    identifier = b"\x06" + der.encode_length(len(content)) + content
    huge = b"\x30" + der.encode_length(len(identifier)) + identifier
    started = time.perf_counter()
    with pytest.raises(crl_module.CRLError, match="OBJECT IDENTIFIER longer than"):
        crl_module.parse_revocation_list(huge)
    assert time.perf_counter() - started < 1.0


def test_crl_verification_rejections() -> None:
    root, intermediate, _leaf = pki.chain()
    parsed = crl_module.parse_revocation_list(pki.crl(root))
    issuer = c.parse_certificate(root.der)
    with pytest.raises(crl_module.CRLError, match="does not match the issuing certificate"):
        crl_module.verify_revocation_list(parsed, c.parse_certificate(intermediate.der), pki.AT)
    same_name = c.parse_certificate(pki.certificate("root", pki.p256(), ca=True, key_usage=pki.CA_USAGE).der)
    with pytest.raises(crl_module.CRLError, match="signature does not verify"):
        crl_module.verify_revocation_list(parsed, same_name, pki.AT)
    no_crl_sign = pki.certificate("root", pki.p256(), ca=True, key_usage=pki.SIGNING_USAGE)
    with pytest.raises(crl_module.CRLError, match="may not sign revocation lists"):
        crl_module.verify_revocation_list(
            crl_module.parse_revocation_list(pki.crl(no_crl_sign)), c.parse_certificate(no_crl_sign.der), pki.AT
        )
    with pytest.raises(crl_module.CRLError, match="not current"):
        crl_module.verify_revocation_list(parsed, issuer, pki.NOT_AFTER + timedelta(seconds=1))
    with pytest.raises(crl_module.CRLError, match="not current"):
        crl_module.verify_revocation_list(parsed, issuer, pki.NOT_BEFORE - timedelta(seconds=1))
    # The window is inclusive at both ends.
    crl_module.verify_revocation_list(parsed, issuer, pki.NOT_BEFORE)
    crl_module.verify_revocation_list(parsed, issuer, pki.NOT_AFTER)
    tampered = bytearray(pki.crl(root))
    tampered[-1] ^= 0x01
    with pytest.raises(crl_module.CRLError, match="signature does not verify"):
        crl_module.verify_revocation_list(crl_module.parse_revocation_list(bytes(tampered)), issuer, pki.AT)
    with pytest.raises(crl_module.CRLError, match="timezone-aware"):
        crl_module.verify_revocation_list(parsed, issuer, datetime(2025, 6, 1))
