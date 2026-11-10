"""The strict DER tokenizer: one accepted encoding per value.

The probe set covers the encodings that lenient decoders accept: non-minimal
lengths and integers, indefinite lengths, BOOLEAN values other than 00/FF,
times without ``Z``, fractions where none are allowed, and implicit tags.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil._v3.verifier._x509 import der


def element(identifier: int, content: bytes) -> bytes:
    return bytes([identifier]) + der.encode_length(len(content)) + content


# --- decode and the tree -----------------------------------------------------


def test_decode_short_form_exposes_raw_and_content() -> None:
    e = der.decode(b"\x02\x01\x07")
    assert (e.tag_class, e.constructed, e.tag, e.content, e.raw) == (0, False, 2, b"\x07", b"\x02\x01\x07")


def test_decode_minimal_long_form_length() -> None:
    content = bytes(200)
    e = der.decode(b"\x04\x81\xc8" + content)
    assert e.content == content


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "empty input"),
        (b"\x02", "truncated element header"),
        (b"\x02\x01\x07\x00", "trailing bytes"),
        (b"\x02\x02\x07", "extends past the end"),
        (b"\x30\x80\x00\x00", "indefinite length"),
        (b"\x04\x81\x05" + bytes(5), "minimal form"),  # fits the short form
        (b"\x04\x82\x00\xc8" + bytes(200), "minimal form"),  # leading zero length octet
        (b"\x04\x85\x00\x00\x00\x00\x01\x00", "exceed the supported range"),
        (b"\x04\x82\x01", "truncated length"),
        (b"\x1f\x01\x00", "long-form tag"),
        (b"\x24\x00", "constructed encoding of a primitive"),  # constructed OCTET STRING
        (b"\x10\x00", "must be constructed"),  # primitive SEQUENCE
    ],
)
def test_decode_rejects_non_der_framing(data: bytes, message: str) -> None:
    with pytest.raises(der.DerError, match=message):
        der.decode(data)


def test_children_consume_the_content_exactly() -> None:
    seq = der.decode(element(0x30, b"\x02\x01\x01\x02\x01\x02"))
    assert [der.integer(c) for c in der.children(seq)] == [1, 2]
    with pytest.raises(der.DerError, match="extends past"):
        der.children(der.decode(element(0x30, b"\x02\x02\x01")))
    with pytest.raises(der.DerError, match="no children"):
        der.children(der.decode(b"\x02\x01\x01"))


def test_children_walk_a_long_sibling_list_without_copying_the_tail() -> None:
    """Each sibling copies only its own bytes, so 20,000 of them take milliseconds, not a quadratic copy."""
    count = 20_000
    seq = der.decode(element(0x30, b"\x05\x00" * count))
    started = time.perf_counter()
    siblings = der.children(seq)
    elapsed = time.perf_counter() - started
    assert len(siblings) == count
    assert all(s.raw == b"\x05\x00" for s in siblings)
    assert elapsed < 1.0
    # decode_at reports the end of the element, never copying what follows.
    e, end = der.decode_at(b"\x02\x01\x07\x04\x01\xff", 0)
    assert (e.raw, end) == (b"\x02\x01\x07", 3)
    e, end = der.decode_at(b"\x02\x01\x07\x04\x01\xff", 3)
    assert (e.raw, end) == (b"\x04\x01\xff", 6)
    with pytest.raises(der.DerError, match="truncated element header"):
        der.decode_at(b"\x02\x01\x07\x04", 3)


def test_implicitly_tagged_primitives_are_left_to_their_schema() -> None:
    # [0] IMPLICIT with content that would be an invalid BOOLEAN: the schema decides, not the tokenizer.
    e = der.decode(b"\x80\x01\x01")
    assert der.is_context(e, 0)
    assert not e.constructed
    der.validate_tree(e)


def test_validate_tree_walks_every_level() -> None:
    # A non-minimal INTEGER nested two levels down.
    bad = element(0x30, element(0x30, b"\x02\x02\x00\x07"))
    with pytest.raises(der.DerError, match="not minimally encoded"):
        der.validate_tree(der.decode(bad))
    # A BOOLEAN of 0x01 nested in a SET.
    with pytest.raises(der.DerError, match="BOOLEAN"):
        der.validate_tree(der.decode(element(0x31, b"\x01\x01\x01")))
    # A NULL with content.
    with pytest.raises(der.DerError, match="NULL must be empty"):
        der.validate_tree(der.decode(element(0x30, b"\x05\x01\x00")))
    # A UTCTime without Z.
    with pytest.raises(der.DerError, match="UTCTime"):
        der.validate_tree(der.decode(element(0x30, element(0x17, b"240101000000"))))
    # A DER fraction on a GeneralizedTime passes the walk; time() decides whether the schema admits it.
    der.validate_tree(der.decode(element(0x30, element(0x18, b"20240101000000.5Z"))))


def test_validate_tree_bounds_nesting() -> None:
    data = b"\x05\x00"
    for _ in range(der.MAX_DEPTH + 1):
        data = element(0x30, data)
    with pytest.raises(der.DerError, match="nesting deeper"):
        der.validate_tree(der.decode(data))


# --- typed accessors ---------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "value"),
    [(b"\x00", 0), (b"\x7f", 127), (b"\x00\x80", 128), (b"\xff", -1), (b"\x80", -128), (b"\xff\x7f", -129)],
)
def test_integer_accepts_minimal_encodings(content: bytes, value: int) -> None:
    assert der.integer(der.decode(element(0x02, content))) == value


@pytest.mark.parametrize("content", [b"", b"\x00\x7f", b"\x00\x00", b"\xff\x80", b"\xff\xff"])
def test_integer_rejects_empty_and_non_minimal(content: bytes) -> None:
    with pytest.raises(der.DerError):
        der.integer(der.decode(element(0x02, content)))


def test_integer_requires_the_integer_tag() -> None:
    with pytest.raises(der.DerError, match="expected INTEGER"):
        der.integer(der.decode(b"\x04\x01\x01"))


def test_boolean_accepts_only_00_and_ff() -> None:
    assert der.boolean(der.decode(b"\x01\x01\x00")) is False
    assert der.boolean(der.decode(b"\x01\x01\xff")) is True
    for content in (b"\x01", b"\x7f", b"", b"\x00\x00"):
        with pytest.raises(der.DerError, match="BOOLEAN"):
            der.boolean(der.decode(element(0x01, content)))


def test_bit_string_requires_zero_unused_bits() -> None:
    assert der.bit_string(der.decode(b"\x03\x02\x00\xab")) == b"\xab"
    assert der.bit_string(der.decode(b"\x03\x01\x00")) == b""
    with pytest.raises(der.DerError, match="no unused bits here"):
        der.bit_string(der.decode(b"\x03\x02\x01\xaa"))
    with pytest.raises(der.DerError, match="must be zero"):
        der.bit_string(der.decode(b"\x03\x02\x01\xab"))
    with pytest.raises(der.DerError, match="exceeds 7"):
        der.bit_string(der.decode(b"\x03\x02\x08\x00"))
    with pytest.raises(der.DerError, match="no unused-bits octet"):
        der.bit_string(der.decode(b"\x03\x00"))
    with pytest.raises(der.DerError, match="empty BIT STRING with unused bits"):
        der.bit_string(der.decode(b"\x03\x01\x03"))


def test_named_bits_reads_a_key_usage_list() -> None:
    # digitalSignature (0) and keyCertSign (5): 1000 0100 with one unused bit.
    assert der.named_bits(der.decode(b"\x03\x02\x01\x84")) == (True, False, False, False, False, True, False)
    # The AMD CA encoding: keyCertSign with the trailing zero bits that DER would trim is accepted.
    assert der.named_bits(der.decode(b"\x03\x02\x01\x04")) == (False, False, False, False, False, True, False)
    assert der.named_bits(der.decode(b"\x03\x01\x00")) == ()
    with pytest.raises(der.DerError, match="must be zero"):
        der.named_bits(der.decode(b"\x03\x02\x01\x87"))


def test_octet_string_and_null() -> None:
    assert der.octet_string(der.decode(b"\x04\x02\xaa\xbb")) == b"\xaa\xbb"
    with pytest.raises(der.DerError, match="expected OCTET STRING"):
        der.octet_string(der.decode(b"\x02\x01\x01"))


@pytest.mark.parametrize(
    ("content", "dotted"),
    [
        (b"\x55\x1d\x11", "2.5.29.17"),
        (b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", "1.2.840.113549.1.1.11"),
        (b"\x81\x34\x03", "2.100.3"),
        (b"\x2b\x06\x01\x04\x01\x83\xbf\x30\x01\x08", "1.3.6.1.4.1.57264.1.8"),
    ],
)
def test_object_identifier_decodes_dotted_form(content: bytes, dotted: str) -> None:
    assert der.object_identifier(der.decode(element(0x06, content))) == dotted


@pytest.mark.parametrize("content", [b"", b"\x55\x9d", b"\x80\x01", b"\x55\x80\x1d"])
def test_object_identifier_rejects_malformed(content: bytes) -> None:
    with pytest.raises(der.DerError):
        der.object_identifier(der.decode(element(0x06, content)))


def test_strings() -> None:
    assert der.ia5_string(der.decode(b"\x16\x03abc")) == "abc"
    with pytest.raises(der.DerError, match="above 0x7F"):
        der.ia5_string(der.decode(b"\x16\x02a\xff"))
    assert der.utf8_string(der.decode(b"\x0c\x02\xc3\xa9")) == "é"
    with pytest.raises(der.DerError, match="not valid UTF-8"):
        der.utf8_string(der.decode(b"\x0c\x01\xff"))
    with pytest.raises(der.DerError, match="expected UTF8String"):
        der.utf8_string(der.decode(b"\x16\x01a"))


@pytest.mark.parametrize(
    ("data", "want"),
    [
        (element(0x17, b"490101000000Z"), datetime(2049, 1, 1, tzinfo=UTC)),
        (element(0x17, b"500101000000Z"), datetime(1950, 1, 1, tzinfo=UTC)),
        (element(0x17, b"991231235959Z"), datetime(1999, 12, 31, 23, 59, 59, tzinfo=UTC)),
        (element(0x18, b"20500101000000Z"), datetime(2050, 1, 1, tzinfo=UTC)),
        (element(0x18, b"20240229120000Z"), datetime(2024, 2, 29, 12, tzinfo=UTC)),
    ],
)
def test_time_decodes_utc_and_generalized(data: bytes, want: datetime) -> None:
    assert der.time(der.decode(data)) == want


@pytest.mark.parametrize(
    "content",
    [
        b"240101000000",  # no Z
        b"240101000000+0000",  # offset
        b"2401010000Z",  # no seconds
        b"240101000000.5Z",  # UTCTime never carries a fraction
        b"240230000000Z",  # impossible date
        b"240101240000Z",  # hour 24
        b"2401010000 0Z",
    ],
)
def test_utc_time_rejects_non_der_forms(content: bytes) -> None:
    with pytest.raises(der.DerError):
        der.time(der.decode(element(0x17, content)))


@pytest.mark.parametrize("content", [b"20240101000000", b"20240101000000+0100", b"202401010000Z", b"20240101000000.Z"])
def test_generalized_time_rejects_non_der_forms(content: bytes) -> None:
    with pytest.raises(der.DerError):
        der.time(der.decode(element(0x18, content)), fractional_seconds=True)


def test_generalized_time_fractions_only_where_admitted() -> None:
    fraction = der.decode(element(0x18, b"20240101000000.5Z"))
    with pytest.raises(der.DerError, match="whole seconds"):
        der.time(fraction)
    assert der.time(fraction, fractional_seconds=True) == datetime(2024, 1, 1, 0, 0, 0, 500000, tzinfo=UTC)
    with pytest.raises(der.DerError, match="trailing zeros"):
        der.time(der.decode(element(0x18, b"20240101000000.50Z")), fractional_seconds=True)
    # Nine digits are accepted and truncated to the microsecond.
    nine = der.decode(element(0x18, b"20240101000000.123456789Z"))
    assert der.time(nine, fractional_seconds=True).microsecond == 123456
    with pytest.raises(der.DerError):
        der.time(der.decode(element(0x18, b"20240101000000.1234567891Z")), fractional_seconds=True)


def test_time_rejects_other_tags() -> None:
    with pytest.raises(der.DerError, match="expected UTCTime or GeneralizedTime"):
        der.time(der.decode(b"\x04\x01\x00"))


# --- PEM ---------------------------------------------------------------------

_PEM = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"


def test_pem_blocks_decodes_each_block_in_order() -> None:
    two = _PEM + "\n" + _PEM.replace("AQID", "BAUG")
    assert der.pem_blocks(two, "CERTIFICATE") == (b"\x01\x02\x03", b"\x04\x05\x06")
    assert der.pem_blocks(two.replace("\n", "\r\n"), "CERTIFICATE") == (b"\x01\x02\x03", b"\x04\x05\x06")
    assert der.pem_blocks("", "CERTIFICATE") == ()


@pytest.mark.parametrize(
    ("pem", "message"),
    [
        (_PEM.replace("CERTIFICATE", "PUBLIC KEY"), "not a CERTIFICATE"),
        ("garbage\n" + _PEM, "text outside"),
        (_PEM + "\x00", "text outside"),
        (_PEM.replace("AQID\n", ""), "empty"),
        (_PEM.replace("AQID", "AQI"), "not valid base64"),
        (_PEM.replace("AQID", "YR=="), "not canonical"),
        (_PEM.replace("AQID", "AQ ID"), "not valid base64"),
        (_PEM.replace("-----END CERTIFICATE-----\n", ""), "unterminated"),
        (_PEM.replace("-----END CERTIFICATE-----", "-----END OTHER-----"), "unexpected boundary"),
    ],
)
def test_pem_blocks_rejects_malformed(pem: str, message: str) -> None:
    with pytest.raises(der.DerError, match=message):
        der.pem_blocks(pem, "CERTIFICATE")


# --- ECDSA signature encodings ------------------------------------------------


def test_ecdsa_signature_round_trips_a_real_signature() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    signature = key.sign(b"data", ec.ECDSA(hashes.SHA256()))
    raw = der.ecdsa_signature_to_raw(signature, 32)
    assert len(raw) == 64
    assert der.raw_signature_to_der(raw, 32) == signature


def test_ecdsa_signature_to_raw_right_aligns_and_strips_sign_bytes() -> None:
    sig = element(0x30, element(0x02, b"\x01") + element(0x02, b"\x00\x80"))
    assert der.ecdsa_signature_to_raw(sig, 2) == b"\x00\x01\x00\x80"
    assert der.raw_signature_to_der(b"\x00\x01\x00\x80", 2) == sig


@pytest.mark.parametrize(
    "sig",
    [
        element(0x30, element(0x02, b"\x00\x01") + element(0x02, b"\x01")),  # non-minimal r
        element(0x30, element(0x02, b"\x80") + element(0x02, b"\x01")),  # negative r
        element(0x30, element(0x02, b"\x00") + element(0x02, b"\x01")),  # zero r
        element(0x30, element(0x02, b"\x01\x02\x03") + element(0x02, b"\x01")),  # too wide
        element(0x30, element(0x02, b"\x01")),  # one component
        element(0x30, element(0x02, b"\x01") * 3),
        b"\x02\x01\x01",
    ],
)
def test_ecdsa_signature_to_raw_rejects_malformed(sig: bytes) -> None:
    with pytest.raises(der.DerError):
        der.ecdsa_signature_to_raw(sig, 2)


def test_raw_signature_to_der_requires_the_width() -> None:
    with pytest.raises(der.DerError, match="must be 4 bytes"):
        der.raw_signature_to_der(b"\x01\x02\x03", 2)


def test_encode_length() -> None:
    assert der.encode_length(0x7F) == b"\x7f"
    assert der.encode_length(0x80) == b"\x81\x80"
    assert der.encode_length(0x1234) == b"\x82\x12\x34"
    for length in (0, 1, 127, 128, 255, 256, 65535, 65536):
        assert der.decode(bytes([0x04]) + der.encode_length(length) + bytes(length)).content == bytes(length)
