import base64
import secrets

import pytest

from tinfoil._v3.verifier._canonical import EncodingError, decode_base64, decode_lower_hex, is_lower_hex


@pytest.mark.parametrize(
    ("value", "want_len", "want"),
    [
        ("00ff10ab", 4, bytes([0x00, 0xFF, 0x10, 0xAB])),
        ("a5" * 32, 32, bytes([0xA5]) * 32),
        ("", 0, b""),
    ],
)
def test_decode_lower_hex(value: str, want_len: int, want: bytes) -> None:
    assert decode_lower_hex("field", value, want_len) == want


@pytest.mark.parametrize(
    ("value", "want_len", "message"),
    [
        ("", 32, "field must be 32 bytes, got 0"),
        ("aabb", 3, "field must be 3 bytes, got 2"),
        ("aabbccdd", 3, "field must be 3 bytes, got 4"),
        ("AABB", 2, "field is not lowercase hex"),
        ("aAbb", 2, "field is not lowercase hex"),
        ("aagg", 2, "field is not lowercase hex"),
        ("0xaabb", 3, "field is not lowercase hex"),
        (" aabb", 2, "field is not lowercase hex"),
        ("aabb\n", 2, "field is not lowercase hex"),
        ("aa\nbb", 2, "field is not lowercase hex"),
        ("００", 1, "field is not lowercase hex"),  # fullwidth digits
        # Odd length passes the character class but is not decodable.
        ("abc", 1, "field is not hex"),
        ("a", 0, "field is not hex"),
    ],
)
def test_decode_lower_hex_rejects(value: str, want_len: int, message: str) -> None:
    with pytest.raises(EncodingError, match=message):
        decode_lower_hex("field", value, want_len)


def test_decode_lower_hex_round_trip() -> None:
    for n in range(65):
        value = secrets.token_bytes(n)
        assert decode_lower_hex("field", value.hex(), n) == value


def test_is_lower_hex_ignores_parity() -> None:
    assert is_lower_hex("abc")
    assert is_lower_hex("")
    assert not is_lower_hex("ABC")


@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("", b""),
        ("YWJj", b"abc"),
        ("YWI=", b"ab"),
        ("YQ==", b"a"),
        ("+/+/", bytes([0xFB, 0xFF, 0xBF])),
    ],
)
def test_decode_base64(value: str, want: bytes) -> None:
    assert decode_base64("field", value) == want


@pytest.mark.parametrize(
    "value",
    [
        "YQ",  # missing padding
        "YQ===",  # extra padding
        "YQ==YWJj",  # padding in the middle
        "YR==",  # non-zero padding bits: would decode like "YQ=="
        "-_-_",  # url-safe alphabet
        "YW Jj",
        "YW*j",
        "YW\nJj",
        "YW\rJj",
        "YWJj\n",
        "\r\nYWJj",
        "\n\n",
    ],
)
def test_decode_base64_rejects(value: str) -> None:
    with pytest.raises(EncodingError, match=r"decoding field|field is not canonical base64"):
        decode_base64("field", value)


def test_decode_base64_round_trip() -> None:
    for n in range(65):
        value = secrets.token_bytes(n)
        assert decode_base64("field", base64.b64encode(value).decode()) == value
