import pytest

from tinfoil.v3.bytesutil import (
    decode_base64,
    decode_canonical_base64,
    decode_hex,
    decode_lower_hex,
    is_lower_hex,
)


def test_decode_hex_go_semantics():
    assert decode_hex("aBcD") == b"\xab\xcd"
    assert decode_hex("") == b""
    for bad in ("abc", "zz", "aa bb", "0x00"):
        with pytest.raises(ValueError):
            decode_hex(bad)


def test_decode_lower_hex():
    assert decode_lower_hex("n", "00ff", 2) == b"\x00\xff"
    with pytest.raises(ValueError, match="not lowercase hex"):
        decode_lower_hex("n", "00FF", 2)
    with pytest.raises(ValueError, match="odd length"):
        decode_lower_hex("n", "0ff", 2)
    with pytest.raises(ValueError, match="must be 2 bytes"):
        decode_lower_hex("n", "00ff00", 2)
    assert is_lower_hex("") and is_lower_hex("0af") and not is_lower_hex("A")


def test_decode_base64_go_std_semantics():
    assert decode_base64("aGk=") == b"hi"
    assert decode_base64("aG\nk=\r") == b"hi"  # \r\n skipped
    assert decode_base64("AB==") == b"\x00"  # non-canonical bits tolerated
    for bad in ("aGk", "a Gk=", "aGk=x", "####"):
        with pytest.raises(ValueError):
            decode_base64(bad)


def test_decode_canonical_base64():
    assert decode_canonical_base64("f", "aGk=") == b"hi"
    assert decode_canonical_base64("f", "") == b""
    # Non-canonical padding bits, missing padding, whitespace all reject.
    for bad in ("AB==", "aGk", "aGk=\n", " aGk="):
        with pytest.raises(ValueError):
            decode_canonical_base64("f", bad)
