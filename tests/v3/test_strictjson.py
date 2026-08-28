"""Strict-JSON semantics tests: the Go strictjson contract that Python's
stdlib json cannot provide (duplicates, unknown members, raw literal ints,
trailing data, UTF-8, surrogate coercion)."""

import pytest

from tinfoil.v3 import strictjson as sj
from tinfoil.v3.strictjson import (
    BOOL,
    RAW,
    STR,
    array_of,
    field,
    int_schema,
    map_of,
    opt_struct_of,
    struct_of,
    uint_schema,
    unmarshal,
)

PAIR = struct_of({"a": field("a", STR), "b": field("b", uint_schema(64))})


def test_happy_struct():
    assert unmarshal(b'{"a":"x","b":7}', PAIR) == {"a": "x", "b": 7}


def test_missing_members_zero_values():
    assert unmarshal(b"{}", PAIR) == {"a": "", "b": 0}


def test_null_yields_zero_values():
    assert unmarshal(b'{"a":null,"b":null}', PAIR) == {"a": "", "b": 0}
    schema = struct_of(
        {
            "p": field("p", uint_schema(8, pointer=True)),
            "r": field("r", RAW),
            "l": field("l", array_of(STR)),
            "m": field("m", map_of(STR)),
        }
    )
    # An explicit null on a RawMessage member retains the literal source
    # (Go: RawMessage.UnmarshalJSON is called even for JSON null); only an
    # absent member yields nil.
    assert unmarshal(b'{"p":null,"r":null,"l":null,"m":null}', schema) == {
        "p": None,
        "r": b"null",
        "l": None,
        "m": {},
    }


def test_pointer_int_absent_vs_zero():
    schema = struct_of({"n": field("n", uint_schema(8, pointer=True))})
    assert unmarshal(b"{}", schema) == {"n": None}
    assert unmarshal(b'{"n":0}', schema) == {"n": 0}


def test_unknown_member_rejected_case_sensitively():
    with pytest.raises(ValueError, match="unknown object member"):
        unmarshal(b'{"A":"x"}', PAIR)
    with pytest.raises(ValueError, match="unknown object member"):
        unmarshal(b'{"c":1}', PAIR)


def test_duplicate_member_rejected():
    with pytest.raises(ValueError, match="duplicate object member"):
        unmarshal(b'{"a":"x","a":"y"}', PAIR)


def test_duplicate_member_rejected_inside_raw_subtree():
    schema = struct_of({"r": field("r", RAW)})
    with pytest.raises(ValueError, match="duplicate object member"):
        unmarshal(b'{"r":{"k":1,"k":2}}', schema)
    with pytest.raises(ValueError, match="duplicate object member"):
        unmarshal(b'{"r":[{"k":1,"k":2}]}', schema)


def test_duplicate_member_rejected_in_map():
    with pytest.raises(ValueError, match="duplicate object member"):
        unmarshal(b'{"k":"1","k":"2"}', map_of(STR))


def test_raw_retains_exact_source_bytes():
    schema = struct_of({"r": field("r", RAW)})
    src = b'{"r": {"z" :  [1, "s", null] } }'
    assert unmarshal(src, schema) == {"r": b'{"z" :  [1, "s", null] }'}


def test_trailing_data_rejected():
    with pytest.raises(ValueError, match="trailing data"):
        unmarshal(b'{"a":"x"} {}', PAIR)
    with pytest.raises(ValueError, match="trailing data"):
        unmarshal(b"1 2", uint_schema(8))


def test_invalid_utf8_rejected():
    with pytest.raises(ValueError, match="not valid UTF-8"):
        unmarshal(b'{"a":"\xff"}', PAIR)


def test_lone_surrogate_escapes_collapse_to_ufffd():
    # Two distinct lone-surrogate names both coerce to U+FFFD -> duplicate.
    with pytest.raises(ValueError, match="duplicate object member"):
        unmarshal(b'{"\\ud800":"1","\\udfff":"2"}', map_of(STR))
    # A lone surrogate also collides with a literal U+FFFD.
    with pytest.raises(ValueError, match="duplicate object member"):
        unmarshal('{"\\ud800":"1","\ufffd":"2"}'.encode("utf-8"), map_of(STR))
    # A valid escaped pair does not coerce.
    out = unmarshal(b'{"\\ud834\\udd1e":"1"}', map_of(STR))
    assert out == {"\U0001d11e": "1"}
    # Values coerce too (Go string conversion semantics).
    assert unmarshal(b'"\\udc00"', STR) == "\ufffd"


def test_integers_parsed_from_raw_literal():
    u64 = uint_schema(64)
    assert unmarshal(b"18446744073709551615", u64) == 2**64 - 1  # exact, > 2^53
    for bad in (b"1.0", b"1e2", b"0.5", b"18446744073709551616", b"-1", b"-0", b"01"):
        with pytest.raises(ValueError):
            unmarshal(bad, u64)
    i64 = int_schema()
    assert unmarshal(b"-0", i64) == 0  # strconv.ParseInt accepts -0
    assert unmarshal(b"-9223372036854775808", i64) == -(2**63)
    with pytest.raises(ValueError):
        unmarshal(b"9223372036854775808", i64)
    assert unmarshal(b"255", uint_schema(8)) == 255
    with pytest.raises(ValueError):
        unmarshal(b"256", uint_schema(8))


def test_nan_and_infinity_rejected():
    for bad in (b"NaN", b"Infinity", b"-Infinity"):
        with pytest.raises(ValueError):
            unmarshal(bad, int_schema())


def test_type_mismatches_rejected():
    with pytest.raises(ValueError, match="cannot unmarshal"):
        unmarshal(b'{"a":1}', PAIR)  # number into string
    with pytest.raises(ValueError, match="cannot unmarshal"):
        unmarshal(b'{"b":"1"}', PAIR)  # string into int
    with pytest.raises(ValueError, match="cannot unmarshal"):
        unmarshal(b'{"a":true}', PAIR)  # bool into string
    with pytest.raises(ValueError, match="cannot unmarshal"):
        unmarshal(b'{"a":{}}', PAIR)  # object into string
    with pytest.raises(ValueError, match="cannot unmarshal"):
        unmarshal(b'{"a":[]}', PAIR)  # array into string
    with pytest.raises(ValueError, match="cannot unmarshal"):
        unmarshal(b"[]", PAIR)  # array into struct


def test_syntax_errors_rejected():
    for bad in (b"", b"{", b'{"a":}', b'{"a":"x",}', b"{1:2}", b'{"a" "x"}', b"tru"):
        with pytest.raises(ValueError):
            unmarshal(bad, PAIR)
    with pytest.raises(ValueError):
        unmarshal(b'["x",]', array_of(STR))


def test_control_characters_in_strings_rejected():
    with pytest.raises(ValueError):
        unmarshal(b'{"a":"x\x01y"}', PAIR)


def test_bool_and_arrays_and_maps():
    schema = struct_of(
        {
            "f": field("f", BOOL),
            "l": field("l", array_of(uint_schema(8))),
            "m": field("m", map_of(array_of(STR))),
        }
    )
    out = unmarshal(b'{"f":true,"l":[1,2],"m":{"h":["a","b"]}}', schema)
    assert out == {"f": True, "l": [1, 2], "m": {"h": ["a", "b"]}}


def test_optstruct_absent_null_present():
    inner = opt_struct_of({"x": field("x", STR)})
    schema = struct_of({"o": field("o", inner)})
    assert unmarshal(b"{}", schema) == {"o": None}
    assert unmarshal(b'{"o":null}', schema) == {"o": None}
    assert unmarshal(b'{"o":{}}', schema) == {"o": {"x": ""}}


def test_struct_cls_construction():
    from dataclasses import dataclass

    @dataclass
    class P:
        a: str
        b: int

    schema = struct_of({"a": field("a", STR), "b": field("b", uint_schema(8))}, cls=P)
    assert unmarshal(b'{"b":3}', schema) == P(a="", b=3)
    assert sj.zero_value(schema) == P(a="", b=0)
