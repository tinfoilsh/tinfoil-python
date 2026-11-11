"""Strict JSON parsing, canonical and compact serialization, and the typed member helpers."""

from __future__ import annotations

import pytest

from tinfoil.verifier import _json
from tinfoil.verifier._json import (
    JsonError,
    JsonNumber,
    JsonObject,
    JsonValue,
    canonicalize,
    serialize,
    strict_parse,
)


def parse(text: str) -> JsonValue:
    return strict_parse(text.encode("utf-8"))


def parse_object(text: str) -> JsonObject:
    value = parse(text)
    assert isinstance(value, JsonObject)
    return value


def canon(text: str) -> str:
    return canonicalize(parse(text)).decode("utf-8")


# --- grammar -----------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "{}",
        " {} \t\r\n",
        "1",
        "-0",
        "1E+2",
        "1.5e-7",
        "true ",
        '"\\/"',
        '"\u007f"',
        '"\u00e9"',
        '{"a":1,"A":2}',
        '[{"a":1},{"a":2}]',
        "[]",
        '[1,[2,{"x":[null,true,false]}]]',
    ],
)
def test_grammar_accepts(text: str) -> None:
    parse(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "{} x",
        "{}{}",
        "01",
        "-01",
        "[01]",
        "1.",
        ".1",
        "1e",
        "1e+",
        "-",
        "+1",
        "NaN",
        "Infinity",
        "-Infinity",
        "[NaN]",
        "nul",
        "True",
        "[1,]",
        '{"a":1,}',
        "{a:1}",
        "{'a':1}",
        '{"a" 1}',
        "[1 2]",
        "\f{}",
        "\x00",
        '"\x01"',
        '"a\nb"',
        '"a\tb"',
        '"\\x"',
        '"\\U0041"',
        '"\\u00"',
        '"\\u00g0"',
        '"abc',
        "[1",
        '{"a":1',
    ],
)
def test_grammar_rejects(text: str) -> None:
    with pytest.raises(JsonError):
        parse(text)


def test_rejects_a_leading_byte_order_mark() -> None:
    with pytest.raises(JsonError):
        strict_parse(b"\xef\xbb\xbf{}")


def test_nesting_depth_is_bounded_and_reported_as_a_json_error() -> None:
    # Containers may nest MAX_DEPTH deep and no deeper. Interpreters whose own
    # recursion limit is lower reject earlier; either way the error is the
    # parser's, never a RecursionError.
    parse("[" * 100 + "]" * 100)
    parse('{"a":' * 100 + "1" + "}" * 100)
    for text in ("[" * (_json.MAX_DEPTH + 1) + "]" * (_json.MAX_DEPTH + 1), "[" * 100_000 + "]" * 100_000):
        with pytest.raises(JsonError, match="depth"):
            parse(text)
    # Exactly MAX_DEPTH parses on an interpreter whose recursion limit allows it and raises the
    # parser's depth error on one that does not, so the exception is optional and pytest.raises
    # cannot express the case.
    try:
        parse("[" * _json.MAX_DEPTH + "]" * _json.MAX_DEPTH)
    except JsonError as err:
        assert "depth" in str(err), "an interpreter below the limit still reports a depth error"  # noqa: PT017


def test_serialization_rejects_values_deeper_than_the_limit() -> None:
    value: JsonValue = ()
    for _ in range(_json.MAX_DEPTH):
        value = (value,)
    with pytest.raises(JsonError, match="depth"):
        canonicalize(value)


def test_converts_arrays_nested_anywhere_to_tuples() -> None:
    value = parse_object('{"a":[[1,[2]],{"b":[[]]}],"c":[]}')
    a = value["a"]
    assert isinstance(a, tuple)
    assert isinstance(a[0], tuple)
    inner = a[0]
    assert isinstance(inner, tuple)
    assert inner[1] == (JsonNumber("2"),)
    b = a[1]
    assert isinstance(b, JsonObject)
    assert b["b"] == ((),)
    assert value["c"] == ()
    deep = parse("[" * 500 + "]" * 500)
    for _ in range(500):
        assert isinstance(deep, tuple)
        assert len(deep) <= 1
        deep = deep[0] if deep else ()


def test_builds_ordered_objects_tuples_and_raw_literal_numbers() -> None:
    value = parse_object('{"z":[1,"x",null,true],"a":{"n":-1.50e3},"__proto__":false}')
    assert list(value) == ["z", "a", "__proto__"]
    z = value["z"]
    assert isinstance(z, tuple)
    assert z[0] == JsonNumber("1")
    assert z[1:] == ("x", None, True)
    a = value["a"]
    assert isinstance(a, JsonObject)
    assert a["n"] == JsonNumber("-1.50e3")
    assert value["__proto__"] is False


def test_keeps_integers_above_2_to_the_53_exact() -> None:
    value = parse("18446744073709551615")
    assert isinstance(value, JsonNumber)
    assert value.raw == "18446744073709551615"
    assert value.to_int(bits=64, signed=False) == 18446744073709551615


def test_keeps_a_very_long_number_literal() -> None:
    digits = "1" * 500_000
    value = parse(digits)
    assert isinstance(value, JsonNumber)
    assert value.raw == digits


# --- duplicate names -----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"a":1,"a":2}',
        '{"a":1,"\\u0061":2}',
        '{"\\u00e9":1,"\u00e9":2}',
        '{"\\ud800\\udc00":1,"\U00010000":2}',
        '{"a":{"b":1,"b":2}}',
        '[{"x":[{"y":1,"y":1}]}]',
        '{"a":1,"b":2,"a":3}',
        '{"__proto__":1,"__proto__":2}',
        '{"a":"}{\\"","a":1}',
        '{"x":["a:",{"a":1,"a":2}]}',
        '{"a:":1,"b":"\\"a\\":","a:":2}',
    ],
)
def test_rejects_duplicate_names(text: str) -> None:
    with pytest.raises(JsonError, match="duplicate"):
        parse(text)


@pytest.mark.parametrize(
    "text",
    [
        '{"a":1,"A":2}',
        '{"a":{"a":1},"b":{"a":2}}',
        '{"a":"a","b":{"a":1}}',
        '["a","a",{"k":"k"}]',
    ],
)
def test_duplicates_are_case_sensitive_and_per_object(text: str) -> None:
    parse(text)


def test_keeps_source_member_order_including_integer_like_names() -> None:
    assert list(parse_object('{"b":1,"10":2,"a":3,"2":4}')) == ["b", "10", "a", "2"]
    assert serialize(parse('{"z":{"9":1,"x":2},"1":[{"5":0,"0":1}]}')) == b'{"z":{"9":1,"x":2},"1":[{"5":0,"0":1}]}'


# --- strings and UTF-8 -------------------------------------------------------


def test_decodes_escapes() -> None:
    assert parse('"\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\u00E9\\uD83D\\uDE00"') == '"\\/\b\f\n\r\tA\u00e9\U0001f600'


def test_decodes_multi_byte_utf8() -> None:
    assert parse('"\u00e9\u20ac\U0001f600"') == "\u00e9\u20ac\U0001f600"


@pytest.mark.parametrize(
    "text",
    [
        '"\\ud800"',
        '"\\udc00"',
        '"\\ud800\\u0041"',
        '"\\ud800x"',
        '"\\udc00\\ud800"',
        '"\\ud800\\ud800"',
        '{"\\ud800":1}',
        '["\\udfff"]',
    ],
)
def test_rejects_unpaired_surrogate_escapes(text: str) -> None:
    with pytest.raises(JsonError):
        parse(text)


@pytest.mark.parametrize(
    "bad",
    [
        b"\xff",  # lone continuation byte
        b"\xc0\xaf",  # overlong '/'
        b"\xe0\x80\x80",  # overlong 3-byte
        b"\xed\xa0\x80",  # UTF-8-encoded surrogate
        b"\xf4\x90\x80\x80",  # above U+10FFFF
        b"\xe2\x82",  # truncated sequence
        b"\x80",  # bare continuation
        b"\xf5\x80\x80\x80",  # 0xF5 lead byte
    ],
)
def test_rejects_invalid_utf8_inside_a_string(bad: bytes) -> None:
    with pytest.raises(JsonError):
        strict_parse(b'"' + bad + b'"')


def test_rejects_invalid_utf8_outside_strings() -> None:
    with pytest.raises(JsonError):
        strict_parse(b"[1,\xff]")
    with pytest.raises(JsonError):
        strict_parse(b"{}\xc3")


def test_accepts_the_edges_of_the_valid_utf8_ranges() -> None:
    assert strict_parse(b'"\xed\x9f\xbf"') == "\ud7ff"
    assert strict_parse(b'"\xf4\x8f\xbf\xbf"') == "\U0010ffff"
    assert strict_parse(b'"\xef\xbb\xbf"') == "\ufeff"


# --- JsonNumber ---------------------------------------------------------------


def test_to_int_signed() -> None:
    assert JsonNumber("0").to_int(bits=64, signed=True) == 0
    assert JsonNumber("-0").to_int(bits=64, signed=True) == 0
    assert JsonNumber("-42").to_int(bits=64, signed=True) == -42
    assert JsonNumber("9223372036854775807").to_int(bits=64, signed=True) == 9223372036854775807
    assert JsonNumber("-9223372036854775808").to_int(bits=64, signed=True) == -9223372036854775808
    for raw in ("9223372036854775808", "-9223372036854775809"):
        with pytest.raises(JsonError, match="overflows int64"):
            JsonNumber(raw).to_int(bits=64, signed=True)


def test_to_int_reports_a_literal_beyond_the_conversion_cap_as_overflow() -> None:
    huge = parse_object('{"n":' + "9" * 5000 + "}")
    with pytest.raises(JsonError, match='overflows uint64 within "/n"'):
        _json.uint(huge, "n", 64)
    with pytest.raises(JsonError, match="overflows int64"):
        _json.int64(huge, "n")


def test_to_int_unsigned_rejects_any_sign() -> None:
    assert JsonNumber("255").to_int(bits=8, signed=False) == 255
    assert JsonNumber("18446744073709551615").to_int(bits=64, signed=False) == 18446744073709551615
    for raw in ("-0", "-1"):
        with pytest.raises(JsonError, match="negative"):
            JsonNumber(raw).to_int(bits=8, signed=False)
    for raw, bits in (("256", 8), ("4294967296", 32), ("18446744073709551616", 64)):
        with pytest.raises(JsonError, match="overflows uint"):
            JsonNumber(raw).to_int(bits=bits, signed=False)


@pytest.mark.parametrize("raw", ["1.0", "1e2", "1E2", "1.5", "0e0", "-1E+0", "01", "+1", "0x10", " 1", "abc", ""])
def test_to_int_rejects_non_integer_literals(raw: str) -> None:
    with pytest.raises(JsonError):
        JsonNumber(raw).to_int(bits=64, signed=True)


def test_to_float_rounds_correctly() -> None:
    assert JsonNumber("0.1").to_float() == 0.1
    assert str(JsonNumber("-0").to_float()) == "-0.0"
    assert JsonNumber("1e-400").to_float() == 0
    assert JsonNumber("4.9e-324").to_float() == 5e-324
    assert JsonNumber("2.4703282292062327e-324").to_float() == 0
    assert JsonNumber("2.4703282292062328e-324").to_float() == 5e-324
    assert JsonNumber("1.7976931348623158e308").to_float() == 1.7976931348623157e308
    assert JsonNumber("9007199254740993").to_float() == 9007199254740992
    assert JsonNumber("1E+2").to_float() == 100


@pytest.mark.parametrize("raw", ["1e400", "-1e400", "1.7976931348623159e308", "NaN", "Infinity", "0x10", ""])
def test_to_float_rejects(raw: str) -> None:
    with pytest.raises(JsonError):
        JsonNumber(raw).to_float()


# --- canonicalize -------------------------------------------------------------


def test_rfc_8785_section_3_2_4_example() -> None:
    text = (
        '{\n  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],\n'
        '  "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",\n'
        '  "literals": [null, true, false]\n}'
    )
    assert canon(text) == (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )


def test_rfc_8785_section_3_2_3_sorting_example() -> None:
    text = (
        '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",'
        '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}'
    )
    reparsed = strict_parse(canonicalize(parse(text)))
    assert isinstance(reparsed, JsonObject)
    assert list(reparsed) == ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"]
    assert canon(text) == (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis",'
        '"\u20ac":"Euro Sign","\U0001f600":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}'
    )


# RFC 8785 Appendix B number vectors; inputs are the IEEE values printed with
# 17 fractional digits, outputs are the canonical forms.
@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("0.00000000000000000e+00", "0"),
        ("-0.00000000000000000e+00", "0"),
        ("4.94065645841246544e-324", "5e-324"),
        ("-4.94065645841246544e-324", "-5e-324"),
        ("1.79769313486231571e+308", "1.7976931348623157e+308"),
        ("-1.79769313486231571e+308", "-1.7976931348623157e+308"),
        ("9.00719925474099200e+15", "9007199254740992"),
        ("-9.00719925474099200e+15", "-9007199254740992"),
        ("2.95147905179352826e+20", "295147905179352830000"),
        ("9.99999999999999748e+22", "9.999999999999997e+22"),
        ("9.99999999999999916e+22", "1e+23"),
        ("1.00000000000000008e+23", "1.0000000000000001e+23"),
        ("9.99999999999999738e+20", "999999999999999700000"),
        ("9.99999999999999869e+20", "999999999999999900000"),
        ("1.00000000000000000e+21", "1e+21"),
        ("9.99999999999999743e-07", "9.999999999999997e-7"),
        ("9.99999999999999955e-07", "0.000001"),
        ("3.33333333333333194e+08", "333333333.3333332"),
        ("3.33333333333333254e+08", "333333333.33333325"),
        ("3.33333333333333313e+08", "333333333.3333333"),
        ("3.33333333333333373e+08", "333333333.3333334"),
        ("3.33333333333333433e+08", "333333333.33333343"),
        ("-3.33333333333333332e-06", "-0.0000033333333333333333"),
        ("1.42495392378120625e+15", "1424953923781206.2"),
        ("-0", "0"),
        ("-0.0", "0"),
        ("1.0", "1"),
        ("1e20", "100000000000000000000"),
        ("1E+30", "1e+30"),
        ("1e-7", "1e-7"),
        ("0.000001", "0.000001"),
        ("123456789012345678901234567890", "1.2345678901234568e+29"),
        ("9007199254740993", "9007199254740992"),
        ("12345678901234567890", "12345678901234567000"),
        ("0.1e1", "1"),
        ("1e400", "1.7976931348623157e+308"),
        ("-1e400", "-1.7976931348623157e+308"),
        ("1e-400", "0"),
        ("-1e-400", "0"),
    ],
)
def test_canonical_numbers(text: str, want: str) -> None:
    assert canon(text) == want


def test_canonical_uses_minimal_string_escaping() -> None:
    assert canon('"\\u0000\\u001e\\u001F\\u007f\\u0080\\u2028\\u2029<>&\\ud83d\\ude00\\/\\ufeff"') == (
        '"\\u0000\\u001e\\u001f\u007f\u0080\u2028\u2029<>&\U0001f600/\ufeff"'
    )
    assert canon('"\\b\\f\\n\\r\\t\\"\\\\"') == '"\\b\\f\\n\\r\\t\\"\\\\"'


def test_canonical_sorts_members_at_every_depth_and_removes_whitespace() -> None:
    assert canon('{"b":[],"a":{},"":null,"A":0}') == '{"":null,"A":0,"a":{},"b":[]}'
    assert canon('[\n 1 , {"y":1, "x":{"d":1,"c":2}} ]') == '[1,{"x":{"c":2,"d":1},"y":1}]'


def test_canonical_is_idempotent() -> None:
    once = canonicalize(parse('{"b":1.50,"a":"\\u00e9","c":[1E2]}'))
    assert canonicalize(strict_parse(once)) == once


def test_canonical_rejects_values_it_cannot_encode() -> None:
    with pytest.raises(JsonError):
        canonicalize("\ud800")
    with pytest.raises(JsonError):
        canonicalize(JsonObject({"\udc00": None, "a": None}))
    with pytest.raises(JsonError):
        canonicalize(JsonNumber("01"))
    with pytest.raises(JsonError):
        canonicalize(JsonNumber("NaN"))


def test_serialization_handles_deep_values_without_recursion() -> None:
    value: JsonValue = ()
    for _ in range(1, 10_000):
        value = (value,)
    assert canonicalize(value) == b"[" * 10_000 + b"]" * 10_000


# --- serialize ----------------------------------------------------------------


def test_serialize_is_compact_and_preserves_order_and_literals() -> None:
    assert (
        serialize(parse('{ "b" : 1.50 , "a" : [ 1E2 , -0 , 18446744073709551616 ] , "c":{} }'))
        == b'{"b":1.50,"a":[1E2,-0,18446744073709551616],"c":{}}'
    )


def test_serialize_re_escapes_minimally_and_round_trips() -> None:
    text = '{"k\\u00e9\\/":"\\u0001\\n\\"\\\\\\ud83d\\ude00 "}'
    out = serialize(parse(text))
    assert out == '{"k\u00e9/":"\\u0001\\n\\"\\\\\U0001f600 "}'.encode()
    assert strict_parse(out) == parse(text)


def test_serialize_scalars() -> None:
    assert serialize(None) == b"null"
    assert serialize(True) == b"true"
    assert serialize("x") == b'"x"'
    assert serialize(JsonNumber("-1.5e-3")) == b"-1.5e-3"


def test_serialize_rejects_lone_surrogates_and_invalid_literals() -> None:
    with pytest.raises(JsonError):
        serialize(("\udc00",))
    with pytest.raises(JsonError):
        serialize(JsonNumber("1."))


# --- typed member helpers -------------------------------------------------------


def test_object_accepts_objects_and_treats_null_as_empty() -> None:
    assert isinstance(_json.object_(parse('{"a":1}'), "S")["a"], JsonNumber)
    assert len(_json.object_(None, "S")) == 0
    assert len(_json.object_(None, "S", ("a",))) == 0


@pytest.mark.parametrize("text", ["[]", '"x"', "1", "true"])
def test_object_rejects_other_kinds(text: str) -> None:
    with pytest.raises(JsonError):
        _json.object_(parse(text), "S")


def test_object_rejects_unknown_members_only_when_known_is_given() -> None:
    value = parse('{"a":1,"zz":2}')
    with pytest.raises(JsonError, match='unknown object member name "zz"'):
        _json.object_(value, "S", ("a",))
    _json.object_(value, "S", ("a", "zz"))
    _json.object_(value, "S")


def test_member_names_match_case_sensitively() -> None:
    with pytest.raises(JsonError):
        _json.object_(parse('{"X":"1"}'), "T", ("x",))
    obj = _json.object_(parse('{"X":"1"}'), "T")
    assert _json.string(obj, "x") == ""
    assert _json.string(obj, "X") == "1"


def test_string_helper() -> None:
    obj = parse_object('{"s":"v","n":null,"num":1,"b":true,"a":[],"o":{}}')
    assert _json.string(obj, "s") == "v"
    assert _json.string(obj, "n") == ""
    assert _json.string(obj, "absent") == ""
    for key in ("num", "b", "a", "o"):
        with pytest.raises(JsonError):
            _json.string(obj, key)


def test_boolean_helper() -> None:
    obj = parse_object('{"t":true,"f":false,"n":null,"s":"true","num":1}')
    assert _json.boolean(obj, "t") is True
    assert _json.boolean(obj, "f") is False
    assert _json.boolean(obj, "n") is False
    assert _json.boolean(obj, "absent") is False
    for key in ("s", "num"):
        with pytest.raises(JsonError):
            _json.boolean(obj, key)


def test_number_helper() -> None:
    obj = parse_object('{"p":1,"n":null,"s":"1","b":false}')
    p = _json.number(obj, "p")
    assert p is not None
    assert p.raw == "1"
    assert _json.number(obj, "n") is None
    assert _json.number(obj, "absent") is None
    for key in ("s", "b"):
        with pytest.raises(JsonError):
            _json.number(obj, key)


def test_array_helper() -> None:
    obj = parse_object('{"a":[1],"e":[],"n":null,"o":{},"s":"x"}')
    a = _json.array(obj, "a")
    assert a is not None
    assert len(a) == 1
    assert _json.array(obj, "e") == ()
    assert _json.array(obj, "n") is None
    assert _json.array(obj, "absent") is None
    for key in ("o", "s"):
        with pytest.raises(JsonError):
            _json.array(obj, key)


def test_raw_helper() -> None:
    obj = parse_object('{"r":{"z":[1, 2]},"n":null}')
    assert serialize(_json.raw(obj, "r")) == b'{"z":[1,2]}'
    assert _json.raw(obj, "n") is None
    assert _json.raw(obj, "absent") is None
    assert "n" in obj
    assert "absent" not in obj


def test_struct_helpers() -> None:
    obj = parse_object('{"s":{"a":1},"n":null,"bad":{"zz":1},"arr":[]}')
    assert list(_json.struct(obj, "s", ("a",))) == ["a"]
    assert len(_json.struct(obj, "n", ("a",))) == 0
    assert len(_json.struct(obj, "absent", ("a",))) == 0
    assert _json.opt_struct(obj, "n", ("a",)) is None
    assert _json.opt_struct(obj, "absent", ("a",)) is None
    s = _json.opt_struct(obj, "s", ("a",))
    assert s is not None
    assert list(s) == ["a"]
    with pytest.raises(JsonError, match="unknown object member name"):
        _json.struct(obj, "bad", ("a",))
    with pytest.raises(JsonError):
        _json.struct(obj, "arr", ("a",))


def test_integer_helpers() -> None:
    obj = parse_object('{"u":255,"neg":-1,"big":18446744073709551615,"frac":1.0,"n":null,"s":"1"}')
    assert _json.uint(obj, "u", 8) == 255
    assert _json.uint(obj, "big", 64) == 18446744073709551615
    assert _json.uint(obj, "n", 8) is None
    assert _json.uint(obj, "absent", 8) is None
    assert _json.int64(obj, "neg") == -1
    with pytest.raises(JsonError, match='within "/u"'):
        _json.uint(obj, "u", 4)
    with pytest.raises(JsonError, match="negative"):
        _json.uint(obj, "neg", 8)
    with pytest.raises(JsonError, match="not an integer"):
        _json.int64(obj, "frac")
    with pytest.raises(JsonError, match="overflows int64"):
        _json.int64(obj, "big")
    with pytest.raises(JsonError):
        _json.uint(obj, "s", 8)


def test_mapping_and_string_array_helpers() -> None:
    obj = parse_object('{"m":{"a":"1","b":null},"n":null,"arr":["x",null],"bad":[1],"notarr":"x"}')
    assert _json.mapping(obj, "m", lambda v, _: v) == {"a": "1", "b": None}
    assert _json.mapping(obj, "n", lambda v, _: v) == {}
    assert _json.mapping(obj, "absent", lambda v, _: v) == {}
    with pytest.raises(JsonError):
        _json.mapping(obj, "arr", lambda v, _: v)
    assert _json.string_array(obj, "arr") == ("x", "")
    assert _json.string_array(obj, "n") is None
    with pytest.raises(JsonError):
        _json.string_array(obj, "bad")
    with pytest.raises(JsonError):
        _json.string_array(obj, "notarr")


def test_json_object_is_an_immutable_ordered_mapping() -> None:
    obj = parse_object('{"b":1,"a":2}')
    assert list(obj.keys()) == ["b", "a"]
    assert obj == JsonObject({"b": JsonNumber("1"), "a": JsonNumber("2")})
    assert obj == JsonObject({"a": JsonNumber("2"), "b": JsonNumber("1")}), "equality ignores order like a dict"
    assert dict(obj.items()) == {"b": JsonNumber("1"), "a": JsonNumber("2")}
    with pytest.raises(TypeError):
        obj["c"] = None  # type: ignore[index]
