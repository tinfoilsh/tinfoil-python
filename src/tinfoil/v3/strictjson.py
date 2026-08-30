"""Strict JSON decoding shared by every verifier-consumed document, a 1:1 port
of Go verifier/internal/strictjson (via the tinfoil-js worked port): unknown
members rejected case-sensitively, duplicate member names rejected everywhere
(including inside opaque raw subtrees), valid UTF-8 required, no trailing data.

Where Go decodes into tagged structs, this module decodes against an explicit
Schema. Scalar semantics mirror encoding/json (v1):
  - JSON null is accepted for any schema and yields the zero value,
  - integer members require an integer literal (no fraction or exponent — Go
    parses the raw literal with strconv) within the type's range; values are
    exact Python ints (no 2^53 pitfall),
  - a missing struct member yields the zero value ("" / False / 0 for
    non-pointer scalars, None for pointer scalars, arrays and raw, an empty
    dict for maps, a zero struct for nested structs).

Raw members (Go json.RawMessage) are retained as the exact JSON source bytes.
All errors are ValueError; the calling module assigns the rejection layer.
Python's json module cannot enforce any of this (duplicates last-win,
NaN/Infinity accepted, ints via float), hence the hand parser.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

# --- Schema -----------------------------------------------------------------


@dataclass(frozen=True)
class Schema:
    kind: str  # string | bool | int | raw | array | map | struct | optstruct
    min: int = 0
    max: int = 0
    pointer: bool = False
    elem: Optional["Schema"] = None  # array
    value: Optional["Schema"] = None  # map
    fields: Optional[dict[str, "Field"]] = None  # struct/optstruct
    cls: Optional[Callable[..., Any]] = None  # struct constructor (kwargs)


@dataclass(frozen=True)
class Field:
    prop: str  # keyword-argument / dict-key name of the decoded member
    schema: Schema


STR = Schema("string")
BOOL = Schema("bool")
RAW = Schema("raw")


def uint_schema(bits: int, pointer: bool = False) -> Schema:
    return Schema("int", min=0, max=(1 << bits) - 1, pointer=pointer)


def int_schema(pointer: bool = False) -> Schema:
    return Schema("int", min=-(1 << 63), max=(1 << 63) - 1, pointer=pointer)


def array_of(elem: Schema) -> Schema:
    return Schema("array", elem=elem)


def map_of(value: Schema) -> Schema:
    return Schema("map", value=value)


def struct_of(fields: dict[str, Field], cls: Callable[..., Any] | None = None) -> Schema:
    return Schema("struct", fields=fields, cls=cls)


def opt_struct_of(fields: dict[str, Field], cls: Callable[..., Any] | None = None) -> Schema:
    return Schema("optstruct", fields=fields, cls=cls)


def field(prop: str, schema: Schema) -> Field:
    return Field(prop, schema)


def unmarshal(data: bytes | str, schema: Schema) -> Any:
    """Strictly decode JSON text (or UTF-8 bytes) against a schema."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("input is not valid UTF-8") from None
    else:
        text = data
    p = _Parser(text)
    v = p.parse_value(schema)
    p.skip_ws()
    if p.pos != len(text):
        raise ValueError("trailing data")
    return v


def zero_value(schema: Schema) -> Any:
    """The decoded value of an absent struct member."""
    kind = schema.kind
    if kind == "string":
        return ""
    if kind == "bool":
        return False
    if kind == "int":
        return None if schema.pointer else 0
    if kind in ("raw", "array", "optstruct"):
        return None  # nil slice / nil RawMessage / nil pointer
    if kind == "map":
        return {}
    # struct
    props = {f.prop: zero_value(f.schema) for f in schema.fields.values()}
    return schema.cls(**props) if schema.cls is not None else props


_WS = " \t\r\n"
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_INT_LITERAL_RE = re.compile(r"-?(?:0|[1-9][0-9]*)$")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _replace_lone_surrogates(s: str) -> str:
    """Mirror Go's UTF-8 coercion: any unpaired surrogate becomes U+FFFD.
    Python's json never combines surrogate escapes into pairs it leaves
    unpaired, so every surrogate code point remaining after decode is lone."""
    if _SURROGATE_RE.search(s) is None:
        return s
    return _SURROGATE_RE.sub("�", s)


class _Parser:
    __slots__ = ("s", "pos")

    def __init__(self, s: str):
        self.s = s
        self.pos = 0

    def skip_ws(self) -> None:
        s, n = self.s, len(self.s)
        while self.pos < n and s[self.pos] in _WS:
            self.pos += 1

    def peek(self) -> str:
        self.skip_ws()
        if self.pos >= len(self.s):
            raise ValueError("unexpected end of JSON input")
        return self.s[self.pos]

    def expect(self, c: str) -> None:
        if self.peek() != c:
            raise ValueError(f"invalid character {self.s[self.pos]!r}, expected {c!r}")
        self.pos += 1

    def parse_value(self, schema: Schema) -> Any:
        c = self.peek()
        if schema.kind == "raw":
            start = self.pos
            self.walk_raw()
            return self.s[start : self.pos].encode("utf-8")
        if c == "n":
            self.parse_keyword("null")
            # null yields the zero value for any schema (Go v1 semantics).
            return zero_value(schema)
        if c == "{":
            if schema.kind in ("struct", "optstruct"):
                return self.parse_struct(schema)
            if schema.kind == "map":
                return self.parse_map(schema.value)
            raise ValueError(f"cannot unmarshal object into {schema.kind}")
        if c == "[":
            if schema.kind != "array":
                raise ValueError(f"cannot unmarshal array into {schema.kind}")
            return self.parse_array(schema.elem)
        if c == '"':
            if schema.kind != "string":
                raise ValueError(f"cannot unmarshal string into {schema.kind}")
            return self.parse_string()
        if c in ("t", "f"):
            self.parse_keyword("true" if c == "t" else "false")
            if schema.kind != "bool":
                raise ValueError(f"cannot unmarshal bool into {schema.kind}")
            return c == "t"
        lit = self.parse_number_literal()
        if schema.kind != "int":
            raise ValueError(f"cannot unmarshal number into {schema.kind}")
        # Go parses the raw literal with strconv.Parse{Int,Uint}: a fraction,
        # exponent, or out-of-range value is a decode error ("-0" rejects for
        # unsigned types, parses as 0 for signed — strconv semantics).
        if _INT_LITERAL_RE.fullmatch(lit) is None or (
            schema.min == 0 and lit.startswith("-")
        ):
            raise ValueError(f"cannot unmarshal number {lit} into integer")
        n = int(lit)
        if n < schema.min or n > schema.max:
            raise ValueError(f"number {lit} out of range")
        return n

    def parse_struct(self, schema: Schema) -> Any:
        fields = schema.fields
        out: dict[str, Any] = {}
        seen: set[str] = set()
        self.expect("{")
        if self.peek() == "}":
            self.pos += 1
        else:
            while True:
                key = self.parse_string()
                if key in seen:
                    raise ValueError(f"duplicate object member {key!r}")
                seen.add(key)
                f = fields.get(key)
                if f is None:
                    raise ValueError(f"unknown object member {key!r}")
                self.expect(":")
                out[f.prop] = self.parse_value(f.schema)
                c = self.peek()
                self.pos += 1
                if c == "}":
                    break
                if c != ",":
                    raise ValueError(f"invalid character {c!r} after object member")
        for name, f in fields.items():
            if name not in seen:
                out[f.prop] = zero_value(f.schema)
        return schema.cls(**out) if schema.cls is not None else out

    def parse_map(self, value: Schema) -> dict[str, Any]:
        out: dict[str, Any] = {}
        self.expect("{")
        if self.peek() == "}":
            self.pos += 1
            return out
        while True:
            key = self.parse_string()
            if key in out:
                raise ValueError(f"duplicate object member {key!r}")
            self.expect(":")
            out[key] = self.parse_value(value)
            c = self.peek()
            self.pos += 1
            if c == "}":
                return out
            if c != ",":
                raise ValueError(f"invalid character {c!r} after object member")

    def parse_array(self, elem: Schema) -> list[Any]:
        out: list[Any] = []
        self.expect("[")
        if self.peek() == "]":
            self.pos += 1
            return out
        while True:
            out.append(self.parse_value(elem))
            c = self.peek()
            self.pos += 1
            if c == "]":
                return out
            if c != ",":
                raise ValueError(f"invalid character {c!r} in array")

    def walk_raw(self) -> None:
        """Validate a raw (schema-less) subtree, still rejecting duplicate
        member names in every object (Go: walkStrictObject, nil schema)."""
        c = self.peek()
        if c == "{":
            self.pos += 1
            seen: set[str] = set()
            if self.peek() == "}":
                self.pos += 1
                return
            while True:
                key = self.parse_string()
                if key in seen:
                    raise ValueError(f"duplicate object member {key!r}")
                seen.add(key)
                self.expect(":")
                self.walk_raw()
                d = self.peek()
                self.pos += 1
                if d == "}":
                    return
                if d != ",":
                    raise ValueError(f"invalid character {d!r} after object member")
        elif c == "[":
            self.pos += 1
            if self.peek() == "]":
                self.pos += 1
                return
            while True:
                self.walk_raw()
                d = self.peek()
                self.pos += 1
                if d == "]":
                    return
                if d != ",":
                    raise ValueError(f"invalid character {d!r} in array")
        elif c == '"':
            self.parse_string()
        elif c == "t":
            self.parse_keyword("true")
        elif c == "f":
            self.parse_keyword("false")
        elif c == "n":
            self.parse_keyword("null")
        else:
            self.parse_number_literal()

    def parse_string(self) -> str:
        if self.peek() != '"':
            raise ValueError("object member name is not a string")
        start = self.pos
        self.pos += 1  # opening quote
        s, n = self.s, len(self.s)
        while self.pos < n:
            c = s[self.pos]
            if c == "\\":
                self.pos += 2
                continue
            if c == '"':
                self.pos += 1
                token = s[start : self.pos]
                # json.loads validates escapes and control characters; Go
                # additionally replaces unpaired surrogates with U+FFFD, which
                # collapses distinct lone-surrogate member names into
                # duplicates — mirror that.
                try:
                    decoded = json.loads(token)
                except json.JSONDecodeError as e:
                    raise ValueError(f"invalid string literal: {e.msg}") from None
                return _replace_lone_surrogates(decoded)
            self.pos += 1
        raise ValueError("unexpected end of string literal")

    def parse_keyword(self, kw: str) -> None:
        self.skip_ws()
        if self.s.startswith(kw, self.pos):
            self.pos += len(kw)
            return
        got = self.s[self.pos] if self.pos < len(self.s) else "<eof>"
        raise ValueError(f"invalid character {got!r} in literal")

    def parse_number_literal(self) -> str:
        self.skip_ws()
        m = _NUMBER_RE.match(self.s, self.pos)
        if m is None:
            got = self.s[self.pos] if self.pos < len(self.s) else "<eof>"
            raise ValueError(f"invalid character {got!r} looking for value")
        self.pos = m.end()
        return m.group(0)
