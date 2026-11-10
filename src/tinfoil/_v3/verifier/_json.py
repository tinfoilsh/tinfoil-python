"""Strict JSON: parsing that rejects what lenient parsers accept, serialization in canonical and compact forms, and
typed member access for hand-written record decoders.

Parsing rules:

- invalid UTF-8 rejects, as does a leading byte-order mark;
- escaped surrogates must form a valid pair (``"\\ud800"`` rejects);
- duplicate member names reject at any depth, compared on decoded names,
  case-sensitively;
- trailing data after the top-level value rejects, as do ``NaN`` and
  ``Infinity``;
- numbers keep their source literal, so 64-bit fields survive intact and
  ``1`` stays distinguishable from ``1.0``;
- objects keep their member order and are immutable mappings; arrays are
  tuples.

Nesting is bounded by the interpreter's recursion limit (about a thousand
levels); a document that deep is rejected rather than accepted, which is the
safe direction.

Unknown-member rejection depends on the member set that each record decoder
expects, so it lives in the decode helpers at the end of this module.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Mapping
from decimal import Decimal
from typing import TypeAlias, TypeVar

T = TypeVar("T")

_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)")
_LONE_SURROGATE = re.compile(r"[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]")


class JsonError(ValueError):
    """A JSON syntax or strictness violation."""


class JsonNumber:
    """A JSON number, kept as its source literal."""

    __slots__ = ("raw",)

    def __init__(self, raw: str) -> None:
        self.raw = raw

    def __repr__(self) -> str:
        return f"JsonNumber({self.raw!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, JsonNumber) and other.raw == self.raw

    def __hash__(self) -> int:
        return hash(self.raw)

    def to_int(self, *, bits: int, signed: bool) -> int:
        """The literal as an integer of the given width.

        A fraction or exponent is not an integer, so ``1.0`` and ``1e2``
        reject. An unsigned field rejects any leading ``-``, so ``-0``
        rejects there; a signed one accepts it as 0.
        """
        if not _INTEGER.fullmatch(self.raw):
            raise JsonError(f"JSON number {self.raw} is not an integer")
        if not signed and self.raw.startswith("-"):
            raise JsonError(f"JSON number {self.raw} is negative")
        try:
            value = int(self.raw)
        except ValueError as err:
            # The interpreter caps the digits that it will convert; a literal
            # beyond that cap is out of range for any width.
            raise JsonError(
                f"JSON number of {len(self.raw)} digits overflows {'int' if signed else 'uint'}{bits}"
            ) from err
        if signed:
            low, high = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        else:
            low, high = 0, (1 << bits) - 1
        if value < low or value > high:
            raise JsonError(f"JSON number {self.raw} overflows {'int' if signed else 'uint'}{bits}")
        return value

    def to_float(self) -> float:
        """The literal's double value, correctly rounded; overflow to infinity is an error."""
        if not _NUMBER.fullmatch(self.raw):
            raise JsonError(f"invalid JSON number {self.raw!r}")
        value = float(self.raw)
        if value in (float("inf"), float("-inf")):
            raise JsonError(f"JSON number {self.raw} is out of range")
        return value


class JsonObject(Mapping[str, "JsonValue"]):
    """An immutable JSON object that keeps its member order."""

    __slots__ = ("_members",)

    def __init__(self, members: Mapping[str, JsonValue] | None = None) -> None:
        self._members: dict[str, JsonValue] = dict(members) if members else {}

    def __getitem__(self, key: str) -> JsonValue:
        return self._members[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._members)

    def __len__(self) -> int:
        return len(self._members)

    def __repr__(self) -> str:
        return f"JsonObject({self._members!r})"


JsonValue: TypeAlias = bool | JsonNumber | str | tuple["JsonValue", ...] | JsonObject | None


def strict_parse(data: bytes) -> JsonValue:
    """Parse exactly one JSON value from UTF-8 bytes. Raises JsonError."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise JsonError("invalid UTF-8") from err
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=JsonNumber,
            parse_float=JsonNumber,
            parse_constant=_reject_constant,
        )
        checked = _checked(parsed)
    except RecursionError as err:
        raise JsonError("exceeded max depth") from err
    except json.JSONDecodeError as err:
        raise JsonError(f"invalid JSON: {err.msg} at offset {err.pos}") from err
    return checked


def _object(pairs: list[tuple[str, object]]) -> JsonObject:
    # The parser calls this for each object as soon as it closes, innermost
    # first, so converting member values here finishes the whole subtree.
    members: dict[str, JsonValue] = {}
    for name, value in pairs:
        if name in members:
            raise JsonError(f"duplicate object member name {json.dumps(name)}")
        members[name] = _convert(value)
    return JsonObject(members)


def _reject_constant(name: str) -> JsonValue:
    raise JsonError(f"invalid JSON: {name} is not a number")


def _checked(root: object) -> JsonValue:
    """Convert the parser's output to JsonValue, rejecting lone surrogates in strings and member names."""
    out = _convert(root)
    stack: list[JsonValue] = [out]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            _check_string(value)
        elif isinstance(value, tuple):
            stack.extend(value)
        elif isinstance(value, JsonObject):
            for name, member in value.items():
                _check_string(name)
                stack.append(member)
    return out


def _convert(value: object) -> JsonValue:
    """Arrays come back from the parser as lists and become tuples; everything else is already in its final form.

    Nested lists are converted with an explicit stack, so a value as deep as
    the parser accepts cannot exhaust the interpreter's own stack here.
    """
    if not isinstance(value, list):
        return _scalar(value)
    # Each frame is a source list, the index of the next item to convert, and
    # the converted items so far.
    stack: list[tuple[list[object], int, list[JsonValue]]] = [(value, 0, [])]
    while True:
        source, index, out = stack[-1]
        if index == len(source):
            stack.pop()
            done: JsonValue = tuple(out)
            if not stack:
                return done
            parent_source, parent_index, parent_out = stack[-1]
            parent_out.append(done)
            stack[-1] = (parent_source, parent_index + 1, parent_out)
            continue
        item = source[index]
        if isinstance(item, list):
            stack.append((item, 0, []))
        else:
            out.append(_scalar(item))
            stack[-1] = (source, index + 1, out)


def _scalar(value: object) -> JsonValue:
    if value is None or isinstance(value, bool | str | JsonNumber | JsonObject):
        return value
    raise JsonError(f"unexpected parser output {type(value).__name__}")


def _check_string(value: str) -> None:
    # Valid UTF-8 cannot encode a surrogate, so a lone one came from an escape
    # such as "\ud800", which is invalid.
    if _LONE_SURROGATE.search(value):
        raise JsonError("invalid escaped surrogate in string")


# --- serialization -----------------------------------------------------------


def canonicalize(value: JsonValue) -> bytes:
    """Serialize in RFC 8785 canonical form: members sorted by UTF-16 code units, minimal escaping, shortest number
    form."""
    out: list[str] = []
    _write(out, value, canonical=True)
    return _encode("".join(out))


def serialize(value: JsonValue) -> bytes:
    """Serialize compactly, preserving member order and number literals."""
    out: list[str] = []
    _write(out, value, canonical=False)
    return _encode("".join(out))


def _encode(text: str) -> bytes:
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as err:
        raise JsonError("invalid UTF-16 in string") from err


class _Token:
    """A piece of punctuation in the output stream."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


_COMMA = _Token(",")
_COLON = _Token(":")
_END_ARRAY = _Token("]")
_END_OBJECT = _Token("}")


def _write(out: list[str], root: JsonValue, *, canonical: bool) -> None:
    # Explicit stack: a value as deep as the parser accepts must still serialize.
    stack: list[Iterator[JsonValue | _Token]] = []
    pending: list[JsonValue | _Token] = [root]
    while pending or stack:
        if not pending:
            try:
                pending.append(next(stack[-1]))
            except StopIteration:
                stack.pop()
            continue
        value = pending.pop()
        if isinstance(value, _Token):
            out.append(value.text)
        elif value is None:
            out.append("null")
        elif value is True:
            out.append("true")
        elif value is False:
            out.append("false")
        elif isinstance(value, str):
            out.append(_quote(value))
        elif isinstance(value, JsonNumber):
            out.append(_canonical_number(value.raw) if canonical else _checked_raw(value.raw))
        elif isinstance(value, tuple):
            out.append("[")
            stack.append(_array_items(value))
        elif isinstance(value, JsonObject):
            out.append("{")
            items = list(value.items())
            if canonical:
                # Sorted by UTF-16 code units. A lone surrogate in a name still
                # sorts here and is rejected when the output is encoded.
                items.sort(key=lambda item: item[0].encode("utf-16-be", "surrogatepass"))
            stack.append(_object_items(items))
        else:
            raise JsonError(f"unsupported JSON value {type(value).__name__}")


def _array_items(items: tuple[JsonValue, ...]) -> Iterator[JsonValue | _Token]:
    for index, item in enumerate(items):
        if index:
            yield _COMMA
        yield item
    yield _END_ARRAY


def _object_items(items: list[tuple[str, JsonValue]]) -> Iterator[JsonValue | _Token]:
    for index, (name, item) in enumerate(items):
        if index:
            yield _COMMA
        yield _Token(_quote(name))
        yield _COLON
        yield item
    yield _END_OBJECT


def _quote(value: str) -> str:
    """Quote with minimal escaping (RFC 8785 section 3.2.2.2)."""
    out = ['"']
    for char in value:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif code >= 0x20:
            out.append(char)
        elif char == "\b":
            out.append("\\b")
        elif char == "\f":
            out.append("\\f")
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        else:
            out.append(f"\\u{code:04x}")
    out.append('"')
    return "".join(out)


def _checked_raw(raw: str) -> str:
    if not _NUMBER.fullmatch(raw):
        raise JsonError(f"invalid JSON number {raw!r}")
    return raw


def _canonical_number(raw: str) -> str:
    """RFC 8785 number form: the double's shortest round-trip digits in ECMAScript layout.

    ``-0`` becomes ``0``; a literal beyond the double range is written as the
    largest finite double of its sign, so any literal that parsing accepted
    can be canonicalized.
    """
    if not _NUMBER.fullmatch(raw):
        raise JsonError(f"invalid JSON number {raw!r}")
    value = float(raw)
    if value == 0:
        return "0"
    if value == float("inf"):
        value = 1.7976931348623157e308
    elif value == float("-inf"):
        value = -1.7976931348623157e308
    sign, digit_tuple, exponent = Decimal(repr(value)).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0") or "0"
    assert isinstance(exponent, int)
    # n is the position of the decimal point relative to the first digit.
    n = len(digit_tuple) + exponent
    k = len(digits)
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
        text = f"{mantissa}e{'+' if e > 0 else '-'}{abs(e)}"
    return ("-" if sign else "") + text


# --- typed member access -----------------------------------------------------
#
# Member names match case-sensitively. A missing member decodes to its type's
# empty value, or to None for the number, array and raw helpers; ``null``
# decodes the same way; a member of the wrong JSON type is an error.


def object_(value: JsonValue, what: str, known: tuple[str, ...] | None = None) -> JsonObject:
    """Require an object. With ``known`` set, members outside it reject. ``null`` is an empty object."""
    if value is None:
        return JsonObject()
    if not isinstance(value, JsonObject):
        raise JsonError(f"cannot unmarshal JSON {_kind(value)} into {what}")
    if known is not None:
        for name in value:
            if name not in known:
                raise JsonError(f"cannot unmarshal into {what}: unknown object member name {json.dumps(name)}")
    return value


def string(obj: JsonObject, key: str) -> str:
    """A string member; absent or null is ""."""
    value = obj.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise _type_error(value, "string", key)
    return value


def boolean(obj: JsonObject, key: str) -> bool:
    """A boolean member; absent or null is False."""
    value = obj.get(key)
    if value is None:
        return False
    if not isinstance(value, bool):
        raise _type_error(value, "bool", key)
    return value


def number(obj: JsonObject, key: str) -> JsonNumber | None:
    """A number member, or None when absent or null."""
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, JsonNumber):
        raise _type_error(value, "number", key)
    return value


def array(obj: JsonObject, key: str) -> tuple[JsonValue, ...] | None:
    """An array member, or None when absent or null."""
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, tuple):
        raise _type_error(value, "slice", key)
    return value


def struct(obj: JsonObject, key: str, known: tuple[str, ...]) -> JsonObject:
    """A nested record whose absence means every field empty: absent or null is an empty object."""
    value = obj.get(key)
    if value is None:
        return JsonObject()
    return object_(value, key, known)


def opt_struct(obj: JsonObject, key: str, known: tuple[str, ...]) -> JsonObject | None:
    """An optional nested record: absent or null is None."""
    value = obj.get(key)
    if value is None:
        return None
    return object_(value, key, known)


def raw(obj: JsonObject, key: str) -> JsonValue:
    """A member kept as parsed JSON; absent reads as null. Callers that must tell them apart test membership."""
    return obj.get(key)


def uint(obj: JsonObject, key: str, bits: int) -> int | None:
    """An unsigned integer member of ``bits`` width, or None when absent or null."""
    value = number(obj, key)
    if value is None:
        return None
    try:
        return value.to_int(bits=bits, signed=False)
    except JsonError as err:
        raise JsonError(f"{err} within {json.dumps('/' + key)}") from None


def int64(obj: JsonObject, key: str) -> int | None:
    """A signed 64-bit integer member, or None when absent or null."""
    value = number(obj, key)
    if value is None:
        return None
    try:
        return value.to_int(bits=64, signed=True)
    except JsonError as err:
        raise JsonError(f"{err} within {json.dumps('/' + key)}") from None


def mapping(obj: JsonObject, key: str, value_of: Callable[[JsonValue, str], T]) -> dict[str, T]:
    """A string-keyed map member: absent or null is empty; values decoded by ``value_of``."""
    value = obj.get(key)
    if value is None:
        return {}
    if not isinstance(value, JsonObject):
        raise _type_error(value, "map", key)
    return {name: value_of(item, name) for name, item in value.items()}


def string_array(obj: JsonObject, key: str) -> tuple[str, ...] | None:
    """A string-array member: absent or null is None; null elements are ""."""
    items = array(obj, key)
    if items is None:
        return None
    out: list[str] = []
    for item in items:
        if item is None:
            out.append("")
        elif isinstance(item, str):
            out.append(item)
        else:
            raise JsonError(f"cannot unmarshal JSON {_kind(item)} into string within {json.dumps('/' + key)}")
    return tuple(out)


def _kind(value: JsonValue) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, JsonNumber):
        return "number"
    if isinstance(value, tuple):
        return "array"
    return "object"


def _type_error(value: JsonValue, want: str, key: str) -> JsonError:
    return JsonError(f"cannot unmarshal JSON {_kind(value)} into {want} within {json.dumps('/' + key)}")
