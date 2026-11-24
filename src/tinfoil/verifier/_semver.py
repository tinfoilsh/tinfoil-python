"""Semantic versions with a leading "v": vMAJOR.MINOR.PATCH, optionally followed by "-prerelease" and "+build" metadata.

MINOR and PATCH may be omitted ("v1", "v1.2") and canonicalize to 0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_BAD_NUMBER = re.compile(r"0[0-9]+")


@dataclass(frozen=True, slots=True)
class _Parsed:
    short: str  # ".0.0" or ".0" when MINOR or PATCH was omitted.
    prerelease: str
    build: str


def is_valid(version: str) -> bool:
    return _parse(version) is not None


def canonical(version: str) -> str:
    """The canonical form vMAJOR.MINOR.PATCH[-pre], build metadata dropped; "" if invalid."""
    parsed = _parse(version)
    if parsed is None:
        return ""
    if parsed.build:
        return version[: len(version) - len(parsed.build)]
    return version + parsed.short


def is_full(version: str) -> bool:
    """Whether ``version`` is valid and written in full, vMAJOR.MINOR.PATCH with any prerelease and build metadata
    as given, so that it has exactly one spelling."""
    return is_valid(version) and canonical(version) + build(version) == version


def build(version: str) -> str:
    """The build-metadata suffix including "+", or ""."""
    parsed = _parse(version)
    return parsed.build if parsed else ""


def _parse(version: str) -> _Parsed | None:
    if not version.startswith("v"):
        return None
    rest = _number(version[1:])
    if rest is None:
        return None
    if rest == "":
        return _Parsed(".0.0", "", "")
    if not rest.startswith("."):
        return None
    rest = _number(rest[1:])
    if rest is None:
        return None
    if rest == "":
        return _Parsed(".0", "", "")
    if not rest.startswith("."):
        return None
    rest = _number(rest[1:])
    if rest is None:
        return None
    prerelease = ""
    build_ = ""
    if rest.startswith("-"):
        end = _prerelease_end(rest)
        if end is None:
            return None
        prerelease, rest = rest[:end], rest[end:]
    if rest.startswith("+"):
        end = _build_end(rest)
        if end is None:
            return None
        build_, rest = rest[:end], rest[end:]
    if rest:
        return None
    return _Parsed("", prerelease, build_)


def _number(text: str) -> str | None:
    """Consume a decimal number without leading zeros; return the rest."""
    if not text or not text[0].isdigit() or not text[0].isascii():
        return None
    i = 1
    while i < len(text) and text[i].isascii() and text[i].isdigit():
        i += 1
    if text[0] == "0" and i != 1:
        return None
    return text[i:]


def _prerelease_end(text: str) -> int | None:
    i = start = 1
    while i < len(text) and text[i] != "+":
        if not _is_ident_char(text[i]) and text[i] != ".":
            return None
        if text[i] == ".":
            if start == i or _BAD_NUMBER.fullmatch(text[start:i]):
                return None
            start = i + 1
        i += 1
    if start == i or _BAD_NUMBER.fullmatch(text[start:i]):
        return None
    return i


def _build_end(text: str) -> int | None:
    i = start = 1
    while i < len(text):
        if not _is_ident_char(text[i]) and text[i] != ".":
            return None
        if text[i] == ".":
            if start == i:
                return None
            start = i + 1
        i += 1
    if start == i:
        return None
    return i


def _is_ident_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char == "-")
