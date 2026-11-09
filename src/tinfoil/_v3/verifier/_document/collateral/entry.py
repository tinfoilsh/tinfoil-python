"""One self-describing collateral record and the shape checks that every entry passes."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier import _json

# Collateral roles (RATS, RFC 9334).
ROLE_ENDORSEMENT = "endorsement"
"""Hardware-vendor material used to cryptographically verify evidence (AMD VCEK chains, Intel PCS)."""
ROLE_REFERENCE_VALUES = "reference-values"
"""Tinfoil-signed expectations used to appraise verified evidence."""

SUBJECT_CPU = "cpu"
"""The reserved collateral subject id for the CPU quote."""


class EntryError(ValueError):
    """A collateral entry list that violates its shape."""


@dataclass(frozen=True, slots=True)
class Entry:
    """One self-describing collateral record."""

    id: str
    role: str
    format: str
    subjects: tuple[str, ...]
    data: _json.JsonValue
    """The entry's payload, kept as parsed JSON. Validation requires an object."""


_ENTRY_MEMBERS = ("id", "role", "format", "subjects", "data")


def decode_entries(value: _json.JsonValue) -> tuple[Entry, ...]:
    """Decode the document's collateral array by member types alone; ``validate`` applies the shape rules."""
    if value is None:
        return ()
    if not isinstance(value, tuple):
        raise _json.JsonError(
            f"cannot unmarshal JSON {'object' if isinstance(value, _json.JsonObject) else 'value'} into collateral"
        )
    entries = []
    for item in value:
        obj = _json.object_(item, "collateral entry", _ENTRY_MEMBERS)
        entries.append(
            Entry(
                id=_json.string(obj, "id"),
                role=_json.string(obj, "role"),
                format=_json.string(obj, "format"),
                subjects=_json.string_array(obj, "subjects") or (),
                data=_json.raw(obj, "data"),
            )
        )
    return tuple(entries)


def validate(entries: tuple[Entry, ...]) -> None:
    """Every entry has an id and a format, ids are unique, roles are known, and data is a JSON object."""
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if entry.id == "" or entry.format == "":
            raise EntryError(f"collateral entry {index} is incomplete")
        if entry.id in seen:
            raise EntryError(f"duplicate collateral entry id {entry.id!r}")
        seen.add(entry.id)
        if entry.role not in (ROLE_ENDORSEMENT, ROLE_REFERENCE_VALUES):
            raise EntryError(f"collateral entry {entry.id!r} has unknown role {entry.role!r}")
        # Only known formats are decoded, so every entry's data is checked
        # here: exactly one JSON object, parsed with the document's strictness.
        if not isinstance(entry.data, _json.JsonObject):
            raise EntryError(f"collateral entry {entry.id!r} data is not a valid JSON object")


def unmarshal_data(entry: Entry, label: str, members: tuple[str, ...]) -> _json.JsonObject:
    """The entry's data as an object with exactly the given members."""
    try:
        return _json.object_(entry.data, label, members)
    except _json.JsonError as err:
        raise _json.JsonError(f"parsing {label} collateral entry {entry.id!r}: {err}") from err
