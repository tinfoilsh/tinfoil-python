"""Access to the conformance vectors for module-level tests.

The vectors are located as the adapter tests locate them; a test that
needs a group skips only when the checkout is absent. A group or a fixture
that the checkout should hold but does not is a failure, never a skip.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from tests.conformance.conftest import fixtures_root
from tinfoil.verifier import _json
from tinfoil.verifier._sigstore import bundle as bm


def vector_group(name: str) -> list[dict[str, Any]]:
    """Every fixture under ``vectors/v3/<name>``, sorted by file name; empty only when the checkout is absent."""
    root = fixtures_root()
    if root is None:
        return []
    group = root / name
    if not group.is_dir():
        raise pytest.UsageError(f"vector group {name!r} is missing under {root}")
    fixtures: list[dict[str, Any]] = []
    for path in sorted(group.glob("*.json")):
        with path.open("rb") as handle:
            data = json.load(handle)
        fixtures.append(data)
    if not fixtures:
        raise pytest.UsageError(f"vector group {name!r} under {root} holds no fixtures")
    return fixtures


def vector_params(name: str) -> list[Any]:
    """``pytest.param`` entries for a group, or one skipped entry when the vectors are absent."""
    fixtures = vector_group(name)
    if not fixtures:
        return [pytest.param(None, id="vectors-absent", marks=pytest.mark.skip(reason="conformance vectors not found"))]
    return [pytest.param(fixture, id=fixture["id"]) for fixture in fixtures]


def vector(name: str, fixture_id: str) -> dict[str, Any]:
    """One fixture by id; skips the calling test when the vectors are absent and fails when the id is unknown."""
    fixtures = vector_group(name)
    if not fixtures:
        pytest.skip("conformance vectors not found")
    return find_vector(fixtures, name, fixture_id)


def find_vector(fixtures: list[dict[str, Any]], name: str, fixture_id: str) -> dict[str, Any]:
    """The fixture of group ``name`` with ``fixture_id``; a group that lacks it is a failure, never an omission."""
    for fixture in fixtures:
        if fixture["id"] == fixture_id:
            return fixture
    pytest.fail(f"vector group {name!r} has no fixture {fixture_id!r}")


def b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def document_collateral(document_b64: str) -> tuple[_json.JsonObject, ...]:
    """The collateral entries of a fixture document, parsed by the strict parser from the input's base64 form."""
    document = _json.strict_parse(b64(document_b64))
    assert isinstance(document, _json.JsonObject)
    entries = document.get("collateral")
    assert isinstance(entries, tuple)
    out: list[_json.JsonObject] = []
    for entry in entries:
        assert isinstance(entry, _json.JsonObject)
        out.append(entry)
    return tuple(out)


def document_bundles(document_b64: str) -> dict[str, tuple[bm.Bundle, _json.JsonObject]]:
    """Every Sigstore bundle in a fixture document by collateral id, with the entry's data record."""
    out: dict[str, tuple[bm.Bundle, _json.JsonObject]] = {}
    for entry in document_collateral(document_b64):
        data = entry.get("data")
        if isinstance(data, _json.JsonObject) and "sigstore_bundle" in data:
            out[_json.string(entry, "id")] = (bm.parse_bundle(data["sigstore_bundle"]), data)
    return out
