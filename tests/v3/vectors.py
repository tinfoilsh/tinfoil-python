"""Access to the conformance vectors for module-level tests.

The vectors are located as the adapter tests locate them; a test that
needs a group skips when the checkout is absent.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from tests.conformance.conftest import fixtures_root


def vector_group(name: str) -> list[dict[str, Any]]:
    """Every fixture under ``vectors/v3/<name>``, sorted by file name; empty when the vectors are absent."""
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
    return fixtures


def vector_params(name: str) -> list[Any]:
    """``pytest.param`` entries for a group, or one skipped entry when the vectors are absent."""
    fixtures = vector_group(name)
    if not fixtures:
        return [pytest.param(None, id="vectors-absent", marks=pytest.mark.skip(reason="conformance vectors not found"))]
    return [pytest.param(fixture, id=fixture["id"]) for fixture in fixtures]


def vector(name: str, fixture_id: str) -> dict[str, Any]:
    """One fixture by id; skips the calling test when the vectors are absent."""
    for fixture in vector_group(name):
        if fixture["id"] == fixture_id:
            return fixture
    pytest.skip("conformance vectors not found")


def b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)
