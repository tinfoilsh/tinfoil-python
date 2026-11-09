"""Fixture discovery for the v3 conformance vectors.

The vectors live in the tinfoil-conformance repository. Their location comes
from ``TINFOIL_CONFORMANCE_FIXTURES`` (the ``vectors/v3`` directory), falling
back to a sibling checkout. Tests that need them skip when neither exists.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SIBLING = _REPO_ROOT.parent / "tinfoil-conformance" / "vectors" / "v3"


def fixtures_root() -> Path | None:
    configured = os.environ.get("TINFOIL_CONFORMANCE_FIXTURES")
    if configured:
        return Path(configured)
    return _SIBLING if _SIBLING.is_dir() else None


def load_fixtures() -> list[tuple[str, dict[str, Any]]]:
    root = fixtures_root()
    if root is None or not root.is_dir():
        return []
    fixtures = []
    for path in sorted(root.rglob("*.json")):
        if "_assets" in path.parts:
            continue
        with path.open("rb") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or "stage" not in data or "input" not in data:
            continue
        fixtures.append((str(path.relative_to(root)), data))
    return fixtures


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "fixture" in metafunc.fixturenames:
        fixtures = load_fixtures()
        if not fixtures:
            metafunc.parametrize("fixture", [pytest.param(None, marks=pytest.mark.skip(reason="conformance vectors not found"))])
            return
        metafunc.parametrize("fixture", [data for _, data in fixtures], ids=[name for name, _ in fixtures])
