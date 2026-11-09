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
    """The vectors directory, or None when nothing is configured and no sibling exists.

    A configured path that is not a directory is an error, so that a
    misconfigured run cannot pass as skipped.
    """
    configured = os.environ.get("TINFOIL_CONFORMANCE_FIXTURES")
    if configured:
        root = Path(configured)
        if not root.is_dir():
            raise pytest.UsageError(f"TINFOIL_CONFORMANCE_FIXTURES is not a directory: {configured}")
        return root
    return _SIBLING if _SIBLING.is_dir() else None


def load_fixtures() -> list[tuple[str, dict[str, Any]]]:
    """Every fixture under the root. A JSON file outside ``_assets`` that is not
    a fixture is an error rather than a silent omission."""
    root = fixtures_root()
    if root is None:
        return []
    fixtures = []
    for path in sorted(root.rglob("*.json")):
        if "_assets" in path.parts:
            continue
        with path.open("rb") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or "stage" not in data or "input" not in data or "expected" not in data:
            raise pytest.UsageError(f"not a conformance fixture (no stage/input/expected): {path}")
        fixtures.append((str(path.relative_to(root)), data))
    return fixtures


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "fixture" in metafunc.fixturenames:
        fixtures = load_fixtures()
        if not fixtures:
            metafunc.parametrize("fixture", [pytest.param(None, marks=pytest.mark.skip(reason="conformance vectors not found"))])
            return
        metafunc.parametrize("fixture", [data for _, data in fixtures], ids=[name for name, _ in fixtures])
