"""Fixtures shared by every test."""

from __future__ import annotations

import pytest

from tinfoil import _cachesecret


@pytest.fixture(autouse=True)
def _pinned_user_cache_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pins the per-process secret for every test, so that a router or gateway client built without the option
    sends a known value. Tests of the generation itself reset it to None explicitly."""
    monkeypatch.setattr(_cachesecret, "_process_secret", "test-secret")
