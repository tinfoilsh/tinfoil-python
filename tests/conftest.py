"""Fixtures shared by every test."""

from __future__ import annotations

import pytest

from tinfoil._v3 import _cachesecret


@pytest.fixture(autouse=True)
def _pinned_user_cache_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pins ``TINFOIL_USER_CACHE_SECRET`` for every test. A router or gateway client resolves the secret when it is
    built; without the variable the resolution would fall through to the secret persisted in the real
    ``~/.tinfoil``, making the tests depend on the machine. Tests of the resolution itself override or remove the
    variable, and point ``HOME`` at a temporary directory, explicitly."""
    monkeypatch.setenv(_cachesecret.ENV, "test-secret")
