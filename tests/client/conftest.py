"""Fixtures shared by the client tests."""

from __future__ import annotations

import pytest

from tinfoil import _enclave


@pytest.fixture(autouse=True)
def _no_retry_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed verification attempt is retried without the one-second delay. A test of the delay restores it."""
    monkeypatch.setattr(_enclave, "VERIFICATION_RETRY_DELAY", 0.0)
