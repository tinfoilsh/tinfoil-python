"""The error that every policy check raises, and the hex field check that every policy block shares."""

from __future__ import annotations

from tinfoil.verifier._canonical import is_lower_hex


class PolicyError(ValueError):
    """A policy artifact that cannot be fully enforced."""


def validate_policy_hex(name: str, value: str, byte_len: int) -> None:
    """Require exactly ``2 * byte_len`` lowercase hex characters."""
    if len(value) != 2 * byte_len:
        raise PolicyError(f"{name} must be {2 * byte_len} hex chars, got {len(value)}")
    if not is_lower_hex(value):
        raise PolicyError(f"{name} must be lowercase hex")
