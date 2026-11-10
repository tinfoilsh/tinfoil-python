"""The steps that both verification contracts share: endorsed-policy lookup, pin application and completion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tinfoil._v3.verifier._measurement import Expected, Measurement
from tinfoil._v3.verifier._policy import Artifact, Policy

if TYPE_CHECKING:
    from tinfoil._v3.verifier._quote.quote import Authenticated

MR_CONFIG_ID_SIZE = 48


@dataclass(frozen=True, slots=True)
class ResolvedValues:
    """What a contract resolves for one quote before the shared assembly."""

    policy: Policy
    policy_name: str
    code: Expected
    """The registers the release fixes."""
    expected: Expected
    """``code`` plus pins and, for legacy TDX, the platform registers."""
    platform_measurement_name: str | None = None
    """The resolved TDX platform configuration under the legacy contract; None otherwise."""
    host_data: str = ""
    """The SEV-SNP HOST_DATA expectation, lowercase hex; "" leaves the policy's value."""
    config_id: bytes = bytes(MR_CONFIG_ID_SIZE)
    """The TDX MR_CONFIG_ID expectation."""


def resolve_policy(endorsements: Artifact, quote: Authenticated) -> tuple[str, Policy]:
    """The endorsed policy for the quote's machine identity and platform; an unendorsed machine is an error."""
    raise NotImplementedError


def apply_pins(code: Expected, platform: str, pins: Expected | None) -> Expected:
    """Fill the registers that ``code`` leaves open from ``pins`` and require every pin that ``code`` also fixes to
    agree with it. Pins for the other platform are an error."""
    raise NotImplementedError


def complete(expected: Expected) -> Measurement:
    """The measurement that ``expected`` requires, failing if any register is still unconstrained: assembly never
    leaves a register unchecked."""
    raise NotImplementedError
