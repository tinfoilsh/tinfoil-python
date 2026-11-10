"""The steps that both verification contracts share: endorsed-policy lookup, pin application and completion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tinfoil._v3.verifier._measurement import SEVSNP, TDX, Expected, ExpectedSEVSNP, ExpectedTDX, Measurement
from tinfoil._v3.verifier._policy import PLATFORM_SEV_SNP, PLATFORM_TDX, Artifact, Policy, PolicyError

if TYPE_CHECKING:
    from tinfoil._v3.verifier._quote.quote import Authenticated

MR_CONFIG_ID_SIZE = 48

_TDX_REGISTERS = ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")
_TDX_LABELS = ("MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3")
_LAUNCH_LABEL = "launch measurement"


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


def assembly_error(message: str) -> ValueError:
    """The assembly error of the quote package, looked up when raised so that the contracts stay importable on
    their own."""
    from tinfoil._v3.verifier._quote.quote import AssemblyError

    return AssemblyError(message)


def resolve_policy(endorsements: Artifact, quote: Authenticated) -> tuple[str, Policy]:
    """The endorsed policy for the quote's machine identity and platform; an unendorsed machine is an error."""
    try:
        return endorsements.policy_for(quote.identity, quote.platform)
    except PolicyError as err:
        raise assembly_error(str(err)) from err


def apply_pins(code: Expected, platform: str, pins: Expected | None) -> Expected:
    """Fill the registers that ``code`` leaves open from ``pins`` and require every pin that ``code`` also fixes to
    agree with it. Pins for the other platform are an error."""
    if pins is None:
        return code
    if isinstance(pins, ExpectedSEVSNP):
        if not isinstance(code, ExpectedSEVSNP):
            raise assembly_error(f"pinned registers are for {PLATFORM_SEV_SNP}, but the enclave is {platform}")
        return ExpectedSEVSNP(launch=_fill(_LAUNCH_LABEL, code.launch, pins.launch))
    if isinstance(pins, ExpectedTDX):
        if not isinstance(code, ExpectedTDX):
            raise assembly_error(f"pinned registers are for {PLATFORM_TDX}, but the enclave is {platform}")
        merged = {
            name: _fill(label, getattr(code, name), getattr(pins, name))
            for name, label in zip(_TDX_REGISTERS, _TDX_LABELS, strict=True)
        }
        return ExpectedTDX(**merged)
    raise assembly_error(f"unsupported pinned measurement {type(pins).__name__}")


def _fill(name: str, fixed: bytes | None, pin: bytes | None) -> bytes | None:
    if pin is None:
        return fixed
    if fixed is None:
        return pin
    if fixed != pin:
        raise assembly_error(f"pinned {name} does not match the signed release measurement")
    return fixed


def complete(expected: Expected) -> Measurement:
    """The measurement that ``expected`` requires, failing if any register is still unconstrained: assembly never
    leaves a register unchecked."""
    if isinstance(expected, ExpectedSEVSNP):
        if expected.launch is None:
            raise assembly_error(f"nothing fixes the expected {_LAUNCH_LABEL}")
        return SEVSNP(launch=expected.launch)
    if isinstance(expected, ExpectedTDX):
        values = {name: getattr(expected, name) for name in _TDX_REGISTERS}
        missing = [label for name, label in zip(_TDX_REGISTERS, _TDX_LABELS, strict=True) if values[name] is None]
        if missing:
            raise assembly_error(f"nothing fixes the expected {', '.join(missing)}")
        return TDX(**values)
    raise assembly_error(f"unsupported expected measurement {type(expected).__name__}")
