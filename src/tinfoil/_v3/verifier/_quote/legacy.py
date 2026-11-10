"""The legacy repository-release contract: the release fixes the code registers and the platform endorsements
supply the rest."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from tinfoil._v3.verifier._measurement import (
    REGISTER_SIZE,
    TDX,
    Expected,
    ExpectedSEVSNP,
    ExpectedTDX,
    parse_register,
)
from tinfoil._v3.verifier._policy import PLATFORM_SEV_SNP, PLATFORM_TDX, Artifact, PolicyError, Shape
from tinfoil._v3.verifier._quote.resolve import ResolvedValues, apply_pins, assembly_error, resolve_policy

if TYPE_CHECKING:
    from tinfoil._v3.verifier._quote.quote import Authenticated


@dataclass(frozen=True, slots=True)
class LegacyReferenceValues:
    endorsements: Artifact
    sevsnp: ExpectedSEVSNP
    """The registers the release fixes on SEV-SNP."""
    tdx: ExpectedTDX
    """The registers the release fixes on TDX: RTMR1 and RTMR2 are set, the other registers are left
    unconstrained and are resolved from the platform endorsements and the pins."""
    shape: Shape | None
    """The VM shape the release declares; selects the TDX platform measurement."""


def resolve_legacy(refs: LegacyReferenceValues, quote: Authenticated, pins: Expected | None) -> ResolvedValues:
    """Resolve the legacy contract for a quote.

    Looks up the endorsed policy and takes the release's registers for the
    quote's platform, then applies the pins. On SEV-SNP the policy's
    ``host_data`` is the expectation. On TDX the release fixes only RTMR1
    and RTMR2: the platform endorsements resolve MRTD and RTMR0 from the
    quote's own values and the required shape, and an unpinned RTMR3 is
    expected to be zero: neither the release nor the platform extends
    RTMR3, so a non-zero value means something was measured after launch
    that no reference value accounts for.
    """
    policy_name, policy = resolve_policy(refs.endorsements, quote)
    code: Expected
    if quote.platform == PLATFORM_SEV_SNP:
        code = refs.sevsnp
    elif quote.platform == PLATFORM_TDX:
        code = refs.tdx
    else:
        raise assembly_error(f"unsupported platform {quote.platform!r}")
    expected = apply_pins(code, quote.platform, pins)
    resolved = ResolvedValues(policy=policy, policy_name=policy_name, code=code, expected=expected)
    if quote.platform == PLATFORM_SEV_SNP:
        if policy.sev_snp is None:
            raise assembly_error(f"policy {policy_name!r} has no {PLATFORM_SEV_SNP} block")
        return replace(resolved, host_data=policy.sev_snp.host_data)
    if policy.tdx is None:
        raise assembly_error(f"policy {policy_name!r} has no {PLATFORM_TDX} block")
    if not isinstance(expected, ExpectedTDX) or not isinstance(quote.measurement, TDX):
        raise assembly_error(f"expected a TDX measurement, got {type(expected).__name__}")
    mrtd, rtmr0 = quote.measurement.mrtd.hex(), quote.measurement.rtmr0.hex()
    try:
        name, platform = refs.endorsements.resolve_platform_measurement(policy.tdx, refs.shape, mrtd, rtmr0)
    except PolicyError as err:
        raise assembly_error(str(err)) from err
    try:
        platform_mrtd = parse_register(platform.mrtd)
    except ValueError as err:
        raise assembly_error(f"platform measurement {name!r} MRTD: {err}") from err
    try:
        platform_rtmr0 = parse_register(platform.rtmr0)
    except ValueError as err:
        raise assembly_error(f"platform measurement {name!r} RTMR0: {err}") from err
    expected = replace(
        expected,
        mrtd=expected.mrtd if expected.mrtd is not None else platform_mrtd,
        rtmr0=expected.rtmr0 if expected.rtmr0 is not None else platform_rtmr0,
        rtmr3=expected.rtmr3 if expected.rtmr3 is not None else bytes(REGISTER_SIZE),
    )
    return replace(resolved, expected=expected, platform_measurement_name=name)
