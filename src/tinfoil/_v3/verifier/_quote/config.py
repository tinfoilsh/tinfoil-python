"""The runtime v1 and config-endorsement v1 contract: the runtime manifest fixes the launch registers and the config
hash binds HOST_DATA (SEV-SNP) or MR_CONFIG_ID (TDX)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tinfoil._v3.verifier._measurement import Expected, ExpectedSEVSNP, ExpectedTDX, parse_register
from tinfoil._v3.verifier._policy import PLATFORM_SEV_SNP, PLATFORM_TDX, Artifact
from tinfoil._v3.verifier._quote.resolve import (
    MR_CONFIG_ID_SIZE,
    AssemblyError,
    ResolvedValues,
    apply_pins,
    resolve_policy,
)
from tinfoil._v3.verifier._runtime import Measurements

if TYPE_CHECKING:
    from tinfoil._v3.verifier._quote.quote import Authenticated

_CONFIG_HASH_SIZE = 32


@dataclass(frozen=True, slots=True)
class ConfigReferenceValues:
    endorsements: Artifact
    runtime: Measurements | None
    """The manifest's measurements; both launches are required at resolution."""
    hash: bytes
    """SHA-256 of the exact config bytes."""


def resolve_config(refs: ConfigReferenceValues, quote: Authenticated, pins: Expected | None) -> ResolvedValues:
    """Resolve the config contract for a quote.

    Requires complete runtime measurements (both launches). Looks up the
    endorsed policy. On SEV-SNP the policy may not set ``host_data`` (the
    config hash takes its place) and the code is the manifest's launch
    measurement; on TDX the policy may not list ``platform_measurements``,
    the config hash becomes MR_CONFIG_ID and the code is the manifest's
    five registers. Then the pins apply.
    """
    if refs.runtime is None:
        raise AssemblyError("complete runtime endorsements are required")
    if len(refs.hash) != _CONFIG_HASH_SIZE:
        raise AssemblyError(f"config hash must be {_CONFIG_HASH_SIZE} bytes, got {len(refs.hash)}")
    policy_name, policy = resolve_policy(refs.endorsements, quote)
    host_data = ""
    config_id = bytes(MR_CONFIG_ID_SIZE)
    code: Expected
    if quote.platform == PLATFORM_SEV_SNP:
        if policy.sev_snp is None or policy.sev_snp.host_data != "":
            raise AssemblyError("config runtime cannot be combined with platform host_data")
        host_data = refs.hash.hex()
        try:
            launch = parse_register(refs.runtime.snp_launch.measurement)
        except ValueError as err:
            raise AssemblyError(f"runtime SNP launch measurement: {err}") from err
        code = ExpectedSEVSNP(launch=launch)
    elif quote.platform == PLATFORM_TDX:
        if policy.tdx is None or len(policy.tdx.platform_measurements) != 0:
            raise AssemblyError("config runtime cannot be combined with platform_measurements")
        config_id = refs.hash + bytes(MR_CONFIG_ID_SIZE - len(refs.hash))
        registers: list[bytes] = []
        for index, value in enumerate(refs.runtime.tdx_launch.registers()):
            try:
                registers.append(parse_register(value))
            except ValueError as err:
                raise AssemblyError(f"runtime TDX register {index}: {err}") from err
        code = ExpectedTDX(
            mrtd=registers[0], rtmr0=registers[1], rtmr1=registers[2], rtmr2=registers[3], rtmr3=registers[4]
        )
    else:
        raise AssemblyError(f"unsupported platform {quote.platform!r}")
    expected = apply_pins(code, quote.platform, pins)
    return ResolvedValues(
        policy=policy,
        policy_name=policy_name,
        code=code,
        expected=expected,
        platform_measurement_name=None,
        host_data=host_data,
        config_id=config_id,
    )
