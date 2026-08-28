"""Measurement value types shared by code provenance and quote verification
(Go: verifier/measurement): register sets keyed by predicate type, and the
display fingerprint helper. All errors are ValueError."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

RTMR3_ZERO = "0" * 96

# CC guest v2 types include the TLS key fingerprint and optionally HPKE public key
SEV_GUEST_V2 = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
TDX_GUEST_V2 = "https://tinfoil.sh/predicate/tdx-guest/v2"

SNP_TDX_MULTI_PLATFORM_V1 = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"


@dataclass
class Measurement:
    type: str
    registers: list[str]


@dataclass
class HardwareMeasurement:
    """Measurement values for a single platform from the hardware measurement
    repo."""

    id: str  # platform@digest
    mrtd: str
    rtmr0: str


def fingerprint(
    m: Measurement, hw: Optional[HardwareMeasurement], target_type: str
) -> str:
    """Compute a fingerprint for a measurement. Single-register measurements
    return the register value directly; multi-register measurements hash the
    type URL concatenated with all register values (no separator)."""
    if m.type == SNP_TDX_MULTI_PLATFORM_V1:  # Source
        if target_type == SEV_GUEST_V2:
            registers = [m.registers[0]]
        elif target_type == TDX_GUEST_V2:
            if hw is None:
                raise ValueError("hardware measurement required for TDX guest types")
            registers = [hw.mrtd, hw.rtmr0, m.registers[1], m.registers[2], RTMR3_ZERO]
        else:
            raise ValueError(f"unsupported target type {target_type}")
    elif m.type == TDX_GUEST_V2:  # Runtime
        r = m.registers
        registers = [r[0], r[1], r[2], r[3], r[4]]
    elif m.type == SEV_GUEST_V2:
        registers = [m.registers[0]]
    else:
        raise ValueError(f"unsupported measurement type {m.type}")

    if len(registers) == 1:
        return registers[0]
    all_ = m.type + "".join(registers)
    return hashlib.sha256(all_.encode("utf-8")).hexdigest()
