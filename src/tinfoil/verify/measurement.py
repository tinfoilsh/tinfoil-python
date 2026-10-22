"""Measurement register sets keyed by predicate type.

Shared by code provenance, which states the registers a release expects, and
quote verification, which reports the registers the hardware attested.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["Measurement", "PredicateType"]


class PredicateType(StrEnum):
    """Register layouts, identified by the predicate type that carries them."""

    SEV_GUEST_V2 = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
    """One register: the SEV-SNP launch measurement."""
    TDX_GUEST_V2 = "https://tinfoil.sh/predicate/tdx-guest/v2"
    """Five registers: MRTD, RTMR0, RTMR1, RTMR2, RTMR3."""
    SNP_TDX_MULTIPLATFORM_V1 = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
    """Three registers: the SEV-SNP launch measurement, then TDX RTMR1 and RTMR2."""


_REGISTER_LABELS = {
    PredicateType.SNP_TDX_MULTIPLATFORM_V1: ("SNP", "RTMR1", "RTMR2"),
    PredicateType.SEV_GUEST_V2: ("SNP",),
    PredicateType.TDX_GUEST_V2: ("MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"),
}


@dataclass(frozen=True, slots=True)
class Measurement:
    """Measurement registers, as hex strings, in the order ``type`` defines."""

    type: str
    registers: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "registers", tuple(self.registers))

    def __str__(self) -> str:
        labels = _REGISTER_LABELS.get(self.type, ())
        lines = [str(self.type)]
        for index, register in enumerate(self.registers):
            label = f"{labels[index]:<5}" if index < len(labels) else f"[{index}]"
            lines.append(f"{label} {register}")
        return "\n".join(lines)
