"""The SEV-SNP TCB version: a 64-bit value packing the security patch levels of each firmware component."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TCBParts:
    """Represents the decomposed parts of a TCB version"""

    ucode_spl: int
    snp_spl: int
    tee_spl: int
    bl_spl: int

    def __str__(self) -> str:
        """Return a human-friendly string with all component SPL values."""
        # Print fields in order starting with the least-significant component (bl_spl)
        return (
            "TCBParts("  # Opening
            f"bl_spl=0x{self.bl_spl:02x}, "
            f"tee_spl=0x{self.tee_spl:02x}, "
            f"snp_spl=0x{self.snp_spl:02x}, "
            f"ucode_spl=0x{self.ucode_spl:02x})"
        )

    @classmethod
    def from_int(cls, tcb: int) -> TCBParts:
        """Build a TCBParts instance from a 64-bit packed TCB value."""
        return cls(
            ucode_spl=((tcb >> 56) & 0xFF),
            snp_spl=((tcb >> 48) & 0xFF),
            tee_spl=((tcb >> 8) & 0xFF),
            bl_spl=((tcb >> 0) & 0xFF),
        )

    def meets_minimum(self, minimum: TCBParts) -> bool:
        """Check if this TCB meets minimum requirements (component-wise)."""
        return (
            self.bl_spl >= minimum.bl_spl
            and self.tee_spl >= minimum.tee_spl
            and self.snp_spl >= minimum.snp_spl
            and self.ucode_spl >= minimum.ucode_spl
        )
