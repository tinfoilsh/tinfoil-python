"""The SEV-SNP TCB version: a 64-bit value packing the security patch levels of each firmware component, in the
layout of the product line that issued it."""

from __future__ import annotations

from dataclasses import dataclass, replace

TCB_STRUCT_VERSION_0 = 0
"""The layout of Milan, Genoa and Siena parts."""
TCB_STRUCT_VERSION_1 = 1
"""The layout of Turin parts, which adds the FMC level and drops the reserved levels."""

HWID_SIZE_VERSION_0 = 64
HWID_SIZE_VERSION_1 = 8

_PRODUCT_LINE_LAYOUT = {
    "milan": TCB_STRUCT_VERSION_0,
    "genoa": TCB_STRUCT_VERSION_0,
    "siena": TCB_STRUCT_VERSION_0,
    "turin": TCB_STRUCT_VERSION_1,
}
_TURIN_RESERVED_MASK = 0x00FF_FFFF_0000_0000
_MAX_LEVEL = 127
"""Every level except the microcode level is at most 127."""


class TcbError(ValueError):
    """A TCB value that does not fit its layout, or a product line without one."""


def tcb_struct_version(product_line: str) -> int:
    """The layout version of a product line, matched case-insensitively."""
    version = _PRODUCT_LINE_LAYOUT.get(product_line.lower())
    if version is None:
        raise TcbError(f"invalid product line {product_line!r}")
    return version


@dataclass(frozen=True, slots=True)
class TCBVersionStruct:
    """A packed TCB_VERSION together with the layout that interprets it."""

    version: int
    tcb: int

    def to_parts(self) -> TCBParts:
        """Unpack the levels; a Turin value with its reserved bits 55 to 32 set is an error."""
        if self.version == TCB_STRUCT_VERSION_1:
            reserved = self.tcb & _TURIN_RESERVED_MASK
            if reserved:
                raise TcbError(f"non-zero reserved bits in Turin TCB: 0x{reserved:x}")
            return TCBParts(
                version=self.version,
                ucode_spl=(self.tcb >> 56) & 0xFF,
                snp_spl=(self.tcb >> 24) & 0xFF,
                tee_spl=(self.tcb >> 16) & 0xFF,
                bl_spl=(self.tcb >> 8) & 0xFF,
                fmc_spl=self.tcb & 0xFF,
            )
        if self.version == TCB_STRUCT_VERSION_0:
            return TCBParts(
                version=self.version,
                ucode_spl=(self.tcb >> 56) & 0xFF,
                snp_spl=(self.tcb >> 48) & 0xFF,
                spl7=(self.tcb >> 40) & 0xFF,
                spl6=(self.tcb >> 32) & 0xFF,
                spl5=(self.tcb >> 24) & 0xFF,
                spl4=(self.tcb >> 16) & 0xFF,
                tee_spl=(self.tcb >> 8) & 0xFF,
                bl_spl=self.tcb & 0xFF,
            )
        raise TcbError(f"unknown TCB version: {self.version}")

    def with_tcb(self, tcb: int) -> TCBVersionStruct:
        """Another packed value in this layout."""
        return TCBVersionStruct(version=self.version, tcb=tcb)

    def same_format(self, other: TCBVersionStruct) -> bool:
        return self.version == other.version

    def __str__(self) -> str:
        if self.version == TCB_STRUCT_VERSION_0:
            return f"Milan or Genoa TCB: 0x{self.tcb:x}"
        if self.version == TCB_STRUCT_VERSION_1:
            return f"Turin TCB: 0x{self.tcb:x}"
        return "Unknown TCB"


def new_tcb_version_struct(product_line: str, tcb: int) -> TCBVersionStruct:
    """A packed value in the layout of ``product_line``."""
    return TCBVersionStruct(version=tcb_struct_version(product_line), tcb=tcb)


@dataclass(frozen=True, slots=True)
class TCBParts:
    """The unpacked security patch levels, tagged with the layout that they belong to."""

    version: int = TCB_STRUCT_VERSION_0
    bl_spl: int = 0
    tee_spl: int = 0
    spl4: int = 0
    spl5: int = 0
    spl6: int = 0
    spl7: int = 0
    snp_spl: int = 0
    ucode_spl: int = 0
    fmc_spl: int = 0

    def to_version_struct(self) -> TCBVersionStruct:
        """Pack the levels; levels above 127 (other than the microcode level) and levels that the layout does not
        carry are errors."""
        for name, value in (
            ("SnpSpl", self.snp_spl),
            ("Spl7", self.spl7),
            ("Spl6", self.spl6),
            ("Spl5", self.spl5),
            ("Spl4", self.spl4),
            ("TeeSpl", self.tee_spl),
            ("BlSpl", self.bl_spl),
            ("FmcSpl", self.fmc_spl),
        ):
            if value > _MAX_LEVEL:
                raise TcbError(f"{name} TCB part is {value}. Expect 0-{_MAX_LEVEL}")
        if self.version == TCB_STRUCT_VERSION_0:
            if self.fmc_spl != 0:
                raise TcbError("FmcSpl is not defined for TCB struct version 0")
            tcb = (
                (self.ucode_spl << 56)
                | (self.snp_spl << 48)
                | (self.spl7 << 40)
                | (self.spl6 << 32)
                | (self.spl5 << 24)
                | (self.spl4 << 16)
                | (self.tee_spl << 8)
                | self.bl_spl
            )
            return TCBVersionStruct(version=self.version, tcb=tcb)
        if self.version == TCB_STRUCT_VERSION_1:
            if self.spl4 or self.spl5 or self.spl6 or self.spl7:
                raise TcbError("reserved Turin TCB components must be zero")
            tcb = (
                (self.ucode_spl << 56) | (self.snp_spl << 24) | (self.tee_spl << 16) | (self.bl_spl << 8) | self.fmc_spl
            )
            return TCBVersionStruct(version=self.version, tcb=tcb)
        raise TcbError(f"unsupported TCB struct version: {self.version}")

    def __str__(self) -> str:
        if self.version == TCB_STRUCT_VERSION_1:
            return (
                f"{{FmcSpl:{self.fmc_spl} BlSpl:{self.bl_spl} TeeSpl:{self.tee_spl} SnpSpl:{self.snp_spl} "
                f"UcodeSpl:{self.ucode_spl}}}"
            )
        return (
            f"{{BlSpl:{self.bl_spl} TeeSpl:{self.tee_spl} Spl4:{self.spl4} Spl5:{self.spl5} Spl6:{self.spl6} "
            f"Spl7:{self.spl7} SnpSpl:{self.snp_spl} UcodeSpl:{self.ucode_spl}}}"
        )


def new_tcb_parts(product_line: str, parts: TCBParts) -> TCBParts:
    """Tag ``parts`` with the layout of ``product_line`` and check that they fit it."""
    tagged = replace(parts, version=tcb_struct_version(product_line))
    tagged.to_version_struct()
    return tagged


def tcb_parts_le(lower: TCBParts, higher: TCBParts) -> bool:
    """Whether every level of ``lower`` is at most the corresponding level of ``higher``, in the same layout."""
    return (
        lower.version == higher.version
        and lower.ucode_spl <= higher.ucode_spl
        and lower.snp_spl <= higher.snp_spl
        and lower.spl7 <= higher.spl7
        and lower.spl6 <= higher.spl6
        and lower.spl5 <= higher.spl5
        and lower.spl4 <= higher.spl4
        and lower.tee_spl <= higher.tee_spl
        and lower.bl_spl <= higher.bl_spl
        and lower.fmc_spl <= higher.fmc_spl
    )
