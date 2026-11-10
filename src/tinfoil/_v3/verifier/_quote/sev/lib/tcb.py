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
_MAX_LEVEL = 127
"""Every level except the microcode level is at most 127."""
_TCB_MASK = (1 << 64) - 1


class TcbError(ValueError):
    """A TCB value that does not fit its layout, or a product line without one."""


@dataclass(frozen=True, slots=True)
class _Level:
    """One security patch level inside a packed TCB_VERSION."""

    field: str
    """The ``TCBParts`` attribute that holds the level."""
    label: str
    """The level's name in messages and renderings."""
    shift: int
    """The position of the level's low bit in the packed value."""
    width: int = 8
    """The number of bits that the packed value reserves for the level."""

    @property
    def mask(self) -> int:
        return (1 << self.width) - 1


@dataclass(frozen=True, slots=True)
class _Layout:
    """The levels of one TCB struct version, in ascending bit order."""

    name: str
    levels: tuple[_Level, ...]
    undefined_levels_error: str
    """The error for a level that this layout does not carry being non-zero."""

    @property
    def reserved_mask(self) -> int:
        """The bits of the packed value that no level covers, which must be zero."""
        covered = 0
        for level in self.levels:
            covered |= level.mask << level.shift
        return _TCB_MASK & ~covered

    def fields(self) -> frozenset[str]:
        return frozenset(level.field for level in self.levels)


_LAYOUTS: dict[int, _Layout] = {
    TCB_STRUCT_VERSION_0: _Layout(
        name="Milan or Genoa",
        levels=(
            _Level("bl_spl", "BlSpl", 0),
            _Level("tee_spl", "TeeSpl", 8),
            _Level("spl4", "Spl4", 16),
            _Level("spl5", "Spl5", 24),
            _Level("spl6", "Spl6", 32),
            _Level("spl7", "Spl7", 40),
            _Level("snp_spl", "SnpSpl", 48),
            _Level("ucode_spl", "UcodeSpl", 56),
        ),
        undefined_levels_error="FmcSpl is not defined for TCB struct version 0",
    ),
    TCB_STRUCT_VERSION_1: _Layout(
        name="Turin",
        levels=(
            _Level("fmc_spl", "FmcSpl", 0),
            _Level("bl_spl", "BlSpl", 8),
            _Level("tee_spl", "TeeSpl", 16),
            _Level("snp_spl", "SnpSpl", 24),
            _Level("ucode_spl", "UcodeSpl", 56),
        ),
        undefined_levels_error="reserved Turin TCB components must be zero",
    ),
}

_LEVELS_CHECKED: tuple[_Level, ...] = (
    *(level for level in _LAYOUTS[TCB_STRUCT_VERSION_0].levels[-2::-1]),
    _LAYOUTS[TCB_STRUCT_VERSION_1].levels[0],
)
"""Every level but the microcode level, in the order that packing range-checks them."""

_ALL_FIELDS: tuple[str, ...] = tuple(
    dict.fromkeys(level.field for layout in _LAYOUTS.values() for level in layout.levels)
)
"""Every level field of any layout, in the order that the comparison applies."""


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
        layout = _LAYOUTS.get(self.version)
        if layout is None:
            raise TcbError(f"unknown TCB version: {self.version}")
        reserved = self.tcb & layout.reserved_mask
        if reserved:
            raise TcbError(f"non-zero reserved bits in {layout.name} TCB: 0x{reserved:x}")
        levels = {level.field: (self.tcb >> level.shift) & level.mask for level in layout.levels}
        return TCBParts(version=self.version, **levels)

    def with_tcb(self, tcb: int) -> TCBVersionStruct:
        """Another packed value in this layout."""
        return TCBVersionStruct(version=self.version, tcb=tcb)

    def same_format(self, other: TCBVersionStruct) -> bool:
        return self.version == other.version

    def __str__(self) -> str:
        layout = _LAYOUTS.get(self.version)
        if layout is None:
            return "Unknown TCB"
        return f"{layout.name} TCB: 0x{self.tcb:x}"


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
        for level in _LEVELS_CHECKED:
            value: int = getattr(self, level.field)
            if value > _MAX_LEVEL:
                raise TcbError(f"{level.label} TCB part is {value}. Expect 0-{_MAX_LEVEL}")
        layout = _LAYOUTS.get(self.version)
        if layout is None:
            raise TcbError(f"unsupported TCB struct version: {self.version}")
        carried = layout.fields()
        if any(getattr(self, field) for field in _ALL_FIELDS if field not in carried):
            raise TcbError(layout.undefined_levels_error)
        tcb = 0
        for level in layout.levels:
            tcb |= getattr(self, level.field) << level.shift
        return TCBVersionStruct(version=self.version, tcb=tcb)

    def __str__(self) -> str:
        layout = _LAYOUTS.get(self.version, _LAYOUTS[TCB_STRUCT_VERSION_0])
        rendered = " ".join(f"{level.label}:{getattr(self, level.field)}" for level in layout.levels)
        return f"{{{rendered}}}"


def new_tcb_parts(product_line: str, parts: TCBParts) -> TCBParts:
    """Tag ``parts`` with the layout of ``product_line`` and check that they fit it."""
    tagged = replace(parts, version=tcb_struct_version(product_line))
    tagged.to_version_struct()
    return tagged


def tcb_parts_le(lower: TCBParts, higher: TCBParts) -> bool:
    """Whether every level of ``lower`` is at most the corresponding level of ``higher``, in the same layout."""
    return lower.version == higher.version and all(
        getattr(lower, field) <= getattr(higher, field) for field in _ALL_FIELDS
    )
