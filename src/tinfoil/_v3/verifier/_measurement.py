"""The register values that verification reports and accepts: what a CPU measured at launch, and the registers that a
release or a caller expects it to have measured.

Each is a closed set with one type per hardware platform, so callers
distinguish them by type.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from typing import TypeAlias

REGISTER_SIZE = 48
"""The size of every SEV-SNP and TDX measurement register, in bytes."""

Register: TypeAlias = bytes
"""A measurement register: exactly ``REGISTER_SIZE`` bytes. Its text form is lowercase hex; ``parse_register``
decodes one and ``bytes.hex()`` encodes one."""


_HEX = re.compile(r"[0-9a-fA-F]*")


def parse_register(text: str) -> Register:
    """Decode a register from hex in either case. A string of the wrong length or with a non-hex character is a
    ValueError."""
    if len(text) != 2 * REGISTER_SIZE:
        raise ValueError(f"register must be {2 * REGISTER_SIZE} hex characters, got {len(text)}")
    # The character class is checked explicitly: the bytes decoder would skip
    # whitespace and return a short register.
    if not _HEX.fullmatch(text):
        raise ValueError("register is not hex: invalid byte")
    return bytes.fromhex(text)


def _check_register(name: str, value: Register | None, *, required: bool) -> None:
    """Reject a register that is absent when required, not bytes, or not REGISTER_SIZE long; every failure is a
    ValueError naming the field."""
    if value is None:
        if required:
            raise ValueError(f"{name}: register is required")
        return
    if not isinstance(value, bytes):
        raise ValueError(f"{name}: register must be bytes, not {type(value).__name__}")
    if len(value) != REGISTER_SIZE:
        raise ValueError(f"{name}: register must be {REGISTER_SIZE} bytes, got {len(value)}")


@dataclass(frozen=True, slots=True)
class SEVSNP:
    """An AMD SEV-SNP launch measurement."""

    launch: Register

    def __post_init__(self) -> None:
        _check_register("launch", self.launch, required=True)

    def expected(self) -> ExpectedSEVSNP:
        """Expectations that pin every register of the measurement."""
        return ExpectedSEVSNP(launch=self.launch)

    def __str__(self) -> str:
        return _format("SEV-SNP", ("launch",), (self.launch,))


@dataclass(frozen=True, slots=True)
class TDX:
    """An Intel TDX build-time measurement and its four runtime registers."""

    mrtd: Register
    rtmr0: Register
    rtmr1: Register
    rtmr2: Register
    rtmr3: Register

    def __post_init__(self) -> None:
        for name, value in zip(_TDX_REGISTERS, self._registers(), strict=True):
            _check_register(name, value, required=True)

    def _registers(self) -> tuple[Register, ...]:
        return (self.mrtd, self.rtmr0, self.rtmr1, self.rtmr2, self.rtmr3)

    def expected(self) -> ExpectedTDX:
        """Expectations that pin every register of the measurement."""
        return ExpectedTDX(mrtd=self.mrtd, rtmr0=self.rtmr0, rtmr1=self.rtmr1, rtmr2=self.rtmr2, rtmr3=self.rtmr3)

    def __str__(self) -> str:
        return _format("TDX", _TDX_REGISTERS, self._registers())


Measurement: TypeAlias = SEVSNP | TDX
"""The set of registers a CPU measured at launch."""


@dataclass(frozen=True, slots=True)
class ExpectedSEVSNP:
    """Constrains an SEV-SNP launch measurement; None leaves it unconstrained."""

    launch: Register | None = None

    def __post_init__(self) -> None:
        _check_register("launch", self.launch, required=False)

    def __str__(self) -> str:
        return _format("SEV-SNP", ("launch",), (self.launch,))


@dataclass(frozen=True, slots=True)
class ExpectedTDX:
    """Constrains a TDX measurement register by register; None leaves a register unconstrained."""

    mrtd: Register | None = None
    rtmr0: Register | None = None
    rtmr1: Register | None = None
    rtmr2: Register | None = None
    rtmr3: Register | None = None

    def __post_init__(self) -> None:
        for name, value in zip(_TDX_REGISTERS, self._registers(), strict=True):
            _check_register(name, value, required=False)

    def _registers(self) -> tuple[Register | None, ...]:
        return tuple(getattr(self, field.name) for field in fields(self))

    def __str__(self) -> str:
        return _format("TDX", _TDX_REGISTERS, self._registers())


Expected: TypeAlias = ExpectedSEVSNP | ExpectedTDX
"""A set of registers that a measurement must match: the registers a release fixes, or a caller's pins."""


def parse_expected_sevsnp(launch: str) -> ExpectedSEVSNP:
    """Parse the launch measurement from hex in either case. "" leaves it unconstrained; anything else that is not a
    register is a ValueError naming the field."""
    return ExpectedSEVSNP(launch=_parse_expected("launch", launch))


def parse_expected_tdx(mrtd: str, rtmr0: str, rtmr1: str, rtmr2: str, rtmr3: str) -> ExpectedTDX:
    """Parse each register from hex in either case. "" leaves that register unconstrained; anything else that is
    not a register is a ValueError naming the field."""
    values = [
        _parse_expected(name, text)
        for name, text in zip(_TDX_REGISTERS, (mrtd, rtmr0, rtmr1, rtmr2, rtmr3), strict=True)
    ]
    return ExpectedTDX(mrtd=values[0], rtmr0=values[1], rtmr1=values[2], rtmr2=values[3], rtmr3=values[4])


def _parse_expected(name: str, text: str) -> Register | None:
    if text == "":
        return None
    try:
        return parse_register(text)
    except ValueError as err:
        raise ValueError(f"{name}: {err}") from None


_TDX_REGISTERS = ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")
"""The TDX register fields, in register order."""


def _format(platform: str, names: tuple[str, ...], registers: tuple[Register | None, ...]) -> str:
    """The platform and one register per line, named as the record's field, with "any" for an unconstrained
    register."""
    lines = [platform]
    for name, register in zip(names, registers, strict=True):
        lines.append(f"{name:<6} {'any' if register is None else register.hex()}")
    return "\n".join(lines)
