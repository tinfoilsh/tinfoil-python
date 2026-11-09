"""The register values that verification reports and accepts: what a CPU measured at launch, and the registers that a
release or a caller expects it to have measured.

Each is a closed set with one type per hardware platform, so callers
distinguish them by type.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import TypeAlias

REGISTER_SIZE = 48
"""The size of every SEV-SNP and TDX measurement register, in bytes."""


def parse_register(text: str) -> bytes:
    """Decode a register from hex in either case."""
    if len(text) != 2 * REGISTER_SIZE:
        raise ValueError(f"register must be {2 * REGISTER_SIZE} hex characters, got {len(text)}")
    try:
        return bytes.fromhex(text)
    except ValueError as err:
        raise ValueError(f"register is not hex: {err}") from None


def _check_register(label: str, value: bytes | None) -> None:
    if value is not None and len(value) != REGISTER_SIZE:
        raise ValueError(f"{label}: register must be {REGISTER_SIZE} bytes, got {len(value)}")


@dataclass(frozen=True, slots=True)
class SEVSNP:
    """An AMD SEV-SNP launch measurement."""

    launch: bytes

    def __post_init__(self) -> None:
        _check_register("Launch", self.launch)

    def expected(self) -> ExpectedSEVSNP:
        """Expectations that pin every register of the measurement."""
        return ExpectedSEVSNP(launch=self.launch)

    def __str__(self) -> str:
        return _format("SEV-SNP", ("Launch",), (self.launch,))


@dataclass(frozen=True, slots=True)
class TDX:
    """An Intel TDX build-time measurement and its four runtime registers."""

    mrtd: bytes
    rtmr0: bytes
    rtmr1: bytes
    rtmr2: bytes
    rtmr3: bytes

    def __post_init__(self) -> None:
        for label, value in zip(_TDX_LABELS, self._registers(), strict=True):
            _check_register(label, value)

    def _registers(self) -> tuple[bytes, ...]:
        return (self.mrtd, self.rtmr0, self.rtmr1, self.rtmr2, self.rtmr3)

    def expected(self) -> ExpectedTDX:
        """Expectations that pin every register of the measurement."""
        return ExpectedTDX(mrtd=self.mrtd, rtmr0=self.rtmr0, rtmr1=self.rtmr1, rtmr2=self.rtmr2, rtmr3=self.rtmr3)

    def __str__(self) -> str:
        return _format("TDX", _TDX_LABELS, self._registers())


Measurement: TypeAlias = SEVSNP | TDX
"""The set of registers a CPU measured at launch."""


@dataclass(frozen=True, slots=True)
class ExpectedSEVSNP:
    """Constrains an SEV-SNP launch measurement; None leaves it unconstrained."""

    launch: bytes | None = None

    def __post_init__(self) -> None:
        _check_register("Launch", self.launch)

    def __str__(self) -> str:
        return _format("SEV-SNP", ("Launch",), (self.launch,))


@dataclass(frozen=True, slots=True)
class ExpectedTDX:
    """Constrains a TDX measurement register by register; None leaves a register unconstrained."""

    mrtd: bytes | None = None
    rtmr0: bytes | None = None
    rtmr1: bytes | None = None
    rtmr2: bytes | None = None
    rtmr3: bytes | None = None

    def __post_init__(self) -> None:
        for label, value in zip(_TDX_LABELS, self._registers(), strict=True):
            _check_register(label, value)

    def _registers(self) -> tuple[bytes | None, ...]:
        return tuple(getattr(self, field.name) for field in fields(self))

    def __str__(self) -> str:
        return _format("TDX", _TDX_LABELS, self._registers())


Expected: TypeAlias = ExpectedSEVSNP | ExpectedTDX
"""A set of registers that a measurement must match: the registers a release fixes, or a caller's pins."""


def parse_expected_sevsnp(launch: str) -> ExpectedSEVSNP:
    """Parse the launch measurement from hex in either case. "" leaves it unconstrained."""
    return ExpectedSEVSNP(launch=_parse_expected("Launch", launch))


def parse_expected_tdx(mrtd: str, rtmr0: str, rtmr1: str, rtmr2: str, rtmr3: str) -> ExpectedTDX:
    """Parse each register from hex in either case. "" leaves that register unconstrained."""
    values = [
        _parse_expected(label, text)
        for label, text in zip(_TDX_LABELS, (mrtd, rtmr0, rtmr1, rtmr2, rtmr3), strict=True)
    ]
    return ExpectedTDX(mrtd=values[0], rtmr0=values[1], rtmr1=values[2], rtmr2=values[3], rtmr3=values[4])


def _parse_expected(label: str, text: str) -> bytes | None:
    if text == "":
        return None
    try:
        return parse_register(text)
    except ValueError as err:
        raise ValueError(f"{label}: {err}") from None


_TDX_LABELS = ("MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3")


def _format(platform: str, labels: tuple[str, ...], registers: tuple[bytes | None, ...]) -> str:
    """The platform and one labeled register per line, with "any" for an unconstrained register."""
    lines = [platform]
    for label, register in zip(labels, registers, strict=True):
        lines.append(f"{label:<6} {'any' if register is None else register.hex()}")
    return "\n".join(lines)
