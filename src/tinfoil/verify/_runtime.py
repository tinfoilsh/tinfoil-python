"""Runtime manifests: the launch measurements of a cvmimage release.

Config verification takes its expected registers from the runtime manifest
that the endorsed config pins by version and digest.
"""

from __future__ import annotations

from dataclasses import dataclass

from .collateral import RuntimeReference

MAX_MANIFEST_SIZE = 1 << 20


@dataclass(frozen=True, slots=True, kw_only=True)
class TdxLaunch:
    """The TDX registers a runtime launches with, as lowercase hex."""

    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str

    @property
    def registers(self) -> tuple[str, str, str, str, str]:
        """MRTD then RTMR0 to RTMR3."""
        return (self.mrtd, self.rtmr0, self.rtmr1, self.rtmr2, self.rtmr3)


@dataclass(frozen=True, slots=True, kw_only=True)
class LaunchMeasurements:
    """A runtime's launch measurements on each platform."""

    snp_launch: str
    """The SEV-SNP launch measurement, as lowercase hex."""
    tdx_launch: TdxLaunch


@dataclass(frozen=True, slots=True, kw_only=True)
class Manifest:
    """A decoded runtime manifest."""

    version: str
    measurements: LaunchMeasurements


def config_runtime(config: bytes) -> RuntimeReference:
    """Extract the runtime pin (``cvm-version``) from exact config bytes."""
    raise NotImplementedError


def parse_manifest(data: bytes, expected: RuntimeReference) -> Manifest:
    """Check that ``data`` is the manifest ``expected`` pins, then decode it."""
    raise NotImplementedError


def decode_manifest(data: bytes) -> Manifest:
    """Check a manifest's size and structure without a pin to match it against."""
    raise NotImplementedError
