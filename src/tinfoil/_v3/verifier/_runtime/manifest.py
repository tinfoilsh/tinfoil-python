"""The IGVM runtime manifest that a config pins: the launch measurements of one runtime release."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from tinfoil._v3.verifier import _json, _semver
from tinfoil._v3.verifier._canonical import EncodingError, decode_lower_hex
from tinfoil._v3.verifier._document.collateral.runtime import RuntimeReference

FORMAT_VERSION = 1
MEASUREMENT_SIZE = 48
MAX_MANIFEST_SIZE = 1 << 20


class ManifestError(ValueError):
    """A runtime manifest that does not match its pin or violates its shape."""


@dataclass(frozen=True, slots=True)
class SNPLaunch:
    measurement: str


@dataclass(frozen=True, slots=True)
class TDXLaunch:
    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str

    def registers(self) -> tuple[str, str, str, str, str]:
        return (self.mrtd, self.rtmr0, self.rtmr1, self.rtmr2, self.rtmr3)


@dataclass(frozen=True, slots=True)
class Measurements:
    """The ``igvm`` member: the launch measurements in one format version."""

    format_version: int
    snp_launch: SNPLaunch | None
    tdx_launch: TDXLaunch | None


@dataclass(frozen=True, slots=True)
class Manifest:
    version: str
    measurements: Measurements | None
    """None for an old manifest without the ``igvm`` member."""


def parse_manifest(data: bytes, expected: RuntimeReference) -> Manifest:
    """Check that ``data`` is the manifest that ``expected`` pins, then decode it.

    The digest is checked before anything is parsed.
    """
    if hashlib.sha256(data).hexdigest() != expected.digest:
        raise ManifestError("runtime manifest does not match the config's digest pin")
    manifest = decode_manifest(data)
    if manifest.version != expected.tag:
        raise ManifestError(
            f"runtime manifest version {_quote(manifest.version)} does not match the config's pin "
            f"{_quote(expected.tag)}"
        )
    return manifest


def decode_manifest(data: bytes) -> Manifest:
    """Check a manifest's size and structure, without a config pin to match it against.

    Unknown members are allowed at every depth, so that a manifest may carry
    download metadata; duplicate member names still reject.
    """
    if len(data) == 0 or len(data) > MAX_MANIFEST_SIZE:
        raise ManifestError("runtime manifest size is outside allowed bounds")
    try:
        manifest = _decode(_json.strict_parse(data))
    except _json.JsonError as err:
        raise ManifestError(f"parsing runtime manifest: {err}") from err
    version = manifest.version
    if not _semver.is_valid(version) or _semver.canonical(version) + _semver.build(version) != version:
        raise ManifestError("runtime manifest version must be a full semantic version")
    if manifest.measurements is None or manifest.measurements.format_version != FORMAT_VERSION:
        raise ManifestError("runtime manifest format is unsupported")
    measurements = manifest.measurements
    if measurements.snp_launch is None or measurements.tdx_launch is None:
        raise ManifestError("runtime manifest requires complete launch measurements")
    try:
        decode_lower_hex("SNP measurement", measurements.snp_launch.measurement, MEASUREMENT_SIZE)
        decode_lower_hex("MRTD", measurements.tdx_launch.mrtd, MEASUREMENT_SIZE)
    except EncodingError as err:
        raise ManifestError(str(err)) from err
    zero = "0" * (MEASUREMENT_SIZE * 2)
    for value in measurements.tdx_launch.registers()[1:]:
        if value != zero:
            raise ManifestError("runtime format v1 requires zero TDX RTMRs")
    return manifest


def _decode(value: _json.JsonValue) -> Manifest:
    obj = _json.object_(value, "runtime manifest")
    igvm = _opt_object(obj, "igvm")
    measurements = None
    if igvm is not None:
        format_version = _json.int64(igvm, "format_version")
        snp_launch = _opt_object(igvm, "snp_launch")
        tdx_launch = _opt_object(igvm, "tdx_launch")
        measurements = Measurements(
            format_version=0 if format_version is None else format_version,
            snp_launch=None if snp_launch is None else SNPLaunch(measurement=_json.string(snp_launch, "measurement")),
            tdx_launch=None
            if tdx_launch is None
            else TDXLaunch(
                mrtd=_json.string(tdx_launch, "mrtd"),
                rtmr0=_json.string(tdx_launch, "rtmr0"),
                rtmr1=_json.string(tdx_launch, "rtmr1"),
                rtmr2=_json.string(tdx_launch, "rtmr2"),
                rtmr3=_json.string(tdx_launch, "rtmr3"),
            ),
        )
    return Manifest(version=_json.string(obj, "version"), measurements=measurements)


def _opt_object(obj: _json.JsonObject, key: str) -> _json.JsonObject | None:
    """An optional nested object whose unknown members are ignored: absent or null is None."""
    value = obj.get(key)
    if value is None:
        return None
    return _json.object_(value, key)


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
