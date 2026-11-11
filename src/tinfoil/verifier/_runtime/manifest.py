"""The IGVM runtime manifest that a config pins: the launch measurements of one runtime release."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from tinfoil.verifier import _json, _semver
from tinfoil.verifier._canonical import EncodingError, decode_lower_hex
from tinfoil.verifier._document.collateral.runtime import RuntimeReference

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
    snp_launch: SNPLaunch
    tdx_launch: TDXLaunch


@dataclass(frozen=True, slots=True)
class Manifest:
    """A decoded manifest. Decoding requires the ``igvm`` member and both launches, so every field is present."""

    version: str
    measurements: Measurements


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
        obj = _json.object_(_json.strict_parse(data), "runtime manifest")
        version = _json.string(obj, "version")
        igvm = _opt_object(obj, "igvm")
        format_version = 0
        snp_launch = tdx_launch = None
        if igvm is not None:
            format_version = _json.int64(igvm, "format_version") or 0
            snp_launch = _decode_snp_launch(_opt_object(igvm, "snp_launch"))
            tdx_launch = _decode_tdx_launch(_opt_object(igvm, "tdx_launch"))
    except _json.JsonError as err:
        raise ManifestError(f"parsing runtime manifest: {err}") from err
    if not _semver.is_full(version):
        raise ManifestError("runtime manifest version must be a full semantic version")
    if igvm is None or format_version != FORMAT_VERSION:
        raise ManifestError("runtime manifest format is unsupported")
    if snp_launch is None or tdx_launch is None:
        raise ManifestError("runtime manifest requires complete launch measurements")
    try:
        decode_lower_hex("SNP measurement", snp_launch.measurement, MEASUREMENT_SIZE)
        decode_lower_hex("MRTD", tdx_launch.mrtd, MEASUREMENT_SIZE)
    except EncodingError as err:
        raise ManifestError(str(err)) from err
    zero = "0" * (MEASUREMENT_SIZE * 2)
    # Format version 1 fixes MRTD alone; RTMR0 through RTMR3 must be zero.
    for value in tdx_launch.registers()[1:]:
        if value != zero:
            raise ManifestError("runtime format v1 requires zero TDX RTMRs")
    return Manifest(
        version=version,
        measurements=Measurements(format_version=format_version, snp_launch=snp_launch, tdx_launch=tdx_launch),
    )


def _decode_snp_launch(obj: _json.JsonObject | None) -> SNPLaunch | None:
    if obj is None:
        return None
    return SNPLaunch(measurement=_json.string(obj, "measurement"))


def _decode_tdx_launch(obj: _json.JsonObject | None) -> TDXLaunch | None:
    if obj is None:
        return None
    return TDXLaunch(
        mrtd=_json.string(obj, "mrtd"),
        rtmr0=_json.string(obj, "rtmr0"),
        rtmr1=_json.string(obj, "rtmr1"),
        rtmr2=_json.string(obj, "rtmr2"),
        rtmr3=_json.string(obj, "rtmr3"),
    )


def _opt_object(obj: _json.JsonObject, key: str) -> _json.JsonObject | None:
    """An optional nested object whose unknown members are ignored: absent or null is None."""
    value = obj.get(key)
    if value is None:
        return None
    return _json.object_(value, key)


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
