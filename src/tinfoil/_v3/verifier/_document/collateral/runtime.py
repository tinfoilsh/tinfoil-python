"""Runtime reference-values collateral: the IGVM runtime manifest and its approval."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier import _json, _semver
from tinfoil._v3.verifier._canonical import decode_base64, decode_lower_hex
from tinfoil._v3.verifier._document.collateral.entry import Entry, unmarshal_data

RUNTIME_REPO = "tinfoilsh/cvmimage"
RUNTIME_ID = "runtime"
RUNTIME_V1_FORMAT = "https://tinfoil.sh/collateral/igvm-runtime/v1"
PLATFORM_ID = "platform"


class RuntimeCollateralError(ValueError):
    """Runtime collateral that violates its shape."""


@dataclass(frozen=True, slots=True)
class RuntimeReference:
    """Identifies a runtime release: the repository, a full semantic version tag and the manifest digest."""

    repo: str
    tag: str
    digest: str

    def validate(self) -> None:
        if self.repo != RUNTIME_REPO:
            raise RuntimeCollateralError(f"runtime repository must be {RUNTIME_REPO}")
        if not _semver.is_valid(self.tag) or _semver.canonical(self.tag) + _semver.build(self.tag) != self.tag:
            raise RuntimeCollateralError("runtime tag must be a full semantic version")
        decode_lower_hex("runtime digest", self.digest, 32)


@dataclass(frozen=True, slots=True)
class Runtime:
    """Decoded, unauthenticated runtime collateral."""

    reference: RuntimeReference
    manifest: bytes
    bundle: _json.JsonValue


_MEMBERS = ("repo", "tag", "digest", "manifest_base64", "sigstore_bundle")


def decode_runtime(entry: Entry) -> Runtime:
    data = unmarshal_data(entry, entry.format, _MEMBERS)
    reference = RuntimeReference(
        repo=_json.string(data, "repo"), tag=_json.string(data, "tag"), digest=_json.string(data, "digest")
    )
    reference.validate()
    manifest = decode_base64("manifest_base64", _json.string(data, "manifest_base64"))
    bundle = _json.raw(data, "sigstore_bundle")
    if not isinstance(bundle, _json.JsonObject):
        raise RuntimeCollateralError("sigstore_bundle must be an object")
    return Runtime(reference=reference, manifest=manifest, bundle=bundle)
