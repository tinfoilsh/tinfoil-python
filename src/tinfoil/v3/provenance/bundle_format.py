"""Sigstore bundle wire shape and the format gates applied before any
cryptography (Go: verifier/provenance/bundle_format.go plus the media-type
validation sigstore-go performs in bundle.UnmarshalJSON). All errors carry
PROVENANCE_REJECTED."""

from __future__ import annotations

import json
import re
from typing import Any

from .. import strictjson
from ..errors import PROVENANCE_REJECTED, VerificationError
from ..strictjson import RAW


def _prov_error(message: str) -> VerificationError:
    return VerificationError(PROVENANCE_REJECTED, message)


_MEDIA_TYPE_BASE = "application/vnd.dev.sigstore.bundle"
_LEGACY_MEDIA_TYPES = tuple(
    f"{_MEDIA_TYPE_BASE}+json;version={v}" for v in ("0.1", "0.2", "0.3")
)
_NEW_VERSION_RE = re.compile(r"^0\.[1-3]$")


def parse_bundle(bundle_json: bytes) -> dict[str, Any]:
    """Decode a Sigstore bundle JSON document and validate its media type.
    The strict pre-walk enforces protojson's structural rules (valid UTF-8,
    duplicate object members reject anywhere, no trailing data), which
    sigstore-go gets from protojson.Unmarshal."""
    try:
        strictjson.unmarshal(bundle_json, RAW)
    except ValueError as e:
        raise _prov_error(f"parsing bundle: {e}") from None
    b = json.loads(bytes(bundle_json).decode("utf-8"))
    if not isinstance(b, dict):
        raise _prov_error("parsing bundle: not a JSON object")
    _check_media_type(b.get("mediaType"))
    return b


def _check_media_type(media_type: Any) -> None:
    """Mirror sigstore-go's getBundleVersion: the legacy ";version=0.x" form
    or the "bundle.v0.x+json" form, versions 0.1-0.3."""
    if not isinstance(media_type, str):
        raise _prov_error("parsing bundle: missing media type")
    if media_type in _LEGACY_MEDIA_TYPES:
        return
    prefix = _MEDIA_TYPE_BASE + ".v"
    suffix = "+json"
    if media_type.startswith(prefix) and media_type.endswith(suffix):
        version = media_type[len(prefix) : -len(suffix)]
        if _NEW_VERSION_RE.fullmatch(version) is not None:
            return
    raise _prov_error(f"parsing bundle: unsupported media type {media_type!r}")


def reject_legacy_bundle_format(b: dict[str, Any]) -> None:
    """SPEC 5.2: only the v0.3 single-certificate layout is accepted. The
    legacy v0.1/v0.2 layout conveys the signing certificate under
    verificationMaterial.x509CertificateChain, which may also carry
    intermediate or root CA certificates - a misuse vector the v0.3
    single-certificate form avoids."""
    vm = b.get("verificationMaterial")
    if isinstance(vm, dict) and vm.get("x509CertificateChain") is not None:
        raise _prov_error(
            "legacy bundle format not supported: the x509CertificateChain "
            "layout requires the v0.3 single-certificate form"
        )


def require_exactly_one_dsse_signature(b: dict[str, Any]) -> None:
    """SPEC 5.2: a DSSE-envelope bundle carries exactly one signature, so
    both the empty (0) and duplicate (>1) cases fail with a clear, uniform
    reason."""
    env = b.get("dsseEnvelope")
    if not isinstance(env, dict):
        return  # not a DSSE-envelope bundle; nothing to check
    sigs = env.get("signatures")
    n = len(sigs) if isinstance(sigs, list) else 0
    if n != 1:
        raise _prov_error(f"DSSE envelope must have exactly one signature, got {n}")
