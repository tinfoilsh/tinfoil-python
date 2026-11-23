"""Container reference-values collateral: the build attestation of one container image."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from tinfoil.verifier import _json
from tinfoil.verifier._canonical import decode_lower_hex
from tinfoil.verifier._document.collateral.entry import Entry, unmarshal_data
from tinfoil.verifier._document.collateral.sigstore import require_bundle

CONTAINER_PROVENANCE_V1_FORMAT = "https://tinfoil.sh/collateral/container-provenance/v1"
"""The build attestation of one container image {digest, sigstore_bundle}, for a config that requires one."""


@dataclass(frozen=True, slots=True)
class ContainerProvenance:
    """A decoded, unauthenticated build attestation for the image with the lowercase hex SHA-256 ``digest``."""

    digest: str
    bundle: _json.JsonValue


_MEMBERS = ("digest", "sigstore_bundle")


def decode_container_provenance(entry: Entry) -> ContainerProvenance:
    data = unmarshal_data(entry, entry.format, _MEMBERS)
    digest = _json.string(data, "digest")
    decode_lower_hex("container digest", digest, hashlib.sha256().digest_size)
    return ContainerProvenance(digest=digest, bundle=require_bundle(entry, data))
