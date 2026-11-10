"""The facts that verification proves about a document, and the record that carries them."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal, TypeAlias

from tinfoil._v3.verifier._document.document import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    CryptoMaterialItem,
)
from tinfoil._v3.verifier._measurement import SEVSNP, Expected, ExpectedSEVSNP, Measurement
from tinfoil._v3.verifier._policy import PLATFORM_SEV_SNP, PLATFORM_TDX

ReferenceSource: TypeAlias = Literal["endorsement", "embedded", "policy"]
"""Why a set of reference values was accepted; the ``SOURCE_*`` constants are its values."""

SOURCE_ENDORSEMENT: Final[ReferenceSource] = "endorsement"
"""Authenticated against an endorsement that the document carries."""
SOURCE_EMBEDDED: Final[ReferenceSource] = "embedded"
"""Supplied by the caller as an embedded reference."""
SOURCE_POLICY: Final[ReferenceSource] = "policy"
"""Authorized by the caller's config authorizer."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigVerification:
    """The config bound to hardware, and how it was accepted.

    A string fact that was not established is ``""`` and a time that was
    not established is None: a caller-authorized config has no endorsement
    reference, signing key hint, registry id, approval time or signature
    time, and an embedded one has only the name and digest that the caller
    supplied.
    """

    source: ReferenceSource
    name: str = ""
    digest: str = ""
    reference: str = ""
    signing_key_hint: str = ""
    approval_time: datetime | None = None
    registry_id: str = ""
    """Authenticated by the certificate, or the public registry for legacy registry approvals."""
    signature_time: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactVerification:
    """Accepted reference values and their authority.

    A string fact that was not established is ``""`` and a time that was
    not established is None: an embedded artifact has no authenticated
    commit, name or approval time, and an embedded platform artifact only
    a digest.
    """

    source: ReferenceSource
    repo: str = ""
    tag: str = ""
    digest: str = ""
    name: str = ""
    commit: str = ""
    approval_time: datetime | None = None


@dataclass(frozen=True, slots=True)
class SoftwareIdentity:
    """Software involved in a verification."""

    name: str
    version: str


@dataclass(frozen=True, slots=True)
class VerificationMetadata:
    """How a verification was performed. The verifier fills it in from its own state; none of it is attested by or
    checked against the document."""

    verifier: SoftwareIdentity
    """The SDK that performed the verification."""
    verified_at: datetime
    """The instant the document was appraised at: read once from the local clock by ``verify_v3``, or the caller's
    verification time for ``verify_v3_at``. It is not a freshness guarantee."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Verification:
    """The facts proven during the verification of an attestation document, and metadata that the verifier adds
    about the verification itself.

    The verifier creates one from a verified document; a hand-built value
    carries no proof. Every field is immutable: the registers are
    ``bytes``, the items are a tuple of frozen records and the times are
    timezone-aware datetimes.
    """

    code_digest: str
    """The digest of the verified code or runtime artifact."""
    code_tag: str
    """The release tag of the verified code or runtime artifact."""
    config_repo: str
    """The selected code or runtime repository, without version pins."""
    code_measurement: Expected
    """The registers the release fixes on the enclave's platform, with None for a register the release leaves to
    the platform."""
    enclave_measurement: Measurement
    """The quote's authenticated registers, proven to match the expectations."""
    crypto_material: tuple[CryptoMaterialItem, ...] = ()
    """The endorsed key items, which are hash-bound into the quote."""
    freshness_expires_at: datetime | None = None
    """The earlier authenticated code/platform witness deadline. Cached verification must not authorize new
    requests at or after this time; re-verifying the same witness does not extend it. Config verification uses the
    earliest config, platform or runtime approval deadline. None means that no endorsed reference supplied an
    approval deadline: embedded components add none, and neither does a caller-authorized config, so a verification
    with every reference embedded, or with a caller-authorized config and an embedded runtime and platform, has
    none. Renewal is then the caller's own policy; None is not a promise that the evidence stays valid."""
    config: ConfigVerification | None = None
    """The config bound to hardware; None for verification against a code release, which has no config."""
    runtime: ArtifactVerification | None = None
    """The runtime that a config-based verification accepted; None for verification against a code release."""
    platform: ArtifactVerification | None = None
    """The platform endorsements that a config-based verification accepted; None for a code release."""
    metadata: VerificationMetadata

    @property
    def tls_public_key_fp(self) -> str | None:
        """The endorsed TLS key fingerprint: the ``tls`` crypto-material entry in the SPKI SHA-256 format, or None
        when the document endorses no such entry, including a ``tls`` entry in another format."""
        return self.crypto_material_data(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT)

    @property
    def hpke_public_key(self) -> str | None:
        """The endorsed HPKE public key: the ``hpke`` crypto-material entry in the X25519 HPKE format, or None when
        the document endorses no such entry, including an ``hpke`` entry in another format."""
        return self.crypto_material_data(CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT)

    def crypto_material_data(self, item_id: str, item_format: str) -> str | None:
        """The endorsed lowercase-hex data for exactly ``item_id`` and ``item_format``, or None when the document
        endorses no such item. Lookup does not refresh evidence or enforce ``freshness_expires_at``."""
        return crypto_material_data(self.crypto_material, item_id, item_format)

    def to_dict(self) -> dict[str, Any]:
        """A plain, JSON-ready copy: registers as lowercase hex, times as ISO 8601 in UTC, facts that were not
        established (None times and empty strings) left out of the config, runtime and platform records."""
        out: dict[str, Any] = {
            "code_digest": self.code_digest,
            "code_tag": self.code_tag,
            "config_repo": self.config_repo,
            "code_measurement": _measurement_dict(self.code_measurement),
            "enclave_measurement": _measurement_dict(self.enclave_measurement),
            "crypto_material": [
                {"id": item.id, "format": item.format, "data": item.data} for item in self.crypto_material
            ],
        }
        if self.config is not None:
            out["config"] = _established(
                {
                    "source": self.config.source,
                    "name": self.config.name,
                    "digest": self.config.digest,
                    "reference": self.config.reference,
                    "signing_key_hint": self.config.signing_key_hint,
                    "approval_time": _time(self.config.approval_time),
                    "registry_id": self.config.registry_id,
                    "signature_time": _time(self.config.signature_time),
                }
            )
        for name, artifact in (("runtime", self.runtime), ("platform", self.platform)):
            if artifact is not None:
                out[name] = _established(
                    {
                        "source": artifact.source,
                        "repo": artifact.repo,
                        "tag": artifact.tag,
                        "digest": artifact.digest,
                        "name": artifact.name,
                        "commit": artifact.commit,
                        "approval_time": _time(artifact.approval_time),
                    }
                )
        if self.freshness_expires_at is not None:
            out["freshness_expires_at"] = _time(self.freshness_expires_at)
        out["metadata"] = {
            "verifier": {"name": self.metadata.verifier.name, "version": self.metadata.verifier.version},
            "verified_at": _time(self.metadata.verified_at),
        }
        return out

    def to_json(self, *, indent: int | None = None) -> str:
        """``to_dict`` serialized as JSON: compact by default, or pretty-printed with ``indent`` spaces per level."""
        if indent is None:
            return json.dumps(self.to_dict(), separators=(",", ":"))
        return json.dumps(self.to_dict(), indent=indent)


def crypto_material_data(items: tuple[CryptoMaterialItem, ...], item_id: str, item_format: str) -> str | None:
    """The data of the one item among ``items`` with exactly ``item_id`` and ``item_format``, or None when none
    matches. A caller holding its own record of a verification reuses this lookup rather than reimplementing it."""
    for item in items:
        if item.id == item_id and item.format == item_format:
            return item.data
    return None


def _measurement_dict(measurement: Measurement | Expected) -> dict[str, Any]:
    """A measurement as its platform and the registers that are set, each as lowercase hex."""
    if isinstance(measurement, SEVSNP | ExpectedSEVSNP):
        out: dict[str, Any] = {"platform": PLATFORM_SEV_SNP}
        if measurement.launch is not None:
            out["launch"] = measurement.launch.hex()
        return out
    out = {"platform": PLATFORM_TDX}
    for name in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"):
        value: bytes | None = getattr(measurement, name)
        if value is not None:
            out[name] = value.hex()
    return out


def _time(at: datetime | None) -> str | None:
    if at is None:
        return None
    return at.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _established(record: dict[str, Any]) -> dict[str, Any]:
    """``record`` without the facts that were not established: a None time or an empty string."""
    return {key: value for key, value in record.items() if value is not None and value != ""}


__all__ = [
    "SOURCE_EMBEDDED",
    "SOURCE_ENDORSEMENT",
    "SOURCE_POLICY",
    "ArtifactVerification",
    "ConfigVerification",
    "ReferenceSource",
    "SoftwareIdentity",
    "Verification",
    "VerificationMetadata",
    "crypto_material_data",
]
