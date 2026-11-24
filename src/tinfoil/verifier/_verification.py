"""The facts that verification proves about a document."""

from __future__ import annotations

import json
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from typing import Any, Final, Literal, TypeAlias

from tinfoil.verifier._document.document import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    CryptoMaterialItem,
)
from tinfoil.verifier._measurement import SEVSNP, Expected, ExpectedSEVSNP, Measurement
from tinfoil.verifier._policy import PLATFORM_SEV_SNP, PLATFORM_TDX

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
    """How a verification was performed. The verifier and the client that called it fill it in from their own
    state; none of it is attested by or checked against the document."""

    verifier: SoftwareIdentity
    """The SDK that performed the verification."""
    verified_at: datetime
    """The instant that the document was appraised at: read once from the local clock by ``verify_v3``, or the caller's
    verification time for ``verify_v3_at``. It is not a freshness guarantee."""
    host: str | None = None
    """The enclave that the client contacted for the document, a host with an optional port: for a router client the
    router that it chose, and for a gateway client the replica. It is what the client connected to, not an attested
    fact, so it proves nothing about the enclave. The verifier doesn't know the host and leaves it None; the clients
    set it on every report that they produce, and a caller that calls the verifier itself can set it on the report
    that it gets, with ``dataclasses.replace``."""


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedFacts:
    """The facts proven by the verification of an attestation document, including the channel keys that a caller
    binds its traffic to.

    The verifier creates one, as the ``verified_facts`` of a report on a
    document that it accepted; a hand-built value carries no proof. Every
    field is immutable: the registers are ``bytes``, the items are a tuple
    of frozen records and the times are timezone-aware datetimes. The
    metadata of the verification is on the report, not here.
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
    """The earliest approval or current CPU collateral deadline. Cached verification must not authorize requests
    at or after this time. Hardware bounds the result even when every reference is embedded; verifying the same
    evidence again does not extend its lifetime. Verifier-produced results always have a deadline; None is allowed
    for manually constructed records, which clients reject as unusable."""
    config: ConfigVerification | None = None
    """The config bound to hardware; None for verification against a code release, which has no config."""
    runtime: ArtifactVerification | None = None
    """The runtime that a config-based verification accepted; None for verification against a code release."""
    platform: ArtifactVerification | None = None
    """The platform endorsements that a config-based verification accepted; None for a code release."""

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
        """The ``verified_facts`` object of the report's JSON form, as a ``dict`` of JSON values:

        .. code-block:: text

            {
              "config_repo": "<owner/name>",
              "code_digest": "<hex>",
              "code_tag": "<tag>",
              "code_measurement": {"platform": "tdx", "rtmr1": "<hex>", "rtmr2": "<hex>"},
              "enclave_measurement": {"platform": "tdx", "mrtd": "<hex>", "rtmr0": "<hex>", ...},
              "config": {"source", "name", "digest", "reference", "signing_key_hint", "approval_time",
                         "registry_id", "signature_time"},
              "runtime": {"source", "repo", "tag", "digest", "name", "commit", "approval_time"},
              "platform": {"source", "repo", "tag", "digest", "name", "commit", "approval_time"},
              "crypto_material": [{"id": "tls", "format": "<format>", "data": "<hex>"}],
              "freshness_expires_at": "<RFC 3339, UTC>"
            }

        Registers are lowercase hex and times are RFC 3339 in UTC, written with ``Z``. A measurement names its
        platform, ``"sev-snp"`` with ``launch`` or ``"tdx"`` with ``mrtd`` and ``rtmr0`` to ``rtmr3``, and leaves
        out a register that the release leaves to the platform; a code measurement that would hold no register is
        left out. A fact that was not established is left out, never written as None or ``""``: ``config``,
        ``runtime`` and ``platform`` are present only for a config-based verification. The channel keys appear only
        in ``crypto_material``.

        The JSON is for display and transport only, and it authorizes nothing: nothing in this SDK parses it back
        into verified facts, and a holder of the JSON cannot tell whether a verifier produced it, so a channel
        binds only to the ``VerifiedFacts`` that a verification returned in process."""
        out: dict[str, Any] = _established({"config_repo": self.config_repo, "code_digest": self.code_digest})
        if self.code_tag:
            out["code_tag"] = self.code_tag
        code = code_measurement_dict(self.code_measurement)
        if code is not None:
            out["code_measurement"] = code
        out["enclave_measurement"] = measurement_dict(self.enclave_measurement)
        if self.config is not None:
            out["config"] = config_dict(self.config)
        for name, artifact in (("runtime", self.runtime), ("platform", self.platform)):
            if artifact is not None:
                out[name] = artifact_dict(artifact)
        out["crypto_material"] = [
            {"id": item.id, "format": item.format, "data": item.data} for item in self.crypto_material
        ]
        if self.freshness_expires_at is not None:
            out["freshness_expires_at"] = time_str(self.freshness_expires_at)
        return out

    def to_json(self, *, indent: int | None = None) -> str:
        """``to_dict`` serialized as JSON: compact by default, or pretty-printed with ``indent`` spaces per level."""
        return json_text(self.to_dict(), indent)


def json_text(value: dict[str, Any], indent: int | None) -> str:
    """``value`` as JSON text: compact when ``indent`` is None, and pretty-printed with ``indent`` spaces per level
    otherwise."""
    if indent is None:
        return json.dumps(value, separators=(",", ":"))
    return json.dumps(value, indent=indent)


def crypto_material_data(items: tuple[CryptoMaterialItem, ...], item_id: str, item_format: str) -> str | None:
    """The data of the one item among ``items`` with exactly ``item_id`` and ``item_format``, or None when none
    matches. A caller holding its own record of a verification reuses this lookup rather than reimplementing it."""
    for item in items:
        if item.id == item_id and item.format == item_format:
            return item.data
    return None


def config_dict(config: ConfigVerification) -> dict[str, Any]:
    """``config`` as the report's JSON form lays it out, without the facts that were not established."""
    return _established(
        {
            "source": config.source,
            "name": config.name,
            "digest": config.digest,
            "reference": config.reference,
            "signing_key_hint": config.signing_key_hint,
            "approval_time": time_str(config.approval_time),
            "registry_id": config.registry_id,
            "signature_time": time_str(config.signature_time),
        }
    )


def artifact_dict(artifact: ArtifactVerification) -> dict[str, Any]:
    """``artifact`` as the report's JSON form lays it out, without the facts that were not established."""
    return _established(
        {
            "source": artifact.source,
            "repo": artifact.repo,
            "tag": artifact.tag,
            "digest": artifact.digest,
            "name": artifact.name,
            "commit": artifact.commit,
            "approval_time": time_str(artifact.approval_time),
        }
    )


def measurement_dict(measurement: Measurement | Expected) -> dict[str, Any]:
    """A measurement as the report's JSON form writes it: its platform and the registers that are set, each as
    lowercase hex."""
    if isinstance(measurement, SEVSNP | ExpectedSEVSNP):
        out: dict[str, Any] = {"platform": PLATFORM_SEV_SNP}
        if measurement.launch is not None:
            out["launch"] = measurement.launch.hex()
        return out
    out = {"platform": PLATFORM_TDX}
    # Every field of a TDX record is a register, so the record itself names them.
    for register in fields(measurement):
        value: bytes | None = getattr(measurement, register.name)
        if value is not None:
            out[register.name] = value.hex()
    return out


def code_measurement_dict(measurement: Expected | None) -> dict[str, Any] | None:
    """The registers that a release fixes, as ``measurement_dict`` writes them, or None when it fixes none, so that a
    code measurement without a register is left out."""
    if measurement is None:
        return None
    out = measurement_dict(measurement)
    return out if len(out) > 1 else None


def time_str(at: datetime | None) -> str | None:
    """``at`` as RFC 3339 in UTC, written with ``Z``, or None for a time that was not established."""
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
    "VerificationMetadata",
    "VerifiedFacts",
    "crypto_material_data",
]
