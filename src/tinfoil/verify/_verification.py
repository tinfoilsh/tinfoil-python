"""The result of a successful verification."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from . import _formats
from .document import CryptoMaterialItem
from .measurement import Measurement


class ReferenceSource(StrEnum):
    """Why reference values were accepted."""

    ENDORSEMENT = "endorsement"
    """A signed endorsement was authenticated."""
    EMBEDDED = "embedded"
    """The caller embedded the values in its verifier."""
    POLICY = "policy"
    """The caller's config authorizer approved them."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigVerification:
    """The config bound to the hardware.

    Configs approved by a caller's authorizer have no name, reference,
    signing key hint or approval time.
    """

    source: ReferenceSource
    digest: str
    name: str | None = None
    reference: str | None = None
    signing_key_hint: str | None = None
    approval_time: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactVerification:
    """Accepted reference values and their authority.

    Embedded artifacts have no authenticated commit or approval time.
    """

    source: ReferenceSource
    digest: str
    repo: str | None = None
    tag: str | None = None
    name: str | None = None
    commit: str | None = None
    approval_time: datetime | None = None


@dataclass(frozen=True, slots=True)
class SoftwareIdentity:
    """Identifies software involved in a verification."""

    name: str
    version: str


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationMetadata:
    """How a verification was performed.

    The verifier fills this in from its own state; none of it is attested by
    or checked against the document.
    """

    verifier: SoftwareIdentity
    """The SDK that performed the verification."""
    verified_at: datetime
    """The instant the document was appraised at. Not a freshness guarantee."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Verification:
    """The facts a verified attestation document proves."""

    config_repo: str | None
    """The selected code or runtime repository, without version pins."""
    code_digest: str
    code_tag: str | None
    code_measurement: Measurement
    enclave_measurement: Measurement
    """The quote's authenticated registers, proven to match the expectations."""
    crypto_material: tuple[CryptoMaterialItem, ...]
    """The endorsed keys, hash-bound into the quote."""
    freshness_expires_at: datetime | None
    """When cached verification stops authorizing new requests.

    The earliest authenticated witness or approval deadline. Verifying the
    same witnesses again does not extend it. None when every reference value
    was embedded, in which case the caller owns renewal.
    """
    metadata: VerificationMetadata
    config: ConfigVerification | None = None
    runtime: ArtifactVerification | None = None
    platform: ArtifactVerification | None = None

    @property
    def tls_public_key_fp(self) -> str | None:
        """The endorsed TLS key fingerprint, or None if the document endorses none.

        A ``tls`` item in another format does not count.
        """
        return self.crypto_material_data(_formats.CRYPTO_MATERIAL_ID_TLS, _formats.KEY_SPKI_FP_SHA256_V1)

    @property
    def hpke_public_key(self) -> str | None:
        """The endorsed HPKE public key, or None if the document endorses none.

        An ``hpke`` item in another format does not count.
        """
        return self.crypto_material_data(_formats.CRYPTO_MATERIAL_ID_HPKE, _formats.KEY_X25519_HPKE_V1)

    def crypto_material_data(self, item_id: str, item_format: str) -> str | None:
        """The endorsed lowercase-hex data for exactly ``item_id`` and ``item_format``.

        A lookup does not refresh evidence or enforce freshness_expires_at.
        """
        return crypto_material_data(self.crypto_material, item_id, item_format)


def crypto_material_data(items: Iterable[CryptoMaterialItem], item_id: str, item_format: str) -> str | None:
    """Look up exactly ``item_id`` and ``item_format`` among endorsed key items.

    For callers that keep their own record of a verification.
    """
    return next((item.data for item in items if item.id == item_id and item.format == item_format), None)
