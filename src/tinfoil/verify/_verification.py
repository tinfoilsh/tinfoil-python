"""The result of a successful verification."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from . import _formats
from .document import CryptoMaterialItem
from .measurement import Measurement


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

    # The SDK that performed the verification.
    verifier: SoftwareIdentity
    # The instant the document was appraised at. Not a freshness guarantee.
    verified_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class Verification:
    """The facts a verified attestation document proves."""

    # The verified code repository, without version pins.
    config_repo: str
    code_digest: str
    code_tag: str
    code_measurement: Measurement
    # The quote's authenticated registers, proven to match the expectations.
    enclave_measurement: Measurement
    # The endorsed keys, hash-bound into the quote.
    crypto_material: tuple[CryptoMaterialItem, ...]
    # When cached verification stops authorizing new requests: the earlier of
    # the code and platform freshness witness deadlines. Verifying the same
    # witnesses again does not extend it.
    freshness_expires_at: datetime
    metadata: VerificationMetadata

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
        """Return the endorsed lowercase-hex data for exactly ``item_id`` and ``item_format``, or None.

        A lookup does not refresh evidence or enforce freshness_expires_at.
        """
        return crypto_material_data(self.crypto_material, item_id, item_format)


def crypto_material_data(items: Iterable[CryptoMaterialItem], item_id: str, item_format: str) -> str | None:
    """Return the data of the endorsed item with exactly ``item_id`` and ``item_format``, or None.

    For callers that keep their own record of a verification.
    """
    return next((item.data for item in items if item.id == item_id and item.format == item_format), None)
