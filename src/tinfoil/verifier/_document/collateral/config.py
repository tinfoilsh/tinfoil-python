"""Config reference-values collateral: an exact config and its registry approval."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil.verifier import _json
from tinfoil.verifier._canonical import decode_base64, decode_lower_hex
from tinfoil.verifier._document.collateral.entry import Entry, unmarshal_data

CONFIG_ENDORSEMENT_V1_FORMAT = "https://tinfoil.sh/collateral/config-endorsement/v1"
"""An exact config and its timestamped registry approval bundle."""
CONFIG_ENDORSEMENT_V2_FORMAT = "https://tinfoil.sh/collateral/config-endorsement/v2"
CONFIG_V1_FORMAT = "https://tinfoil.sh/collateral/config/v1"
"""Exact config bytes authorized by caller policy."""

CONFIG_FORMATS = (CONFIG_ENDORSEMENT_V1_FORMAT, CONFIG_ENDORSEMENT_V2_FORMAT, CONFIG_V1_FORMAT)

CONFIG_ID = "tinfoil-config"
"""The id of the config-endorsement entry."""


class ConfigCollateralError(ValueError):
    """Config collateral that violates its format's shape."""


@dataclass(frozen=True, slots=True)
class ConfigEndorsement:
    """Untrusted config material decoded from a document.

    Plain config collateral has no reference or bundle and requires caller
    authorization. A signed reference must match the independently verified
    endorsement. A config authorizer decides on ``config``; nothing here has
    been authenticated when it runs.
    """

    reference: str
    """The endorsement reference, ``sha256:<hex>``; ``""`` for plain config collateral."""
    config: bytes | None
    """The exact config bytes; None when v2 endorsement collateral carries only the reference."""
    bundle: bytes | None
    """The entry's Sigstore bundle as JSON bytes; None for plain config collateral."""
    issuer: bytes | None
    """The DER issuer certificate of a certified endorsement, or None."""


_MEMBERS = ("endorsement_ref", "config_base64", "sigstore_bundle", "issuer_certificate_der")


def decode_config_endorsement(entry: Entry) -> ConfigEndorsement:
    data = unmarshal_data(entry, entry.format, _MEMBERS)
    reference = _json.string(data, "endorsement_ref")
    encoded_config = _json.string(data, "config_base64")
    raw_bundle = _json.raw(data, "sigstore_bundle")
    encoded_issuer = _json.string(data, "issuer_certificate_der")

    if encoded_issuer != "" and entry.format != CONFIG_ENDORSEMENT_V2_FORMAT:
        raise ConfigCollateralError("issuer certificates require v2 config collateral")
    if entry.format == CONFIG_V1_FORMAT:
        if reference != "" or "sigstore_bundle" in data:
            raise ConfigCollateralError("plain config collateral cannot contain an endorsement")
    else:
        if not reference.startswith("sha256:"):
            raise ConfigCollateralError("endorsement_ref must be a SHA-256 reference")
        decode_lower_hex("endorsement_ref", reference.removeprefix("sha256:"), 32)
        if not isinstance(raw_bundle, _json.JsonObject):
            raise ConfigCollateralError("sigstore_bundle must be an object")

    bundle = None if raw_bundle is None else _json.serialize(raw_bundle)
    issuer = decode_base64("issuer_certificate_der", encoded_issuer) if encoded_issuer != "" else None
    if entry.format == CONFIG_ENDORSEMENT_V2_FORMAT and encoded_config == "":
        return ConfigEndorsement(reference=reference, config=None, bundle=bundle, issuer=issuer)
    config = decode_base64("config_base64", encoded_config)
    if len(config) == 0:
        raise ConfigCollateralError("config_base64 must not be empty")
    return ConfigEndorsement(reference=reference, config=config, bundle=bundle, issuer=issuer)
