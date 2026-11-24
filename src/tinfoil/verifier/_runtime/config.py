"""The runtime pin that a Tinfoil config carries: its ``cvm-version`` names a runtime release and the SHA-256 digest of
that release's manifest."""

from __future__ import annotations

from tinfoil.verifier import _json
from tinfoil.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference

_VERSION_KEY = "cvm-version"
_DIGEST_SEPARATOR = "@sha256:"
_PREFIX = "parsing config runtime pin"
_NOT_A_JSON_CONFIG = f"{_PREFIX}: not a JSON config that states cvm-version; YAML configs are not read"


class RuntimeConfigError(ValueError):
    """A config whose runtime pin is missing or malformed."""


def runtime_from_config(data: bytes) -> RuntimeReference:
    """Extract the immutable runtime pin without changing the config bytes.

    The publisher and guest own validation of the workload's other fields;
    only ``cvm-version`` is read here, from a JSON config. A YAML config is
    not read.
    """
    version, found, digest = _read_cvm_version(data).partition(_DIGEST_SEPARATOR)
    if not found:
        raise RuntimeConfigError("cvm-version must pin a runtime manifest SHA-256 digest")
    reference = RuntimeReference(repo=RUNTIME_REPO, tag="v" + version.removeprefix("v"), digest=digest)
    try:
        reference.validate()
    except ValueError as err:
        raise RuntimeConfigError(str(err)) from err
    return reference


def _read_cvm_version(data: bytes) -> str:
    """The top-level ``cvm-version`` string of a config that is one JSON object. Anything else, such as a YAML config,
    is an error."""
    try:
        config = _json.strict_parse(data)
    except _json.JsonError as err:
        raise RuntimeConfigError(_NOT_A_JSON_CONFIG) from err
    if not isinstance(config, _json.JsonObject):
        raise RuntimeConfigError(_NOT_A_JSON_CONFIG)
    pin = config.get(_VERSION_KEY)
    if not isinstance(pin, str):
        raise RuntimeConfigError(_NOT_A_JSON_CONFIG)
    return pin
