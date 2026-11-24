"""The runtime pin that a Tinfoil config carries: its ``cvm-version`` names a runtime release and the SHA-256 digest of
that release's manifest."""

from __future__ import annotations

from tinfoil.verifier import _json
from tinfoil.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference

_DIGEST_SEPARATOR = "@sha256:"
_PREFIX = "parsing config runtime pin"


class RuntimeConfigError(ValueError):
    """A config whose runtime pin is missing or malformed."""


def runtime_from_config(data: bytes) -> RuntimeReference:
    """Extract the immutable runtime pin without changing the config bytes.

    The publisher and guest own validation of the workload's other fields;
    only ``cvm-version`` is read here.
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
    """The top-level ``cvm-version`` string, or "" when the key is absent or null."""
    try:
        return _json.string(_json.object_(_json.strict_parse(data), "config"), "cvm-version")
    except _json.JsonError as err:
        raise RuntimeConfigError(f"{_PREFIX}: {err}") from err
