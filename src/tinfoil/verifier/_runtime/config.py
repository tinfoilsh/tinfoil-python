"""The runtime pin that a Tinfoil config carries: its ``cvm-version`` names a runtime release and the SHA-256 digest of
that release's manifest."""

from __future__ import annotations

import re

from tinfoil.verifier import _json, _semver
from tinfoil.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference

JSON_CONFIG_MIN_VERSION = "v0.15.5-rc.1"
"""The first ``cvm-version`` whose config is JSON. A config that pins it or a later version is canonical JSON.
Earlier versions measure YAML, which this package does not read."""

_VERSION_KEY = "cvm-version"
_DIGEST_SEPARATOR = "@sha256:"
_PREFIX = "parsing config runtime pin"
_JSON_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)")
_MAX_JSON_INTEGER = (1 << 53) - 1
"""The largest integer that every JSON implementation reads exactly."""
_NOT_A_JSON_CONFIG = (
    f"{_PREFIX}: not a JSON config that states cvm-version; "
    f"the YAML configs of versions before {JSON_CONFIG_MIN_VERSION} are not read"
)


class RuntimeConfigError(ValueError):
    """A config whose runtime pin is missing or malformed."""


def runtime_from_config(data: bytes) -> RuntimeReference:
    """Extract the immutable runtime pin without changing the config bytes.

    The publisher and guest own validation of the workload's other fields;
    only ``cvm-version`` is read here. The config is JSON in its one byte
    form, which is what ``cvm-version`` JSON_CONFIG_MIN_VERSION and later
    measure. The YAML that earlier versions measure is not read.
    """
    config, pin = _json_config_pin(data)
    reference = _runtime_from_pin(pin)
    if not _requires_json(pin):
        raise RuntimeConfigError(f"a JSON config pins cvm-version {JSON_CONFIG_MIN_VERSION} or later")
    _check_json_config_form(data, config)
    return reference


def _runtime_from_pin(pin: str) -> RuntimeReference:
    version, found, digest = pin.partition(_DIGEST_SEPARATOR)
    if not found:
        raise RuntimeConfigError("cvm-version must pin a runtime manifest SHA-256 digest")
    reference = RuntimeReference(repo=RUNTIME_REPO, tag="v" + version.removeprefix("v"), digest=digest)
    try:
        reference.validate()
    except ValueError as err:
        raise RuntimeConfigError(str(err)) from err
    return reference


def _requires_json(pin: str) -> bool:
    """Whether a config with this ``cvm-version`` must be JSON. A version that is not valid does not require it."""
    version = pin.partition(_DIGEST_SEPARATOR)[0]
    return _semver.compare("v" + version.removeprefix("v"), JSON_CONFIG_MIN_VERSION) >= 0


def _json_config_pin(data: bytes) -> tuple[_json.JsonObject, str]:
    """The config read as a JSON object, with the ``cvm-version`` that it states as a string. Anything else, such
    as a YAML config, is an error."""
    try:
        config = _json.strict_parse(data)
    except _json.JsonError as err:
        raise RuntimeConfigError(_NOT_A_JSON_CONFIG) from err
    if not isinstance(config, _json.JsonObject):
        raise RuntimeConfigError(_NOT_A_JSON_CONFIG)
    pin = config.get(_VERSION_KEY)
    if not isinstance(pin, str):
        raise RuntimeConfigError(_NOT_A_JSON_CONFIG)
    return config, pin


def _check_json_config_form(data: bytes, config: _json.JsonObject) -> None:
    """Require the one byte form that a JSON config has: RFC 8785 canonical JSON whose numbers are integers that
    every implementation reads exactly, without null. No two parsers can then read its bytes differently."""
    # Depth first in member order, so the first violation in the bytes is the one reported.
    pending: list[_json.JsonValue] = [config]
    while pending:
        value = pending.pop()
        if value is None:
            raise RuntimeConfigError(f"{_PREFIX}: null is not allowed in a JSON config")
        if isinstance(value, _json.JsonNumber) and not _is_exact_integer(value.raw):
            raise RuntimeConfigError(
                f"{_PREFIX}: number {value.raw} in a JSON config is not an integer between -(2^53-1) and 2^53-1"
            )
        if isinstance(value, tuple):
            pending.extend(reversed(value))
        elif isinstance(value, _json.JsonObject):
            pending.extend(reversed(tuple(value.values())))
    try:
        canonical = _json.canonicalize(config)
    except _json.JsonError as err:
        raise RuntimeConfigError(f"{_PREFIX}: {err}") from err
    if canonical != data:
        raise RuntimeConfigError(f"{_PREFIX}: JSON config is not in canonical form (RFC 8785)")


def _is_exact_integer(literal: str) -> bool:
    """Whether a JSON number literal is an integer of magnitude at most _MAX_JSON_INTEGER.

    The literal is judged as written: a fraction or an exponent is not an
    integer whatever its value, and one with more digits than the bound is
    out of range without being converted, since the interpreter caps the
    digits that it converts.
    """
    if not _JSON_INTEGER.fullmatch(literal):
        return False
    digits = literal.removeprefix("-")
    return len(digits) <= len(str(_MAX_JSON_INTEGER)) and int(digits) <= _MAX_JSON_INTEGER
