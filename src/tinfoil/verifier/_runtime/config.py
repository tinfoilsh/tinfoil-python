"""The runtime pin that a Tinfoil config carries: its ``cvm-version`` names a runtime release and the SHA-256 digest of
that release's manifest."""

from __future__ import annotations

import re

import yaml

from tinfoil.verifier import _json, _semver
from tinfoil.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference

JSON_CONFIG_MIN_VERSION = "v0.15.5-rc.1"
"""The first ``cvm-version`` whose config is JSON. A config that pins it or a later version is canonical JSON, and
YAML is refused; earlier versions keep YAML."""

_VERSION_KEY = "cvm-version"
_DIGEST_SEPARATOR = "@sha256:"
_MERGE_TAG = "tag:yaml.org,2002:merge"
_BINARY_TAG = "tag:yaml.org,2002:binary"
_STR_TAG = "tag:yaml.org,2002:str"
_PREFIX = "parsing config runtime pin"
_JSON_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)")
_MAX_JSON_INTEGER = (1 << 53) - 1
"""The largest integer that every JSON implementation reads exactly."""


class RuntimeConfigError(ValueError):
    """A config whose runtime pin is missing or malformed."""


def runtime_from_config(data: bytes) -> RuntimeReference:
    """Extract the immutable runtime pin without changing the config bytes.

    The publisher and guest own validation of the workload's other fields;
    only ``cvm-version`` is read here. The pinned version selects the
    format: a config that pins JSON_CONFIG_MIN_VERSION or a later version
    is JSON in its one byte form, and an earlier one is YAML.
    """
    stated = _json_config_pin(data)
    if stated is not None and _requires_json(stated[1]):
        config, pin = stated
        _check_json_config_form(data, config)
        return _runtime_from_pin(pin)
    pin = _read_cvm_version(data)
    reference = _runtime_from_pin(pin)
    if _requires_json(pin):
        raise RuntimeConfigError(f"cvm-version {JSON_CONFIG_MIN_VERSION} and later take a JSON config")
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


def _json_config_pin(data: bytes) -> tuple[_json.JsonObject, str] | None:
    """The config read as a JSON object, with the ``cvm-version`` that it states; None when the bytes are not a JSON
    object that states one as a string."""
    try:
        config = _json.strict_parse(data)
    except _json.JsonError:
        return None
    if not isinstance(config, _json.JsonObject):
        return None
    pin = config.get(_VERSION_KEY)
    if not isinstance(pin, str):
        return None
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


def _read_cvm_version(data: bytes) -> str:
    """The text of the top-level ``cvm-version`` scalar, or "" when the key is absent.

    The config must hold exactly one YAML document, a mapping. Any scalar
    value reads as its source text, so a null reads as text that carries no
    pin. The key is found without constructing the rest of the document, so
    the other members are only required to be well-formed YAML, except at
    the top-level mapping: every key there must be a plain string (a scalar
    that resolves to the string tag, so a quoted ``"5"`` passes and a bare
    ``5``, ``true`` or ``~`` does not), and no key may repeat. A merge key
    at the top level, a non-scalar value and a binary-tagged value are
    rejected.
    """
    try:
        documents = yaml.compose_all(data, Loader=yaml.SafeLoader)
        root = next(documents, None)
        second = None if root is None else next(documents, None)
    except (yaml.YAMLError, ValueError) as err:
        # The scanner raises a ValueError of its own for a quoted escape
        # that names a code point beyond the Unicode range.
        raise RuntimeConfigError(f"{_PREFIX}: {err}") from err
    except RecursionError as err:
        # Composition recurses once per nesting level, so a document nested
        # deeper than the interpreter allows is rejected rather than crashing.
        raise RuntimeConfigError(f"{_PREFIX}: config is nested too deeply") from err
    if root is None:
        raise RuntimeConfigError(f"{_PREFIX}: EOF")
    if second is not None:
        raise RuntimeConfigError("config must contain exactly one YAML document")
    if not isinstance(root, yaml.MappingNode):
        raise RuntimeConfigError(f"{_PREFIX}: config is not a mapping")
    value_node: object = None
    seen: set[str] = set()
    for key_node, item_node in root.value:
        if not isinstance(key_node, yaml.ScalarNode):
            raise RuntimeConfigError(f"{_PREFIX}: mapping keys must be scalars")
        if key_node.tag == _MERGE_TAG:
            raise RuntimeConfigError(f"{_PREFIX}: merge keys are not supported")
        if key_node.tag != _STR_TAG or not isinstance(key_node.value, str):
            raise RuntimeConfigError(f"{_PREFIX}: config keys must be plain strings")
        key: str = key_node.value
        if key in seen:
            raise RuntimeConfigError(f"{_PREFIX}: mapping key {key!r} already defined")
        seen.add(key)
        if key == _VERSION_KEY:
            value_node = item_node
    if value_node is None:
        return ""
    if not isinstance(value_node, yaml.ScalarNode):
        raise RuntimeConfigError(f"{_PREFIX}: cvm-version must be a scalar")
    if value_node.tag == _BINARY_TAG:
        raise RuntimeConfigError(f"{_PREFIX}: cvm-version must not be binary")
    text = value_node.value
    if not isinstance(text, str):
        raise RuntimeConfigError(f"{_PREFIX}: cvm-version must be a scalar")
    return text
