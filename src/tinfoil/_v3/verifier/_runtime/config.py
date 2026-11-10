"""The runtime pin that a Tinfoil config carries: its ``cvm-version`` names a runtime release and the SHA-256 digest of
that release's manifest."""

from __future__ import annotations

import yaml

from tinfoil._v3.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference

_DIGEST_SEPARATOR = "@sha256:"
_MERGE_TAG = "tag:yaml.org,2002:merge"
_BINARY_TAG = "tag:yaml.org,2002:binary"
_VALUE_TAGS = frozenset(f"tag:yaml.org,2002:{kind}" for kind in ("int", "float", "bool", "null"))
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
    """The text of the top-level ``cvm-version`` scalar, or "" when the key is absent.

    The config must hold exactly one YAML document, a mapping. Any scalar
    value reads as its source text, so a null reads as text that carries no
    pin. The key is found without constructing the rest of the document, so
    the other members are only required to be well-formed YAML, except that
    the top-level mapping must not repeat a key: two keys are the same when
    their source text is the same or, for numbers, booleans and nulls, when
    their values are. A merge key at the top level, a non-scalar key, a
    non-scalar value and a binary-tagged value are rejected.
    """
    try:
        documents = yaml.compose_all(data, Loader=yaml.SafeLoader)
        root = next(documents, None)
        if root is None:
            raise RuntimeConfigError(f"{_PREFIX}: EOF")
        if next(documents, None) is not None:
            raise RuntimeConfigError("config must contain exactly one YAML document")
    except yaml.YAMLError as err:
        raise RuntimeConfigError(f"{_PREFIX}: {err}") from err
    if not isinstance(root, yaml.MappingNode):
        raise RuntimeConfigError(f"{_PREFIX}: config is not a mapping")
    value_node: object = None
    seen: set[object] = set()
    for key_node, item_node in root.value:
        if not isinstance(key_node, yaml.ScalarNode):
            raise RuntimeConfigError(f"{_PREFIX}: mapping keys must be scalars")
        if key_node.tag == _MERGE_TAG:
            raise RuntimeConfigError(f"{_PREFIX}: merge keys are not supported")
        identities = _key_identities(key_node)
        if not seen.isdisjoint(identities):
            raise RuntimeConfigError(f"{_PREFIX}: mapping key {key_node.value!r} already defined")
        seen.update(identities)
        if key_node.value == "cvm-version":
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


def _key_identities(key: yaml.ScalarNode) -> set[object]:
    """What a top-level key is compared by: its source text and, when it resolves to a number, boolean or null, the
    value, so that differently spelled equal values collide."""
    identities: set[object] = {("text", key.value)}
    if key.tag in _VALUE_TAGS:
        try:
            value = yaml.constructor.SafeConstructor().construct_object(key)
        except yaml.YAMLError:
            return identities
        if isinstance(value, int | float) or value is None:
            identities.add(("value", value))
    return identities
