"""The runtime pin that a Tinfoil config carries: its ``cvm-version`` names a runtime release and the SHA-256 digest of
that release's manifest."""

from __future__ import annotations

import yaml

from tinfoil.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference

_DIGEST_SEPARATOR = "@sha256:"
_MERGE_TAG = "tag:yaml.org,2002:merge"
_BINARY_TAG = "tag:yaml.org,2002:binary"
_STR_TAG = "tag:yaml.org,2002:str"
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
    the other members are only required to be well-formed YAML, except at
    the top-level mapping: every key there must be a plain string (a scalar
    that resolves to the string tag, so a quoted ``"5"`` passes and a bare
    ``5``, ``true`` or ``~`` does not), and no key may repeat. A merge key
    at the top level, a non-scalar value and a binary-tagged value are
    rejected.
    """
    root = compose_config(data, _PREFIX, RuntimeConfigError)
    value_node = mapping_members(root, _PREFIX, RuntimeConfigError).get("cvm-version")
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


def compose_config(data: bytes, prefix: str, error: type[ValueError]) -> yaml.MappingNode:
    """The config's one YAML document, composed without constructing it; it must be a mapping. A failure raises
    ``error``, with ``prefix`` naming what was being read."""
    try:
        documents = yaml.compose_all(data, Loader=yaml.SafeLoader)
        root = next(documents, None)
        second = None if root is None else next(documents, None)
    except (yaml.YAMLError, ValueError) as err:
        # The scanner raises a ValueError of its own for a quoted escape
        # that names a code point beyond the Unicode range.
        raise error(f"{prefix}: {err}") from err
    except RecursionError as err:
        # Composition recurses once per nesting level, so a document nested
        # deeper than the interpreter allows is rejected rather than crashing.
        raise error(f"{prefix}: config is nested too deeply") from err
    if root is None:
        raise error(f"{prefix}: EOF")
    if second is not None:
        raise error("config must contain exactly one YAML document")
    if not isinstance(root, yaml.MappingNode):
        raise error(f"{prefix}: config is not a mapping")
    return root


def mapping_members(
    node: yaml.MappingNode, prefix: str, error: type[ValueError], merged: list[yaml.Node] | None = None
) -> dict[str, yaml.Node]:
    """The members of a mapping by key. Every key must be a plain string and no key may repeat. The value of the
    mapping's merge key is appended to ``merged``; without ``merged``, a merge key is rejected. A failure raises
    ``error``, with ``prefix`` naming what was being read."""
    members: dict[str, yaml.Node] = {}
    for key_node, item_node in node.value:
        if not isinstance(key_node, yaml.ScalarNode):
            raise error(f"{prefix}: mapping keys must be scalars")
        if key_node.tag == _MERGE_TAG:
            if merged is None:
                raise error(f"{prefix}: merge keys are not supported")
            if merged:
                raise error(f"{prefix}: mapping key {key_node.value!r} already defined")
            merged.append(item_node)
            continue
        if key_node.tag != _STR_TAG or not isinstance(key_node.value, str):
            raise error(f"{prefix}: config keys must be plain strings")
        key: str = key_node.value
        if key in members:
            raise error(f"{prefix}: mapping key {key!r} already defined")
        members[key] = item_node
    return members
