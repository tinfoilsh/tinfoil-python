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
        if key == "cvm-version":
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
