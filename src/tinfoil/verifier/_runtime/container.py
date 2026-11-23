"""The builds that a Tinfoil config requires for its container images: a container's ``provenance`` names the
GitHub Actions workflow run that must have produced the image that it pins."""

from __future__ import annotations

import re
from dataclasses import dataclass

import yaml

from tinfoil.verifier._runtime.config import compose_config, mapping_members

_NULL_TAG = "tag:yaml.org,2002:null"
_BINARY_TAG = "tag:yaml.org,2002:binary"
_STR_TAG = "tag:yaml.org,2002:str"
_INT_TAG = "tag:yaml.org,2002:int"
_MAP_TAG = "tag:yaml.org,2002:map"
_PREFIX = "parsing config provenance"

_PROVENANCE_FIELDS = ("github",)
_GITHUB_FIELDS = ("repository", "repository_id", "workflow", "ref")

# A verifier builds a regular expression from these values, so their length
# bounds its size.
_MAX_REPOSITORY_LENGTH = 140
_MAX_WORKFLOW_LENGTH = 255
_MAX_REF_LENGTH = 255
_MAX_REPOSITORY_ID_DIGITS = 18

# The patterns are applied with ``fullmatch`` so that a trailing newline never
# slips past the end.
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
# YAML libraries disagree on other spellings of an integer, such as a leading
# zero, so the ID must be written in plain decimal.
_REPOSITORY_ID_RE = re.compile(rf"[1-9][0-9]{{0,{_MAX_REPOSITORY_ID_DIGITS - 1}}}")
_WORKFLOW_RE = re.compile(r"[A-Za-z0-9_.-]+\.ya?ml")
_REF_RE = re.compile(r"refs/(?:tags|heads)/[A-Za-z0-9_.*-]+(?:/[A-Za-z0-9_.*-]+)*")
# The name excludes the ASCII whitespace characters, spelled out because
# ``\s`` also excludes other separators.
_IMAGE_DIGEST_RE = re.compile(r"[^@\t\n\f\r ]+@sha256:([0-9a-f]{64})")


class ContainerConfigError(ValueError):
    """A config whose container build requirements cannot be read in full."""


@dataclass(frozen=True, slots=True)
class ContainerProvenance:
    """The build that a config requires for one container image: a GitHub Actions workflow run in a named
    repository."""

    container: str
    digest: str
    """The image's SHA-256 digest as lowercase hex."""
    repository: str
    repository_id: str
    """The repository's numeric ID in decimal."""
    workflow: str
    ref: str
    """A tag or branch ref pattern in which ``*`` matches any run of characters other than ``/``."""


def container_provenance_from_config(data: bytes) -> tuple[ContainerProvenance, ...]:
    """The build requirements that a config declares, in container order.

    A requirement that cannot be read in full is rejected, so that a
    verifier never treats an unknown kind of requirement as met. The config
    must hold exactly one YAML document, a mapping, whose ``containers`` are
    mappings. Both have plain string keys, none repeated, and their merge
    keys are resolved. An absent or null ``provenance`` declares no
    requirement.
    """
    root = compose_config(data, _PREFIX, ContainerConfigError)
    containers = _members(root, _PREFIX).get("containers")
    if containers is None or _is_null(containers):
        return ()
    if not isinstance(containers, yaml.SequenceNode):
        raise ContainerConfigError(f"{_PREFIX}: containers must be a sequence")
    requirements: list[ContainerProvenance] = []
    for index, container in enumerate(containers.value):
        path = f"containers[{index}]"
        if _is_null(container):
            continue
        if not isinstance(container, yaml.MappingNode):
            raise ContainerConfigError(f"{_PREFIX}: {path} must be a mapping")
        members = _members(container, f"{_PREFIX}: {path}")
        name = _text(members.get("name"), f"{_PREFIX}: {path}.name")
        image = _text(members.get("image"), f"{_PREFIX}: {path}.image")
        provenance = members.get("provenance")
        if provenance is None or _is_null(provenance):
            continue
        repository, repository_id, workflow, ref = _github_provenance(provenance, f"{path}.provenance")
        digest = _IMAGE_DIGEST_RE.fullmatch(image)
        if digest is None:
            raise ContainerConfigError(f"{path}.image must pin a SHA-256 digest to declare provenance")
        requirements.append(
            ContainerProvenance(
                container=name,
                digest=digest[1],
                repository=repository,
                repository_id=repository_id,
                workflow=workflow,
                ref=ref,
            )
        )
    return tuple(requirements)


def _members(node: yaml.MappingNode, what: str) -> dict[str, yaml.Node]:
    """The members of a mapping with its merge keys resolved.

    The mapping's own members take precedence over those that it merges, an
    earlier merged mapping over a later one, and a merged mapping's own
    members over those that it merges in turn. A mapping that merges itself
    is rejected.
    """
    members: dict[str, yaml.Node] = {}
    merging: set[int] = set()
    read: set[int] = set()
    pending: list[tuple[yaml.MappingNode, bool]] = [(node, False)]
    while pending:
        mapping, finished = pending.pop()
        if finished:
            merging.discard(id(mapping))
            read.add(id(mapping))
            continue
        if id(mapping) in merging:
            raise ContainerConfigError(f"{what}: a merged mapping contains itself")
        if id(mapping) in read:
            continue
        merging.add(id(mapping))
        pending.append((mapping, True))
        merged: list[yaml.Node] = []
        for key, item in mapping_members(mapping, what, ContainerConfigError, merged).items():
            members.setdefault(key, item)
        pending.extend((source, False) for source in reversed(_merge_sources(merged, what)))
    return members


def _merge_sources(merged: list[yaml.Node], what: str) -> list[yaml.MappingNode]:
    """The mappings that a mapping's merge key names, in order: its value is a mapping or a sequence of
    mappings."""
    sources: list[yaml.MappingNode] = []
    for value in merged:
        for source in value.value if isinstance(value, yaml.SequenceNode) else [value]:
            if not isinstance(source, yaml.MappingNode):
                raise ContainerConfigError(f"{what}: a merge key requires a mapping or a sequence of mappings")
            sources.append(source)
    return sources


def _github_provenance(node: yaml.Node, path: str) -> tuple[str, str, str, str]:
    """The repository, its ID, the workflow and the ref pattern of a ``provenance`` member, whose one known kind of
    requirement is ``github``."""
    github = _known_fields(node, path, _PROVENANCE_FIELDS).get("github")
    path = f"{path}.github"
    if github is None:
        raise ContainerConfigError(f"{path} is required")
    fields = _known_fields(github, path, _GITHUB_FIELDS)
    repository = _text(fields.get("repository"), f"{path}.repository")
    repository_id = _repository_id(fields.get("repository_id"))
    workflow = _text(fields.get("workflow"), f"{path}.workflow")
    ref = _text(fields.get("ref"), f"{path}.ref")
    if len(repository) > _MAX_REPOSITORY_LENGTH or _REPOSITORY_RE.fullmatch(repository) is None:
        raise ContainerConfigError(f"{path}.repository {repository!r} must be owner/name")
    if repository_id is None:
        raise ContainerConfigError(f"{path}.repository_id must be the repository's numeric ID")
    if len(workflow) > _MAX_WORKFLOW_LENGTH or _WORKFLOW_RE.fullmatch(workflow) is None:
        raise ContainerConfigError(f"{path}.workflow {workflow!r} must be a workflow file name")
    if len(ref) > _MAX_REF_LENGTH or _REF_RE.fullmatch(ref) is None:
        raise ContainerConfigError(f"{path}.ref {ref!r} must be a tag or branch ref pattern")
    return repository, repository_id, workflow, ref


def _known_fields(node: yaml.Node, path: str, allowed: tuple[str, ...]) -> dict[str, yaml.Node]:
    """The members of a mapping that may only hold the ``allowed`` fields, each at most once and each named by a
    plain string. A key that is not a scalar reads as the empty name, which no mapping allows. A mapping that is
    tagged as anything else, such as a null, is not a mapping."""
    if not isinstance(node, yaml.MappingNode) or node.tag != _MAP_TAG:
        raise ContainerConfigError(f"{path} must be a mapping")
    fields: dict[str, yaml.Node] = {}
    for key_node, item_node in node.value:
        field: str = key_node.value if isinstance(key_node, yaml.ScalarNode) else ""
        if field in fields:
            raise ContainerConfigError(f"{path} has duplicate field {field!r}")
        if field not in allowed or key_node.tag != _STR_TAG:
            raise ContainerConfigError(f"{path} has unknown field {field!r}")
        fields[field] = item_node
    return fields


def _text(node: yaml.Node | None, what: str) -> str:
    """The text of a scalar member, "" when the member is absent or null. A non-scalar value and a binary-tagged
    value are rejected, with ``what`` naming the member."""
    if node is None:
        return ""
    if not isinstance(node, yaml.ScalarNode):
        raise ContainerConfigError(f"{what} must be a scalar")
    if node.tag == _BINARY_TAG:
        raise ContainerConfigError(f"{what} must not be binary")
    text: str = "" if node.tag == _NULL_TAG else node.value
    return text


def _repository_id(node: yaml.Node | None) -> str | None:
    """The text of a repository ID, or None when the member is not one: an integer scalar written in plain decimal,
    without a sign, a leading zero or a separator. The text is read as written and never converted."""
    if not isinstance(node, yaml.ScalarNode) or node.tag != _INT_TAG:
        return None
    text: str = node.value
    return text if _REPOSITORY_ID_RE.fullmatch(text) is not None else None


def _is_null(node: yaml.Node) -> bool:
    return isinstance(node, yaml.ScalarNode) and node.tag == _NULL_TAG
