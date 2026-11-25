"""Container provenance: the builds that a config requires for its container images."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil.verifier import _json
from tinfoil.verifier._canonical import is_lower_hex

# Precedes the hex SHA-256 digest that ends a pinned image reference.
_IMAGE_DIGEST_PREFIX = "@sha256:"
_IMAGE_DIGEST_LENGTH = 64
_PROVENANCE_MEMBERS = ("github",)
_GITHUB_MEMBERS = ("repository", "repository_id", "workflow", "ref")


class ContainerConfigError(ValueError):
    """A config whose container build requirements cannot be read."""


@dataclass(frozen=True, slots=True)
class ContainerProvenance:
    """The build that a config requires for the container image with the lowercase hex SHA-256 ``digest``: a run of a
    GitHub Actions workflow of a repository. In ``ref``, ``*`` stands for any run of characters other than ``/``."""

    digest: str
    repository: str
    repository_id: str
    workflow: str
    ref: str


def container_provenance_from_config(data: bytes) -> tuple[ContainerProvenance, ...]:
    """The builds that a config requires, in container order.

    A requirement of any shape but the one read here is an error, so that an
    unknown kind of requirement is never treated as met. The publisher and
    guest own validation of the values.
    """
    try:
        config = _json.object_(_json.strict_parse(data), "config")
    except _json.JsonError as err:
        raise ContainerConfigError(f"parsing config containers: {err}") from err
    if "containers" not in config:
        return ()
    containers = config["containers"]
    if not isinstance(containers, tuple):
        raise ContainerConfigError("config containers must be an array of objects")
    required = []
    for index, container in enumerate(containers):
        if not isinstance(container, _json.JsonObject):
            raise ContainerConfigError("config containers must be an array of objects")
        if "provenance" not in container:
            continue
        try:
            provenance = _exact_object(container["provenance"], "provenance", _PROVENANCE_MEMBERS)
            github = _exact_object(provenance["github"], "github", _GITHUB_MEMBERS)
            fields = {name: _json.string(github, name) for name in _GITHUB_MEMBERS}
            image = _json.string(container, "image")
        except _json.JsonError as err:
            raise ContainerConfigError(f"containers[{index}]: {err}") from err
        split = len(image) - _IMAGE_DIGEST_LENGTH
        if split < 0 or not image[:split].endswith(_IMAGE_DIGEST_PREFIX) or not is_lower_hex(image[split:]):
            raise ContainerConfigError(
                f"containers[{index}].image must end with {_IMAGE_DIGEST_PREFIX} and a lowercase hex digest"
            )
        required.append(ContainerProvenance(digest=image[split:], **fields))
    return tuple(required)


def _exact_object(value: _json.JsonValue, what: str, members: tuple[str, ...]) -> _json.JsonObject:
    """``value`` as an object with exactly ``members``, none of them null."""
    obj = _json.object_(value, what, members)
    for name in members:
        if obj.get(name) is None:
            raise _json.JsonError(f"{what} must have {name}")
    return obj
