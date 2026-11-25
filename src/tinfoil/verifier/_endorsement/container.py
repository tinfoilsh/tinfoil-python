"""Container provenance: the builds that a config requires for its container images, and the SLSA build attestations
that prove them."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tinfoil.verifier import _json
from tinfoil.verifier._canonical import is_lower_hex
from tinfoil.verifier._endorsement._common import ProvenanceError
from tinfoil.verifier._endorsement.runtime import SLSA_PROVENANCE_V1
from tinfoil.verifier._sigstore.bundle import IN_TOTO_STATEMENT_V1
from tinfoil.verifier._sigstore.certificate import (
    GITHUB_OIDC_ISSUER,
    RUNNER_ENVIRONMENT_GITHUB_HOSTED,
    SigningIdentity,
)
from tinfoil.verifier._x509.certificate import uri_sans

if TYPE_CHECKING:
    from tinfoil.verifier._endorsement.provenance import ProvenanceClient

# Precedes the hex SHA-256 digest that ends a pinned image reference.
_IMAGE_DIGEST_PREFIX = "@sha256:"
_IMAGE_DIGEST_LENGTH = 64
_PROVENANCE_MEMBERS = ("github",)
_GITHUB_MEMBERS = ("repository", "repository_id", "workflow", "ref")

# Accepts every GitHub signing identity. The identity of a container build is
# compared as text once its bundle verifies.
_GITHUB_IDENTITY = SigningIdentity(
    san=re.compile(r"\Ahttps://github\.com/"),
    issuer=GITHUB_OIDC_ISSUER,
    runner_environment=RUNNER_ENVIRONMENT_GITHUB_HOSTED,
)
_GITHUB_URL_PREFIX = "https://github.com/"
_GITHUB_WORKFLOWS_PATH = "/.github/workflows/"
_WORKFLOW_REF_SEPARATOR = "@"

_REF_SEGMENT_SEPARATOR = "/"
_REF_WILDCARD = "*"


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


def authenticate_containers(
    client: ProvenanceClient, config: bytes, attestation: Callable[[str], _json.JsonValue]
) -> None:
    """Verify the build of every container image for which ``config`` requires one. ``attestation`` returns the
    Sigstore bundle that a document carries for the image with a lowercase hex SHA-256 digest."""
    for required in container_provenance_from_config(config):
        bundle = attestation(required.digest)
        try:
            authenticate_container(client, bundle, required)
        except ProvenanceError as err:
            raise ProvenanceError(f"container image sha256:{required.digest}: {err}") from err


def authenticate_container(client: ProvenanceClient, bundle: _json.JsonValue, required: ContainerProvenance) -> None:
    """Verify that ``bundle`` is a SLSA build attestation of the image with ``required.digest``, signed on a
    GitHub-hosted runner by the required workflow of the required repository, at a ref that ``required.ref``
    matches."""
    try:
        verified, statement = client.verify_bundle_with_identity(bundle, _GITHUB_IDENTITY, required.digest)
    except ProvenanceError as err:
        raise ProvenanceError(f"verifying container provenance: {err}") from err
    if statement.type != IN_TOTO_STATEMENT_V1 or statement.predicate_type != SLSA_PROVENANCE_V1:
        raise ProvenanceError("container provenance must use SLSA v1")
    # The source fields name the repository and ref that the run built. The
    # identity names the workflow file that signed, which must be that
    # repository's own file at that ref and not one called from elsewhere.
    extensions = verified.extensions
    source_ref = extensions.source_repository_ref
    repository = _GITHUB_URL_PREFIX + required.repository
    identity = repository + _GITHUB_WORKFLOWS_PATH + required.workflow + _WORKFLOW_REF_SEPARATOR + source_ref
    # Verification accepted the certificate's one URI subject alternative name.
    signer = uri_sans(verified.leaf)[0]
    if extensions.source_repository_uri != repository:
        raise ProvenanceError(
            f"container provenance source repository {extensions.source_repository_uri!r} is not {repository!r}"
        )
    if extensions.source_repository_identifier != required.repository_id:
        raise ProvenanceError(
            f"container provenance source repository ID {extensions.source_repository_identifier!r} "
            f"is not {required.repository_id!r}"
        )
    if signer != identity:
        raise ProvenanceError(f"container provenance workflow identity {signer!r} is not {identity!r}")
    if not ref_matches(required.ref, source_ref):
        raise ProvenanceError(f"container provenance source ref {source_ref!r} does not match {required.ref!r}")


def ref_matches(pattern: str, ref: str) -> bool:
    """Whether the whole of ``ref`` matches ``pattern``, in which ``*`` stands for any run of characters, possibly
    empty, other than ``/``, and every other character stands for itself. It takes time bounded by the product of
    the two lengths."""
    patterns, segments = pattern.split(_REF_SEGMENT_SEPARATOR), ref.split(_REF_SEGMENT_SEPARATOR)
    return len(patterns) == len(segments) and all(map(_ref_segment_matches, patterns, segments))


def _ref_segment_matches(pattern: str, segment: str) -> bool:
    """``ref_matches`` for one segment of each."""
    pieces = pattern.split(_REF_WILDCARD)
    first, last = pieces[0], pieces[-1]
    if len(pieces) == 1:
        return segment == first
    if len(segment) < len(first) + len(last) or not segment.startswith(first) or not segment.endswith(last):
        return False
    # Each piece between the first and the last is taken at its earliest
    # occurrence, which leaves the most room for those after it.
    rest = segment[len(first) : len(segment) - len(last)]
    for piece in pieces[1:-1]:
        found = rest.find(piece)
        if found < 0:
            return False
        rest = rest[found + len(piece) :]
    return True
