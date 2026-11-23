"""Container provenance: the recorded build attestation of a published image, the certificate fields over minted
bundles and the ref patterns."""

from __future__ import annotations

import dataclasses
import itertools
import re
import time
from pathlib import Path
from typing import Any

import pytest

from tests.sigstore_world import FulcioIdentity, World, as_json, statement
from tinfoil.verifier import _json
from tinfoil.verifier._endorsement.container import (
    GITHUB_REPOSITORY_URL_PREFIX,
    Container,
    ContainerProvenanceError,
    authenticate_container,
    ref_pattern,
)
from tinfoil.verifier._endorsement.provenance import ProvenanceClient
from tinfoil.verifier._endorsement.runtime import SLSA_PROVENANCE_V1
from tinfoil.verifier._runtime import ContainerProvenance
from tinfoil.verifier._sigstore.certificate import workflow_identity_pattern

# The recorded bundle is the published build attestation of this image.
RECORDED_BUNDLE = Path(__file__).parent / "testdata" / "container-provenance-bundle.json"
RECORDED_REPOSITORY = "tinfoilsh/measure-image-action"
RECORDED_DIGEST = "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1"
RECORDED_COMMIT = "01a05df207140a8e8e1d2cd26028ab7c51dad9d1"
RECORDED_REF = "refs/tags/build-v0.14.2"
RECORDED_REQUIREMENT = ContainerProvenance(
    container="app",
    digest=RECORDED_DIGEST,
    repository=RECORDED_REPOSITORY,
    repository_id="924941172",
    workflow="build.yml",
    ref="refs/tags/build-v*",
)

MINTED_REF = "refs/tags/build-v1.2.3"
MINTED_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def recorded_bundle() -> _json.JsonValue:
    return _json.strict_parse(RECORDED_BUNDLE.read_bytes())


def test_recorded_bundle_authenticates_under_the_embedded_root() -> None:
    client = ProvenanceClient.default()
    want = Container(
        digest=RECORDED_DIGEST,
        repository=RECORDED_REPOSITORY,
        workflow="build.yml",
        ref=RECORDED_REF,
        commit=RECORDED_COMMIT,
    )
    assert authenticate_container(client, recorded_bundle(), RECORDED_REQUIREMENT) == want
    assert client.authenticate_container(recorded_bundle(), RECORDED_REQUIREMENT) == want
    exact = dataclasses.replace(RECORDED_REQUIREMENT, ref=RECORDED_REF)
    assert client.authenticate_container(recorded_bundle(), exact) == want


@pytest.mark.parametrize(
    ("change", "message"),
    [
        pytest.param({"digest": "00" + RECORDED_DIGEST[2:]}, "verifying container provenance", id="another image"),
        pytest.param({"repository": "tinfoilsh/cvmimage"}, "verifying container provenance", id="another repository"),
        pytest.param(
            {"repository": "tinfoilsh/measure-image"}, "verifying container provenance", id="repository prefix"
        ),
        pytest.param({"repository_id": "902195777"}, "source repository ID", id="another repository ID"),
        pytest.param({"workflow": "release.yml"}, "verifying container provenance", id="another workflow"),
        pytest.param({"workflow": "build.ym"}, "verifying container provenance", id="workflow prefix"),
        pytest.param({"ref": "refs/tags/v*"}, "verifying container provenance", id="another tag series"),
        pytest.param({"ref": "refs/tags/build-v0.14.3"}, "verifying container provenance", id="exact other tag"),
        pytest.param({"ref": "refs/heads/main"}, "verifying container provenance", id="branch"),
    ],
)
def test_recorded_bundle_does_not_prove_another_requirement(change: dict[str, str], message: str) -> None:
    required = dataclasses.replace(RECORDED_REQUIREMENT, **change)
    with pytest.raises(ContainerProvenanceError, match=message):
        ProvenanceClient.default().authenticate_container(recorded_bundle(), required)


def minted_identity(**overrides: str) -> FulcioIdentity:
    """What the signing certificate of a build that meets the recorded requirement asserts, at ``MINTED_REF``."""
    repository_url = GITHUB_REPOSITORY_URL_PREFIX + RECORDED_REPOSITORY
    identity = FulcioIdentity(
        san=f"{repository_url}/.github/workflows/{RECORDED_REQUIREMENT.workflow}@{MINTED_REF}",
        source_repository_uri=repository_url,
        source_repository_digest=MINTED_COMMIT,
        source_repository_ref=MINTED_REF,
        source_repository_identifier=RECORDED_REQUIREMENT.repository_id,
    )
    return dataclasses.replace(identity, **overrides)


def minted_bundle(
    world: World,
    identity: FulcioIdentity | None = None,
    *,
    subjects: list[dict[str, Any]] | None = None,
    predicate_type: str = SLSA_PROVENANCE_V1,
) -> dict[str, Any]:
    """A build attestation signed in ``world``, as JSON-ready data: a SLSA statement about the recorded image digest
    unless ``subjects`` says otherwise."""
    if subjects is None:
        subjects = [{"name": "ghcr.io/" + RECORDED_REPOSITORY, "digest": {"sha256": RECORDED_DIGEST}}]
    payload = statement(subjects, predicate_type, {"buildDefinition": {}, "runDetails": {}})
    return world.fulcio_bundle(payload, identity or minted_identity())


def authenticate(
    world: World, bundle: dict[str, Any], required: ContainerProvenance = RECORDED_REQUIREMENT
) -> Container:
    return ProvenanceClient(world.trusted_root()).authenticate_container(as_json(bundle), required)


def test_minted_bundle_authenticates() -> None:
    world = World()
    assert authenticate(world, minted_bundle(world)) == Container(
        digest=RECORDED_DIGEST,
        repository=RECORDED_REPOSITORY,
        workflow="build.yml",
        ref=MINTED_REF,
        commit=MINTED_COMMIT,
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        # A workflow in another repository can call the required workflow
        # file, which then signs with its own identity.
        pytest.param(
            {"source_repository_uri": GITHUB_REPOSITORY_URL_PREFIX + "attacker/fork"},
            "source repository 'https://github.com/attacker/fork' does not match",
            id="called from another repository",
        ),
        pytest.param({"source_repository_identifier": "1"}, "source repository ID", id="recreated repository"),
        pytest.param({"source_repository_identifier": ""}, "source repository ID", id="missing repository ID"),
        pytest.param({"source_repository_ref": "refs/pull/7/merge"}, "source ref", id="pull request ref"),
        pytest.param({"source_repository_ref": "refs/tags/build-v1/extra"}, "source ref", id="nested tag"),
        pytest.param({"source_repository_digest": ""}, "Git commit", id="no commit"),
        pytest.param({"source_repository_digest": MINTED_COMMIT.upper()}, "Git commit", id="uppercase commit"),
        pytest.param({"source_repository_digest": MINTED_COMMIT + "\n"}, "Git commit", id="commit and a newline"),
        pytest.param(
            {"san": f"{GITHUB_REPOSITORY_URL_PREFIX}{RECORDED_REPOSITORY}/.github/workflows/buildxyml@{MINTED_REF}"},
            "verifying container provenance",
            id="workflow that the required name matches as a pattern",
        ),
        pytest.param({"runner_environment": "self-hosted"}, "verifying container provenance", id="self-hosted runner"),
        pytest.param(
            {"issuer": "https://gitlab.com"}, "verifying container provenance", id="another identity provider"
        ),
    ],
)
def test_signing_certificate_must_name_the_required_source(overrides: dict[str, str], message: str) -> None:
    world = World()
    with pytest.raises(ContainerProvenanceError, match=message):
        authenticate(world, minted_bundle(world, minted_identity(**overrides)))


def test_exact_ref_does_not_match_a_source_ref_followed_by_a_newline() -> None:
    world = World()
    exact = dataclasses.replace(RECORDED_REQUIREMENT, ref=MINTED_REF)
    assert authenticate(world, minted_bundle(world), exact).ref == MINTED_REF
    followed = minted_bundle(world, minted_identity(source_repository_ref=MINTED_REF + "\n"))
    with pytest.raises(ContainerProvenanceError, match="source ref"):
        authenticate(world, followed, exact)


def test_statement_must_be_slsa_provenance_of_the_image() -> None:
    world = World()
    with pytest.raises(ContainerProvenanceError, match="must use SLSA v1"):
        authenticate(world, minted_bundle(world, predicate_type="https://spdx.dev/Document/v2.3"))
    image = {"name": "image", "digest": {"sha256": RECORDED_DIGEST}}
    other = {"name": "other", "digest": {"sha256": "ab" * 32}}
    assert authenticate(world, minted_bundle(world, subjects=[image, other])).digest == RECORDED_DIGEST
    with pytest.raises(ContainerProvenanceError, match=r"subject\[0\] digest"):
        authenticate(world, minted_bundle(world, subjects=[other, image]))


def ref_matches(pattern: str, ref: str) -> bool:
    """Whether the signing identity that ``pattern`` requires accepts a workflow run at ``ref``."""
    identity = workflow_identity_pattern("tinfoilsh/inference", re.escape("containers.yml"), ref_pattern(pattern))
    return identity.search("https://github.com/tinfoilsh/inference/.github/workflows/containers.yml@" + ref) is not None


@pytest.mark.parametrize(
    ("pattern", "ref", "want"),
    [
        ("refs/tags/vllm-v*", "refs/tags/vllm-v0.34.0", True),
        ("refs/tags/vllm-v*", "refs/tags/vllm-v", True),
        ("refs/tags/vllm-v*", "refs/tags/omni-v0.34.0", False),
        ("refs/tags/vllm-v*", "refs/tags/vllm-v0/34", False),
        ("refs/tags/vllm-v*", "refs/heads/vllm-v0.34.0", False),
        ("refs/tags/vllm-v*", "refs/tags/vllm-v0.34.0@refs/heads/main", False),
        ("refs/tags/v1.2.3", "refs/tags/v1.2.3", True),
        ("refs/tags/v1.2.3", "refs/tags/v1x2x3", False),
        ("refs/tags/v1.2.3", "refs/tags/v1.2.3\n", False),
        ("refs/heads/main", "refs/heads/main", True),
        ("refs/heads/main", "refs/heads/maintenance", False),
        ("refs/heads/main", "refs/heads/main\n", False),
        ("refs/heads/release/*", "refs/heads/release/2026", True),
        ("refs/heads/release/*", "refs/heads/release/2026/hotfix", False),
        ("refs/tags/*-rc*", "refs/tags/v1-rc2", True),
        ("refs/tags/*-rc*", "refs/tags/v1-rc-rc2", True),
        ("refs/tags/*-rc*", "refs/tags/v1-beta2", False),
        ("refs/tags/v*-rc", "refs/tags/v1-rc-rc", True),
        ("refs/tags/v*-rc", "refs/tags/v1-rc2", False),
        ("refs/tags/v**", "refs/tags/v1", True),
        ("refs/heads/*/main", "refs/heads/team/main", True),
        ("refs/heads/*/main", "refs/heads/team/sub/main", False),
    ],
)
def test_ref_pattern(pattern: str, ref: str, want: bool) -> None:
    assert ref_matches(pattern, ref) is want


def test_ref_pattern_accepts_what_a_wildcard_run_would() -> None:
    """Every short pattern accepts exactly the refs that the direct translation does, in which each wildcard is a
    run of characters other than ``/`` and ``@``."""
    refs = ["".join(ref) for length in range(6) for ref in itertools.product("ab/@", repeat=length)]
    for length in range(5):
        for symbols in itertools.product("ab*/", repeat=length):
            pattern = "".join(symbols)
            direct = re.compile("[^/@]*".join(re.escape(literal) for literal in pattern.split("*")))
            port = re.compile(ref_pattern(pattern))
            different = [ref for ref in refs if (port.fullmatch(ref) is None) != (direct.fullmatch(ref) is None)]
            assert different == [], pattern


def test_ref_pattern_with_many_wildcards_rejects_quickly() -> None:
    """A run of wildcards, each followed by a literal, is matched without retrying every way to split a ref among
    them. Retrying takes about half a minute for this pattern, and each further wildcard quadruples it."""
    allowance_seconds = 5.0
    wildcards = 16
    pattern = "refs/tags/" + "*a" * wildcards
    near_miss = "refs/tags/" + "a" * (2 * wildcards) + "b"
    started = time.monotonic()
    assert not ref_matches(pattern, near_miss)
    assert ref_matches(pattern, near_miss[:-1])
    assert time.monotonic() - started < allowance_seconds
