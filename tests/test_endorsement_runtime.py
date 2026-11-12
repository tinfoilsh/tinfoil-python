"""Runtime provenance: the subject rule, the release identity and the full path over a minted manifest and SLSA
bundle."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any

import pytest

from tests.sigstore_world import FulcioIdentity, World, as_json, statement
from tinfoil.verifier._document.collateral.runtime import RUNTIME_REPO, Runtime, RuntimeReference
from tinfoil.verifier._endorsement.provenance import ProvenanceClient
from tinfoil.verifier._endorsement.reference import RUNTIME_REPO_ID, TINFOIL_ORGANIZATION_ID, AuthenticatedArtifact
from tinfoil.verifier._endorsement.runtime import (
    SLSA_PROVENANCE_V1,
    RuntimeProvenanceError,
    authenticate_runtime,
    enforce_artifact_subject,
    runtime_identity,
    runtime_subject_name,
)
from tinfoil.verifier._sigstore import bundle as bm

MEASUREMENT = "cd" * 48
ZERO = "0" * 96
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def subject(name: str, digest: str) -> bm.Subject:
    return bm.parse_statement(statement([{"name": name, "digest": {"sha256": digest}}], "t", {})).subjects[0]


def test_runtime_subject_must_be_unique_and_match_name_and_digest() -> None:
    name = "tinfoil-inference-v0.15.0-manifest.json"
    digest = "ab" * 32
    matching = subject(name, digest)
    other = subject("other-artifact", "cd" * 32)
    enforce_artifact_subject([other, matching], name, digest)
    enforce_artifact_subject([subject(name, digest.upper())], name, digest)
    for _label, subjects in {
        "missing": [other],
        "duplicate": [matching, matching],
        "wrong digest": [subject(name, "cd" * 32)],
        "no statement": [],
    }.items():
        with pytest.raises(RuntimeProvenanceError):
            enforce_artifact_subject(subjects, name, digest)
    with pytest.raises(RuntimeProvenanceError, match="subject\\[0\\] digest"):
        enforce_artifact_subject([other, matching], "", digest)
    with pytest.raises(RuntimeProvenanceError, match="has no subject"):
        enforce_artifact_subject([], "", digest)


def test_runtime_identity_names_the_release_workflow_at_the_tag() -> None:
    assert runtime_subject_name("v0.15.0+gpu") == "tinfoil-inference-v0.15.0+gpu-manifest.json"
    pattern = runtime_identity("v0.15.0")
    assert pattern.search("https://github.com/tinfoilsh/cvmimage/.github/workflows/release.yml@refs/tags/v0.15.0")
    for san in [
        "https://github.com/tinfoilsh/cvmimage/.github/workflows/release.yml@refs/tags/v0.15.0+gpu",
        "https://github.com/tinfoilsh/cvmimage/.github/workflows/release.yml@refs/tags/v0.15.01",
        "https://github.com/tinfoilsh/cvmimage/.github/workflows/other.yml@refs/tags/v0.15.0",
        "https://github.com/tinfoilsh/cvmimage/.github/workflows/release.yml@refs/heads/v0.15.0",
    ]:
        assert pattern.search(san) is None, san


def manifest_bytes(version: str = "v0.15.0") -> bytes:
    return json.dumps(
        {
            "version": version,
            "igvm": {
                "format_version": 1,
                "snp_launch": {"measurement": MEASUREMENT},
                "tdx_launch": {"mrtd": MEASUREMENT, "rtmr0": ZERO, "rtmr1": ZERO, "rtmr2": ZERO, "rtmr3": ZERO},
            },
        }
    ).encode()


def release_identity(tag: str = "v0.15.0", **overrides: Any) -> FulcioIdentity:
    identity = FulcioIdentity(
        san=f"https://github.com/{RUNTIME_REPO}/.github/workflows/release.yml@refs/tags/{tag}",
        source_repository_uri=f"https://github.com/{RUNTIME_REPO}",
        source_repository_ref=f"refs/tags/{tag}",
        source_repository_identifier=RUNTIME_REPO_ID,
        source_repository_owner_identifier=TINFOIL_ORGANIZATION_ID,
    )
    return dataclasses.replace(identity, **overrides)


def slsa_payload(subjects: list[dict[str, Any]], predicate_type: str = SLSA_PROVENANCE_V1) -> bytes:
    return statement(subjects, predicate_type, {"buildDefinition": {}, "runDetails": {}})


def material_for(
    world: World, tag: str = "v0.15.0", manifest_version: str | None = None, **bundle: Any
) -> tuple[Runtime, RuntimeReference]:
    manifest = manifest_bytes(manifest_version or tag)
    digest = hashlib.sha256(manifest).hexdigest()
    reference = RuntimeReference(repo=RUNTIME_REPO, tag=tag, digest=digest)
    name = runtime_subject_name(tag)
    payload = bundle.pop("payload", None) or slsa_payload([{"name": name, "digest": {"sha256": digest}}])
    identity = bundle.pop("identity", None) or release_identity(tag.split("+")[0])
    return Runtime(
        reference=reference, manifest=manifest, bundle=as_json(world.fulcio_bundle(payload, identity))
    ), reference


def test_authenticate_runtime_binds_manifest_subject_and_release_identity() -> None:
    world = World()
    client = ProvenanceClient(world.trusted_root())
    material, expected = material_for(world)
    got = authenticate_runtime(client, material, expected)
    assert got.artifact == AuthenticatedArtifact(
        RUNTIME_REPO, "v0.15.0", COMMIT, "tinfoil-inference-v0.15.0-manifest.json", expected.digest
    )
    assert got.manifest.version == "v0.15.0"
    assert got.manifest.measurements.snp_launch.measurement == MEASUREMENT
    assert client.authenticate_runtime(material, expected) == got
    # Build metadata in the pin selects the manifest by name; the release tag is the canonical version.
    material, expected = material_for(world, "v0.15.0+gpu")
    got = authenticate_runtime(client, material, expected)
    assert got.artifact.tag == "v0.15.0"
    assert got.artifact.subject_name == "tinfoil-inference-v0.15.0+gpu-manifest.json"
    # A matching subject that is not first still counts, as long as it is the only one.
    material, expected = material_for(world)
    two = slsa_payload(
        [
            {"name": "other", "digest": {"sha256": "ab" * 32}},
            {"name": runtime_subject_name("v0.15.0"), "digest": {"sha256": expected.digest}},
        ]
    )
    material, expected = material_for(world, payload=two)
    assert authenticate_runtime(client, material, expected).manifest.version == "v0.15.0"


def test_authenticate_runtime_rejections() -> None:
    world = World()
    client = ProvenanceClient(world.trusted_root())
    material, expected = material_for(world)
    with pytest.raises(RuntimeProvenanceError, match="does not match the endorsed config's runtime pin"):
        authenticate_runtime(client, material, dataclasses.replace(expected, tag="v0.15.1"))
    with pytest.raises(RuntimeProvenanceError, match="does not match the config's digest pin"):
        authenticate_runtime(client, dataclasses.replace(material, manifest=material.manifest + b" "), expected)
    material, expected = material_for(world, manifest_version="v0.15.1")
    with pytest.raises(RuntimeProvenanceError, match="does not match the config's pin"):
        authenticate_runtime(client, material, expected)
    for _case, overrides, message in [
        ("other repository id", {"source_repository_identifier": "1"}, "source repository ID"),
        ("missing repository id", {"source_repository_identifier": ""}, "source repository ID"),
        ("other organization", {"source_repository_owner_identifier": "1"}, "source repository owner ID"),
        (
            "branch ref",
            {
                "san": release_identity().san.replace("refs/tags", "refs/heads"),
                "source_repository_ref": "refs/heads/v0.15.0",
            },
            "verifying runtime provenance",
        ),
        ("other tag", release_identity("v0.16.0").__dict__, "verifying runtime provenance"),
        ("bad commit", {"source_repository_digest": "abc"}, "not a lowercase Git commit"),
    ]:
        material, expected = material_for(world, identity=release_identity(**overrides))
        with pytest.raises(RuntimeProvenanceError, match=message):
            authenticate_runtime(client, material, expected)
    digest = hashlib.sha256(manifest_bytes()).hexdigest()
    name = runtime_subject_name("v0.15.0")
    for _label, payload, message in [
        (
            "not SLSA",
            slsa_payload([{"name": name, "digest": {"sha256": digest}}], "https://slsa.dev/provenance/v0.2"),
            "must use SLSA v1",
        ),
        (
            "renamed subject",
            slsa_payload([{"name": "other", "digest": {"sha256": digest}}]),
            "exactly one matching manifest subject",
        ),
        (
            "duplicate subject",
            slsa_payload([{"name": name, "digest": {"sha256": digest}}] * 2),
            "exactly one matching manifest subject",
        ),
        (
            "other digest",
            slsa_payload([{"name": name, "digest": {"sha256": "ab" * 32}}]),
            "verifying runtime provenance",
        ),
    ]:
        material, expected = material_for(world, payload=payload)
        with pytest.raises(RuntimeProvenanceError, match=message):
            authenticate_runtime(client, material, expected)
