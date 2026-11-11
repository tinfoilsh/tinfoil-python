"""Release provenance: the provenance and policy vectors through the client, the workflow identities, the
multiplatform predicate, the artifact identity recovered from a verified bundle and the production document."""

from __future__ import annotations

import base64
import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.sigstore_world import FulcioIdentity, World, as_json, statement
from tests.vectors import vector, vector_group, vector_params
from tinfoil.verifier import _json
from tinfoil.verifier._document import document
from tinfoil.verifier._document.collateral.collateral import NotFoundError
from tinfoil.verifier._endorsement import provenance
from tinfoil.verifier._endorsement.provenance import (
    MULTI_PLATFORM_PREDICATE_TYPE,
    ProvenanceClient,
    ProvenanceError,
    authenticated_artifact,
    measurements_from_statement,
    shape_from_predicate,
    signed_predicate,
)
from tinfoil.verifier._endorsement.reference import (
    PLATFORM_ENDORSEMENTS_REPO,
    RUNTIME_REPO_ID,
    TINFOIL_ORGANIZATION_ID,
    AuthenticatedArtifact,
    Reference,
    parse_reference,
)
from tinfoil.verifier._endorsement.runtime import RuntimeProvenanceError, enforce_artifact_subject
from tinfoil.verifier._measurement import ExpectedTDX
from tinfoil.verifier._policy import ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2, Shape, parse
from tinfoil.verifier._sigstore import bundle as bm
from tinfoil.verifier._sigstore import certificate as sc
from tinfoil.verifier._sigstore.trusted_root import embedded_trusted_root, parse_trusted_root

PLATFORM_FIXTURE = Path(__file__).parent / "testdata" / "platform-endorsements.json"
LAUNCH, RTMR1, RTMR2 = "aa" * 48, "bb" * 48, "cc" * 48
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def client_for(fixture: dict[str, Any]) -> ProvenanceClient:
    encoded = fixture["input"].get("sigstore_trusted_root_json_b64")
    if not encoded:
        return ProvenanceClient.default()
    return ProvenanceClient(parse_trusted_root(base64.b64decode(encoded)))


def decoded_document(fixture: dict[str, Any]) -> document.Document:
    return document.decode_unbound(base64.b64decode(fixture["input"]["document_b64"]))


def provenance_fixtures() -> list[Any]:
    """The provenance vectors plus the embedded-roots fixture that drives the provenance stage."""
    params = vector_params("provenance")
    for fixture in vector_group("embedded-roots"):
        if fixture["stage"] == "v3-authenticate-provenance":
            params.append(pytest.param(fixture, id=fixture["id"]))
    return params


@pytest.mark.parametrize("fixture", provenance_fixtures())
def test_provenance_vectors(fixture: dict[str, Any]) -> None:
    """Every vector of the provenance stage: the verdict and, on accept, the digest and the predicate's registers."""
    expected = fixture["expected"]
    client = client_for(fixture)
    parsed = decoded_document(fixture)
    try:
        ref = parsed.sigstore_code()
        pin = parse_reference(fixture["input"]["repo"])
        code = client.authenticate_code(ref.bundle, pin, ref.tag, ref.digest)
    except (NotFoundError, ProvenanceError):
        assert not expected["accepted"], fixture["id"]
        return
    assert expected["accepted"], fixture["id"]
    assert code.artifact.digest == expected["code_digest"]
    assert code.sevsnp.launch is not None
    assert code.tdx.rtmr1 is not None
    assert code.tdx.rtmr2 is not None
    assert code.tdx.mrtd is None
    assert code.tdx.rtmr0 is None
    assert code.tdx.rtmr3 is None
    registers = [code.sevsnp.launch.hex(), code.tdx.rtmr1.hex(), code.tdx.rtmr2.hex()]
    assert expected["code_measurement"] == {"type": MULTI_PLATFORM_PREDICATE_TYPE, "registers": registers}
    assert code.shape == Shape(cpus=8, memory_mb=32768, disks=2, gpus=1)
    assert code.artifact.repo == fixture["input"]["repo"]
    assert code.artifact.tag.startswith("v")


@pytest.mark.parametrize("fixture", vector_params("policy"))
def test_policy_vectors(fixture: dict[str, Any]) -> None:
    """Every vector of the policy stage: the platform-endorsements bundle under the v1 artifact format."""
    expected = fixture["expected"]
    client = client_for(fixture)
    parsed = decoded_document(fixture)
    try:
        ref = parsed.sigstore_platform()
        endorsements = client.authenticate_platform_endorsements(
            ref.bundle, ref.repo, ref.tag, ref.digest, ARTIFACT_FORMAT
        )
    except (NotFoundError, ProvenanceError):
        assert not expected["accepted"], fixture["id"]
        return
    assert expected["accepted"], fixture["id"]
    assert endorsements.endorsements.format == ARTIFACT_FORMAT
    assert endorsements.artifact.repo == PLATFORM_ENDORSEMENTS_REPO
    assert endorsements.artifact.digest == ref.digest
    assert endorsements.endorsements.machines


# --- identities ---------------------------------------------------------------


def test_signing_identity_is_anchored_to_one_workflow_at_a_tag() -> None:
    identity = provenance.signing_identity("tinfoilsh/confidential-model")
    assert identity.issuer == sc.GITHUB_OIDC_ISSUER
    assert identity.runner_environment == sc.RUNNER_ENVIRONMENT_GITHUB_HOSTED
    assert identity.san.search(
        "https://github.com/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/tags/v1.2.3"
    )
    for name, san in {
        "other repo prefix": "https://github.com/tinfoilsh/confidential-modelx/.github/workflows/release.yml@refs/tags/v1",
        "unescaped dot in host": "https://githubXcom/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/tags/v1",
        "branch ref": "https://github.com/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/heads/main",
        "nested workflow path": "https://github.com/tinfoilsh/confidential-model/.github/workflows/a/b.yml@refs/tags/v1",
        "trailing content": "https://github.com/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/tags/v1@evil",
        "embedded match": "prefix https://github.com/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/tags/v1",
    }.items():
        assert identity.san.search(san) is None, name
    for repo in ["", "noslash", "a/b/c", "a/(b|c)"]:
        with pytest.raises(ProvenanceError, match="invalid repository name"):
            provenance.signing_identity(repo)


def test_pinned_workflow_identities_are_anchored() -> None:
    platform = provenance.platform_endorsements_identity().san
    prefix = "https://github.com/tinfoilsh/cvmimage/.github/workflows/"
    assert platform.search(prefix + "platform-release.yml@refs/tags/platform-v1.2.3")
    assert platform.search(prefix + "platform-release.yml@refs/tags/platform-v1.2.3-rc.1")
    for san in [
        prefix + "release.yml@refs/tags/platform-v1.2.3",
        prefix + "platform-release.yml@refs/tags/v1.2.3",
        prefix + "platform-release.yml@refs/heads/platform-v1.2.3",
        prefix + "platform-release.yml@refs/tags/platform-v1.2.3@extra",
        prefix + "platform-release.yml@refs/tags/platform-vX",
        "https://github.com/tinfoilsh/platform-endorsements/.github/workflows/build.yml@refs/tags/v1.2.3",
    ]:
        assert platform.search(san) is None, san
    witness = provenance.freshness_witness_identity().san
    assert witness.search(
        "https://github.com/tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/heads/main"
    )
    assert (
        witness.search("https://github.com/tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/tags/v1")
        is None
    )
    assert (
        witness.search("https://github.com/tinfoilsh/freshness-witness/.github/workflows/freshnessXyml@refs/heads/main")
        is None
    )


# --- the multiplatform predicate ----------------------------------------------


def multiplatform_statement(
    predicate: dict[str, Any], predicate_type: str = MULTI_PLATFORM_PREDICATE_TYPE
) -> bm.Statement:
    return bm.parse_statement(statement([{"name": "cip", "digest": {"sha256": "ab" * 32}}], predicate_type, predicate))


def predicate_with(snp: Any, rtmr1: Any, rtmr2: Any) -> dict[str, Any]:
    return {"snp_measurement": snp, "tdx_measurement": {"rtmr1": rtmr1, "rtmr2": rtmr2}}


def test_measurements_from_statement_reads_the_three_registers() -> None:
    sevsnp, tdx = measurements_from_statement(multiplatform_statement(predicate_with(LAUNCH, RTMR1, RTMR2)))
    assert sevsnp.launch is not None
    assert sevsnp.launch.hex() == LAUNCH
    assert tdx == ExpectedTDX(rtmr1=bytes.fromhex(RTMR1), rtmr2=bytes.fromhex(RTMR2))
    upper, _ = measurements_from_statement(multiplatform_statement(predicate_with(LAUNCH.upper(), RTMR1, RTMR2)))
    assert upper == sevsnp


@pytest.mark.parametrize(
    ("predicate", "message"),
    [
        (predicate_with("abcd", RTMR1, RTMR2), "invalid multiplatform measurement: snp measurement"),
        (predicate_with(LAUNCH, "zz" * 48, RTMR2), "invalid multiplatform measurement: rtmr1"),
        (predicate_with(LAUNCH, RTMR1, ""), "invalid multiplatform measurement: rtmr2"),
        (predicate_with(LAUNCH, RTMR1, 12), "invalid multiplatform measurement: rtmr2"),
        (predicate_with(None, RTMR1, RTMR2), "invalid multiplatform measurement: snp measurement"),
        ({"tdx_measurement": {"rtmr1": RTMR1, "rtmr2": RTMR2}}, "no snp measurement"),
        ({"snp_measurement": LAUNCH}, "no tdx measurement"),
        ({"snp_measurement": LAUNCH, "tdx_measurement": None}, "tdx measurement is not a struct"),
        ({"snp_measurement": LAUNCH, "tdx_measurement": "x"}, "tdx measurement is not a struct"),
        ({"snp_measurement": LAUNCH, "tdx_measurement": {"rtmr2": RTMR2}}, "no rtmr1"),
        ({"snp_measurement": LAUNCH, "tdx_measurement": {"rtmr1": RTMR1}}, "no rtmr2"),
    ],
)
def test_measurements_from_statement_rejections(predicate: dict[str, Any], message: str) -> None:
    with pytest.raises(ProvenanceError, match=message):
        measurements_from_statement(multiplatform_statement(predicate))


def test_measurements_from_statement_requires_the_multiplatform_predicate_type() -> None:
    other = multiplatform_statement(
        predicate_with(LAUNCH, RTMR1, RTMR2), "https://tinfoil.sh/predicate/sev-snp-guest/v2"
    )
    with pytest.raises(ProvenanceError, match="unsupported predicate type"):
        measurements_from_statement(other)


def shape_statement(shape: Any) -> bm.Statement:
    predicate = predicate_with(LAUNCH, RTMR1, RTMR2)
    if shape is not None:
        predicate["vm_shape"] = shape
    return multiplatform_statement(predicate)


def test_shape_from_predicate_reads_integral_numbers() -> None:
    assert shape_from_predicate(shape_statement({"cpus": 4, "memory_mb": 4096, "gpus": 0, "disks": 3})) == Shape(
        cpus=4, memory_mb=4096, disks=3, gpus=0
    )
    # Numbers are read at double precision, so integral literals with a fraction or exponent are accepted.
    assert shape_from_predicate(shape_statement({"cpus": 4.0, "memory_mb": 4.096e3, "gpus": 0, "disks": 3})) == Shape(
        cpus=4, memory_mb=4096, disks=3, gpus=0
    )


@pytest.mark.parametrize(
    ("shape", "message"),
    [
        (None, "declares no vm_shape"),
        ("x", "vm_shape is not an object"),
        ({"memory_mb": 1, "gpus": 0, "disks": 1}, "vm_shape is missing 'cpus'"),
        ({"cpus": -1, "memory_mb": 1, "gpus": 0, "disks": 1}, "'cpus' is not a non-negative integer"),
        ({"cpus": 1.5, "memory_mb": 1, "gpus": 0, "disks": 1}, "'cpus' is not a non-negative integer"),
        ({"cpus": "4", "memory_mb": 1, "gpus": 0, "disks": 1}, "'cpus' is not a non-negative integer"),
        ({"cpus": 1, "memory_mb": 1, "gpus": None, "disks": 1}, "'gpus' is not a non-negative integer"),
        ({"cpus": 1, "memory_mb": 1, "gpus": 0, "disks": 9223372036854775808}, "'disks' is not a non-negative integer"),
    ],
)
def test_shape_from_predicate_rejections(shape: Any, message: str) -> None:
    with pytest.raises(ProvenanceError, match=message):
        shape_from_predicate(shape_statement(shape))


def test_shape_number_out_of_range_never_parses() -> None:
    """A literal beyond double range is rejected by the strict statement parser, before any shape rule."""
    with pytest.raises(bm.BundleError, match="is not a number"):
        shape_statement({"cpus": 1, "memory_mb": 1, "gpus": 0, "disks": 1e400})


# --- the recovered artifact ---------------------------------------------------


def verified_with(extensions: sc.FulcioExtensions, payload: bytes = b"{}") -> sc.VerifiedBundle:
    at = datetime(2025, 1, 1, tzinfo=UTC)
    return sc.VerifiedBundle(payload=payload, leaf=None, extensions=extensions, signed_at=at, logged_at=at)  # type: ignore[arg-type]


def extensions_for(ref: str, commit: str = COMMIT, repository_id: str = "", owner_id: str = "") -> sc.FulcioExtensions:
    return sc.FulcioExtensions(
        issuer=sc.GITHUB_OIDC_ISSUER,
        source_repository_uri="",
        source_repository_digest=commit,
        source_repository_ref=ref,
        source_repository_identifier=repository_id,
        source_repository_owner_identifier=owner_id,
        runner_environment=sc.RUNNER_ENVIRONMENT_GITHUB_HOSTED,
        build_signer_uri="",
    )


def named_statement(name: str = "platform-endorsements.json", digest: str = "ab" * 32) -> bm.Statement:
    return bm.parse_statement(statement([{"name": name, "digest": {"sha256": digest}}], "t", {}))


def test_authenticated_artifact_pins_repository_identity() -> None:
    repo, other_repo_id, other_org_id = "tinfoilsh/cvmimage", "1", "1"
    for _name, repository_id, owner_id, message in [
        ("matching IDs", RUNTIME_REPO_ID, TINFOIL_ORGANIZATION_ID, ""),
        ("different repository", other_repo_id, TINFOIL_ORGANIZATION_ID, "source repository ID"),
        ("missing repository", "", TINFOIL_ORGANIZATION_ID, "source repository ID"),
        ("different organization", RUNTIME_REPO_ID, other_org_id, "source repository owner ID"),
        ("missing organization", RUNTIME_REPO_ID, "", "source repository owner ID"),
    ]:
        verified = verified_with(extensions_for("refs/tags/v0.0.4", repository_id=repository_id, owner_id=owner_id))
        if message:
            with pytest.raises(ProvenanceError, match=message):
                authenticated_artifact(verified, named_statement(), repo, "v0.0.4", "ab" * 32, "artifact")
            continue
        got = authenticated_artifact(verified, named_statement(), repo, "v0.0.4", "ab" * 32, "artifact")
        assert got == AuthenticatedArtifact(repo, "v0.0.4", COMMIT, "platform-endorsements.json", "ab" * 32)
    # Any other repository skips the id checks.
    verified = verified_with(extensions_for("refs/tags/v0.0.4"))
    assert authenticated_artifact(verified, named_statement(), "org/repo", "", "ab" * 32, "code").tag == "v0.0.4"


def test_authenticated_artifact_requires_a_tag_ref_commit_and_subject() -> None:
    with pytest.raises(ProvenanceError, match="source ref 'refs/heads/main' is not a tag"):
        authenticated_artifact(
            verified_with(extensions_for("refs/heads/main")), named_statement(), "o/r", "", "ab" * 32, "code"
        )
    with pytest.raises(ProvenanceError, match="does not match tag 'v2'"):
        authenticated_artifact(
            verified_with(extensions_for("refs/tags/v1")), named_statement(), "o/r", "v2", "ab" * 32, "code"
        )
    with pytest.raises(ProvenanceError, match="not a lowercase Git commit"):
        authenticated_artifact(
            verified_with(extensions_for("refs/tags/v1", commit=COMMIT.upper())),
            named_statement(),
            "o/r",
            "",
            "ab" * 32,
            "x",
        )
    with pytest.raises(ProvenanceError, match="statement has no named subject"):
        authenticated_artifact(
            verified_with(extensions_for("refs/tags/v1")), named_statement(name=""), "o/r", "", "ab" * 32, "x"
        )


def test_authenticated_digest_is_canonical() -> None:
    """A digest given in upper case is accepted for the subject check and recorded in lower case."""
    digest = "ab" * 32
    subjects = named_statement(digest=digest).subjects
    enforce_artifact_subject(subjects, "", digest.upper())
    verified = verified_with(
        extensions_for("refs/tags/v0.0.4", repository_id=RUNTIME_REPO_ID, owner_id=TINFOIL_ORGANIZATION_ID)
    )
    got = authenticated_artifact(
        verified, named_statement(digest=digest), "tinfoilsh/cvmimage", "v0.0.4", digest.upper(), "code"
    )
    assert got.digest == digest
    with pytest.raises(RuntimeProvenanceError, match="does not match expected artifact digest"):
        enforce_artifact_subject(subjects, "", "ff" * 32)


# --- the signed predicate -------------------------------------------------------


def test_signed_predicate_keeps_the_signed_bytes() -> None:
    fixture = PLATFORM_FIXTURE.read_text()
    vector_literal = "9223372036854775809"
    predicate = fixture.replace(
        '"minimum_launch_mitigation_vector": 0', '"minimum_launch_mitigation_vector": ' + vector_literal, 1
    )
    assert predicate != fixture

    def payload(predicate_text: str) -> bytes:
        return (
            '{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"platform-endorsements.json","digest":{"sha256":"'
            + "ab" * 32
            + '"}}],"predicateType":"'
            + ARTIFACT_FORMAT
            + '","predicate":'
            + predicate_text
            + "}"
        ).encode()

    signed = signed_predicate(payload(predicate))
    assert vector_literal.encode() in signed
    artifact = parse(signed)
    vectors = {p.sev_snp.minimum_launch_mitigation_vector for p in artifact.policies.values() if p.sev_snp}
    assert 9223372036854775809 in vectors
    # Literals the strict parser rejects for integer fields stay rejected instead of being normalized.
    fractional = fixture.replace('"minimum_build": 21', '"minimum_build": 21.0', 1)
    assert fractional != fixture
    with pytest.raises(ValueError, match="parsing policy artifact"):
        parse(signed_predicate(payload(fractional)))
    for _name, bad in {
        "no predicate": b'{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{}}],"predicateType":"t"}',
        "null predicate": b'{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{}}],"predicateType":"t","predicate":null}',
        "not JSON": b"{",
    }.items():
        with pytest.raises(ProvenanceError, match="parsing"):
            signed_predicate(bad)


# --- platform endorsements -------------------------------------------------------


def test_platform_endorsements_checks_format_and_repo_before_the_bundle() -> None:
    client = ProvenanceClient.default()
    for repo, artifact_format, message in [
        ("tinfoilsh/platform-endorsements", ARTIFACT_FORMAT_V2, "platform endorsements repo"),
        ("tinfoilsh/platform-endorsements", ARTIFACT_FORMAT, "platform endorsements repo"),
        (PLATFORM_ENDORSEMENTS_REPO, "unsupported", "unsupported platform artifact format"),
    ]:
        with pytest.raises(ProvenanceError, match=message):
            client.authenticate_platform_endorsements(None, repo, "platform-v1.2.3", "a" * 64, artifact_format)


def platform_payload(predicate_text: str, predicate_type: str = ARTIFACT_FORMAT) -> tuple[bytes, str]:
    import hashlib

    digest = hashlib.sha256(predicate_text.encode()).hexdigest()
    payload = (
        '{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"platform-endorsements.json","digest":{"sha256":"'
        + digest
        + '"}}],"predicateType":"'
        + predicate_type
        + '","predicate":'
        + predicate_text
        + "}"
    ).encode()
    return payload, digest


def platform_identity(tag: str = "platform-v1.2.3", workflow: str = "platform-release.yml") -> FulcioIdentity:
    # The platform repository is the runtime repository, so its ids are pinned too.
    return FulcioIdentity(
        san=f"https://github.com/tinfoilsh/cvmimage/.github/workflows/{workflow}@refs/tags/{tag}",
        source_repository_uri="https://github.com/tinfoilsh/cvmimage",
        source_repository_ref=f"refs/tags/{tag}",
        source_repository_identifier=RUNTIME_REPO_ID,
        source_repository_owner_identifier=TINFOIL_ORGANIZATION_ID,
    )


def test_platform_endorsements_from_the_release_workflow() -> None:
    world = World()
    client = ProvenanceClient(world.trusted_root())
    payload, digest = platform_payload(PLATFORM_FIXTURE.read_text())
    bundle = as_json(world.fulcio_bundle(payload, platform_identity()))
    got = client.authenticate_platform_endorsements(
        bundle, PLATFORM_ENDORSEMENTS_REPO, "platform-v1.2.3", digest, ARTIFACT_FORMAT
    )
    assert got.artifact == AuthenticatedArtifact(
        PLATFORM_ENDORSEMENTS_REPO, "platform-v1.2.3", COMMIT, "platform-endorsements.json", digest
    )
    assert got.endorsements == parse(PLATFORM_FIXTURE.read_bytes())
    # Without a tag hint the certificate's tag is taken as is; a different hint rejects.
    assert (
        client.authenticate_platform_endorsements(
            bundle, PLATFORM_ENDORSEMENTS_REPO, "", digest, ARTIFACT_FORMAT
        ).artifact.tag
        == "platform-v1.2.3"
    )
    with pytest.raises(ProvenanceError, match="does not match tag"):
        client.authenticate_platform_endorsements(
            bundle, PLATFORM_ENDORSEMENTS_REPO, "platform-v9.9.9", digest, ARTIFACT_FORMAT
        )
    # The flow's format must be the artifact's and the statement's.
    with pytest.raises(ProvenanceError, match="platform predicate and artifact must use"):
        client.authenticate_platform_endorsements(
            bundle, PLATFORM_ENDORSEMENTS_REPO, "platform-v1.2.3", digest, ARTIFACT_FORMAT_V2
        )
    v2_payload, v2_digest = platform_payload(PLATFORM_FIXTURE.read_text(), ARTIFACT_FORMAT_V2)
    v2_bundle = as_json(world.fulcio_bundle(v2_payload, platform_identity()))
    with pytest.raises(ProvenanceError, match="platform predicate and artifact must use"):
        client.authenticate_platform_endorsements(
            v2_bundle, PLATFORM_ENDORSEMENTS_REPO, "", v2_digest, ARTIFACT_FORMAT_V2
        )
    with pytest.raises(ProvenanceError, match="platform predicate and artifact must use"):
        client.authenticate_platform_endorsements(v2_bundle, PLATFORM_ENDORSEMENTS_REPO, "", v2_digest, ARTIFACT_FORMAT)


def test_platform_endorsements_rejects_other_signing_identities() -> None:
    world = World()
    client = ProvenanceClient(world.trusted_root())
    payload, digest = platform_payload(PLATFORM_FIXTURE.read_text())
    for identity in [
        platform_identity(workflow="release.yml"),
        platform_identity(tag="v1.2.3"),
        FulcioIdentity(
            san="https://github.com/tinfoilsh/other/.github/workflows/platform-release.yml@refs/tags/platform-v1.2.3"
        ),
        dataclasses.replace(platform_identity(), issuer="https://accounts.example"),
        dataclasses.replace(platform_identity(), runner_environment="self-hosted"),
    ]:
        bundle = as_json(world.fulcio_bundle(payload, identity))
        with pytest.raises(ProvenanceError, match="verifying platform endorsements bundle"):
            client.authenticate_platform_endorsements(bundle, PLATFORM_ENDORSEMENTS_REPO, "", digest, ARTIFACT_FORMAT)
    # A malformed policy artifact rejects after the bundle verified.
    bad_payload, bad_digest = platform_payload(PLATFORM_FIXTURE.read_text().replace('"format"', '"formatx"', 1))
    with pytest.raises(ProvenanceError, match="parsing policy artifact"):
        client.authenticate_platform_endorsements(
            as_json(world.fulcio_bundle(bad_payload, platform_identity())),
            PLATFORM_ENDORSEMENTS_REPO,
            "",
            bad_digest,
            ARTIFACT_FORMAT,
        )


# --- code provenance ----------------------------------------------------------------


def test_authenticate_code_pins_take_precedence_over_the_document_hints() -> None:
    fixture = vector("provenance", "provenance-happy")
    client = client_for(fixture)
    ref = decoded_document(fixture).sigstore_code()
    repo, tag, digest = fixture["input"]["repo"], ref.tag, ref.digest
    code = client.authenticate_code(ref.bundle, Reference(repo), tag, digest)
    assert code.artifact.tag == tag
    assert code.artifact.digest == digest
    for reference, tag_hint, digest_hint, valid in [
        (repo, tag, digest, True),
        (repo + "@" + tag, "untrusted-tag", digest, True),
        (repo + "@sha256:" + digest, tag, "untrusted-digest", True),
        (repo + "@" + tag + "@sha256:" + digest, "untrusted-tag", "untrusted-digest", True),
        (repo, "", digest, True),
        (repo + "@wrong-tag", tag, digest, False),
        (repo + "@sha256:" + "00" * 32, tag, digest, False),
        (repo + "@wrong-tag@sha256:" + digest, tag, digest, False),
        ("tinfoilsh/other", tag, digest, False),
    ]:
        pin = parse_reference(reference)
        if valid:
            assert client.authenticate_code(ref.bundle, pin, tag_hint, digest_hint) == code, reference
        else:
            with pytest.raises(ProvenanceError):
                client.authenticate_code(ref.bundle, pin, tag_hint, digest_hint)
    with pytest.raises(ProvenanceError, match="decoding hex digest"):
        client.authenticate_code(ref.bundle, Reference(repo), tag, "zz" * 32)
    with pytest.raises(ProvenanceError, match="decoding hex digest"):
        client.authenticate_code(ref.bundle, Reference(repo), tag, digest[:-1])


def test_authenticate_code_with_a_minted_bundle() -> None:
    world = World()
    client = ProvenanceClient(world.trusted_root())
    predicate = {
        **predicate_with(LAUNCH, RTMR1, RTMR2),
        "vm_shape": {"cpus": 4, "memory_mb": 4096, "gpus": 0, "disks": 3},
    }
    payload = statement(
        [{"name": "tinfoil-deployment.json", "digest": {"sha256": "ab" * 32}}], MULTI_PLATFORM_PREDICATE_TYPE, predicate
    )
    identity = FulcioIdentity(
        san="https://github.com/tinfoilsh/confidential-debug/.github/workflows/release.yml@refs/tags/v0.0.52",
        source_repository_ref="refs/tags/v0.0.52",
    )
    code = client.authenticate_code(
        as_json(world.fulcio_bundle(payload, identity)), Reference("tinfoilsh/confidential-debug"), "", "AB" * 32
    )
    assert code.artifact == AuthenticatedArtifact(
        "tinfoilsh/confidential-debug", "v0.0.52", COMMIT, "tinfoil-deployment.json", "ab" * 32
    )
    assert code.shape == Shape(cpus=4, memory_mb=4096, disks=3, gpus=0)
    # The same bundle with a receipt that carries no time and a signature timestamp as the observer.
    timestamped = as_json(world.fulcio_bundle(payload, identity, receipt="v2", timestamp=True))
    assert (
        client.authenticate_code(timestamped, Reference("tinfoilsh/confidential-debug"), "v0.0.52", "ab" * 32) == code
    )


# --- the client -------------------------------------------------------------------------


def test_client_construction() -> None:
    assert ProvenanceClient.default().root == embedded_trusted_root()
    world = World()
    assert ProvenanceClient.from_json(world.trusted_root_json()).root == world.trusted_root()
    with pytest.raises(ProvenanceError, match="parsing trust root"):
        ProvenanceClient.from_json(b"{}")


def test_verify_bundle_parses_the_bundle_first() -> None:
    client = ProvenanceClient.default()
    with pytest.raises(ProvenanceError, match="parsing bundle"):
        client.verify_bundle(as_json({"mediaType": "x"}), "org/repo", "ab" * 32)
    with pytest.raises(ProvenanceError, match="parsing bundle"):
        client.verify_bundle(None, "org/repo", "ab" * 32)


def test_production_document_verifies_under_the_embedded_root() -> None:
    """The real document's code bundle authenticates under the embedded root; its platform entry names the
    repository under its former name, which the pinned platform repository rejects."""
    fixture = vector("real-frozen", "real-sev-inference-tinfoil")
    client = ProvenanceClient.default()
    parsed = decoded_document(fixture)
    ref = parsed.sigstore_code()
    code = client.authenticate_code(ref.bundle, Reference(fixture["input"]["repo"]), ref.tag, ref.digest)
    assert code.artifact.repo == fixture["input"]["repo"]
    assert code.artifact.tag == ref.tag
    assert code.artifact.digest == ref.digest
    assert code.artifact.subject_name == "tinfoil-deployment.json"
    assert code.shape is not None
    assert code.tdx.rtmr1 is not None
    assert code.tdx.mrtd is None
    platform = parsed.sigstore_platform()
    with pytest.raises(ProvenanceError, match="platform endorsements repo"):
        client.authenticate_platform_endorsements(
            platform.bundle, platform.repo, platform.tag, platform.digest, ARTIFACT_FORMAT
        )


def test_predicate_bytes_are_read_strictly() -> None:
    """A predicate that the strict parser rejects (a duplicate member) never reaches the register checks."""
    raw = (
        b'{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"'
        + b"ab" * 32
        + b'"}}],"predicateType":"'
        + MULTI_PLATFORM_PREDICATE_TYPE.encode()
        + b'","predicate":{"snp_measurement":"'
        + LAUNCH.encode()
        + b'","snp_measurement":"'
        + LAUNCH.encode()
        + b'"}}'
    )
    with pytest.raises((ProvenanceError, bm.BundleError)):
        measurements_from_statement(bm.parse_statement(raw))
    good = json.loads(raw.replace(b'"snp_measurement":"' + LAUNCH.encode() + b'",', b"", 1))
    assert isinstance(_json.strict_parse(json.dumps(good).encode()), _json.JsonObject)
