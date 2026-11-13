"""Signed approvals: config endorsement and artifact freshness statements, the registry id and config name rules,
registry signing certificates, and the key-signed, certified and freshness verifiers over a synthetic Sigstore
world and the approval-bundle vectors."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests import pki
from tests.sigstore_world import World, as_json, b64, statement
from tests.vectors import vector_params
from tinfoil.verifier import _json
from tinfoil.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference
from tinfoil.verifier._endorsement import approval
from tinfoil.verifier._endorsement.approval import (
    ARTIFACT_FRESHNESS_DOMAIN,
    ARTIFACT_FRESHNESS_PREDICATE_TYPE,
    CONFIG_FRESHNESS_DOMAIN,
    CONFIG_FRESHNESS_DOMAIN_V2,
    CONFIG_PREDICATE_TYPE,
    CONFIG_PREDICATE_TYPE_V2,
    KIND_PLATFORM,
    KIND_RUNTIME,
    MAX_SLUG_LENGTH,
    PLATFORM_NAME,
    PLATFORM_REPO,
    PLATFORM_TAG_PREFIX,
    PUBLIC_REGISTRY_ID,
    REGISTRY_ID_PREFIX,
    ApprovalError,
    ApprovalVerifier,
    ConfigPolicy,
    ConfigVerifier,
    FreshnessArtifact,
    FreshnessPolicy,
    FreshnessVerifier,
    artifact_freshness_timestamp_input,
    config_timestamp_input,
    is_runtime_name,
    parse_artifact_freshness_statement,
    parse_config_statement,
    parse_name,
    public_signing_keys,
    runtime_name,
    validate_registry_id,
    verify_signing_certificate,
)
from tinfoil.verifier._endorsement.time import DEFAULT_FUTURE_SKEW, DEFAULT_MAX_AGE
from tinfoil.verifier._sigstore import bundle as bm
from tinfoil.verifier._sigstore.keyed import key_hint
from tinfoil.verifier._sigstore.trusted_root import parse_trusted_root
from tinfoil.verifier._x509.certificate import load_public_key_pem

IDENTITY = "/tinfoil/model-router"
NAME = IDENTITY + "/v0.0.155"
CONFIG = b"# Approved config bytes\nname: gpt-oss-120b\n"
MAX_REVISION_LENGTH = 128
ONE_US = timedelta(microseconds=1)
PRIVATE_REGISTRY_ID = REGISTRY_ID_PREFIX + "9c4a7f21e0b836d56a13c8fe42d907ab"


# --- statement builders ----------------------------------------------------------------


def config_core(
    name: str, digest: str, *, registry_id: str = "", runtime: RuntimeReference | None = None
) -> dict[str, Any]:
    predicate: dict[str, Any] = {}
    if registry_id:
        predicate["scope"] = registry_id
    if runtime is not None:
        predicate["runtime"] = {"repo": runtime.repo, "tag": runtime.tag, "digest": runtime.digest}
    predicate_type = CONFIG_PREDICATE_TYPE_V2 if runtime is not None or registry_id else CONFIG_PREDICATE_TYPE
    return {
        "_type": bm.IN_TOTO_STATEMENT_V1,
        "subject": [{"name": name, "digest": {"sha256": digest}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def timestamp_input_of(domain: bytes, core: dict[str, Any]) -> bytes:
    return domain + _json.canonicalize(as_json(core))


def complete(world: World, core: dict[str, Any], domain: bytes, at: datetime, timestamp: bytes | None = None) -> bytes:
    """The statement with its inner timestamp over the core (or the given token) as the payload bytes."""
    token = timestamp if timestamp is not None else world.timestamp(timestamp_input_of(domain, core), at)
    record = json.loads(json.dumps(core))
    record["predicate"]["freshness"] = {"rfc3161Timestamp": b64(token)}
    return json.dumps(record).encode()


def config_payload(world: World, at: datetime, config: bytes = CONFIG, name: str = NAME) -> bytes:
    """A v1 config endorsement of ``config`` timestamped at ``at``."""
    return complete(world, config_core(name, hashlib.sha256(config).hexdigest()), CONFIG_FRESHNESS_DOMAIN, at)


def deployment_core(config: bytes, registry_id: str = PUBLIC_REGISTRY_ID) -> dict[str, Any]:
    version = config.decode().split("cvm-version: ")[1].strip()
    tag, digest = version.split("@sha256:")
    runtime = RuntimeReference(repo=RUNTIME_REPO, tag="v" + tag.removeprefix("v"), digest=digest)
    return config_core(NAME, hashlib.sha256(config).hexdigest(), registry_id=registry_id, runtime=runtime)


def deployment_payload(world: World, at: datetime, config: bytes, registry_id: str = PUBLIC_REGISTRY_ID) -> bytes:
    return complete(world, deployment_core(config, registry_id), CONFIG_FRESHNESS_DOMAIN_V2, at)


def artifact(kind: str) -> FreshnessArtifact:
    if kind == KIND_PLATFORM:
        return FreshnessArtifact(kind, PLATFORM_REPO, PLATFORM_TAG_PREFIX + "v1.2.3", PLATFORM_NAME, "ab" * 32)
    return FreshnessArtifact(kind, RUNTIME_REPO, "v1.2.3", runtime_name("v1.2.3"), "ab" * 32)


def freshness_core(a: FreshnessArtifact) -> dict[str, Any]:
    return {
        "_type": bm.IN_TOTO_STATEMENT_V1,
        "subject": [{"name": a.name, "digest": {"sha256": a.digest}}],
        "predicateType": ARTIFACT_FRESHNESS_PREDICATE_TYPE,
        "predicate": {"kind": a.kind, "repo": a.repo, "tag": a.tag},
    }


def freshness_payload(world: World, a: FreshnessArtifact, at: datetime, timestamp: bytes | None = None) -> bytes:
    return complete(world, freshness_core(a), ARTIFACT_FRESHNESS_DOMAIN, at, timestamp)


def policy(world: World, **overrides: Any) -> ConfigPolicy:
    """The pins of a verifier under caller-supplied keys: no registry is involved."""
    fields: dict[str, Any] = {"identity": IDENTITY, "now": world.now, "registry_ids": None}
    fields.update(overrides)
    return ConfigPolicy(**fields)


def config_verifier(world: World, keys: list[ec.EllipticCurvePublicKey] | None = None) -> ConfigVerifier:
    return ConfigVerifier(world.trusted_root(), keys or [world.key.public_key()])


def freshness_verifier(world: World, keys: list[ec.EllipticCurvePublicKey] | None = None) -> FreshnessVerifier:
    return FreshnessVerifier(world.trusted_root(), keys or [world.key.public_key()])


def apply(mutate: Any, value: Any) -> Any:
    """Apply a mutation written as a lambda, whose type the checker cannot infer from a mixed list."""
    return mutate(value)


def mutated(bundle: dict[str, Any], change: Any) -> _json.JsonValue:
    copied = json.loads(json.dumps(bundle))
    apply(change, copied)
    return as_json(copied)


def flip_signature(b: dict[str, Any]) -> None:
    signature = bytearray(base64.b64decode(b["dsseEnvelope"]["signatures"][0]["sig"]))
    signature[-1] ^= 1
    b["dsseEnvelope"]["signatures"][0]["sig"] = b64(bytes(signature))


# --- config statements -----------------------------------------------------------------


def test_timestamp_core_canonicalization() -> None:
    world = World()
    core = config_core(NAME, "a" * 64)
    want = (
        b"tinfoil-config-freshness/v1\x00"
        b'{"_type":"https://in-toto.io/Statement/v1","predicate":{},"predicateType":"https://tinfoil.sh/predicate/config-endorsement/v1",'
        b'"subject":[{"digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"name":"/tinfoil/model-router/v0.0.155"}]}'
    )
    assert timestamp_input_of(CONFIG_FRESHNESS_DOMAIN, core) == want
    parsed = parse_config_statement(complete(world, core, CONFIG_FRESHNESS_DOMAIN, world.now))
    assert config_timestamp_input(parsed) == want
    assert parsed.name == NAME
    assert parsed.digest == "a" * 64
    assert parsed.predicate.runtime is None
    assert parsed.predicate.registry_id == ""
    # The core is built from the decoded members: an explicit empty scope or null runtime leaves it unchanged.
    explicit = json.loads(complete(world, core, CONFIG_FRESHNESS_DOMAIN, world.now))
    explicit["predicate"]["scope"] = ""
    explicit["predicate"]["runtime"] = None
    assert config_timestamp_input(parse_config_statement(json.dumps(explicit).encode())) == want


def test_deployment_statement_requires_runtime_binding() -> None:
    world = World()
    config = b"cvm-version: 0.15.0@sha256:" + b"ab" * 32 + b"\n"
    payload = deployment_payload(world, world.now, config)
    parsed = parse_config_statement(payload)
    assert parsed.predicate.runtime == RuntimeReference(RUNTIME_REPO, "v0.15.0", "ab" * 32)
    assert parsed.predicate.registry_id == PUBLIC_REGISTRY_ID
    assert config_timestamp_input(parsed).startswith(CONFIG_FRESHNESS_DOMAIN_V2)
    for _name, mutate, message in [
        ("missing registry ID", lambda s: s["predicate"].pop("scope"), "canonical registry URI"),
        (
            "noncanonical registry ID",
            lambda s: s["predicate"].update(scope=PUBLIC_REGISTRY_ID + "/"),
            "canonical registry URI",
        ),
        ("missing runtime", lambda s: s["predicate"].pop("runtime"), "requires a runtime reference"),
        ("wrong repository", lambda s: s["predicate"]["runtime"].update(repo="other/runtime"), "runtime repository"),
        ("invalid digest", lambda s: s["predicate"]["runtime"].update(digest="ab"), "runtime digest"),
        ("short tag", lambda s: s["predicate"]["runtime"].update(tag="v0.15"), "full semantic version"),
        ("v1 runtime", lambda s: s.update(predicateType=CONFIG_PREDICATE_TYPE), "cannot contain a runtime reference"),
        (
            "v1 scope",
            lambda s: (s.update(predicateType=CONFIG_PREDICATE_TYPE), s["predicate"].pop("runtime")),
            "cannot contain a runtime reference",
        ),
    ]:
        record = json.loads(payload)
        apply(mutate, record)
        with pytest.raises(ApprovalError, match=message):
            parse_config_statement(json.dumps(record).encode())


@pytest.mark.parametrize(
    "invalid",
    [
        "/org/project",
        "org/project/v1",
        "//org/project/v1",
        "/org//v1",
        "/org/Project/v1",
        "/Org/project/v1",
        "/org/project/enclave/v1",
        "/tinfoil/org/project/enclave/v1",
        "/org/../v1",
        "/org/project/../v1",
        "/org/project/%2F",
        "/org/project/v1/",
        "/org/project/.hidden",
        "/org/project/",
        "/org/project/v1\x00",
        "/org/project/" + "a" * (MAX_REVISION_LENGTH + 1),
        "/" + "a" * (MAX_SLUG_LENGTH + 1) + "/project/v1",
        "/org/" + "a" * (MAX_SLUG_LENGTH + 1) + "/v1",
        "/org/proj-/v1",
        "/org/-proj/v1",
        "/org/pro--ject/v1",
        "/org/project/v1\n",
        "/örg/project/v1",
    ],
)
def test_names_are_canonical_rejects(invalid: str) -> None:
    with pytest.raises(ApprovalError):
        parse_name(invalid)


@pytest.mark.parametrize(
    ("name", "identity", "revision"),
    [
        (NAME, IDENTITY, "v0.0.155"),
        ("/org/project/v0.1.0", "/org/project", "v0.1.0"),
        ("/org-1/project-2/Release_1.2-rc", "/org-1/project-2", "Release_1.2-rc"),
        (
            "/" + "a" * MAX_SLUG_LENGTH + "/" + "b" * MAX_SLUG_LENGTH + "/" + "c" * MAX_REVISION_LENGTH,
            "/" + "a" * MAX_SLUG_LENGTH + "/" + "b" * MAX_SLUG_LENGTH,
            "c" * MAX_REVISION_LENGTH,
        ),
    ],
)
def test_names_are_canonical_accepts(name: str, identity: str, revision: str) -> None:
    assert parse_name(name) == (identity, revision)


def test_strict_statement_decoding() -> None:
    world = World()
    payload = config_payload(world, world.now)
    for _name, mutate in [
        ("duplicate property", lambda p: p.replace(b'"predicate":', b'"predicate":{},"predicate":', 1)),
        ("unknown property", lambda p: p.replace(b'"predicate": {', b'"predicate": {"issuedAt": "2026-01-01",', 1)),
        ("case folding", lambda p: p.replace(b'"freshness":', b'"Freshness":', 1)),
        ("trailing JSON", lambda p: p + b"{}"),
        ("invalid UTF-8", lambda p: p.replace(NAME.encode(), b"/tinfoil/\xff", 1)),
        ("renamed timestamp member", lambda p: p.replace(b'"freshness":', b'"x":', 1)),
        ("empty timestamp", lambda p: re.sub(rb'"rfc3161Timestamp": "[^"]*"', b'"rfc3161Timestamp": ""', p, count=1)),
        ("non-canonical base64", lambda p: p.replace(b'"rfc3161Timestamp": "', b'"rfc3161Timestamp": "\\n', 1)),
        ("null subject", lambda p: p.replace(b'"subject": [{', b'"subject": [null, {', 1)),
        (
            "two subjects",
            lambda p: p.replace(
                b'"subject": [{',
                b'"subject": [{"name": "' + NAME.encode() + b'", "digest": {"sha256": "' + b"a" * 64 + b'"}}, {',
                1,
            ),
        ),
        (
            "uppercase digest",
            lambda p: p.replace(
                hashlib.sha256(CONFIG).hexdigest().encode(), hashlib.sha256(CONFIG).hexdigest().upper().encode(), 1
            ),
        ),
        ("two digests", lambda p: p.replace(b'"digest": {', b'"digest": {"sha512": "ab", ', 1)),
        ("wrong statement type", lambda p: p.replace(b"Statement/v1", b"Statement/v0.1", 1)),
        ("wrong predicate type", lambda p: p.replace(b"config-endorsement/v1", b"config-endorsement/v3", 1)),
        ("null", lambda p: b"null"),
        ("array", lambda p: b"[]"),
    ]:
        with pytest.raises(ApprovalError):
            parse_config_statement(apply(mutate, payload))
    with pytest.raises(ApprovalError, match="unknown object member name"):
        parse_config_statement(payload.replace(b'"freshness":', b'"x":', 1))
    without_timestamp = json.loads(payload)
    without_timestamp["predicate"].pop("freshness")
    with pytest.raises(ApprovalError, match="requires an inner timestamp"):
        parse_config_statement(json.dumps(without_timestamp).encode())
    padded = payload + b" " * (bm.MAX_STATEMENT_SIZE - len(payload))
    parse_config_statement(padded)
    with pytest.raises(ApprovalError, match="statement size is outside allowed bounds"):
        parse_config_statement(padded + b" ")
    with pytest.raises(ApprovalError, match="statement size is outside allowed bounds"):
        parse_config_statement(b"")
    record = json.loads(payload)
    record["predicate"]["freshness"]["rfc3161Timestamp"] = b64(b"x" * (bm.MAX_TIMESTAMP_SIZE + 1))
    with pytest.raises(ApprovalError, match="inner timestamp exceeds size limit"):
        parse_config_statement(json.dumps(record).encode())


def test_renewal_changes_approval_without_changing_artifact() -> None:
    world = World()
    first_payload = config_payload(world, world.now - timedelta(minutes=1))
    second_payload = config_payload(world, world.now)
    first, second = parse_config_statement(first_payload), parse_config_statement(second_payload)
    assert first.subjects == second.subjects
    assert config_timestamp_input(first) == config_timestamp_input(second)
    assert first.predicate.freshness is not None
    assert second.predicate.freshness is not None
    assert first.predicate.freshness.rfc3161_timestamp != second.predicate.freshness.rfc3161_timestamp
    assert bm.endorsement_reference(first_payload) != bm.endorsement_reference(second_payload)
    assert bm.endorsement_reference(first_payload) != bm.endorsement_reference(first_payload + b" ")
    assert first.digest == hashlib.sha256(CONFIG).hexdigest()


@pytest.mark.parametrize(
    "registry_id",
    [
        PUBLIC_REGISTRY_ID,
        PRIVATE_REGISTRY_ID,
        REGISTRY_ID_PREFIX + "0" * 32,
        REGISTRY_ID_PREFIX + "f" * 32,
    ],
)
def test_registry_id_canonicalization_accepts(registry_id: str) -> None:
    validate_registry_id(registry_id)


@pytest.mark.parametrize(
    "registry_id",
    [
        "",
        PRIVATE_REGISTRY_ID + "/",
        PRIVATE_REGISTRY_ID + "?x=1",
        PRIVATE_REGISTRY_ID + "#x",
        PRIVATE_REGISTRY_ID + "\n",
        " " + PRIVATE_REGISTRY_ID,
        PUBLIC_REGISTRY_ID + "\n",
        PRIVATE_REGISTRY_ID[:-1],
        PRIVATE_REGISTRY_ID + "a",
        PRIVATE_REGISTRY_ID.replace("9c4a", "9C4A", 1),
        PRIVATE_REGISTRY_ID.replace("9c4a", "9g4a", 1),
        PRIVATE_REGISTRY_ID.replace("9c4a", "9 4a", 1),
        PRIVATE_REGISTRY_ID.replace("9c4a", "%39c4a", 1),
        PRIVATE_REGISTRY_ID.replace("https:", "http:", 1),
        PRIVATE_REGISTRY_ID.replace("https:", "HTTPS:", 1),
        PRIVATE_REGISTRY_ID.replace("registry.tinfoil.sh", "user@registry.tinfoil.sh", 1),
        PRIVATE_REGISTRY_ID.replace("registry.tinfoil.sh", "registry.tinfoil.sh:443", 1),
        PRIVATE_REGISTRY_ID.replace("scopes/", "scopes/v1/", 1),
        PRIVATE_REGISTRY_ID.replace("9c4a", "9c-4a", 1),
        PRIVATE_REGISTRY_ID.replace("9c4a", "９c4a", 1),
    ],
)
def test_registry_id_canonicalization_rejects(registry_id: str) -> None:
    with pytest.raises(ApprovalError, match="canonical registry URI"):
        validate_registry_id(registry_id)


# --- artifact freshness statements --------------------------------------------------------


@pytest.mark.parametrize(
    ("tag", "valid"),
    [
        ("platform-v1.2.3", True),
        ("platform-v1.2.3-rc.1", True),
        ("v1.2.3", False),
        ("platform-v1.2", False),
        ("platform-v1.2.3+build", False),
        ("platform-v01.2.3", False),
        ("platform-", False),
    ],
)
def test_platform_release_identity(tag: str, valid: bool) -> None:
    platform = FreshnessArtifact(KIND_PLATFORM, PLATFORM_REPO, tag, PLATFORM_NAME, "a" * 64)
    if valid:
        platform.validate()
    else:
        with pytest.raises(ApprovalError):
            platform.validate()
    runtime = FreshnessArtifact(KIND_RUNTIME, RUNTIME_REPO, tag, runtime_name(tag), "a" * 64)
    if tag == "v1.2.3":
        runtime.validate()
    else:
        with pytest.raises(ApprovalError):
            runtime.validate()


@pytest.mark.parametrize(
    ("tag", "version", "valid"),
    [
        ("v0.15.0", "v0.15.0", True),
        ("v0.15.0", "v0.15.0+gpu", True),
        ("v0.15.0-rc.1", "v0.15.0-rc.1+gpu", True),
        ("v0.15.0", "v0.15.0+mini", True),
        ("v0.15.0", "v0.15.0+containers.initrd-1", True),
        ("v0.15.0", "v0.15.0+GPU", True),
        ("v0.15.0", "v0.15.1+gpu", False),
        ("v0.15.0+gpu", "v0.15.0+gpu", False),
        ("v0.15.0", "v0.15.0+", False),
        ("v0.15.0", "v0.15.0+mini/other", False),
        ("v0.15.0", "v0.15+mini", False),
    ],
)
def test_runtime_manifest_identities(tag: str, version: str, valid: bool) -> None:
    a = FreshnessArtifact(KIND_RUNTIME, RUNTIME_REPO, tag, runtime_name(version), "ab" * 32)
    assert is_runtime_name(tag, a.name) == valid
    if not valid:
        with pytest.raises(ApprovalError):
            a.validate()
        return
    a.validate()
    parsed = parse_artifact_freshness_statement(freshness_payload(World(), a, World().now))
    assert parsed.artifact == a
    with pytest.raises(ApprovalError):
        dataclasses.replace(a, name="other-" + a.name).validate()


def test_freshness_artifact_validate_rejections() -> None:
    with pytest.raises(ApprovalError, match="unsupported freshness artifact kind"):
        dataclasses.replace(artifact(KIND_RUNTIME), kind="other").validate()
    with pytest.raises(ApprovalError, match="cvmimage platform artifact"):
        dataclasses.replace(artifact(KIND_PLATFORM), repo="other/repo").validate()
    with pytest.raises(ApprovalError, match="cvmimage platform artifact"):
        dataclasses.replace(artifact(KIND_PLATFORM), name="other.json").validate()
    with pytest.raises(ApprovalError, match="versioned runtime manifest"):
        dataclasses.replace(artifact(KIND_RUNTIME), repo="other/repo").validate()
    with pytest.raises(ApprovalError, match="artifact digest"):
        dataclasses.replace(artifact(KIND_RUNTIME), digest="AB" * 32).validate()
    with pytest.raises(ApprovalError, match="artifact digest"):
        dataclasses.replace(artifact(KIND_RUNTIME), digest="ab" * 31).validate()


def test_timestamp_binds_every_artifact_field() -> None:
    world = World()
    a = artifact(KIND_RUNTIME)
    core = (
        b'{"_type":"https://in-toto.io/Statement/v1","predicate":{"kind":"runtime","repo":"tinfoilsh/cvmimage","tag":"v1.2.3"},'
        b'"predicateType":"https://tinfoil.sh/predicate/artifact-freshness/v1",'
        b'"subject":[{"digest":{"sha256":"abababababababababababababababababababababababababababababababab"},"name":"tinfoil-inference-v1.2.3-manifest.json"}]}'
    )
    want = b"tinfoil-artifact-freshness/v1\x00" + core
    assert timestamp_input_of(ARTIFACT_FRESHNESS_DOMAIN, freshness_core(a)) == want
    token = world.timestamp(want, world.now)
    payload = freshness_payload(world, a, world.now, token)
    parsed = parse_artifact_freshness_statement(payload)
    assert artifact_freshness_timestamp_input(parsed) == want
    verified = freshness_verifier(world).verify(as_json(world.keyed_bundle(payload)), FreshnessPolicy(a, world.now))
    assert verified.approval_time == world.now
    # The same token over a statement with another digest no longer matches the core.
    other = dataclasses.replace(a, digest="cd" * 32)
    with pytest.raises(ApprovalError, match="inner timestamp"):
        freshness_verifier(world).verify(
            as_json(world.keyed_bundle(freshness_payload(world, other, world.now, token))),
            FreshnessPolicy(other, world.now),
        )


def test_artifact_freshness_statement_decoding() -> None:
    world = World()
    a = artifact(KIND_PLATFORM)
    payload = freshness_payload(world, a, world.now)
    assert parse_artifact_freshness_statement(payload).artifact == a
    for _name, mutate, message in [
        ("unknown member", lambda s: s["predicate"].update(extra=1), "unknown object member name"),
        (
            "wrong predicate type",
            lambda s: s.update(predicateType=CONFIG_PREDICATE_TYPE),
            "unsupported artifact freshness statement",
        ),
        ("two subjects", lambda s: s["subject"].append(s["subject"][0]), "unsupported artifact freshness statement"),
        (
            "two digests",
            lambda s: s["subject"][0]["digest"].update(sha512="ab"),
            "unsupported artifact freshness statement",
        ),
        ("wrong kind", lambda s: s["predicate"].update(kind="other"), "unsupported freshness artifact kind"),
        ("missing timestamp", lambda s: s["predicate"].pop("freshness"), "requires an inner timestamp"),
        (
            "empty timestamp",
            lambda s: s["predicate"].update(freshness={"rfc3161Timestamp": ""}),
            "requires an inner timestamp",
        ),
    ]:
        record = json.loads(payload)
        apply(mutate, record)
        with pytest.raises(ApprovalError, match=message):
            parse_artifact_freshness_statement(json.dumps(record).encode())
    with pytest.raises(ApprovalError, match="statement size"):
        parse_artifact_freshness_statement(b"")


# --- registry certificates and certified endorsements --------------------------------------------


def test_scoped_config_certificate_and_timestamp_bindings() -> None:
    world = World()
    root_key = world.key
    leaf_key = pki.p256()
    certificate = world.scope_certificate(leaf_key, PUBLIC_REGISTRY_ID)
    config = b"cvm-version: 0.15.3-rc.1@sha256:" + b"ab" * 32 + b"\n"
    payload = deployment_payload(world, world.now, config)
    bundle = world.certified_bundle(payload, certificate, leaf_key, world.now)
    verifier = ConfigVerifier(world.trusted_root(), [root_key.public_key()], root_keys=[root_key.public_key()])
    registry_policy = ConfigPolicy(
        identity=IDENTITY, now=world.now + timedelta(hours=24), registry_ids=(PUBLIC_REGISTRY_ID,)
    )

    def check(b: _json.JsonValue, issuer: bytes, p: ConfigPolicy = registry_policy) -> Any:
        return verifier.verify_certified(None, b, issuer, p)

    approved = check(as_json(bundle), certificate.issuer)
    assert approved.registry_id == PUBLIC_REGISTRY_ID
    assert approved.signature_time == world.now
    assert approved.approval_time == world.now
    assert approved.signing_key_hint == key_hint(leaf_key.public_key())
    assert approved.runtime == RuntimeReference(RUNTIME_REPO, "v0.15.3-rc.1", "ab" * 32)
    assert verifier.verify_certified(config, as_json(bundle), certificate.issuer, registry_policy) == approved
    with pytest.raises(ApprovalError, match="requires an issuer certificate"):
        verifier.verify(None, as_json(bundle), registry_policy)
    with pytest.raises(ApprovalError, match="requires an issuer certificate"):
        verifier.verify_certified(None, as_json(bundle), b"", registry_policy)
    with pytest.raises(ApprovalError, match="registry root trust is not configured"):
        config_verifier(world).verify_certified(None, as_json(bundle), certificate.issuer, registry_policy)
    with pytest.raises(ApprovalError, match="untrusted registry root"):
        verify_signing_certificate(certificate.certificate, certificate.issuer, [leaf_key.public_key()], world.now)
    root_leaf = world.scope_certificate(root_key, PUBLIC_REGISTRY_ID)
    with pytest.raises(ApprovalError, match="registry root cannot serve"):
        verify_signing_certificate(root_leaf.certificate, root_leaf.issuer, [root_key.public_key()], world.now)
    replacement = world.scope_certificate(leaf_key, PUBLIC_REGISTRY_ID)
    signature = base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"])

    def relog_with_key(b: dict[str, Any]) -> None:
        keyed_entry = world.keyed_bundle(payload)["verificationMaterial"]["tlogEntries"]
        b["verificationMaterial"]["tlogEntries"] = keyed_entry

    for _name, mutate, message in [
        (
            "missing signature timestamp",
            lambda b: b["verificationMaterial"].pop("timestampVerificationData"),
            "signature timestamp",
        ),
        (
            "wrong signature timestamp",
            lambda b: b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0].update(
                signedTimestamp=b64(world.timestamp(b"other signature", world.now))
            ),
            "signature timestamp",
        ),
        (
            "certificate log substitution",
            lambda b: b["verificationMaterial"].update(certificate={"rawBytes": b64(replacement.certificate)}),
            "log entry",
        ),
        ("raw key log substitution", relog_with_key, "log entry"),
        (
            "timestamp before certificate",
            lambda b: b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0].update(
                signedTimestamp=b64(world.timestamp(signature, world.now - timedelta(hours=1)))
            ),
            "verifying config signing certificate",
        ),
        (
            "timestamp after certificate",
            lambda b: b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0].update(
                signedTimestamp=b64(world.timestamp(signature, world.now + timedelta(hours=1)))
            ),
            "verifying config signing certificate",
        ),
        (
            "duplicate signature",
            lambda b: b["dsseEnvelope"]["signatures"].append(b["dsseEnvelope"]["signatures"][0]),
            "exactly one signature",
        ),
        ("no log entries", lambda b: b["verificationMaterial"].update(tlogEntries=[]), "transparency log entries"),
    ]:
        with pytest.raises(ApprovalError, match=message):
            check(mutated(bundle, mutate), certificate.issuer)
    # A certificate for another registry, logged for this envelope, does not match the signed registry id.
    other = world.scope_certificate(leaf_key, PRIVATE_REGISTRY_ID)
    relogged = world.certified_bundle(payload, other, leaf_key, world.now)
    with pytest.raises(ApprovalError, match="does not match signed registry ID"):
        check(as_json(relogged), other.issuer)
    # The inner timestamp must fall inside the window, and may not follow the signature by more than the skew.
    stale = deployment_payload(world, world.now - timedelta(days=8), config)
    with pytest.raises(ApprovalError, match="too old"):
        check(as_json(world.certified_bundle(stale, certificate, leaf_key, world.now)), certificate.issuer)
    late_inner = deployment_payload(world, world.now + timedelta(minutes=2), config)
    with pytest.raises(ApprovalError, match="approval timestamp follows signature timestamp"):
        check(as_json(world.certified_bundle(late_inner, certificate, leaf_key, world.now)), certificate.issuer)
    within_skew = deployment_payload(world, world.now + timedelta(seconds=59), config)
    assert check(
        as_json(world.certified_bundle(within_skew, certificate, leaf_key, world.now)), certificate.issuer
    ).approval_time == world.now + timedelta(seconds=59)
    # The approval expires even though the signature remains historically valid.
    with pytest.raises(ApprovalError, match="too old"):
        check(
            as_json(bundle),
            certificate.issuer,
            dataclasses.replace(registry_policy, now=world.now + DEFAULT_MAX_AGE + timedelta(hours=1)),
        )
    historical = world.certified_bundle(within_skew, certificate, leaf_key, world.now)
    after_signature_age = world.now + DEFAULT_MAX_AGE + timedelta(seconds=30)
    assert (
        check(
            as_json(historical),
            certificate.issuer,
            dataclasses.replace(registry_policy, now=after_signature_age),
        ).signature_time
        == world.now
    )
    # A v1 statement cannot be certified, and a registry outside the accepted set rejects.
    v1_bundle = as_json(world.certified_bundle(config_payload(world, world.now), certificate, leaf_key, world.now))
    with pytest.raises(ApprovalError, match="digest verification requires a v2 config endorsement"):
        check(v1_bundle, certificate.issuer)
    with pytest.raises(ApprovalError, match="requires a v2 statement"):
        verifier.verify_certified(CONFIG, v1_bundle, certificate.issuer, registry_policy)
    with pytest.raises(ApprovalError, match="not accepted by the caller"):
        check(
            as_json(bundle),
            certificate.issuer,
            dataclasses.replace(registry_policy, registry_ids=(PRIVATE_REGISTRY_ID,)),
        )
    assert (
        check(as_json(bundle), certificate.issuer, dataclasses.replace(registry_policy, registry_ids=None)).registry_id
        == PUBLIC_REGISTRY_ID
    )


def test_signing_certificate_profile() -> None:
    world = World()
    root_key = world.key
    leaf_key = pki.p256()
    certificate = world.scope_certificate(leaf_key, PUBLIC_REGISTRY_ID)
    cert, issuer = verify_signing_certificate(
        certificate.certificate, certificate.issuer, [root_key.public_key()], world.now
    )
    assert cert.serial_number == 1
    assert issuer.serial_number == 1
    issued_root = pki.Issued(certificate.issuer, root_key)
    now = world.now
    base: dict[str, Any] = {
        "subject_name": x509.Name([]),
        "key_usage": pki.SIGNING_USAGE,
        "eku": [ExtendedKeyUsageOID.CODE_SIGNING],
        "sans": [x509.UniformResourceIdentifier(PUBLIC_REGISTRY_ID)],
        "san_critical": True,
        "not_before": now - timedelta(minutes=1),
        "not_after": now + timedelta(minutes=9),
        "serial": 1,
    }
    ca_usage = x509.KeyUsage(True, False, False, False, False, True, False, False, False)
    hidden_san = x509.SubjectAlternativeName(
        [x509.UniformResourceIdentifier(PUBLIC_REGISTRY_ID), x509.DirectoryName(x509.Name([]))]
    )
    profiles: dict[str, dict[str, Any]] = {
        "CA": {"ca": True, "key_usage": ca_usage},
        "TLS purpose": {"eku": [ExtendedKeyUsageOID.SERVER_AUTH]},
        "two purposes": {"eku": [ExtendedKeyUsageOID.CODE_SIGNING, ExtendedKeyUsageOID.SERVER_AUTH]},
        "no purpose": {"eku": None},
        "no key usage": {"key_usage": None},
        "extra key usage": {"key_usage": x509.KeyUsage(True, True, False, False, False, False, False, False, False)},
        "long lifetime": {"not_after": now + timedelta(hours=1)},
        "before issuer": {"not_before": now - timedelta(hours=2)},
        "identity subject": {"subject_name": pki.name("customer")},
        "extra DNS identity": {
            "sans": [x509.UniformResourceIdentifier(PUBLIC_REGISTRY_ID), x509.DNSName("customer.example")]
        },
        "missing registry ID": {"sans": None},
        "duplicate registry ID": {"sans": [x509.UniformResourceIdentifier(PUBLIC_REGISTRY_ID)] * 2},
        "other registry URI": {"sans": [x509.UniformResourceIdentifier("https://registry.tinfoil.sh/scopes/PUBLIC")]},
        "noncritical SAN": {"san_critical": False},
        "hidden SAN identity": {"sans": None, "extra": [(hidden_san, True)]},
        "unknown critical extension": {
            "extra": [(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00"), True)]
        },
        "P-384 key": {"key": pki.p384()},
    }
    for _name, overrides in profiles.items():
        fields = {**base, **overrides}
        key = fields.pop("key", leaf_key)
        mutated_der = pki.certificate("", key, issued_root, **fields).der
        with pytest.raises(ApprovalError):
            verify_signing_certificate(mutated_der, certificate.issuer, [root_key.public_key()], now)
    # The time and the byte bounds are checked before anything is parsed.
    with pytest.raises(ApprovalError, match="requires a time and bounded certificate bytes"):
        verify_signing_certificate(
            certificate.certificate, certificate.issuer, [root_key.public_key()], now.replace(tzinfo=None)
        )
    with pytest.raises(ApprovalError, match="requires a time and bounded certificate bytes"):
        verify_signing_certificate(b"", certificate.issuer, [root_key.public_key()], now)
    with pytest.raises(ApprovalError, match="requires a time and bounded certificate bytes"):
        verify_signing_certificate(
            certificate.certificate, b"x" * (approval.MAX_CERTIFICATE_SIZE + 1), [root_key.public_key()], now
        )
    # An issuer that is not a self-signed certificate authority is rejected after its key matched a root.
    not_ca = pki.certificate(
        "registry test root",
        root_key,
        key_usage=pki.SIGNING_USAGE,
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(days=1),
    )
    with pytest.raises(ApprovalError, match="invalid registry root certificate"):
        verify_signing_certificate(certificate.certificate, not_ca.der, [root_key.public_key()], now)
    # Outside the certificate's validity the chain fails.
    with pytest.raises(ApprovalError, match="verifying config signing certificate"):
        verify_signing_certificate(
            certificate.certificate, certificate.issuer, [root_key.public_key()], now + timedelta(hours=1)
        )


# --- key-signed config approvals ----------------------------------------------------------------


def test_verify_config_approval() -> None:
    world = World()
    payload = config_payload(world, world.now - timedelta(minutes=1))
    bundle = world.keyed_bundle(payload)
    got = config_verifier(world).verify(CONFIG, as_json(bundle), policy(world))
    assert got.name == NAME
    assert got.approval_time == world.now - timedelta(minutes=1)
    assert got.reference == bm.endorsement_reference(payload)
    assert got.signing_key_hint == world.hint
    assert got.registry_id == ""
    assert got.signature_time is None
    assert got.runtime is None
    assert "timestampVerificationData" not in bundle["verificationMaterial"]
    pinned = policy(world, revision="v0.0.155", digest=got.digest)
    assert config_verifier(world).verify(CONFIG, as_json(bundle), pinned) == got
    # The default registry set names the public registry, which a caller-key verifier never attributes.
    with pytest.raises(ApprovalError, match="not accepted by the caller"):
        config_verifier(world).verify(CONFIG, as_json(bundle), ConfigPolicy(identity=IDENTITY, now=world.now))


def test_verify_config_digest_and_runtime() -> None:
    world = World()
    config = b"cvm-version: 0.15.0@sha256:" + b"ab" * 32 + b"\n"
    payload = deployment_payload(world, world.now, config)
    bundle = as_json(world.keyed_bundle(payload))
    got = config_verifier(world).verify(None, bundle, policy(world))
    assert got.digest == hashlib.sha256(config).hexdigest()
    assert got.name == NAME
    assert got.runtime == RuntimeReference(RUNTIME_REPO, "v0.15.0", "ab" * 32)
    assert got.approval_time == world.now
    assert got.registry_id == ""
    assert config_verifier(world).verify(config, bundle, policy(world)) == got
    with pytest.raises(ApprovalError, match="config size is outside allowed bounds"):
        config_verifier(world).verify(b"", bundle, policy(world))
    with pytest.raises(ApprovalError, match="config size is outside allowed bounds"):
        config_verifier(world).verify(b"x" * (approval.MAX_CONFIG_SIZE + 1), bundle, policy(world))
    for _name, mutate in [
        ("signature", flip_signature),
        ("missing log", lambda b: b["verificationMaterial"].update(tlogEntries=[])),
        (
            "unsigned runtime change",
            lambda b: b["dsseEnvelope"].update(payload=b64(payload.replace(b"v0.15.0", b"v0.16.0", 1))),
        ),
    ]:
        with pytest.raises(ApprovalError):
            config_verifier(world).verify(None, mutated(world.keyed_bundle(payload), mutate), policy(world))
    with pytest.raises(ApprovalError, match="requires a v2"):
        config_verifier(world).verify(
            None, as_json(world.keyed_bundle(config_payload(world, world.now))), policy(world)
        )
    with pytest.raises(ApprovalError, match="pinned digest"):
        config_verifier(world).verify(None, bundle, policy(world, digest="cd" * 32))
    with pytest.raises(ApprovalError, match="too old"):
        config_verifier(world).verify(
            None, bundle, policy(world, now=world.now + DEFAULT_MAX_AGE + timedelta(seconds=1))
        )
    # A registry verifier attributes a key-signed v1 approval to the public registry, and rejects a key-signed v2 one.
    registry = ConfigVerifier(world.trusted_root(), [world.key.public_key()], root_keys=[world.key.public_key()])
    with pytest.raises(ApprovalError, match="v2 registry endorsement requires an issuer certificate"):
        registry.verify(None, bundle, policy(world))


def test_deployment_runtime_requires_approval_and_matches_config() -> None:
    world = World()
    config = b"cvm-version: 0.15.0@sha256:" + b"ab" * 32 + b"\n"
    core = deployment_core(config)
    token = world.timestamp(timestamp_input_of(CONFIG_FRESHNESS_DOMAIN_V2, core), world.now)
    altered = json.loads(json.dumps(core))
    altered["predicate"]["runtime"]["digest"] = "cd" * 32
    payload = complete(world, altered, CONFIG_FRESHNESS_DOMAIN_V2, world.now, token)
    with pytest.raises(ApprovalError, match="inner timestamp"):
        config_verifier(world).verify(None, as_json(world.keyed_bundle(payload)), policy(world))
    payload = complete(world, altered, CONFIG_FRESHNESS_DOMAIN_V2, world.now)
    with pytest.raises(ApprovalError, match="config runtime does not match"):
        config_verifier(world).verify(config, as_json(world.keyed_bundle(payload)), policy(world))
    with pytest.raises(ApprovalError, match="cvm-version must pin"):
        config_verifier(world).verify(
            CONFIG,
            as_json(
                world.keyed_bundle(
                    complete(
                        world,
                        {
                            **deployment_core(config),
                            "subject": [{"name": NAME, "digest": {"sha256": hashlib.sha256(CONFIG).hexdigest()}}],
                        },
                        CONFIG_FRESHNESS_DOMAIN_V2,
                        world.now,
                    )
                )
            ),
            policy(world),
        )


def test_policy_validate_pins() -> None:
    p = ConfigPolicy(identity=IDENTITY)
    p.validate_pins()
    p = ConfigPolicy(identity=IDENTITY, revision="v0.0.155", digest="ab" * 32)
    p.validate_pins()
    changes: dict[str, dict[str, Any]] = {
        "identity": {"identity": "/tinfoil"},
        "revision": {"revision": "../v1"},
        "digest": {"digest": ("ab" * 32).upper()},
        "empty registries": {"registry_ids": ()},
        "bad registry": {"registry_ids": ("https://registry.tinfoil.sh/scopes/x",)},
        "duplicate registry": {"registry_ids": (PUBLIC_REGISTRY_ID, PUBLIC_REGISTRY_ID)},
    }
    for _name, change in changes.items():
        with pytest.raises(ApprovalError):
            dataclasses.replace(p, **change).validate_pins()
    ConfigPolicy(registry_ids=(PUBLIC_REGISTRY_ID, PRIVATE_REGISTRY_ID)).validate_pins()
    ConfigPolicy(registry_ids=None).validate_pins()
    with pytest.raises(ApprovalError, match="clock and nonnegative age and skew are required"):
        config_verifier(World()).verify(CONFIG, None, ConfigPolicy(identity=IDENTITY))


def test_approval_verification_requires_tsa_trust() -> None:
    world = World()
    trust = parse_trusted_root(world.trusted_root_json(tsa=False))
    keys = [world.key.public_key()]
    configs = ConfigVerifier(trust, keys)
    approvals = FreshnessVerifier(trust, keys)
    config_bundle = as_json(world.keyed_bundle(config_payload(world, world.now)))
    a = artifact(KIND_RUNTIME)
    approval_bundle = as_json(world.keyed_bundle(freshness_payload(world, a, world.now)))
    with pytest.raises(ApprovalError, match="no trusted timestamp authority"):
        configs.verify(CONFIG, config_bundle, policy(world))
    with pytest.raises(ApprovalError, match="no trusted timestamp authority"):
        approvals.verify(approval_bundle, FreshnessPolicy(a, world.now))
    with pytest.raises(ApprovalError, match="Rekor trust is required"):
        ConfigVerifier(parse_trusted_root(world.trusted_root_json(tlogs=False)), keys)


def test_verify_rejects_wrong_pins_and_untrusted_keys() -> None:
    world = World()
    bundle = as_json(world.keyed_bundle(config_payload(world, world.now)))
    changes: dict[str, dict[str, Any]] = {
        "identity": {"identity": "/tinfoil/other"},
        "revision": {"revision": "v0.0.156"},
        "digest": {"digest": "0" * 64},
        "missing clock": {"now": None},
        "negative age": {"max_age": -timedelta(seconds=1)},
        "negative skew": {"future_skew": -timedelta(seconds=1)},
    }
    for _name, change in changes.items():
        with pytest.raises(ApprovalError):
            config_verifier(world).verify(CONFIG, bundle, policy(world, **change))
    with pytest.raises(ApprovalError, match="config bytes"):
        config_verifier(world).verify(CONFIG + b"\n", bundle, policy(world))
    other = World()
    with pytest.raises(ApprovalError, match="untrusted approval signing key"):
        config_verifier(world, [other.key.public_key()]).verify(CONFIG, bundle, policy(world))


def test_verify_requires_signed_approval_and_log_inclusion() -> None:
    world = World()
    payload = config_payload(world, world.now)
    signature = base64.b64decode(world.keyed_bundle(payload)["dsseEnvelope"]["signatures"][0]["sig"])
    for _name, mutate in [
        ("signature", flip_signature),
        (
            "checkpoint",
            lambda b: b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"].update(
                envelope="invalid"
            ),
        ),
        (
            "proof",
            lambda b: b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"].update(hashes=[b64(bytes(32))]),
        ),
        ("missing log", lambda b: b["verificationMaterial"].update(tlogEntries=[])),
        ("legacy log", lambda b: b["verificationMaterial"]["tlogEntries"][0]["kindVersion"].update(version="0.0.1")),
        (
            "integrated time",
            lambda b: b["verificationMaterial"]["tlogEntries"][0].update(
                integratedTime=str(int(world.now.timestamp()))
            ),
        ),
        (
            "unexpected outer timestamp",
            lambda b: b["verificationMaterial"].update(
                timestampVerificationData={
                    "rfc3161Timestamps": [{"signedTimestamp": b64(world.timestamp(signature, world.now))}]
                }
            ),
        ),
        ("duplicate signature", lambda b: b["dsseEnvelope"]["signatures"].append(b["dsseEnvelope"]["signatures"][0])),
        ("unknown key", lambda b: b["verificationMaterial"]["publicKey"].update(hint="untrusted")),
        ("key id", lambda b: b["dsseEnvelope"]["signatures"][0].update(keyid=world.hint)),
        (
            "signing certificate",
            lambda b: (
                b["verificationMaterial"].pop("publicKey"),
                b["verificationMaterial"].update(certificate={"rawBytes": b64(world.tsa_leaf.der)}),
            ),
        ),
        ("other media type", lambda b: b.update(mediaType="application/vnd.dev.sigstore.bundle.v0.2+json")),
    ]:
        with pytest.raises(ApprovalError):
            config_verifier(world).verify(CONFIG, mutated(world.keyed_bundle(payload), mutate), policy(world))
    with pytest.raises(ApprovalError, match="parsing endorsement bundle"):
        config_verifier(world).verify(CONFIG, None, policy(world))


def test_inner_timestamp_binds_complete_core() -> None:
    world = World()
    payload = config_payload(world, world.now)
    for name, mutate in [
        ("name", lambda s: s["subject"][0].update(name=IDENTITY + "/changed")),
        (
            "timestamp on other input",
            lambda s: s["predicate"]["freshness"].update(rfc3161Timestamp=b64(world.timestamp(b"other", world.now))),
        ),
    ]:
        record = json.loads(payload)
        apply(mutate, record)
        altered = json.dumps(record).encode()
        with pytest.raises(ApprovalError, match="inner timestamp"):
            (
                config_verifier(world).verify(CONFIG, as_json(world.keyed_bundle(altered)), policy(world, identity="")),
                name,
            )


def test_freshness_uses_inner_time_and_inclusive_bounds() -> None:
    world = World()
    inner = world.now - timedelta(minutes=1)
    bundle = as_json(world.keyed_bundle(config_payload(world, inner)))
    assert (
        config_verifier(world).verify(CONFIG, bundle, policy(world, now=inner + DEFAULT_MAX_AGE)).approval_time == inner
    )
    with pytest.raises(ApprovalError, match="too old"):
        config_verifier(world).verify(CONFIG, bundle, policy(world, now=inner + DEFAULT_MAX_AGE + ONE_US))
    assert (
        config_verifier(world).verify(CONFIG, bundle, policy(world, now=inner - DEFAULT_FUTURE_SKEW)).approval_time
        == inner
    )
    with pytest.raises(ApprovalError, match="future"):
        config_verifier(world).verify(CONFIG, bundle, policy(world, now=inner - DEFAULT_FUTURE_SKEW - ONE_US))
    # An explicit zero age accepts only an approval at the clock itself.
    assert (
        config_verifier(world).verify(CONFIG, bundle, policy(world, now=inner, max_age=timedelta(0))).approval_time
        == inner
    )
    with pytest.raises(ApprovalError, match="too old"):
        config_verifier(world).verify(CONFIG, bundle, policy(world, now=inner + ONE_US, max_age=timedelta(0)))


def test_archived_config_requires_authenticated_approval() -> None:
    world = World()
    inner = world.now - timedelta(minutes=1)
    bundle = as_json(world.keyed_bundle(config_payload(world, inner)))
    with pytest.raises(ApprovalError, match="too old"):
        config_verifier(world).verify(CONFIG, bundle, policy(world, now=inner + DEFAULT_MAX_AGE + timedelta(hours=1)))
    verified = config_verifier(world).verify(CONFIG, bundle, policy(world, now=inner))
    assert verified.approval_time == inner
    with pytest.raises(ApprovalError, match="config bytes"):
        config_verifier(world).verify(CONFIG + b"\n", bundle, policy(world, now=inner))
    with pytest.raises(ApprovalError, match="untrusted approval signing key"):
        config_verifier(world, [World().key.public_key()]).verify(CONFIG, bundle, policy(world, now=inner))


def test_untrusted_inner_tsa_and_wrong_policy() -> None:
    world = World()
    core = config_core(NAME, hashlib.sha256(CONFIG).hexdigest())
    data = timestamp_input_of(CONFIG_FRESHNESS_DOMAIN, core)
    other = World()
    for response in [other.timestamp(data, world.now), world.timestamp(data, world.now, "1.2.3.4")]:
        payload = complete(world, core, CONFIG_FRESHNESS_DOMAIN, world.now, response)
        with pytest.raises(ApprovalError, match="inner timestamp"):
            config_verifier(world).verify(CONFIG, as_json(world.keyed_bundle(payload)), policy(world))


def test_signing_key_rotation_allows_overlap_and_rejects_removed_keys() -> None:
    world = World()
    old_key = world.key.public_key()
    old_bundle = as_json(world.keyed_bundle(config_payload(world, world.now)))
    new_private = pki.p256()
    new_key = new_private.public_key()
    new_bundle = as_json(world.keyed_bundle(config_payload(world, world.now), new_private))
    verifier = ConfigVerifier(world.trusted_root(), [old_key, new_key])
    for bundle in (old_bundle, new_bundle):
        verifier.verify(CONFIG, bundle, policy(world))
    verifier = ConfigVerifier(world.trusted_root(), [new_key])
    with pytest.raises(ApprovalError, match="untrusted approval signing key"):
        verifier.verify(CONFIG, old_bundle, policy(world))
    assert verifier.verify(CONFIG, new_bundle, policy(world)).signing_key_hint == key_hint(new_key)


def test_registry_legacy_public_cannot_satisfy_private_registry_id_policy() -> None:
    world = World()
    verifier = ConfigVerifier(world.trusted_root(), [world.key.public_key()], root_keys=[world.key.public_key()])
    raw = as_json(world.keyed_bundle(config_payload(world, world.now)))
    public = policy(world, registry_ids=(PUBLIC_REGISTRY_ID,))
    approved = verifier.verify(CONFIG, raw, public)
    assert approved.registry_id == PUBLIC_REGISTRY_ID
    with pytest.raises(ApprovalError, match="requires an issuer certificate"):
        verifier.verify_certified(CONFIG, raw, b"", public)
    with pytest.raises(ApprovalError, match="registry ID is not accepted"):
        verifier.verify(CONFIG, raw, policy(world, registry_ids=(PRIVATE_REGISTRY_ID,)))
    # The default policy accepts the public registry.
    assert (
        verifier.verify(CONFIG, raw, ConfigPolicy(identity=IDENTITY, now=world.now)).registry_id == PUBLIC_REGISTRY_ID
    )


# --- artifact freshness approvals -----------------------------------------------------------------


@pytest.mark.parametrize("kind", [KIND_PLATFORM, KIND_RUNTIME])
def test_verify_artifact_approval(kind: str) -> None:
    world = World()
    a = artifact(kind)
    at = world.now - timedelta(minutes=1)
    payload = freshness_payload(world, a, at)
    got = freshness_verifier(world).verify(as_json(world.keyed_bundle(payload)), FreshnessPolicy(a, world.now))
    assert got.artifact == a
    assert got.approval_time == at
    assert got.reference == bm.endorsement_reference(payload)
    assert got.signing_key_hint == world.hint


def test_runtime_freshness_binds_each_manifest() -> None:
    world = World()
    cpu = artifact(KIND_RUNTIME)
    gpu = dataclasses.replace(cpu, name=runtime_name(cpu.tag + "+gpu"), digest="cd" * 32)
    mini = dataclasses.replace(gpu, name=runtime_name(mini_tag := gpu.tag + "+mini"))
    assert mini_tag == "v1.2.3+mini"
    verifier = freshness_verifier(world)
    for endorsed in (cpu, gpu, mini):
        bundle = as_json(world.keyed_bundle(freshness_payload(world, endorsed, world.now)))
        for expected in (cpu, gpu, mini):
            if expected != endorsed:
                with pytest.raises(ApprovalError):
                    verifier.verify(bundle, FreshnessPolicy(expected, world.now))
                continue
            assert verifier.verify(bundle, FreshnessPolicy(expected, world.now)).artifact == endorsed


def test_verify_rejects_wrong_artifact_and_key() -> None:
    world = World()
    a = artifact(KIND_RUNTIME)
    bundle = as_json(world.keyed_bundle(freshness_payload(world, a, world.now)))
    for _name, pin in {
        "kind": artifact(KIND_PLATFORM),
        "repo": dataclasses.replace(a, repo="other/cvmimage"),
        "tag": dataclasses.replace(a, tag="v1.2.4", name=runtime_name("v1.2.4")),
        "name": dataclasses.replace(a, name="other.json"),
        "digest": dataclasses.replace(a, digest="cd" * 32),
    }.items():
        with pytest.raises(ApprovalError):
            freshness_verifier(world).verify(bundle, FreshnessPolicy(pin, world.now))
    with pytest.raises(ApprovalError, match="untrusted approval signing key"):
        freshness_verifier(world, [World().key.public_key()]).verify(bundle, FreshnessPolicy(a, world.now))


def test_verify_requires_signature_timestamp_and_inclusion() -> None:
    world = World()
    a = artifact(KIND_PLATFORM)
    payload = freshness_payload(world, a, world.now)
    for name, mutate in [
        ("signature", flip_signature),
        ("inclusion", lambda b: b["verificationMaterial"].update(tlogEntries=[])),
        (
            "checkpoint",
            lambda b: b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"].update(
                envelope="invalid"
            ),
        ),
        (
            "outer timestamp",
            lambda b: b["verificationMaterial"].update(
                timestampVerificationData={"rfc3161Timestamps": [{"signedTimestamp": b64(b"untrusted")}]}
            ),
        ),
    ]:
        with pytest.raises(ApprovalError):
            (
                freshness_verifier(world).verify(
                    mutated(world.keyed_bundle(payload), mutate), FreshnessPolicy(a, world.now)
                ),
                name,
            )
    core = freshness_core(a)
    data = timestamp_input_of(ARTIFACT_FRESHNESS_DOMAIN, core)
    for token in [World().timestamp(data, world.now), world.timestamp(b"different core", world.now)]:
        altered = complete(world, core, ARTIFACT_FRESHNESS_DOMAIN, world.now, token)
        with pytest.raises(ApprovalError, match="inner timestamp"):
            freshness_verifier(world).verify(as_json(world.keyed_bundle(altered)), FreshnessPolicy(a, world.now))


def test_approval_age_uses_inner_time() -> None:
    world = World()
    a = artifact(KIND_RUNTIME)
    bundle = as_json(world.keyed_bundle(freshness_payload(world, a, world.now)))
    for name, now, accept in [
        ("age boundary", world.now + DEFAULT_MAX_AGE, True),
        ("expired", world.now + DEFAULT_MAX_AGE + ONE_US, False),
        ("future boundary", world.now - DEFAULT_FUTURE_SKEW, True),
        ("future", world.now - DEFAULT_FUTURE_SKEW - ONE_US, False),
    ]:
        if accept:
            assert freshness_verifier(world).verify(bundle, FreshnessPolicy(a, now)).approval_time == world.now, name
        else:
            with pytest.raises(ApprovalError):
                freshness_verifier(world).verify(bundle, FreshnessPolicy(a, now))
    with pytest.raises(ApprovalError, match="clock and nonnegative age and skew"):
        freshness_verifier(world).verify(bundle, FreshnessPolicy(a, world.now.replace(tzinfo=None)))
    for p in [
        FreshnessPolicy(a, world.now, max_age=-timedelta(seconds=1)),
        FreshnessPolicy(a, world.now, future_skew=-timedelta(seconds=1)),
    ]:
        with pytest.raises(ApprovalError, match="nonnegative age and skew"):
            freshness_verifier(world).verify(bundle, p)
    with pytest.raises(ApprovalError, match="unsupported freshness artifact kind"):
        freshness_verifier(world).verify(bundle, FreshnessPolicy(dataclasses.replace(a, kind="x"), world.now))


# --- the approval verifier and the vectors -----------------------------------------------------------


def test_approval_verifier_construction() -> None:
    world = World()
    verifier = ApprovalVerifier(world.trusted_root(), [world.key.public_key()])
    assert [key.hint for key in verifier.keys] == [world.hint]
    assert verifier.root == world.trusted_root()
    with pytest.raises(ApprovalError, match="at least one independently trusted signing key"):
        ApprovalVerifier(world.trusted_root(), [])
    with pytest.raises(ApprovalError, match="duplicate signing key"):
        ApprovalVerifier(world.trusted_root(), [world.key.public_key(), world.key.public_key()])
    with pytest.raises(ApprovalError, match="ECDSA P-256"):
        ApprovalVerifier(world.trusted_root(), [pki.p384().public_key()])
    with pytest.raises(ApprovalError, match="Rekor trust is required"):
        ApprovalVerifier(parse_trusted_root(world.trusted_root_json(tlogs=False)), [world.key.public_key()])


def test_verify_timestamp_applies_the_window() -> None:
    world = World()
    verifier = ApprovalVerifier(world.trusted_root(), [world.key.public_key()])
    window = policy(world).time_policy()
    assert verifier.verify_timestamp(world.timestamp(b"data", world.now), b"data", window) == world.now
    with pytest.raises(ApprovalError, match="too old"):
        verifier.verify_timestamp(world.timestamp(b"data", world.now - timedelta(days=8)), b"data", window)
    with pytest.raises(ApprovalError, match="does not match the input"):
        verifier.verify_timestamp(world.timestamp(b"data", world.now), b"other", window)
    with pytest.raises(ApprovalError, match="timestamp input size"):
        verifier.verify_timestamp(world.timestamp(b"", world.now), b"", window)
    with pytest.raises(ApprovalError, match="unexpected timestamp policy"):
        verifier.verify_timestamp(world.timestamp(b"data", world.now, "1.2.3.4"), b"data", window)


@pytest.mark.parametrize("fixture", vector_params("approval-bundle"))
def test_approval_bundle_vectors(fixture: dict[str, Any]) -> None:
    """Every approval-bundle vector through the approval verifier: the verdict and, on accept, the signing key hint."""
    expected = fixture["expected"]
    root = parse_trusted_root(base64.b64decode(fixture["input"]["sigstore_trusted_root_json_b64"]))
    verifier = ApprovalVerifier(root, [load_public_key_pem(pem) for pem in fixture["input"]["signing_keys_pem"]])
    bundle = _json.strict_parse(base64.b64decode(fixture["input"]["bundle_json_b64"]))
    digest = bytes.fromhex(fixture["input"]["artifact_digest_hex"])
    try:
        hint = verifier.verify(approval._parse_approval_bundle(bundle), digest)
    except ApprovalError:
        assert not expected["accepted"], fixture["id"]
        return
    assert expected["accepted"], fixture["id"]
    assert hint == expected["signing_key_hint"]


def test_public_signing_keys_are_the_embedded_p256_keys() -> None:
    keys = public_signing_keys()
    assert len(keys) == 1
    assert isinstance(keys[0], ec.EllipticCurvePublicKey)
    # Standard base64 of SHA-256 over the DER SubjectPublicKeyInfo of the embedded key.
    assert key_hint(keys[0]) == "J4/dwixneOvUPEEizF3WGcRiLOpQvzk5Kd8ThACLK60="
    assert ApprovalVerifier(World().trusted_root(), keys).keys[0].hint == key_hint(keys[0])


def test_statement_helper_matches_the_decoder() -> None:
    """The in-toto builder used by the other tests produces what the config statement decoder accepts."""
    world = World()
    payload = complete(world, config_core(NAME, "a" * 64), CONFIG_FRESHNESS_DOMAIN, world.now)
    assert parse_config_statement(payload).type == bm.IN_TOTO_STATEMENT_V1
    built = bm.parse_statement(
        statement([{"name": NAME, "digest": {"sha256": "a" * 64}}], CONFIG_PREDICATE_TYPE, {"scope": ""})
    )
    assert built.type == bm.IN_TOTO_STATEMENT_V1
    assert built.predicate_type == CONFIG_PREDICATE_TYPE
    assert [(subject.name, dict(subject.digest)) for subject in built.subjects] == [(NAME, {"sha256": "a" * 64})]
    assert _json.strict_parse(built.predicate) == _json.JsonObject({"scope": ""})
