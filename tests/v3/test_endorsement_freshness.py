"""Freshness witnesses: the witness statement, the artifact binding, the log-time window and the full path over
minted and production bundles."""

from __future__ import annotations

import base64
import dataclasses
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from tests.v3.sigstore_world import FulcioIdentity, World, as_json
from tests.v3.vectors import vector
from tinfoil._v3.verifier._document import document
from tinfoil._v3.verifier._endorsement.freshness import (
    FRESHNESS_PREDICATE_FORMAT,
    MAX_FRESHNESS_AGE,
    MAX_FRESHNESS_FUTURE_SKEW,
    FreshnessError,
    FreshnessWitness,
    WitnessEndorsement,
    WitnessSubject,
    authenticate_freshness,
    parse_freshness_witness,
    validate_freshness_time,
    validate_witness,
)
from tinfoil._v3.verifier._endorsement.provenance import ProvenanceClient
from tinfoil._v3.verifier._endorsement.reference import (
    FRESHNESS_WITNESS_REPO,
    PLATFORM_ENDORSEMENTS_REPO,
    AuthenticatedArtifact,
    Reference,
)
from tinfoil._v3.verifier._endorsement.time import new_time_policy

NOW = datetime(2026, 8, 6, tzinfo=UTC)
ONE_US = timedelta(microseconds=1)


def sample_artifact() -> AuthenticatedArtifact:
    return AuthenticatedArtifact(
        repo=PLATFORM_ENDORSEMENTS_REPO,
        tag="v0.0.4",
        commit="0123456789abcdef0123456789abcdef01234567",
        subject_name="platform-endorsements.json",
        digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )


def sample_witness(expected: AuthenticatedArtifact | None = None) -> FreshnessWitness:
    expected = expected or sample_artifact()
    return FreshnessWitness(
        format=FRESHNESS_PREDICATE_FORMAT,
        endorses=WitnessEndorsement(
            repo=expected.repo,
            tag=expected.tag,
            commit=expected.commit,
            subject=WitnessSubject(name=expected.subject_name, digest="sha256:" + expected.digest),
        ),
    )


def test_validate_witness() -> None:
    validate_witness(sample_witness(), sample_artifact())
    bad = dataclasses.replace(
        sample_witness().endorses, subject=WitnessSubject("platform-endorsements.json", "sha256:abc")
    )
    with pytest.raises(FreshnessError, match="does not match authenticated artifact"):
        validate_witness(FreshnessWitness(FRESHNESS_PREDICATE_FORMAT, bad), sample_artifact())
    for field, value in [("repo", "o/r"), ("tag", "v9"), ("commit", "f" * 40)]:
        endorses = dataclasses.replace(sample_witness().endorses, **cast(dict[str, Any], {field: value}))
        with pytest.raises(FreshnessError, match="does not match authenticated artifact"):
            validate_witness(FreshnessWitness(FRESHNESS_PREDICATE_FORMAT, endorses), sample_artifact())
    with pytest.raises(FreshnessError):
        validate_witness(sample_witness(), dataclasses.replace(sample_artifact(), subject_name="other"))


def test_validate_freshness_time_takes_the_earliest_log_time() -> None:
    policy = new_time_policy(NOW, MAX_FRESHNESS_AGE)
    assert validate_freshness_time([NOW - timedelta(hours=2), NOW - timedelta(hours=3)], policy) == NOW - timedelta(
        hours=3
    )
    with pytest.raises(FreshnessError, match="no verified transparency-log timestamp"):
        validate_freshness_time([], policy)
    for name, offset, message in [
        ("age inside", -MAX_FRESHNESS_AGE + ONE_US, ""),
        ("age boundary", -MAX_FRESHNESS_AGE, ""),
        ("age outside", -MAX_FRESHNESS_AGE - ONE_US, "stale"),
        ("future inside", MAX_FRESHNESS_FUTURE_SKEW - ONE_US, ""),
        ("future boundary", MAX_FRESHNESS_FUTURE_SKEW, ""),
        ("future outside", MAX_FRESHNESS_FUTURE_SKEW + ONE_US, "in the future"),
    ]:
        want = NOW + offset
        if message:
            with pytest.raises(FreshnessError, match=message):
                validate_freshness_time([want], policy)
        else:
            assert validate_freshness_time([want], policy) == want, name
    day_old = [NOW - timedelta(hours=25)]
    with pytest.raises(FreshnessError, match="stale"):
        validate_freshness_time(day_old, new_time_policy(NOW, timedelta(hours=24)))
    assert validate_freshness_time(day_old, new_time_policy(NOW, timedelta(days=30))) == day_old[0]


def witness_predicate(expected: AuthenticatedArtifact) -> dict[str, Any]:
    witness = sample_witness(expected)
    return {
        "format": witness.format,
        "endorses": {
            "repo": witness.endorses.repo,
            "tag": witness.endorses.tag,
            "commit": witness.endorses.commit,
            "subject": {"name": witness.endorses.subject.name, "digest": witness.endorses.subject.digest},
        },
    }


def witness_payload(expected: AuthenticatedArtifact, **overrides: Any) -> bytes:
    record: dict[str, Any] = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": expected.subject_name, "digest": {"sha256": expected.digest}}],
        "predicateType": FRESHNESS_PREDICATE_FORMAT,
        "predicate": witness_predicate(expected),
    }
    record.update(overrides)
    return json.dumps(record).encode()


def test_parse_freshness_witness_is_strict() -> None:
    predicate = witness_predicate(sample_artifact())
    assert parse_freshness_witness(json.dumps(predicate).encode()) == sample_witness()
    with pytest.raises(FreshnessError, match="unknown object member name"):
        parse_freshness_witness(json.dumps({**predicate, "extra": 1}).encode())
    with pytest.raises(FreshnessError, match="unknown object member name"):
        parse_freshness_witness(json.dumps({"format": "f", "endorses": {"repo": "r", "note": 1}}).encode())
    with pytest.raises(FreshnessError, match="duplicate"):
        parse_freshness_witness(b'{"format":"a","format":"b"}')
    with pytest.raises(FreshnessError, match="into string"):
        parse_freshness_witness(json.dumps({**predicate, "format": 1}).encode())
    with pytest.raises(FreshnessError, match="into freshness witness"):
        parse_freshness_witness(b"[]")
    # Missing members decode as empty, which the matching rejects later.
    empty = parse_freshness_witness(b"{}")
    assert empty.format == ""
    assert empty.endorses.subject.digest == ""


WITNESS = FulcioIdentity(
    san=f"https://github.com/{FRESHNESS_WITNESS_REPO}/.github/workflows/freshness.yml@refs/heads/main",
    source_repository_uri=f"https://github.com/{FRESHNESS_WITNESS_REPO}",
    source_repository_ref="refs/heads/main",
)


def test_authenticate_freshness_returns_the_log_time() -> None:
    world = World()
    client = ProvenanceClient(world.trusted_root())
    expected = sample_artifact()
    logged = world.now - timedelta(hours=1)
    bundle = as_json(world.fulcio_bundle(witness_payload(expected), WITNESS, logged))
    assert authenticate_freshness(client, bundle, expected, world.now) == logged
    assert client.authenticate_freshness(bundle, expected, world.now, timedelta(hours=2)) == logged
    with pytest.raises(FreshnessError, match="stale"):
        authenticate_freshness(client, bundle, expected, world.now, timedelta(minutes=30))
    with pytest.raises(FreshnessError, match="stale"):
        authenticate_freshness(client, bundle, expected, logged + MAX_FRESHNESS_AGE + ONE_US)
    assert authenticate_freshness(client, bundle, expected, logged + MAX_FRESHNESS_AGE) == logged
    assert authenticate_freshness(client, bundle, expected, logged - MAX_FRESHNESS_FUTURE_SKEW) == logged
    with pytest.raises(FreshnessError, match="in the future"):
        authenticate_freshness(client, bundle, expected, logged - MAX_FRESHNESS_FUTURE_SKEW - ONE_US)
    with pytest.raises(FreshnessError, match="must not be negative"):
        authenticate_freshness(client, bundle, expected, world.now, -timedelta(seconds=1))
    with pytest.raises(FreshnessError, match="clock"):
        authenticate_freshness(client, bundle, expected, world.now.replace(tzinfo=None))


def test_authenticate_freshness_rejections() -> None:
    world = World()
    client = ProvenanceClient(world.trusted_root())
    expected = sample_artifact()
    at = world.now - timedelta(hours=1)

    def witness_bundle(payload: bytes, identity: FulcioIdentity = WITNESS, **kwargs: Any) -> Any:
        return as_json(world.fulcio_bundle(payload, identity, at, **kwargs))

    with pytest.raises(FreshnessError, match="authenticated artifact tag is empty"):
        authenticate_freshness(
            client, witness_bundle(witness_payload(expected)), dataclasses.replace(expected, tag=""), world.now
        )
    with pytest.raises(FreshnessError, match="verifying freshness witness bundle"):
        authenticate_freshness(
            client,
            witness_bundle(witness_payload(expected)),
            dataclasses.replace(expected, digest="ff" * 32),
            world.now,
        )
    other_workflow = dataclasses.replace(WITNESS, san=WITNESS.san.replace("refs/heads/main", "refs/tags/v1"))
    with pytest.raises(FreshnessError, match="verifying freshness witness bundle"):
        authenticate_freshness(client, witness_bundle(witness_payload(expected), other_workflow), expected, world.now)
    # A statement of another type never passes the bundle layer, which accepts in-toto v1 alone.
    with pytest.raises(FreshnessError, match="verifying freshness witness bundle"):
        authenticate_freshness(
            client,
            witness_bundle(witness_payload(expected, _type="https://in-toto.io/Statement/v0.1")),
            expected,
            world.now,
        )
    with pytest.raises(FreshnessError, match="unexpected freshness predicate format"):
        authenticate_freshness(
            client,
            witness_bundle(witness_payload(expected, predicateType="https://tinfoil.sh/predicate/other/v1")),
            expected,
            world.now,
        )
    wrong_format = witness_payload(expected)
    wrong_format = wrong_format.replace(b'"format": "' + FRESHNESS_PREDICATE_FORMAT.encode(), b'"format": "x', 1)
    with pytest.raises(FreshnessError, match="unexpected freshness predicate format"):
        authenticate_freshness(client, witness_bundle(wrong_format), expected, world.now)
    # The predicate decodes strictly from the signed bytes: an unknown member rejects.
    extra_member = witness_payload(expected, predicate={**witness_predicate(expected), "extra": 1})
    with pytest.raises(FreshnessError, match=r"parsing freshness witness: .*unknown object member name"):
        authenticate_freshness(client, witness_bundle(extra_member), expected, world.now)
    two_subjects = witness_payload(
        expected,
        subject=[
            {"name": expected.subject_name, "digest": {"sha256": expected.digest}},
            {"name": "other", "digest": {"sha256": expected.digest}},
        ],
    )
    with pytest.raises(FreshnessError, match="subject does not match authenticated artifact"):
        authenticate_freshness(client, witness_bundle(two_subjects), expected, world.now)
    renamed = witness_payload(expected, subject=[{"name": "other.json", "digest": {"sha256": expected.digest}}])
    with pytest.raises(FreshnessError, match="subject does not match authenticated artifact"):
        authenticate_freshness(client, witness_bundle(renamed), expected, world.now)
    # The witness must name the artifact down to the commit.
    wrong_commit = json.loads(witness_payload(expected))
    wrong_commit["predicate"]["endorses"]["commit"] = "f" * 40
    with pytest.raises(FreshnessError, match="witness does not match authenticated artifact"):
        authenticate_freshness(client, witness_bundle(json.dumps(wrong_commit).encode()), expected, world.now)
    # A receipt that attests no time, with only a signature timestamp as the observer, leaves no log time.
    with pytest.raises(FreshnessError, match="no verified transparency-log timestamp"):
        authenticate_freshness(
            client, witness_bundle(witness_payload(expected), receipt="v2", timestamp=True), expected, world.now
        )


def test_production_witness_authenticates_the_real_code_artifact() -> None:
    fixture = vector("real-frozen", "real-sev-inference-tinfoil")
    client = ProvenanceClient.default()
    parsed = document.decode_unbound(base64.b64decode(fixture["input"]["document_b64"]))
    ref = parsed.sigstore_code()
    code = client.authenticate_code(ref.bundle, Reference(fixture["input"]["repo"]), ref.tag, ref.digest)
    witness = parsed.freshness("code-freshness")
    raw = json.loads(base64.b64decode(fixture["input"]["document_b64"]))
    entry = next(e for e in raw["collateral"] if e["id"] == "code-freshness")
    logged = datetime.fromtimestamp(
        int(entry["data"]["sigstore_bundle"]["verificationMaterial"]["tlogEntries"][0]["integratedTime"]), UTC
    )
    assert client.authenticate_freshness(witness.bundle, code.artifact, logged + timedelta(hours=1)) == logged
    with pytest.raises(FreshnessError, match="stale"):
        client.authenticate_freshness(witness.bundle, code.artifact, logged + timedelta(days=8))
    with pytest.raises(FreshnessError, match="does not match"):
        client.authenticate_freshness(witness.bundle, dataclasses.replace(code.artifact, tag="v0.0.1"), logged)
