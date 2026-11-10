"""The verifier: its options and their conflicts, the pipeline's layer attribution, repository pins, embedded
references, caller-authorized configs, endorsed configs over a synthetic Sigstore world, and freshness deadlines."""

from __future__ import annotations

import dataclasses
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.v3 import document_builder, pki
from tests.v3 import verifier_fixtures as vf
from tests.v3.sigstore_world import World, as_json, b64
from tests.v3.test_endorsement_approval import (
    PRIVATE_REGISTRY_ID,
    complete,
    config_core,
    config_payload,
    freshness_payload,
)
from tinfoil._v3.verifier._config import (
    ReferencesError,
    _authenticate_artifact_freshness,
    config_references,
    freshness_expiration,
    reference_pins,
)
from tinfoil._v3.verifier._document.collateral.collateral import (
    AMD_CRL_V1_FORMAT,
    AMD_VCEK_V1_FORMAT,
    ARTIFACT_FRESHNESS_V1_FORMAT,
    FORMAT_V2,
    FORMAT_V3,
    FRESHNESS_ID_PLATFORM,
    FRESHNESS_ID_RUNTIME,
    SIGSTORE_CODE_V1_FORMAT,
    NotFoundError,
)
from tinfoil._v3.verifier._document.collateral.config import (
    CONFIG_ENDORSEMENT_V1_FORMAT,
    CONFIG_ENDORSEMENT_V2_FORMAT,
    CONFIG_ID,
    CONFIG_V1_FORMAT,
    ConfigEndorsement,
)
from tinfoil._v3.verifier._document.collateral.runtime import PLATFORM_ID, RUNTIME_ID, RUNTIME_REPO
from tinfoil._v3.verifier._document.document import NONCE_SIZE
from tinfoil._v3.verifier._embedded import EmbeddedConfig, EmbeddedConfigReference, EmbeddedReferences
from tinfoil._v3.verifier._endorsement.approval import (
    CONFIG_FRESHNESS_DOMAIN_V2,
    KIND_RUNTIME,
    PUBLIC_REGISTRY_ID,
    ConfigPolicy,
    ConfigVerifier,
    FreshnessArtifact,
    public_signing_keys,
    runtime_name,
)
from tinfoil._v3.verifier._endorsement.reference import AuthenticatedArtifact
from tinfoil._v3.verifier._endorsement.time import DEFAULT_MAX_AGE
from tinfoil._v3.verifier._errors import (
    LAYER_ENVELOPE,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    UsageError,
    VerificationError,
)
from tinfoil._v3.verifier._measurement import SEVSNP, ExpectedSEVSNP, ExpectedTDX
from tinfoil._v3.verifier._quote import ConfigReferenceValues
from tinfoil._v3.verifier._runtime import decode_manifest, runtime_from_config
from tinfoil._v3.verifier._sigstore.bundle import endorsement_reference
from tinfoil._v3.verifier._trust.amd_turin import AMD_TURIN_CERT_CHAIN_PEM
from tinfoil._v3.verifier._verification import (
    SOURCE_EMBEDDED,
    SOURCE_ENDORSEMENT,
    SOURCE_POLICY,
    ConfigVerification,
)
from tinfoil._v3.verifier._verifier import Overrides, Verifier, _build, parse_reference

REGISTER = bytes([0xAB]) * 48
NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)


def rejected_at(err: BaseException, layer: str) -> None:
    """``err`` is a VerificationError from ``layer``."""
    assert isinstance(err, VerificationError), err
    assert err.layer == layer, err


def trust_of(verifier: Verifier) -> Any:
    return verifier._trust


def with_trust(verifier: Verifier, **changes: Any) -> Verifier:
    """A verifier whose policy has ``changes`` applied; what the constructor would never build on its own."""
    verifier._trust = dataclasses.replace(verifier._trust, **changes)
    return verifier


def authorize_all(config: ConfigEndorsement) -> None:
    return None


# --- options --------------------------------------------------------------------------------


def test_new_defaults() -> None:
    v = Verifier()
    assert v.freshness_max_age == DEFAULT_MAX_AGE
    assert v.pinned_registers is None
    assert v.caller_authorizes_config is False


def test_freshness_max_age() -> None:
    # None keeps the default; every non-negative age is honoured, including zero, which accepts only a witness that
    # is no older than the verification instant.
    assert Verifier(freshness_max_age=None).freshness_max_age == DEFAULT_MAX_AGE
    assert Verifier(freshness_max_age=timedelta(0)).freshness_max_age == timedelta(0)
    assert Verifier(freshness_max_age=timedelta(microseconds=1)).freshness_max_age == timedelta(microseconds=1)
    assert Verifier(freshness_max_age=timedelta(hours=24)).freshness_max_age == timedelta(hours=24)
    for max_age in (timedelta(microseconds=-1), timedelta(hours=-1)):
        with pytest.raises(UsageError, match="freshness maximum age must not be negative"):
            Verifier(freshness_max_age=max_age)
    for bad in (0, 3600, "7d"):
        with pytest.raises(UsageError, match="freshness maximum age must be a timedelta"):
            Verifier(freshness_max_age=bad)  # type: ignore[arg-type]


def test_pinned_registers_must_be_expected_values() -> None:
    pins = ExpectedTDX(rtmr3=REGISTER)
    assert Verifier(pinned_registers=pins).pinned_registers == pins
    assert Verifier(pinned_registers=ExpectedSEVSNP(launch=REGISTER)).pinned_registers == ExpectedSEVSNP(
        launch=REGISTER
    )
    for bad in (SEVSNP(launch=REGISTER), "pins", {"launch": REGISTER}):
        with pytest.raises(UsageError, match="pinned registers must be an ExpectedSEVSNP or ExpectedTDX value"):
            Verifier(pinned_registers=bad)  # type: ignore[arg-type]


def test_verify_v3_rejects_bad_repo() -> None:
    v = Verifier()
    code = vf.reference_entry(
        "code", SIGSTORE_CODE_V1_FORMAT, {"repo": "", "tag": "", "digest": "digest", "sigstore_bundle": {}}
    )
    raw, nonce, _ = vf.embedded_document(None, code)
    with pytest.raises(UsageError, match="invalid release reference"):
        v.verify_v3(raw, nonce, "not a repo reference")


def test_verify_rejects_an_unbuilt_verifier() -> None:
    # A verifier that skipped its constructor carries neither a trust root nor a clock: a usage error rather than
    # an attribute error once a well-formed document is in hand.
    unbuilt = object.__new__(Verifier)
    with pytest.raises(UsageError, match="verifier must be built"):
        unbuilt.verify_v3(b"{}", bytes(NONCE_SIZE), "org/repo")


def test_verify_v3_at_requires_an_aware_instant() -> None:
    v = Verifier(embedded_references=vf.embedded_inputs())
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    with pytest.raises(UsageError, match="verification time must be timezone-aware"):
        v.verify_v3_at(raw, nonce, "", datetime(2026, 1, 1))
    with pytest.raises(UsageError, match="verification time is required"):
        v.verify_v3_at(raw, nonce, "", None)  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="document must be bytes"):
        v.verify_v3_at("{}", nonce, "", NOW)  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="nonce must be bytes"):
        v.verify_v3_at(raw, nonce.hex(), "", NOW)  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="expected nonce must be"):
        v.verify_v3_at(raw, nonce[:-1], "", NOW)


def test_errors_name_their_layer() -> None:
    assert str(VerificationError(LAYER_QUOTE, "report signature is invalid")) == (
        "verification error: quote: report signature is invalid"
    )
    assert str(UsageError("verification time is required")) == "usage error: verification time is required"
    assert parse_reference("org/project@v1").tag == "v1"


# --- the pipeline ---------------------------------------------------------------------------


def test_verify_appraises_cpu_evidence_at_the_verification_instant() -> None:
    """The CPU evidence layer appraises vendor collateral at the verification instant. The AMD CRL window is
    checked before the report is parsed, so a CRL valid only at a frozen instant shows which clock the quote layer
    used."""
    appraisal = datetime(2020, 1, 1, tzinfo=UTC)
    issuer = pki.certificate("test CRL issuer", pki.p256(), ca=True, key_usage=pki.CA_USAGE)
    crl = pki.crl(issuer, this_update=appraisal - timedelta(hours=1), next_update=appraisal + timedelta(hours=1))
    vcek = vf.endorsement_entry(
        "vcek",
        AMD_VCEK_V1_FORMAT,
        {"vcek_der_base64": b64(b"vcek"), "cert_chain_pem": AMD_TURIN_CERT_CHAIN_PEM.decode()},
    )
    crl_entry = vf.endorsement_entry("crl", AMD_CRL_V1_FORMAT, {"crl_der_base64": b64(crl)})
    raw, nonce, _ = vf.embedded_document(FORMAT_V3, vcek, crl_entry, report=b"unauthenticated quote")
    v = Verifier(embedded_references=vf.embedded_inputs())
    with pytest.raises(VerificationError, match="outside its validity window") as now_rejected:
        v.verify_v3(raw, nonce, "")
    rejected_at(now_rejected.value, LAYER_QUOTE)
    with pytest.raises(VerificationError, match="must be exactly") as then_rejected:
        v.verify_v3_at(raw, nonce, "", appraisal)
    rejected_at(then_rejected.value, LAYER_QUOTE)
    assert then_rejected.value.__cause__ is not None, "the CRL window passed at the caller's instant"


def test_collateral_version_selects_verification() -> None:
    v = Verifier()
    for format_, want in (
        (None, SIGSTORE_CODE_V1_FORMAT),
        (FORMAT_V2, SIGSTORE_CODE_V1_FORMAT),
        (FORMAT_V3, CONFIG_ID),
    ):
        raw, nonce, _ = vf.embedded_document(format_)
        with pytest.raises(VerificationError, match=want) as rejected:
            v.verify_v3(raw, nonce, "org/project")
        rejected_at(rejected.value, LAYER_PROVENANCE)
        assert isinstance(rejected.value.__cause__, NotFoundError)


def test_unknown_collateral_format_never_reaches_the_reference_values() -> None:
    v = Verifier()
    nonce = document_builder.test_nonce()
    _, raw = document_builder.build(
        nonce, collateral_format="https://tinfoil.sh/predicate/attestation-collaterals/v9", collateral_entries=[]
    )
    with pytest.raises(VerificationError, match="unsupported collateral format") as rejected:
        v.verify_v3(raw, nonce, "org/project")
    rejected_at(rejected.value, LAYER_ENVELOPE)


def test_config_reference_pins() -> None:
    v = Verifier()
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    repo = "org/project"
    digest = "ab" * 32
    for ref in ("", repo, repo + "@v1", repo + "@sha256:" + digest, repo + "@v1@sha256:" + digest):
        with pytest.raises(VerificationError) as rejected:
            v.verify_v3(raw, nonce, ref)
        assert isinstance(rejected.value.__cause__, NotFoundError), "valid pins must reach endorsement verification"
    for ref in (
        "/org/project",
        "Org/project",
        "org/project_name",
        "org/project@v1/path",
        "org/project@sha256:bad",
        "org/project@v1@v2",
    ):
        with pytest.raises(UsageError):
            v.verify_v3(raw, nonce, ref)


def test_v3_collateral_requires_config_identity_pins() -> None:
    v = Verifier()
    v.check_repo_verifiability("Org/My_Repo")
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    with pytest.raises(UsageError, match="identity"):
        v.verify_v3(raw, nonce, "Org/My_Repo")


def test_check_repo_verifiability() -> None:
    inputs = vf.embedded_inputs()
    cases: list[tuple[str, dict[str, Any], str, bool]] = [
        ("defaults with a pin", {}, "org/repo@v1", True),
        ("defaults with a pin only v2 collateral accepts", {}, "Org/My_Repo", True),
        ("defaults without a pin", {}, "", True),
        ("defaults with a malformed pin", {}, "not a reference", False),
        ("embedded config without a pin", {"embedded_references": inputs}, "", True),
        ("embedded config with its own pin", {"embedded_references": inputs}, "org/project@v1", True),
        ("embedded config with another pin", {"embedded_references": inputs}, "org/repo", False),
        ("config authorizer without a pin", {"config_authorizer": authorize_all}, "", True),
        ("config authorizer with a pin", {"config_authorizer": authorize_all}, "org/repo", False),
    ]
    for name, options, ref, valid in cases:
        v = Verifier(**options)
        if valid:
            v.check_repo_verifiability(ref)
        else:
            with pytest.raises(UsageError):
                v.check_repo_verifiability(ref)
        assert name


def test_caller_authorizes_config() -> None:
    inputs = vf.embedded_inputs()
    without_config = dataclasses.replace(inputs, config=None)
    assert Verifier().caller_authorizes_config is False
    assert Verifier(embedded_references=without_config).caller_authorizes_config is False
    assert Verifier(embedded_references=inputs).caller_authorizes_config is True
    assert Verifier(config_authorizer=authorize_all).caller_authorizes_config is True


# --- config authorizer ------------------------------------------------------------------------


def test_config_authorizer_error_never_chooses_the_type() -> None:
    """A config authorizer's error is the cause of a VerificationError. It never chooses the error type, even when it
    is one of the verifier's own types."""
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    config = inputs.config.data
    entry = vf.reference_entry(CONFIG_ID, CONFIG_V1_FORMAT, {"config_base64": b64(config)})
    raw, nonce, _ = vf.embedded_document(FORMAT_V3, entry)
    refused = UsageError("config is not authorized")

    def refuse(candidate: ConfigEndorsement) -> None:
        raise refused

    v = Verifier(embedded_references=dataclasses.replace(inputs, config=None), config_authorizer=refuse)
    with pytest.raises(VerificationError) as rejected:
        v.verify_v3(raw, nonce, "")
    rejected_at(rejected.value, LAYER_PROVENANCE)
    assert rejected.value.__cause__ is refused, "the authorizer's error remains the cause"
    assert "authorizing config" in str(rejected.value)


def test_config_authorizer_preserves_references_and_hardware_checks() -> None:
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    config = inputs.config.data
    digest = hashlib.sha256(config).digest()
    entry = vf.reference_entry(CONFIG_ID, CONFIG_V1_FORMAT, {"config_base64": b64(config)})
    raw, nonce, doc = vf.embedded_document(FORMAT_V3, entry)
    v = Verifier(embedded_references=dataclasses.replace(inputs, config=None))
    with pytest.raises(ReferencesError, match="unsigned config"):
        config_references(trust_of(v), doc, "org/project", NOW)
    rejected = ValueError("config is not authorized")

    def authorize(candidate: ConfigEndorsement) -> None:
        if candidate.config is None or hashlib.sha256(candidate.config).digest() != digest:
            raise rejected

    with_trust(v, config_authorizer=authorize)
    refs = config_references(trust_of(v), doc, "", NOW)
    assert isinstance(refs.quote, ConfigReferenceValues)
    assert refs.quote.hash == digest
    assert refs.config == ConfigVerification(source=SOURCE_POLICY, digest=digest.hex())
    assert refs.freshness_expires_at is None
    with pytest.raises(UsageError, match="cannot authenticate repository"):
        config_references(trust_of(v), doc, "org/project", NOW)
    with pytest.raises(VerificationError) as hardware:
        v.verify_v3(raw, nonce, "")
    rejected_at(hardware.value, LAYER_QUOTE)

    embedded = trust_of(v).embedded
    altered = dataclasses.replace(trust_of(v), embedded=dataclasses.replace(embedded, runtime=embedded.runtime + b"\n"))
    with pytest.raises(ValueError, match="digest pin"):
        config_references(altered, doc, "", NOW)
    no_runtime = dataclasses.replace(trust_of(v), embedded=dataclasses.replace(embedded, runtime=None))
    with pytest.raises(NotFoundError, match=RUNTIME_ID):
        config_references(no_runtime, doc, "", NOW)
    no_platform = dataclasses.replace(trust_of(v), embedded=dataclasses.replace(embedded, platform=None))
    with pytest.raises(NotFoundError, match=PLATFORM_ID):
        config_references(no_platform, doc, "", NOW)

    digest = bytes([digest[0] ^ 1]) + digest[1:]
    with pytest.raises(VerificationError) as refused:
        config_references(trust_of(v), doc, "", NOW)
    assert refused.value.__cause__ is rejected
    _, _, legacy = vf.embedded_document(FORMAT_V2)
    with pytest.raises(VerificationError, match="configured trust requires") as v2:
        v.verify_v3(*vf.embedded_document(FORMAT_V2)[:2], "org/project")
    rejected_at(v2.value, LAYER_PROVENANCE)
    assert legacy.collateral_format() == FORMAT_V2


def test_config_authorizer_rejects_conflicting_trust() -> None:
    inputs = vf.embedded_inputs()
    keys = public_signing_keys()
    with pytest.raises(UsageError, match="config authorizer conflicts"):
        Verifier(config_authorizer=authorize_all, embedded_references=inputs)
    with pytest.raises(UsageError, match="config authorizer conflicts"):
        Verifier(config_authorizer=authorize_all, config_signing_keys=keys)
    with pytest.raises(UsageError, match="config authorizer must be callable"):
        Verifier(config_authorizer="authorize")  # type: ignore[arg-type]


def test_config_size_is_bounded_before_the_authorizer_runs() -> None:
    inputs = vf.embedded_inputs()
    calls: list[bytes | None] = []

    def record(candidate: ConfigEndorsement) -> None:
        calls.append(candidate.config)

    v = Verifier(embedded_references=dataclasses.replace(inputs, config=None), config_authorizer=record)
    reference = endorsement_reference(b"statement")
    entry = vf.reference_entry(
        CONFIG_ID, CONFIG_ENDORSEMENT_V2_FORMAT, {"endorsement_ref": reference, "sigstore_bundle": {}}
    )
    _, _, doc = vf.embedded_document(FORMAT_V3, entry)
    with pytest.raises(ReferencesError, match="config size is outside allowed bounds"):
        config_references(trust_of(v), doc, "", NOW)
    assert calls == []


# --- embedded references ----------------------------------------------------------------------


def test_config_pins_one_runtime_manifest() -> None:
    _, _, doc = vf.embedded_document(FORMAT_V3)
    for suffix in ("", "+gpu", "+mini", "+containers.initrd-1"):
        if suffix:
            manifest = vf.manifest_bytes("v0.15.0" + suffix, snp_launch="ef" * 48, mrtd="12" * 48)
        else:
            manifest = vf.manifest_bytes()
        inputs = EmbeddedReferences(
            config=EmbeddedConfig(data=vf.config_bytes(manifest, "0.15.0" + suffix), name=vf.EMBEDDED_CONFIG_NAME),
            runtime=manifest,
            platform=vf.platform_bytes(),
        )
        v = Verifier(embedded_references=inputs)
        refs = config_references(trust_of(v), doc, "", NOW)
        assert isinstance(refs.quote, ConfigReferenceValues)
        assert isinstance(inputs.config, EmbeddedConfig)
        assert refs.quote.hash == hashlib.sha256(inputs.config.data).digest()
        assert refs.quote.runtime == decode_manifest(manifest).measurements
        assert refs.artifact.tag == "v0.15.0"
        assert refs.artifact.source == SOURCE_EMBEDDED
        if suffix:
            with pytest.raises(UsageError, match="digest pin"):
                Verifier(embedded_references=dataclasses.replace(inputs, runtime=vf.manifest_bytes()))


def test_embedded_config_reference_without_config_bytes() -> None:
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    digest = hashlib.sha256(inputs.config.data).hexdigest()
    runtime = runtime_from_config(inputs.config.data)
    reference = EmbeddedConfigReference(name=vf.EMBEDDED_CONFIG_NAME, digest=digest, runtime=runtime)
    v = Verifier(embedded_references=dataclasses.replace(inputs, config=reference))
    assert v.caller_authorizes_config is True
    v.check_repo_verifiability("")
    v.check_repo_verifiability("org/project@v1@sha256:" + digest)
    with pytest.raises(UsageError):
        v.check_repo_verifiability("org/project@v2")
    with pytest.raises(UsageError):
        v.check_repo_verifiability("org/project@sha256:" + "ab" * 32)
    raw, nonce, doc = vf.embedded_document(FORMAT_V3)
    refs = config_references(trust_of(v), doc, "org/project@v1", NOW)
    assert isinstance(refs.quote, ConfigReferenceValues)
    assert refs.quote.hash == bytes.fromhex(digest)
    assert refs.artifact.digest == runtime.digest
    for ref in ("org/project@v1", ""):
        with pytest.raises(VerificationError) as rejected:
            v.verify_v3(raw, nonce, ref)
        rejected_at(rejected.value, LAYER_QUOTE)
    for bad in (
        dataclasses.replace(reference, digest=""),
        dataclasses.replace(reference, runtime=dataclasses.replace(runtime, digest="cd" * 32)),
        dataclasses.replace(reference, name="/invalid"),
    ):
        with pytest.raises(UsageError):
            Verifier(embedded_references=dataclasses.replace(inputs, config=bad))


def test_embedded_references_preserve_bindings() -> None:
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    config_hash = hashlib.sha256(inputs.config.data).digest()
    v = Verifier(embedded_references=inputs)
    raw, nonce, doc = vf.embedded_document(FORMAT_V3)
    refs = config_references(trust_of(v), doc, "org/project@v1@sha256:" + config_hash.hex(), NOW)
    assert isinstance(refs.quote, ConfigReferenceValues)
    assert refs.quote.hash == config_hash
    assert refs.quote.runtime is not None
    assert refs.quote.runtime.snp_launch.measurement == vf.SNP_LAUNCH
    assert refs.quote.endorsements.format == "https://tinfoil.sh/predicate/platform-endorsements/v2"
    assert refs.config is not None
    assert refs.platform is not None
    assert refs.config.source == SOURCE_EMBEDDED
    assert refs.artifact.source == SOURCE_EMBEDDED
    assert refs.platform.source == SOURCE_EMBEDDED
    assert refs.config.reference == ""
    assert refs.config.signing_key_hint == ""
    assert refs.config.approval_time is None
    assert refs.freshness_expires_at is None
    with pytest.raises(VerificationError) as pinned:
        v.verify_v3(raw, nonce, "org/project@v1")
    rejected_at(pinned.value, LAYER_QUOTE)
    with pytest.raises(VerificationError) as unpinned:
        v.verify_v3(raw, nonce, "")
    rejected_at(unpinned.value, LAYER_QUOTE)


def test_embedded_references_cannot_override_pins() -> None:
    inputs = vf.embedded_inputs()
    v = Verifier(embedded_references=inputs)
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    for ref in ("other/project", "org/project@v2", "org/project@sha256:" + "00" * 32):
        with pytest.raises(UsageError, match="does not match the caller's pins"):
            v.verify_v3(raw, nonce, ref)
    assert inputs.runtime is not None
    with pytest.raises(UsageError, match="digest pin"):
        Verifier(embedded_references=dataclasses.replace(inputs, runtime=inputs.runtime + b"\n"))

    assert isinstance(inputs.config, EmbeddedConfig)
    unnamed = dataclasses.replace(inputs, config=dataclasses.replace(inputs.config, name=""))
    v = Verifier(embedded_references=unnamed)
    with pytest.raises(UsageError, match="does not match the caller's pins"):
        v.verify_v3(raw, nonce, "org/project")
    with pytest.raises(VerificationError) as rejected:
        v.verify_v3(raw, nonce, "")
    rejected_at(rejected.value, LAYER_QUOTE)


def test_embedded_references_still_require_other_endorsements() -> None:
    _, _, doc = vf.embedded_document(FORMAT_V3)
    for component, changes in (
        (CONFIG_ID, {"config": None}),
        (RUNTIME_ID, {"runtime": None}),
        (PLATFORM_ID, {"platform": None}),
    ):
        v = Verifier(embedded_references=dataclasses.replace(vf.embedded_inputs(), **changes))
        with pytest.raises(NotFoundError, match=component):
            config_references(trust_of(v), doc, "org/project", NOW)


def test_embedded_trust_rejects_invalid_or_unused_inputs() -> None:
    inputs = vf.embedded_inputs()
    keys = public_signing_keys()
    for refs in (
        EmbeddedReferences(),
        EmbeddedReferences(config=EmbeddedConfig(data=b"")),
        EmbeddedReferences(runtime=b""),
        EmbeddedReferences(runtime=b"{}"),
        EmbeddedReferences(platform=b""),
        EmbeddedReferences(platform=b'{"format":"unknown"}'),
        EmbeddedReferences(platform=b'{"format":"https://tinfoil.sh/predicate/platform-endorsements/v1"}'),
    ):
        with pytest.raises(UsageError):
            Verifier(embedded_references=refs)
    for version in ("", "0.15.0", "v0.15"):
        with pytest.raises(UsageError):
            Verifier(embedded_references=EmbeddedReferences(runtime=vf.manifest_bytes(version)))
    for config in (b"config bytes", "sha256:" + "cd" * 32, {"data": b"config bytes"}):
        with pytest.raises(UsageError, match="embedded config must be an EmbeddedConfig or EmbeddedConfigReference"):
            Verifier(embedded_references=EmbeddedReferences(config=config))  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="conflicting trust sources"):
        Verifier(embedded_references=inputs, config_signing_keys=keys)
    with pytest.raises(UsageError, match="no endorsed artifact"):
        Verifier(embedded_references=inputs, freshness_signing_keys=keys)
    raw, nonce, _ = vf.embedded_document(FORMAT_V2)
    configured: list[dict[str, Any]] = [
        {"embedded_references": inputs},
        {"config_signing_keys": keys},
        {"freshness_signing_keys": keys},
        {"config_registry_ids": [PRIVATE_REGISTRY_ID]},
        {"config_authorizer": authorize_all},
    ]
    for options in configured:
        v = Verifier(**options)
        with pytest.raises(VerificationError, match="configured trust requires") as rejected:
            v.verify_v3(raw, nonce, "org/project")
        rejected_at(rejected.value, LAYER_PROVENANCE)


# --- endorsed configs over the synthetic world ------------------------------------------------


def config_entry(format_: str, **data: Any) -> dict[str, Any]:
    return vf.reference_entry(CONFIG_ID, format_, data)


def test_endorsed_config_with_embedded_artifacts_retains_freshness_and_authority() -> None:
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    config = inputs.config.data
    world = World()
    at = world.now - timedelta(minutes=1)
    payload = config_payload(world, at, config, vf.EMBEDDED_CONFIG_NAME)
    bundle = world.keyed_bundle(payload)
    v = vf.world_verifier(
        world,
        embedded_references=EmbeddedReferences(runtime=inputs.runtime, platform=inputs.platform),
        config_signing_keys=[world.key.public_key()],
    )
    pins = ConfigPolicy(identity="/org/project", now=world.now, max_age=v.freshness_max_age, registry_ids=None)
    approved = trust_of(v).config_verifier.verify(config, as_json(bundle), pins)
    entry = config_entry(
        CONFIG_ENDORSEMENT_V1_FORMAT,
        endorsement_ref=approved.reference,
        config_base64=b64(config),
        sigstore_bundle=bundle,
    )
    _, _, doc = vf.embedded_document(FORMAT_V3, entry)
    refs = config_references(trust_of(v), doc, "org/project", world.now)
    assert refs.config is not None
    assert refs.config.source == SOURCE_ENDORSEMENT
    assert refs.artifact.source == SOURCE_EMBEDDED
    assert refs.config.approval_time == at
    assert refs.config.registry_id == ""
    assert refs.freshness_expires_at == at + v.freshness_max_age
    rejected = ValueError("config is not authorized")

    def refuse(candidate: ConfigEndorsement) -> None:
        raise rejected

    with_trust(v, config_authorizer=refuse)
    with pytest.raises(VerificationError) as refused:
        config_references(trust_of(v), doc, "", world.now)
    assert refused.value.__cause__ is rejected, "a valid endorsement must not bypass caller policy"
    with_trust(v, config_authorizer=None)
    with pytest.raises(ReferencesError, match="too old"):
        config_references(trust_of(v), doc, "org/project", refs.freshness_expires_at + timedelta(seconds=1))

    other = World()
    with_trust(v, config_verifier=ConfigVerifier(world.trusted_root(), [other.key.public_key()]))
    with pytest.raises(ReferencesError, match="untrusted approval signing key"):
        config_references(trust_of(v), doc, "org/project", world.now)


def test_config_trust_requires_endorsements() -> None:
    keys = [pki.p256().public_key()]
    with pytest.raises(UsageError, match="must not be empty"):
        Verifier(freshness_signing_keys=[])
    with pytest.raises(UsageError, match="must not be empty"):
        Verifier(config_signing_keys=[])
    v = Verifier(config_signing_keys=keys, freshness_signing_keys=keys)
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    with pytest.raises(VerificationError, match=CONFIG_ID) as rejected:
        v.verify_v3(raw, nonce, "org/project")
    rejected_at(rejected.value, LAYER_PROVENANCE)
    assert isinstance(rejected.value.__cause__, NotFoundError)


def test_digest_endorsement_binds_quote_and_runtime_without_config() -> None:
    world = World()
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    config = inputs.config.data
    core = config_core(
        vf.EMBEDDED_CONFIG_NAME,
        hashlib.sha256(config).hexdigest(),
        registry_id=PUBLIC_REGISTRY_ID,
        runtime=runtime_from_config(config),
    )
    payload = complete(world, core, CONFIG_FRESHNESS_DOMAIN_V2, world.now)
    reference = endorsement_reference(payload)
    entry = config_entry(
        CONFIG_ENDORSEMENT_V2_FORMAT, endorsement_ref=reference, sigstore_bundle=world.keyed_bundle(payload)
    )
    raw, nonce, doc = vf.embedded_document(FORMAT_V3, entry)
    artifacts = EmbeddedReferences(runtime=inputs.runtime, platform=inputs.platform)
    v = vf.world_verifier(world, embedded_references=artifacts, config_signing_keys=[world.key.public_key()])
    refs = config_references(trust_of(v), doc, "org/project@v1", world.now)
    assert isinstance(refs.quote, ConfigReferenceValues)
    assert refs.quote.hash == hashlib.sha256(config).digest()
    assert refs.quote.runtime is not None
    assert refs.quote.runtime.snp_launch.measurement == vf.SNP_LAUNCH
    assert refs.config is not None
    assert refs.config.source == SOURCE_ENDORSEMENT
    assert refs.config.reference == reference
    assert refs.freshness_expires_at == world.now + v.freshness_max_age
    with pytest.raises(VerificationError) as rejected:
        v.verify_v3_at(raw, nonce, "org/project@v1", world.now)
    rejected_at(rejected.value, LAYER_QUOTE)
    with pytest.raises(ReferencesError, match="pinned identity"):
        config_references(trust_of(v), doc, "org/other", world.now)
    altered = bytes([config[0] ^ 1]) + config[1:]
    for attached in (config, altered, config + b"\n"):
        _, _, with_bytes = vf.embedded_document(
            FORMAT_V3,
            config_entry(
                CONFIG_ENDORSEMENT_V2_FORMAT,
                endorsement_ref=reference,
                config_base64=b64(attached),
                sigstore_bundle=world.keyed_bundle(payload),
            ),
        )
        if attached != config:
            with pytest.raises(ReferencesError, match="config bytes do not match"):
                config_references(trust_of(v), with_bytes, "org/project@v1", world.now)
        else:
            assert config_references(trust_of(v), with_bytes, "org/project@v1", world.now) == refs
    assert inputs.runtime is not None
    v = vf.world_verifier(
        world,
        embedded_references=dataclasses.replace(artifacts, runtime=inputs.runtime + b"\n"),
        config_signing_keys=[world.key.public_key()],
    )
    with pytest.raises(ValueError, match="digest pin"):
        config_references(trust_of(v), doc, "org/project@v1", world.now)


def test_scoped_config_retains_freshness_after_certificate_expiry() -> None:
    world = World()
    root_key = world.key
    leaf = pki.p256()
    certificate = world.scope_certificate(leaf, PRIVATE_REGISTRY_ID)
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    config = inputs.config.data
    core = config_core(
        vf.EMBEDDED_CONFIG_NAME,
        hashlib.sha256(config).hexdigest(),
        registry_id=PRIVATE_REGISTRY_ID,
        runtime=runtime_from_config(config),
    )
    payload = complete(world, core, CONFIG_FRESHNESS_DOMAIN_V2, world.now)
    reference = endorsement_reference(payload)
    entry = config_entry(
        CONFIG_ENDORSEMENT_V2_FORMAT,
        endorsement_ref=reference,
        issuer_certificate_der=b64(certificate.issuer),
        sigstore_bundle=world.certified_bundle(payload, certificate, leaf, world.now),
    )
    _, _, doc = vf.embedded_document(FORMAT_V3, entry)
    artifacts = EmbeddedReferences(runtime=inputs.runtime, platform=inputs.platform)
    registry = ConfigVerifier(world.trusted_root(), [root_key.public_key()], root_keys=[root_key.public_key()])
    for name, options, accepted in (
        ("default", {}, False),
        ("exclusive", {"config_registry_ids": [PRIVATE_REGISTRY_ID]}, True),
        ("additive", {"config_registry_ids": [PUBLIC_REGISTRY_ID, PRIVATE_REGISTRY_ID]}, True),
        ("other registry", {"config_registry_ids": [PUBLIC_REGISTRY_ID]}, False),
    ):
        v = vf.world_verifier(world, embedded_references=artifacts, **options)
        with_trust(v, config_verifier=registry)
        later = world.now + timedelta(hours=24)
        if not accepted:
            with pytest.raises(ReferencesError, match="registry ID is not accepted"):
                config_references(trust_of(v), doc, "org/project@v1", later)
            continue
        refs = config_references(trust_of(v), doc, "org/project@v1", later)
        assert refs.config is not None, name
        assert refs.config.registry_id == PRIVATE_REGISTRY_ID
        assert refs.config.signature_time == world.now
        assert refs.freshness_expires_at == world.now + v.freshness_max_age
        with pytest.raises(ReferencesError, match="pinned identity"):
            config_references(trust_of(v), doc, "org/other", world.now)


def test_config_registry_id_options_reject_ambiguous_trust() -> None:
    key = pki.p256().public_key()
    conflicts: list[tuple[dict[str, Any], str]] = [
        ({"config_registry_ids": []}, "must not be empty"),
        ({"config_registry_ids": [""]}, "registry"),
        ({"config_registry_ids": [PRIVATE_REGISTRY_ID, PRIVATE_REGISTRY_ID]}, "duplicate config registry ID"),
        (
            {"config_registry_ids": [PRIVATE_REGISTRY_ID], "config_signing_keys": [key]},
            "requires Tinfoil registry root",
        ),
        (
            {"config_registry_ids": [PRIVATE_REGISTRY_ID], "embedded_references": vf.embedded_inputs()},
            "require endorsement verification",
        ),
        ({"config_registry_ids": [PRIVATE_REGISTRY_ID], "config_authorizer": authorize_all}, "require endorsement"),
    ]
    for options, want in conflicts:
        with pytest.raises(UsageError, match=want):
            Verifier(**options)
    registry_ids = [PRIVATE_REGISTRY_ID]
    v = Verifier(config_registry_ids=registry_ids)
    registry_ids[0] = PUBLIC_REGISTRY_ID
    assert reference_pins(trust_of(v), "").registry_ids == (PRIVATE_REGISTRY_ID,)
    raw, nonce, _ = vf.embedded_document(FORMAT_V2)
    with pytest.raises(VerificationError, match="configured trust requires"):
        v.verify_v3(raw, nonce, "org/project")


def test_registry_ids_default_to_the_public_registry_only_under_registry_trust() -> None:
    assert reference_pins(trust_of(Verifier()), "").registry_ids == (PUBLIC_REGISTRY_ID,)
    keyed = Verifier(config_signing_keys=[pki.p256().public_key()])
    assert reference_pins(trust_of(keyed), "").registry_ids is None, "caller keys authorize without a registry"
    pins = reference_pins(trust_of(Verifier()), "org/project@v1@sha256:" + "ab" * 32)
    assert (pins.identity, pins.revision, pins.digest) == ("/org/project", "v1", "ab" * 32)


def test_configured_keys_preserve_proof_verification() -> None:
    world = World()
    other = World()
    trusted_root = world.trusted_root_json(fulcio=False, ctlogs=False)
    config = b"cvm-version: 0.15.0@sha256:" + b"ab" * 32 + b"\n"
    payload = config_payload(world, world.now, config, vf.EMBEDDED_CONFIG_NAME)
    config_data = {
        "endorsement_ref": endorsement_reference(payload),
        "config_base64": b64(config),
        "sigstore_bundle": world.keyed_bundle(payload),
    }
    artifact = FreshnessArtifact(KIND_RUNTIME, RUNTIME_REPO, "v0.15.0", runtime_name("v0.15.0"), "ab" * 32)
    approval = freshness_payload(world, artifact, world.now)
    freshness_data = {"sigstore_bundle": world.keyed_bundle(approval, key=other.key)}
    _, _, doc = vf.embedded_document(
        FORMAT_V3,
        config_entry(CONFIG_ENDORSEMENT_V1_FORMAT, **config_data),
        vf.reference_entry(FRESHNESS_ID_RUNTIME, ARTIFACT_FRESHNESS_V1_FORMAT, freshness_data),
    )
    for expired in (False, True):
        v = _build(
            overrides=Overrides(sigstore_root=trusted_root),
            config_signing_keys=[world.key.public_key()],
            freshness_signing_keys=[other.key.public_key()],
        )
        now = world.now + (DEFAULT_MAX_AGE + timedelta(seconds=1) if expired else timedelta(0))
        if expired:
            with pytest.raises(ReferencesError, match="too old"):
                config_references(trust_of(v), doc, "org/project@v1", now)
        else:
            with pytest.raises(NotFoundError, match=RUNTIME_ID):
                config_references(trust_of(v), doc, "org/project@v1", now)
        authenticated = AuthenticatedArtifact(
            repo=artifact.repo, tag=artifact.tag, commit="", subject_name=artifact.name, digest=artifact.digest
        )
        if expired:
            with pytest.raises(ValueError, match="too old"):
                _authenticate_artifact_freshness(
                    trust_of(v), doc, FRESHNESS_ID_RUNTIME, KIND_RUNTIME, authenticated, now
                )
        else:
            at = _authenticate_artifact_freshness(
                trust_of(v), doc, FRESHNESS_ID_RUNTIME, KIND_RUNTIME, authenticated, now
            )
            assert at == world.now
        with pytest.raises(NotFoundError):
            _authenticate_artifact_freshness(trust_of(v), doc, FRESHNESS_ID_PLATFORM, KIND_RUNTIME, authenticated, now)
        with pytest.raises(ValueError, match="does not match"):
            _authenticate_artifact_freshness(
                trust_of(v),
                doc,
                FRESHNESS_ID_RUNTIME,
                KIND_RUNTIME,
                dataclasses.replace(authenticated, digest="cd" * 32),
                now,
            )
        with pytest.raises(ReferencesError, match="pinned identity"):
            config_references(trust_of(v), doc, "org/other", now)


# --- freshness ------------------------------------------------------------------------------


def test_freshness_expiration() -> None:
    issued_at = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
    later = issued_at + timedelta(hours=1)
    for name, code_at, platform_at in (
        ("code expires first", issued_at, later),
        ("platform expires first", later, issued_at),
        ("same issuance time", issued_at, issued_at),
        ("first component embedded", None, issued_at),
        ("second component embedded", issued_at, None),
    ):
        for max_age in (timedelta(hours=24), DEFAULT_MAX_AGE, timedelta(days=30)):
            assert freshness_expiration(max_age, code_at, platform_at) == issued_at + max_age, name
    assert freshness_expiration(DEFAULT_MAX_AGE, None, None) is None


def test_config_bound_freshness_expiration_includes_every_approval() -> None:
    older = NOW - timedelta(hours=1)
    for times in ((older, NOW, NOW), (NOW, older, NOW), (NOW, NOW, older)):
        assert freshness_expiration(timedelta(hours=1), *times) == older + timedelta(hours=1)


def test_document_builder_quote_is_not_authentic() -> None:
    """The dummy report that the embedded documents carry never authenticates, so every test that reaches the
    quote layer is rejected there and not later."""
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    v = Verifier(embedded_references=vf.embedded_inputs())
    with pytest.raises(VerificationError) as rejected:
        v.verify_v3(raw, nonce, "")
    rejected_at(rejected.value, LAYER_QUOTE)
    assert document_builder.test_nonce() == nonce
