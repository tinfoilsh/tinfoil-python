"""The verifier: its options and their conflicts, the pipeline's layer attribution, repository pins, embedded
references, caller-authorized configs, endorsed configs over a synthetic Sigstore world, and freshness deadlines."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tests import document_builder, pki
from tests import verifier_fixtures as vf
from tests.sigstore_world import World, as_json, b64
from tests.test_endorsement_approval import (
    PRIVATE_REGISTRY_ID,
    complete,
    config_core,
    config_payload,
    freshness_payload,
)
from tinfoil.verifier._config import (
    ReferencesError,
    _authenticate_artifact_freshness,
    config_references,
    freshness_expiration,
    load_public_key,
    reference_pins,
)
from tinfoil.verifier._document.collateral.collateral import (
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
from tinfoil.verifier._document.collateral.config import (
    CONFIG_ENDORSEMENT_V1_FORMAT,
    CONFIG_ENDORSEMENT_V2_FORMAT,
    CONFIG_ID,
    CONFIG_V1_FORMAT,
    ConfigEndorsement,
)
from tinfoil.verifier._document.collateral.runtime import PLATFORM_ID, RUNTIME_ID, RUNTIME_REPO, RuntimeReference
from tinfoil.verifier._document.document import NONCE_SIZE
from tinfoil.verifier._endorsement.approval import (
    CONFIG_FRESHNESS_DOMAIN_V2,
    KIND_RUNTIME,
    PUBLIC_REGISTRY_ID,
    ConfigPolicy,
    ConfigVerifier,
    FreshnessArtifact,
    public_signing_keys,
    runtime_name,
)
from tinfoil.verifier._endorsement.reference import AuthenticatedArtifact, Reference
from tinfoil.verifier._endorsement.time import DEFAULT_MAX_AGE, MAX_AGE_SPAN
from tinfoil.verifier._errors import (
    LAYER_ENVELOPE,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    UsageError,
    VerificationError,
    VerifyError,
)
from tinfoil.verifier._measurement import SEVSNP, ExpectedSEVSNP, ExpectedTDX
from tinfoil.verifier._options import (
    ConfigAuthorizer,
    ConfigSigningKeys,
    EmbeddedArtifacts,
    EmbeddedConfig,
    EmbeddedConfigReference,
    EndorsedArtifacts,
    Policy,
    Registries,
)
from tinfoil.verifier._quote import ConfigReferenceValues
from tinfoil.verifier._runtime import decode_manifest, runtime_from_config
from tinfoil.verifier._sigstore.bundle import endorsement_reference
from tinfoil.verifier._trust.amd_turin import AMD_TURIN_CERT_CHAIN_PEM
from tinfoil.verifier._verification import (
    SOURCE_EMBEDDED,
    SOURCE_ENDORSEMENT,
    SOURCE_POLICY,
    ConfigVerification,
)
from tinfoil.verifier._verifier import Overrides, Pin, Verifier, _build, parse_reference

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


def test_freshness_max_age() -> None:
    # None keeps the default and every positive age is honored. Zero is refused rather than read as a bound of zero,
    # which would reject every witness, and so is an age that rounds to zero microseconds.
    assert Verifier(policy=Policy(freshness_max_age=None)).freshness_max_age == DEFAULT_MAX_AGE
    for zero in (timedelta(0), timedelta(seconds=0), timedelta(microseconds=0.4), -timedelta(0)):
        with pytest.raises(UsageError, match="freshness maximum age must be positive"):
            Verifier(policy=Policy(freshness_max_age=zero))
    assert Verifier(policy=Policy(freshness_max_age=timedelta(microseconds=1))).freshness_max_age == timedelta(
        microseconds=1
    )
    assert Verifier(policy=Policy(freshness_max_age=timedelta(hours=24))).freshness_max_age == timedelta(hours=24)
    for max_age in (timedelta(microseconds=-1), timedelta(hours=-1)):
        with pytest.raises(UsageError, match="freshness maximum age must not be negative"):
            Verifier(policy=Policy(freshness_max_age=max_age))
    for bad in (0, 3600, "7d"):
        with pytest.raises(UsageError, match="freshness maximum age must be a timedelta"):
            Verifier(policy=Policy(freshness_max_age=bad))  # type: ignore[arg-type]
    # The longest window spans the representable datetimes; a longer age could not be anchored on any verification
    # instant, and would reject every document as stale rather than fail the caller.
    assert Verifier(policy=Policy(freshness_max_age=MAX_AGE_SPAN)).freshness_max_age == MAX_AGE_SPAN
    for too_long in (MAX_AGE_SPAN + timedelta(microseconds=1), timedelta.max):
        with pytest.raises(UsageError, match="freshness maximum age is longer than any representable window"):
            Verifier(policy=Policy(freshness_max_age=too_long))


def test_pinned_registers_must_be_expected_values() -> None:
    pins = ExpectedTDX(rtmr3=REGISTER)
    assert Verifier(policy=Policy(pinned_registers=pins)).pinned_registers == pins
    assert Verifier(policy=Policy(pinned_registers=ExpectedSEVSNP(launch=REGISTER))).pinned_registers == ExpectedSEVSNP(
        launch=REGISTER
    )
    for bad in (SEVSNP(launch=REGISTER), "pins", {"launch": REGISTER}):
        with pytest.raises(UsageError, match="pinned registers must be an ExpectedSEVSNP or ExpectedTDX value"):
            Verifier(policy=Policy(pinned_registers=bad))  # type: ignore[arg-type]


def test_verify_v3_rejects_bad_repo() -> None:
    v = Verifier()
    code = vf.reference_entry(
        "code", SIGSTORE_CODE_V1_FORMAT, {"repo": "", "tag": "", "digest": "digest", "sigstore_bundle": {}}
    )
    raw, nonce, _ = vf.embedded_document(None, code)
    with pytest.raises(UsageError, match="invalid release reference"):
        v.verify_v3(raw, nonce, Pin(repo="not a repo reference"))


def test_malformed_pin_is_a_usage_error_whatever_the_collateral() -> None:
    v = Verifier()
    for format_ in (None, FORMAT_V2, FORMAT_V3):
        raw, nonce, _ = vf.embedded_document(format_)
        for repo, project in (("not a reference", "org/project"), ("org/project", "not a reference")):
            with pytest.raises(UsageError, match="invalid release reference"):
                v.verify_v3(raw, nonce, Pin(repo=repo, project=project))


def test_v2_collateral_requires_a_repository_pin() -> None:
    """v2 collateral is verified against a code release, so a document that carries it needs a repository pin: None
    and "" both mean no pin and are a UsageError."""
    v = Verifier()
    code = vf.reference_entry(
        "code", SIGSTORE_CODE_V1_FORMAT, {"repo": "", "tag": "", "digest": "digest", "sigstore_bundle": {}}
    )
    raw, nonce, parsed = vf.embedded_document(None, code)
    assert parsed.collateral_format() == FORMAT_V2
    for repo in (None, ""):
        with pytest.raises(UsageError, match="pin names nothing"):
            v.verify_v3(raw, nonce, Pin(repo=repo))
        with pytest.raises(UsageError, match="pin names nothing"):
            v.verify_v3_at(raw, nonce, Pin(repo=repo), NOW)


def test_verify_rejects_an_unbuilt_verifier() -> None:
    # A verifier that skipped its constructor carries neither a trust root nor a clock: a usage error rather than
    # an attribute error once a well-formed document is in hand.
    unbuilt = object.__new__(Verifier)
    with pytest.raises(UsageError, match="verifier must be built"):
        unbuilt.verify_v3(b"{}", bytes(NONCE_SIZE), Pin(repo="org/repo"))


def test_verify_v3_at_requires_an_aware_instant() -> None:
    v = vf.embedded_verifier(vf.embedded_inputs())
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    with pytest.raises(UsageError, match="verification time must be timezone-aware"):
        v.verify_v3_at(raw, nonce, Pin(), datetime(2026, 1, 1))
    with pytest.raises(UsageError, match="verification time is required"):
        v.verify_v3_at(raw, nonce, Pin(), None)  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="document must be bytes"):
        v.verify_v3_at("{}", nonce, Pin(), NOW)  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="nonce must be bytes"):
        v.verify_v3_at(raw, nonce.hex(), Pin(), NOW)  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="expected nonce must be"):
        v.verify_v3_at(raw, nonce[:-1], Pin(), NOW)


def test_pin_must_be_a_string_before_any_layer_runs() -> None:
    """A repository or project reference that is neither a string nor None is a UsageError from every entry point,
    raised before the envelope is opened, rather than a provenance-layer verification error or a TypeError."""
    v = Verifier()
    for project in (123, b"org/project", ["org/project"]):
        with pytest.raises(UsageError, match="pin project must be a string or None"):
            v.check_pin_verifiability(Pin(project=project))  # type: ignore[arg-type]
        with pytest.raises(UsageError, match="pin project must be a string or None"):
            v.verify_v3_at(b"not a document", bytes(NONCE_SIZE), Pin(project=project), NOW)  # type: ignore[arg-type]
        with pytest.raises(UsageError, match="pin project must be a string or None"):
            v.verify_v3(b"not a document", bytes(NONCE_SIZE), Pin(project=project))  # type: ignore[arg-type]
    for repo in (123, b"org/repo", ["org/repo"]):
        with pytest.raises(UsageError, match="pin repository must be a string or None"):
            v.check_pin_verifiability(Pin(repo=repo))  # type: ignore[arg-type]
        with pytest.raises(UsageError, match="pin repository must be a string or None"):
            v.verify_v3_at(b"not a document", bytes(NONCE_SIZE), Pin(repo=repo), NOW)  # type: ignore[arg-type]
        with pytest.raises(UsageError, match="pin repository must be a string or None"):
            v.verify_v3(b"not a document", bytes(NONCE_SIZE), Pin(repo=repo))  # type: ignore[arg-type]


def test_pin_must_be_a_pin_before_any_layer_runs() -> None:
    """Anything but a Pin is a UsageError from every entry point: a bare reference string in particular is refused
    rather than read as an empty pin, which would verify unpinned."""
    v = Verifier()
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    for pin in ("org/repo", "", None, ("org/repo", "org/project"), {"repo": "org/repo"}):
        with pytest.raises(UsageError, match=r"pass Pin\(repo=...\) .* or Pin\(project=...\)"):
            v.check_pin_verifiability(pin)  # type: ignore[arg-type]
        with pytest.raises(UsageError, match="pin must be a Pin"):
            v.verify_v3_at(raw, nonce, pin, NOW)  # type: ignore[arg-type]
        with pytest.raises(UsageError, match="pin must be a Pin"):
            v.verify_v3(raw, nonce, pin)  # type: ignore[arg-type]


def test_pin_is_frozen_and_keyword_only() -> None:
    pin = Pin(repo="org/repo", project="org/project")
    assert (pin.repo, pin.project) == ("org/repo", "org/project")
    assert Pin() == Pin(repo=None, project=None)
    assert Pin(repo="org/name") != Pin(project="org/name")
    with pytest.raises(dataclasses.FrozenInstanceError):
        pin.repo = "org/other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        Pin("org/repo")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        Pin("org/repo", "org/project")  # type: ignore[call-arg]


def test_none_means_no_pin() -> None:
    """None and "" are the same pin: none. Both pass the verifiability check, both reach the envelope
    layer, and a config authorizer, which accepts no pin, accepts both. Default config trust refuses both."""
    for pin in (Pin(), Pin(repo="", project="")):
        with pytest.raises(UsageError, match="pin names nothing"):
            Verifier().check_pin_verifiability(pin)
        with pytest.raises(UsageError, match="pin names nothing"):
            Verifier().verify_v3_at(b"not a document", bytes(NONCE_SIZE), pin, NOW)
    v = Verifier(Registries([PUBLIC_REGISTRY_ID]))
    v.check_pin_verifiability(Pin())
    v.check_pin_verifiability(Pin(repo="", project=""))
    for part in (None, ""):
        with pytest.raises(VerificationError) as envelope:
            v.verify_v3_at(b"not a document", bytes(NONCE_SIZE), Pin(repo=part, project=part), NOW)
        rejected_at(envelope.value, LAYER_ENVELOPE)
        with pytest.raises(VerificationError) as live:
            v.verify_v3(b"not a document", bytes(NONCE_SIZE), Pin(repo=part, project=part))
        rejected_at(live.value, LAYER_ENVELOPE)
    authorizing = Verifier(ConfigAuthorizer(authorize_all))
    authorizing.check_pin_verifiability(Pin())
    with pytest.raises(UsageError, match="cannot authenticate repository"):
        authorizing.check_pin_verifiability(Pin(project="org/project"))


def test_errors_name_their_layer() -> None:
    err = VerificationError(LAYER_QUOTE, "report signature is invalid")
    assert str(err) == "quote: report signature is invalid"
    assert (err.layer, err.message) == (LAYER_QUOTE, "report signature is invalid")
    usage = UsageError("verification time is required")
    assert str(usage) == "verification time is required"
    assert usage.message == "verification time is required"
    assert parse_reference("org/project@v1").tag == "v1"


def test_usage_error_is_a_value_error() -> None:
    """A UsageError is a ValueError as well as a VerifyError; a VerificationError is neither a ValueError nor a
    UsageError, so the two stay distinguishable."""
    assert issubclass(UsageError, ValueError)
    assert issubclass(UsageError, VerifyError)
    assert not issubclass(VerificationError, ValueError)
    assert not issubclass(VerificationError, UsageError)
    with pytest.raises(ValueError, match="nonce must be bytes"):
        Verifier().verify_v3_at(b"", "nonce", Pin(), NOW)  # type: ignore[arg-type]


def test_parse_reference_rejects_with_a_usage_error() -> None:
    assert parse_reference("org/project@v1@sha256:" + "ab" * 32) == Reference(
        repo="org/project", tag="v1", digest="ab" * 32
    )
    with pytest.raises(UsageError, match="invalid release reference 'org'") as invalid:
        parse_reference("org")
    assert isinstance(invalid.value.__cause__, ValueError)
    with pytest.raises(UsageError, match="release reference must be a string, not NoneType"):
        parse_reference(None)  # type: ignore[arg-type]


def test_repr_shows_the_policy() -> None:
    assert repr(Verifier()) == f"Verifier(pinned_registers=None, freshness_max_age={DEFAULT_MAX_AGE!r})"
    pinned = ExpectedSEVSNP(launch=bytes(48))
    v = Verifier(ConfigAuthorizer(authorize_all), Policy(pinned_registers=pinned, freshness_max_age=timedelta(hours=1)))
    assert repr(v) == f"Verifier(pinned_registers={pinned!r}, freshness_max_age={timedelta(hours=1)!r})"


def test_load_public_key() -> None:
    """PEM text, PEM bytes and SPKI DER of an ECDSA P-256 key decode to the same key; every other key type, a
    malformed input and a PEM with several blocks are a UsageError."""
    key = pki.p256()
    pem = pki.public_pem(key)
    want = pki.spki(key)
    for encoded in (pem, pem.encode(), want):
        loaded = load_public_key(encoded)
        assert isinstance(loaded, ec.EllipticCurvePublicKey)
        assert loaded.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == want
    Verifier(
        ConfigSigningKeys([load_public_key(pem)]),
        Policy(artifacts=EndorsedArtifacts(freshness_keys=[load_public_key(want)])),
    )
    for other in (pki.p384(), pki.rsa_key(), pki.ed25519_key()):
        with pytest.raises(UsageError, match="ECDSA P-256"):
            load_public_key(pki.public_pem(other))
        with pytest.raises(UsageError, match="ECDSA P-256"):
            load_public_key(pki.spki(other))
    with pytest.raises(UsageError, match="exactly one PUBLIC KEY block"):
        load_public_key(pem + pem)
    with pytest.raises(UsageError, match="public key: text outside PEM blocks"):
        load_public_key("not a key")
    with pytest.raises(UsageError, match="public key"):
        load_public_key(b"\x30\x00")
    with pytest.raises(UsageError, match="public key"):
        load_public_key(b"")
    with pytest.raises(UsageError, match="not int"):
        load_public_key(123)  # type: ignore[arg-type]


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
    v = vf.embedded_verifier(vf.embedded_inputs())
    with pytest.raises(VerificationError, match="outside its validity window") as now_rejected:
        v.verify_v3(raw, nonce, Pin())
    rejected_at(now_rejected.value, LAYER_QUOTE)
    with pytest.raises(VerificationError, match="must be exactly") as then_rejected:
        v.verify_v3_at(raw, nonce, Pin(), appraisal)
    rejected_at(then_rejected.value, LAYER_QUOTE)
    assert then_rejected.value.__cause__ is not None, "the CRL window passed at the caller's instant"


def test_collateral_version_selects_verification() -> None:
    """The document's collateral decides which part of the pin applies, and a pin in one namespace is never
    satisfied by collateral from the other."""
    v = Verifier()
    name = "org/project"
    repository_only, no_repository = "only a GitHub repository is pinned", "only a registry project is pinned"
    cases: list[tuple[str, str | None, str | None, str | None, str]] = [
        ("repository collateral, repository", FORMAT_V2, name, None, SIGSTORE_CODE_V1_FORMAT),
        ("unversioned collateral, repository", None, name, None, SIGSTORE_CODE_V1_FORMAT),
        ("repository collateral, project", FORMAT_V2, None, name, no_repository),
        ("unversioned collateral, project", None, None, name, no_repository),
        ("repository collateral, both", FORMAT_V2, name, name, SIGSTORE_CODE_V1_FORMAT),
        ("registry collateral, project", FORMAT_V3, None, name, CONFIG_ID),
        ("registry collateral, repository", FORMAT_V3, name, None, repository_only),
        ("registry collateral, both", FORMAT_V3, name, name, CONFIG_ID),
    ]
    for case, format_, repo, project, want in cases:
        raw, nonce, _ = vf.embedded_document(format_)
        with pytest.raises(VerificationError, match=want) as rejected:
            v.verify_v3(raw, nonce, Pin(repo=repo, project=project))
        rejected_at(rejected.value, LAYER_PROVENANCE)
        # A pin that the collateral covers reaches the reference values, which the document lacks.
        assert isinstance(rejected.value.__cause__, NotFoundError) == (want in (SIGSTORE_CODE_V1_FORMAT, CONFIG_ID)), (
            case
        )


def test_repository_collateral_under_registry_only_trust_keeps_its_error() -> None:
    v = vf.embedded_verifier(vf.embedded_inputs())
    raw, nonce, _ = vf.embedded_document(FORMAT_V2)
    for repo, project in ((None, None), (None, "org/project@v1"), ("org/project", "org/project@v1")):
        with pytest.raises(VerificationError, match="configured trust requires") as rejected:
            v.verify_v3(raw, nonce, Pin(repo=repo, project=project))
        rejected_at(rejected.value, LAYER_PROVENANCE)


def test_unknown_collateral_format_never_reaches_the_reference_values() -> None:
    v = Verifier()
    nonce = document_builder.test_nonce()
    _, raw = document_builder.build(
        nonce, collateral_format="https://tinfoil.sh/predicate/attestation-collaterals/v9", collateral_entries=[]
    )
    with pytest.raises(VerificationError, match="unsupported collateral format") as rejected:
        v.verify_v3(raw, nonce, Pin(repo="org/project"))
    rejected_at(rejected.value, LAYER_ENVELOPE)


def test_config_reference_pins() -> None:
    v = Verifier()
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    project = "org/project"
    digest = "ab" * 32
    for ref in (project, project + "@v1", project + "@sha256:" + digest, project + "@v1@sha256:" + digest):
        with pytest.raises(VerificationError) as rejected:
            v.verify_v3(raw, nonce, Pin(project=ref))
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
            v.verify_v3(raw, nonce, Pin(project=ref))


def test_v3_collateral_requires_config_identity_pins() -> None:
    v = Verifier()
    v.check_pin_verifiability(Pin(project="Org/My_Repo"))
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    with pytest.raises(UsageError, match="identity"):
        v.verify_v3(raw, nonce, Pin(project="Org/My_Repo"))


def test_check_pin_verifiability() -> None:
    inputs = vf.embedded_inputs()
    defaults: dict[str, Any] = {}
    embedded: dict[str, Any] = dict(zip(("config", "policy"), inputs.options(), strict=True))
    authorizer: dict[str, Any] = {"config": ConfigAuthorizer(authorize_all)}
    registry_only: list[tuple[str, dict[str, Any]]] = [
        ("embedded config", embedded),
        ("config authorizer", authorizer),
        ("config signing keys", {"config": ConfigSigningKeys(public_signing_keys())}),
        (
            "freshness signing keys",
            {"policy": Policy(artifacts=EndorsedArtifacts(freshness_keys=public_signing_keys()))},
        ),
        ("config registry IDs", {"config": Registries([PUBLIC_REGISTRY_ID])}),
    ]
    cases: list[tuple[str, dict[str, Any], str | None, str | None, bool]] = [
        ("defaults with a project", defaults, None, "org/repo@v1", True),
        ("defaults with a repository", defaults, "Org/My_Repo", None, True),
        ("defaults with both", defaults, "Org/My_Repo", "org/project", True),
        ("defaults without a pin", defaults, None, None, False),
        ("defaults with empty pins", defaults, "", "", False),
        ("defaults with a malformed project", defaults, None, "not a reference", False),
        ("defaults with a malformed repository", defaults, "not a reference", None, False),
        ("defaults with a malformed repository beside a project", defaults, "not a reference", "org/project", False),
        ("embedded config without a pin", embedded, None, None, True),
        ("embedded config with its own project", embedded, None, "org/project@v1", True),
        ("embedded config with another project", embedded, None, "org/repo", False),
        ("embedded config with its own project and a repository", embedded, "org/project", "org/project@v1", True),
        ("config authorizer without a pin", authorizer, None, None, True),
        ("config authorizer with a project", authorizer, None, "org/repo", False),
        ("config authorizer with both", authorizer, "org/repo", "org/repo", False),
        *((f"{name} with a repository alone", options, "org/project", None, False) for name, options in registry_only),
    ]
    for name, options, repo, project, valid in cases:
        v = Verifier(**options)
        if valid:
            v.check_pin_verifiability(Pin(repo=repo, project=project))
        else:
            with pytest.raises(UsageError):
                v.check_pin_verifiability(Pin(repo=repo, project=project))
        assert name
    with pytest.raises(UsageError, match="verifies registry collateral only"):
        Verifier(**embedded).check_pin_verifiability(Pin(repo="org/project"))


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

    v = vf.embedded_verifier(dataclasses.replace(inputs, config=ConfigAuthorizer(refuse)))
    with pytest.raises(VerificationError) as rejected:
        v.verify_v3(raw, nonce, Pin())
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
    v = vf.embedded_verifier(dataclasses.replace(inputs, config=None))
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
        v.verify_v3(raw, nonce, Pin())
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
        v.verify_v3(*vf.embedded_document(FORMAT_V2)[:2], Pin(repo="org/project"))
    rejected_at(v2.value, LAYER_PROVENANCE)
    assert legacy.collateral_format() == FORMAT_V2


def test_config_authorizer_must_be_callable() -> None:
    with pytest.raises(UsageError, match="config authorizer must be callable"):
        Verifier(ConfigAuthorizer("authorize"))  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="config authorizer must be callable"):
        Verifier(ConfigAuthorizer(None))  # type: ignore[arg-type]


def test_config_size_is_bounded_before_the_authorizer_runs() -> None:
    inputs = vf.embedded_inputs()
    calls: list[bytes | None] = []

    def record(candidate: ConfigEndorsement) -> None:
        calls.append(candidate.config)

    v = vf.embedded_verifier(dataclasses.replace(inputs, config=ConfigAuthorizer(record)))
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
        inputs = vf.EmbeddedInputs(
            config=EmbeddedConfig(data=vf.config_bytes(manifest, "0.15.0" + suffix), name=vf.EMBEDDED_CONFIG_NAME),
            runtime=manifest,
            platform=vf.platform_bytes(),
        )
        v = vf.embedded_verifier(inputs)
        refs = config_references(trust_of(v), doc, "", NOW)
        assert isinstance(refs.quote, ConfigReferenceValues)
        assert isinstance(inputs.config, EmbeddedConfig)
        assert refs.quote.hash == hashlib.sha256(inputs.config.data).digest()
        assert refs.quote.runtime == decode_manifest(manifest).measurements
        assert refs.artifact.tag == "v0.15.0"
        assert refs.artifact.source == SOURCE_EMBEDDED
        if suffix:
            with pytest.raises(UsageError, match="digest pin"):
                vf.embedded_verifier(dataclasses.replace(inputs, runtime=vf.manifest_bytes()))


def test_embedded_config_reference_without_config_bytes() -> None:
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    digest = hashlib.sha256(inputs.config.data).hexdigest()
    runtime = runtime_from_config(inputs.config.data)
    reference = EmbeddedConfigReference(name=vf.EMBEDDED_CONFIG_NAME, digest=digest, runtime=runtime)
    v = vf.embedded_verifier(dataclasses.replace(inputs, config=reference))
    v.check_pin_verifiability(Pin())
    v.check_pin_verifiability(Pin(project="org/project@v1@sha256:" + digest))
    with pytest.raises(UsageError):
        v.check_pin_verifiability(Pin(project="org/project@v2"))
    with pytest.raises(UsageError):
        v.check_pin_verifiability(Pin(project="org/project@sha256:" + "ab" * 32))
    raw, nonce, doc = vf.embedded_document(FORMAT_V3)
    refs = config_references(trust_of(v), doc, "org/project@v1", NOW)
    assert isinstance(refs.quote, ConfigReferenceValues)
    assert refs.quote.hash == bytes.fromhex(digest)
    assert refs.artifact.digest == runtime.digest
    for ref in ("org/project@v1", ""):
        with pytest.raises(VerificationError) as rejected:
            v.verify_v3(raw, nonce, Pin(project=ref))
        rejected_at(rejected.value, LAYER_QUOTE)
    for bad in (
        dataclasses.replace(reference, digest=""),
        dataclasses.replace(reference, runtime=dataclasses.replace(runtime, digest="cd" * 32)),
        dataclasses.replace(reference, name="/invalid"),
    ):
        with pytest.raises(UsageError):
            vf.embedded_verifier(dataclasses.replace(inputs, config=bad))


def test_embedded_references_preserve_bindings() -> None:
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    config_hash = hashlib.sha256(inputs.config.data).digest()
    v = vf.embedded_verifier(inputs)
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
        v.verify_v3(raw, nonce, Pin(project="org/project@v1"))
    rejected_at(pinned.value, LAYER_QUOTE)
    with pytest.raises(VerificationError) as unpinned:
        v.verify_v3(raw, nonce, Pin())
    rejected_at(unpinned.value, LAYER_QUOTE)


def test_embedded_references_cannot_override_pins() -> None:
    inputs = vf.embedded_inputs()
    v = vf.embedded_verifier(inputs)
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    for ref in ("other/project", "org/project@v2", "org/project@sha256:" + "00" * 32):
        with pytest.raises(UsageError, match="does not match the caller's pins"):
            v.verify_v3(raw, nonce, Pin(project=ref))
    assert inputs.runtime is not None
    with pytest.raises(UsageError, match="digest pin"):
        vf.embedded_verifier(dataclasses.replace(inputs, runtime=inputs.runtime + b"\n"))

    assert isinstance(inputs.config, EmbeddedConfig)
    unnamed = dataclasses.replace(inputs, config=dataclasses.replace(inputs.config, name=""))
    v = vf.embedded_verifier(unnamed)
    with pytest.raises(UsageError, match="does not match the caller's pins"):
        v.verify_v3(raw, nonce, Pin(project="org/project"))
    with pytest.raises(VerificationError) as rejected:
        v.verify_v3(raw, nonce, Pin())
    rejected_at(rejected.value, LAYER_QUOTE)


def test_embedded_references_still_require_other_endorsements() -> None:
    _, _, doc = vf.embedded_document(FORMAT_V3)
    for component, changes in (
        (CONFIG_ID, {"config": None}),
        (RUNTIME_ID, {"runtime": None}),
        (PLATFORM_ID, {"platform": None}),
    ):
        v = vf.embedded_verifier(dataclasses.replace(vf.embedded_inputs(), **changes))
        with pytest.raises(NotFoundError, match=component):
            config_references(trust_of(v), doc, "org/project", NOW)


def test_embedded_trust_rejects_invalid_or_unused_inputs() -> None:
    inputs = vf.embedded_inputs()
    keys = public_signing_keys()
    with pytest.raises(UsageError, match="embedded artifacts must contain a runtime or a platform"):
        Verifier(policy=Policy(artifacts=EmbeddedArtifacts()))
    for refs in (
        vf.EmbeddedInputs(config=EmbeddedConfig(data=b"")),
        vf.EmbeddedInputs(runtime=b""),
        vf.EmbeddedInputs(runtime=b"{}"),
        vf.EmbeddedInputs(platform=b""),
        vf.EmbeddedInputs(platform=b'{"format":"unknown"}'),
        vf.EmbeddedInputs(platform=b'{"format":"https://tinfoil.sh/predicate/platform-endorsements/v1"}'),
    ):
        with pytest.raises(UsageError):
            vf.embedded_verifier(refs)
    for version in ("", "0.15.0", "v0.15"):
        with pytest.raises(UsageError):
            vf.embedded_verifier(vf.EmbeddedInputs(runtime=vf.manifest_bytes(version)))
    for config in (b"config bytes", "sha256:" + "cd" * 32, {"data": b"config bytes"}, PUBLIC_REGISTRY_ID, keys):
        with pytest.raises(UsageError, match="config trust must be a Registries, ConfigSigningKeys, ConfigAuthorizer"):
            Verifier(config)  # type: ignore[arg-type]
    for artifacts in (b"runtime", {"runtime": b"{}"}, inputs, keys):
        with pytest.raises(UsageError, match="artifact trust must be an EndorsedArtifacts or EmbeddedArtifacts"):
            Verifier(policy=Policy(artifacts=artifacts))  # type: ignore[arg-type]
    for not_a_policy in ({"freshness_max_age": timedelta(hours=1)}, EndorsedArtifacts(), "policy"):
        with pytest.raises(UsageError, match="policy must be a Policy value"):
            Verifier(policy=not_a_policy)  # type: ignore[arg-type]
    both = EmbeddedArtifacts(runtime=inputs.runtime, platform=inputs.platform, freshness_keys=keys)
    with pytest.raises(UsageError, match="no endorsed artifact"):
        Verifier(policy=Policy(artifacts=both))
    raw, nonce, _ = vf.embedded_document(FORMAT_V2)
    configured: list[tuple[Any, Policy | None]] = [
        inputs.options(),
        (ConfigSigningKeys(keys), None),
        (None, Policy(artifacts=EndorsedArtifacts(freshness_keys=keys))),
        (None, Policy(artifacts=EmbeddedArtifacts(platform=inputs.platform))),
        (Registries([PRIVATE_REGISTRY_ID]), None),
        (ConfigAuthorizer(authorize_all), None),
    ]
    for config, policy in configured:
        v = Verifier(config, policy)
        with pytest.raises(VerificationError, match="configured trust requires") as rejected:
            v.verify_v3(raw, nonce, Pin(repo="org/project"))
        rejected_at(rejected.value, LAYER_PROVENANCE)


def _refs(**fields: Any) -> dict[str, Any]:
    """The verifier arguments that select embedded values with fields of any type, for the type checks."""
    config, policy = vf.EmbeddedInputs(**fields).options()
    return {"config": config, "policy": policy}


def _config(**fields: Any) -> EmbeddedConfig:
    return EmbeddedConfig(**fields)


def _reference(base: EmbeddedConfigReference, **changes: Any) -> EmbeddedConfigReference:
    return dataclasses.replace(base, **changes)


def _runtime(base: RuntimeReference, **changes: Any) -> RuntimeReference:
    return dataclasses.replace(base, **changes)


def test_option_fields_of_the_wrong_type_are_usage_errors() -> None:
    """A caller's type mistake in a registry id or an embedded reference field is a UsageError, never an attribute
    or type error from the code that reads the field."""
    inputs = vf.embedded_inputs()
    assert isinstance(inputs.config, EmbeddedConfig)
    runtime = runtime_from_config(inputs.config.data)
    digest = hashlib.sha256(inputs.config.data).hexdigest()
    reference = EmbeddedConfigReference(name=vf.EMBEDDED_CONFIG_NAME, digest=digest, runtime=runtime)
    config_text = inputs.config.data.decode()
    cases: list[tuple[dict[str, Any], str]] = [
        ({"config": Registries([5])}, "config registry IDs must be strings"),  # type: ignore[list-item]
        ({"config": Registries([PRIVATE_REGISTRY_ID, None])}, "config registry IDs must be strings"),  # type: ignore[list-item]
        ({"config": Registries(5)}, "config registry IDs must be a sequence"),  # type: ignore[arg-type]
        ({"config": Registries(PRIVATE_REGISTRY_ID)}, "config registry IDs must be a sequence"),
        ({"config": ConfigSigningKeys(5)}, "config signing keys must be a sequence of keys"),  # type: ignore[arg-type]
        (
            {"policy": Policy(artifacts=EndorsedArtifacts(freshness_keys=object()))},  # type: ignore[arg-type]
            "freshness signing keys must be a sequence of keys",
        ),
        (_refs(runtime="{}"), "embedded runtime manifest must be bytes"),
        (_refs(platform="{}"), "embedded platform artifact must be bytes"),
        (_refs(config=_config(data=config_text)), "embedded config data must be bytes"),
        (_refs(config=_config(data=None)), "embedded config data must be bytes"),
        (
            _refs(config=_config(data=inputs.config.data, name=None)),
            "embedded config name must be a string",
        ),
        (
            _refs(config=_reference(reference, digest=None)),
            "embedded config digest must be a string",
        ),
        (
            _refs(config=_reference(reference, name=None)),
            "embedded config name must be a string",
        ),
        (
            _refs(config=_reference(reference, runtime=(runtime.repo, runtime.tag, runtime.digest))),
            "embedded config runtime must be a RuntimeReference",
        ),
        (
            _refs(config=_reference(reference, runtime=_runtime(runtime, repo=None))),
            "embedded config runtime repo must be a string",
        ),
        (
            _refs(config=_reference(reference, runtime=_runtime(runtime, tag=(0, 15, 0)))),
            "embedded config runtime tag must be a string",
        ),
        (
            _refs(config=_reference(reference, runtime=_runtime(runtime, digest=b"\x00"))),
            "embedded config runtime digest must be a string",
        ),
    ]
    for options, message in cases:
        with pytest.raises(UsageError, match=message):
            Verifier(**options)
    # A bytes-like value of another kind is accepted and copied: a later change to the caller's buffer does not
    # reach the verifier's policy.
    manifest = bytearray(inputs.runtime or b"")
    platform = bytearray(inputs.platform or b"")
    config = bytearray(inputs.config.data)
    v = Verifier(
        **_refs(
            config=_config(data=memoryview(config), name=vf.EMBEDDED_CONFIG_NAME),
            runtime=manifest,
            platform=memoryview(platform),
        )
    )
    embedded = trust_of(v).embedded
    assert embedded.runtime == inputs.runtime
    assert embedded.platform == inputs.platform
    assert embedded.config.digest == digest
    manifest[:] = b"{}" + bytes(len(manifest) - 2)
    platform[:] = bytes(len(platform))
    config[:] = bytes(len(config))
    assert embedded.runtime == inputs.runtime
    assert embedded.platform == inputs.platform
    assert embedded.config.digest == digest
    assert isinstance(embedded.runtime, bytes)
    assert isinstance(embedded.platform, bytes)


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
        ConfigSigningKeys([world.key.public_key()]),
        Policy(artifacts=EmbeddedArtifacts(runtime=inputs.runtime, platform=inputs.platform)),
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
    seen: list[ConfigEndorsement] = []

    def refuse(candidate: ConfigEndorsement) -> None:
        seen.append(candidate)
        raise rejected

    with_trust(v, config_authorizer=refuse)
    with pytest.raises(VerificationError) as refused:
        config_references(trust_of(v), doc, "", world.now)
    assert refused.value.__cause__ is rejected, "a valid endorsement must not bypass caller policy"
    (candidate,) = seen
    assert candidate.config == config
    assert candidate.reference == approved.reference
    assert isinstance(candidate.bundle, bytes)
    assert json.loads(candidate.bundle) == bundle, "the authorizer sees the entry's bundle as its JSON bytes"
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
        Verifier(policy=Policy(artifacts=EndorsedArtifacts(freshness_keys=[])))
    with pytest.raises(UsageError, match="must not be empty"):
        Verifier(policy=Policy(artifacts=EmbeddedArtifacts(platform=vf.platform_bytes(), freshness_keys=[])))
    with pytest.raises(UsageError, match="must not be empty"):
        Verifier(ConfigSigningKeys([]))
    v = Verifier(ConfigSigningKeys(keys), Policy(artifacts=EndorsedArtifacts(freshness_keys=keys)))
    raw, nonce, _ = vf.embedded_document(FORMAT_V3)
    with pytest.raises(VerificationError, match=CONFIG_ID) as rejected:
        v.verify_v3(raw, nonce, Pin(project="org/project"))
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
    artifacts = EmbeddedArtifacts(runtime=inputs.runtime, platform=inputs.platform)
    v = vf.world_verifier(world, ConfigSigningKeys([world.key.public_key()]), Policy(artifacts=artifacts))
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
        v.verify_v3_at(raw, nonce, Pin(project="org/project@v1"), world.now)
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
        ConfigSigningKeys([world.key.public_key()]),
        Policy(artifacts=dataclasses.replace(artifacts, runtime=inputs.runtime + b"\n")),
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
    artifacts = Policy(artifacts=EmbeddedArtifacts(runtime=inputs.runtime, platform=inputs.platform))
    registry = ConfigVerifier(world.trusted_root(), [root_key.public_key()], root_keys=[root_key.public_key()])
    for name, registries, accepted in (
        ("default", None, False),
        ("exclusive", Registries([PRIVATE_REGISTRY_ID]), True),
        ("additive", Registries([PUBLIC_REGISTRY_ID, PRIVATE_REGISTRY_ID]), True),
        ("other registry", Registries([PUBLIC_REGISTRY_ID]), False),
    ):
        v = vf.world_verifier(world, registries, artifacts)
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


def test_registries_reject_invalid_ids() -> None:
    invalid: list[tuple[list[str], str]] = [
        ([], "must not be empty"),
        ([""], "registry"),
        ([PRIVATE_REGISTRY_ID, PRIVATE_REGISTRY_ID], "duplicate config registry ID"),
    ]
    for ids, want in invalid:
        with pytest.raises(UsageError, match=want):
            Verifier(Registries(ids))
    registry_ids = [PRIVATE_REGISTRY_ID]
    v = Verifier(Registries(registry_ids))
    registry_ids[0] = PUBLIC_REGISTRY_ID
    assert reference_pins(trust_of(v), "").registry_ids == (PRIVATE_REGISTRY_ID,)
    raw, nonce, _ = vf.embedded_document(FORMAT_V2)
    with pytest.raises(VerificationError, match="configured trust requires"):
        v.verify_v3(raw, nonce, Pin(repo="org/project"))


def test_registry_ids_default_to_the_public_registry_only_under_registry_trust() -> None:
    assert reference_pins(trust_of(Verifier()), "").registry_ids == (PUBLIC_REGISTRY_ID,)
    keyed = Verifier(ConfigSigningKeys([pki.p256().public_key()]))
    assert reference_pins(trust_of(keyed), "").registry_ids is None, "caller keys authorize without a registry"
    pins = reference_pins(trust_of(Verifier()), "org/project@v1@sha256:" + "ab" * 32)
    assert (pins.identity, pins.revision, pins.digest) == ("/org/project", "v1", "ab" * 32)


def test_configured_keys_preserve_proof_verification() -> None:
    world = World()
    other = World()
    trusted_root = world.trusted_root_json(fulcio=False, ctlogs=False)
    config = b'{"cvm-version":"0.15.0@sha256:' + b"ab" * 32 + b'"}'
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
            ConfigSigningKeys([world.key.public_key()]),
            Policy(artifacts=EndorsedArtifacts(freshness_keys=[other.key.public_key()])),
            overrides=Overrides(sigstore_root=trusted_root),
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
    v = vf.embedded_verifier(vf.embedded_inputs())
    with pytest.raises(VerificationError) as rejected:
        v.verify_v3(raw, nonce, Pin())
    rejected_at(rejected.value, LAYER_QUOTE)
    assert document_builder.test_nonce() == nonce
