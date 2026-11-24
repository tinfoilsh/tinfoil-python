"""The verifier package's public surface: every name of the contract is importable, nothing else is exported, and
a consumer written against the surface type-checks under strict mypy and runs.
"""

from __future__ import annotations

import importlib
import inspect
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

# The package the surface test addresses.
MODULE = "tinfoil.verifier"

REPO_ROOT = Path(__file__).resolve().parents[1]

# The contract, pinned. A change here is a change to the public API.
EXPECTED_ALL = (
    "CRYPTO_MATERIAL_ID_HPKE",
    "CRYPTO_MATERIAL_ID_TLS",
    "KEY_SPKI_FP_SHA256_V1_FORMAT",
    "KEY_SPKI_V1_FORMAT",
    "KEY_X25519_HPKE_V1_FORMAT",
    "LAYER_ENVELOPE",
    "LAYER_POLICY",
    "LAYER_PROVENANCE",
    "LAYER_QUOTE",
    "NONCE_SIZE",
    "PUBLIC_REGISTRY_ID",
    "REGISTER_SIZE",
    "REPORT_SCHEMA_VERSION",
    "SEVSNP",
    "SOURCE_EMBEDDED",
    "SOURCE_ENDORSEMENT",
    "SOURCE_POLICY",
    "STEP_FAILED",
    "STEP_NOT_RUN",
    "STEP_PASSED",
    "STEP_SKIPPED",
    "TDX",
    "ArtifactTrust",
    "ArtifactVerification",
    "CPUEvidence",
    "ConfigAuthorizer",
    "ConfigEndorsement",
    "ConfigSigningKeys",
    "ConfigTrust",
    "ConfigVerification",
    "CryptoMaterialItem",
    "EmbeddedArtifacts",
    "EmbeddedConfig",
    "EmbeddedConfigReference",
    "EndorsedArtifacts",
    "Expected",
    "ExpectedFacts",
    "ExpectedSEVSNP",
    "ExpectedTDX",
    "Layer",
    "MeasuredFacts",
    "Measurement",
    "PartialFacts",
    "Pin",
    "Policy",
    "PublicKey",
    "Reference",
    "ReferenceSource",
    "Register",
    "Registries",
    "RuntimeReference",
    "SoftwareIdentity",
    "Step",
    "StepStatus",
    "UsageError",
    "VerificationError",
    "VerificationMetadata",
    "VerificationReport",
    "VerifiedFacts",
    "Verifier",
    "VerifyError",
    "cert_pubkey_fp",
    "crypto_material_data",
    "hpke_public_key_fp",
    "load_public_key",
    "parse_expected_sevsnp",
    "parse_expected_tdx",
    "parse_reference",
    "parse_register",
    "random_nonce",
)

# The exports that are plain values (a str or an int) and the ones that are functions, as the contract pins them;
# every other export is a class or a type alias. Membership is checked against the values, not the names.
CONSTANTS = (
    "CRYPTO_MATERIAL_ID_HPKE",
    "CRYPTO_MATERIAL_ID_TLS",
    "KEY_SPKI_FP_SHA256_V1_FORMAT",
    "KEY_SPKI_V1_FORMAT",
    "KEY_X25519_HPKE_V1_FORMAT",
    "LAYER_ENVELOPE",
    "LAYER_POLICY",
    "LAYER_PROVENANCE",
    "LAYER_QUOTE",
    "NONCE_SIZE",
    "PUBLIC_REGISTRY_ID",
    "REGISTER_SIZE",
    "REPORT_SCHEMA_VERSION",
    "SOURCE_EMBEDDED",
    "SOURCE_ENDORSEMENT",
    "SOURCE_POLICY",
    "STEP_FAILED",
    "STEP_NOT_RUN",
    "STEP_PASSED",
    "STEP_SKIPPED",
)
FUNCTIONS = (
    "cert_pubkey_fp",
    "crypto_material_data",
    "hpke_public_key_fp",
    "load_public_key",
    "parse_expected_sevsnp",
    "parse_expected_tdx",
    "parse_reference",
    "parse_register",
    "random_nonce",
)

# Names that exist for the conformance harness or inside the package and must never be reachable from it.
PRIVATE_NAMES = ("Overrides", "_build", "ResolvedReferences", "resolve_artifacts", "resolve_config", "TrustPolicy")

# The TLS connection checks, which are private to the client package (``tinfoil._pin``): the verifier takes no
# socket or connection objects, and the client package does not export them either.
CONNECTION_CHECKS = ("connection_cert_fp", "pin_tls_key")

# Exported aliases of builtin types, which carry no module of their own.
BUILTIN_ALIASES = ("Layer", "Register")

# Exported type aliases that are neither classes nor functions: two Literals and four unions.
TYPE_ALIASES = ("ArtifactTrust", "ConfigTrust", "Expected", "Measurement", "ReferenceSource", "StepStatus")

# The exported key type is a class of the cryptography library, not of this package.
FOREIGN_CLASSES = ("PublicKey",)


@pytest.fixture(scope="module")
def surface() -> ModuleType:
    return importlib.import_module(MODULE)


def _isort_key(name: str) -> tuple[int, str]:
    """The linter's isort-style order for ``__all__``: SCREAMING_SNAKE_CASE names, then CamelCase, then the rest,
    each alphabetically. It is a spelling rule, not a classification; ``SEVSNP`` and ``TDX`` are classes that it
    sorts with the constants."""
    return (0 if name.isupper() else 1 if name[0].isupper() else 2, name)


def _kind(value: object) -> str:
    """What an export is, judged by its value: a function, a class, a constant (a str or an int), or else a type
    alias (a union, a Literal or a Callable)."""
    if inspect.isfunction(value):
        return "function"
    if inspect.isclass(value):
        return "class"
    if isinstance(value, str | int):
        return "constant"
    return "alias"


def test_all_is_pinned_and_sorted(surface: ModuleType) -> None:
    assert tuple(surface.__all__) == EXPECTED_ALL
    assert list(EXPECTED_ALL) == sorted(EXPECTED_ALL, key=_isort_key)
    assert len(set(EXPECTED_ALL)) == len(EXPECTED_ALL)


def test_exports_are_classified_by_value(surface: ModuleType) -> None:
    """The constants and functions of the contract are exactly the exports whose values are plain values and
    functions; the type aliases are exactly the names listed; everything else is a class."""
    kinds = {name: _kind(getattr(surface, name)) for name in EXPECTED_ALL}
    assert [name for name, kind in kinds.items() if kind == "constant"] == list(CONSTANTS)
    assert [name for name, kind in kinds.items() if kind == "function"] == list(FUNCTIONS)
    assert [name for name, kind in kinds.items() if kind == "alias"] == sorted(TYPE_ALIASES)
    classes = [name for name, kind in kinds.items() if kind == "class"]
    assert set(classes).isdisjoint(CONSTANTS + FUNCTIONS + TYPE_ALIASES)
    assert set(classes) >= set(BUILTIN_ALIASES) | set(FOREIGN_CLASSES)


def test_every_name_of_the_contract_is_importable(surface: ModuleType) -> None:
    for name in EXPECTED_ALL:
        assert hasattr(surface, name), name
        assert not name.startswith("_"), name


def test_classes_and_functions_come_from_the_package(surface: ModuleType) -> None:
    """A re-exported class or function is defined inside this package, not in a dependency, except the two aliases
    of builtin types and the key type of the cryptography library."""
    for name in EXPECTED_ALL:
        value = getattr(surface, name)
        if name in BUILTIN_ALIASES:
            assert value.__module__ == "builtins", name
        elif name in FOREIGN_CLASSES:
            assert inspect.isclass(value), name
            assert value.__module__.startswith("cryptography."), name
        elif _kind(value) in ("class", "function"):
            assert value.__module__.startswith(MODULE + "."), (name, value.__module__)


def test_nothing_private_is_exported(surface: ModuleType) -> None:
    for name in PRIVATE_NAMES:
        assert name not in surface.__all__, name
        assert not hasattr(surface, name), name
    exported_modules = [name for name in surface.__all__ if inspect.ismodule(getattr(surface, name))]
    assert exported_modules == []
    # Every public attribute of the package is in the contract, and every submodule is private.
    for name, value in vars(surface).items():
        if name.startswith("_"):
            continue
        assert name in EXPECTED_ALL, f"{name} is reachable from the package but not in __all__"
        assert not inspect.ismodule(value), name
    for name, value in vars(surface).items():
        if inspect.ismodule(value) and value.__name__.startswith(MODULE + "."):
            assert name.startswith("_"), f"submodule {value.__name__} is exported as {name}"


def test_connection_checks_are_not_public(surface: ModuleType) -> None:
    import tinfoil

    for name in CONNECTION_CHECKS:
        assert name not in surface.__all__, name
        assert not hasattr(surface, name), name
        assert name not in tinfoil.__all__, name
        assert not hasattr(tinfoil, name), name


def test_the_package_is_typed() -> None:
    package_root = Path(importlib.import_module("tinfoil").__file__ or "").parent
    assert (package_root / "py.typed").is_file()


PROBE = '''
"""A consumer of the verifier surface: builds a verifier, verifies, reads the report."""

from datetime import UTC, datetime, timedelta
from typing import NoReturn

from {module} import (
    LAYER_ENVELOPE,
    NONCE_SIZE,
    PUBLIC_REGISTRY_ID,
    REGISTER_SIZE,
    SOURCE_EMBEDDED,
    STEP_FAILED,
    STEP_NOT_RUN,
    STEP_PASSED,
    ArtifactTrust,
    ConfigAuthorizer,
    ConfigEndorsement,
    ConfigSigningKeys,
    ConfigTrust,
    EmbeddedArtifacts,
    EmbeddedConfig,
    EmbeddedConfigReference,
    EndorsedArtifacts,
    Expected,
    ExpectedSEVSNP,
    ExpectedTDX,
    Layer,
    Measurement,
    Pin,
    Policy,
    PublicKey,
    Reference,
    ReferenceSource,
    Register,
    Registries,
    RuntimeReference,
    SEVSNP,
    TDX,
    PartialFacts,
    Step,
    StepStatus,
    UsageError,
    VerificationError,
    VerificationReport,
    VerifiedFacts,
    Verifier,
    VerifyError,
    crypto_material_data,
    hpke_public_key_fp,
    load_public_key,
    parse_expected_tdx,
    parse_reference,
    parse_register,
    random_nonce,
)

PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXpD92epoTkV8GlS2ypQYAlvSllIy
Z8MUPsliFK+r0GnUBcgHcZUn17zcl3kTdJLObY7I8GMq3ID/KUO/Sa9p8Q==
-----END PUBLIC KEY-----
"""


def describe(measurement: Measurement) -> str:
    match measurement:
        case SEVSNP(launch=launch):
            return launch.hex()
        case TDX(mrtd=mrtd):
            return mrtd.hex()


def pins(expected: Expected) -> list[Register | None]:
    if isinstance(expected, ExpectedSEVSNP):
        return [expected.launch]
    return [expected.mrtd, expected.rtmr0, expected.rtmr1, expected.rtmr2, expected.rtmr3]


def authorize(endorsement: ConfigEndorsement) -> None:
    bundle: bytes | None = endorsement.bundle
    if endorsement.config is None or bundle is None:
        raise ValueError("no config")


def source_of(verified: VerifiedFacts) -> ReferenceSource | None:
    source: ReferenceSource | None = verified.config.source if verified.config is not None else None
    if verified.runtime is not None and verified.runtime.source == SOURCE_EMBEDDED:
        return SOURCE_EMBEDDED
    return source


def report(result: VerificationReport) -> str:
    verified = result.verified_facts
    if verified is None:
        fail("an accepted report has no verified facts")
    fp: str | None = verified.tls_public_key_fp
    key: str | None = verified.hpke_public_key
    data: str | None = crypto_material_data(verified.crypto_material, "tls", "format")
    expires: datetime | None = verified.freshness_expires_at
    name = verified.config.name if verified.config is not None else ""
    runtime_tag = verified.runtime.tag if verified.runtime is not None else ""
    verified_at: datetime = result.metadata.verified_at
    registers: list[Register | None] = pins(verified.code_measurement)
    return "".join(
        (verified.code_digest, verified.code_tag, verified.config_repo, describe(verified.enclave_measurement),
         fp or "", key or "", data or "", str(expires), name, runtime_tag, verified_at.isoformat(),
         str(len(registers)), verified.to_json(), verified.to_json(indent=2),
         str(verified.to_dict()), str(source_of(verified)), result.to_json())
    )


def rejected(err: VerificationError) -> str:
    result: VerificationReport | None = err.report
    assert result is not None and result.verified_facts is None
    failed: Step | None = result.failed_step
    assert failed is not None and failed.status == STEP_FAILED and failed.layer == err.layer
    statuses: list[StepStatus] = [step.status for step in result.steps]
    assert statuses[1:] == [STEP_NOT_RUN] * 3 and STEP_PASSED not in statuses
    partial: PartialFacts | None = result.partial_facts
    assert partial is not None and partial.expected is None and partial.measured is None
    assert hpke_public_key_fp("00") == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    return result.to_json()


def main() -> None:
    register: Register = parse_register("ab" * REGISTER_SIZE)
    expected: ExpectedTDX = parse_expected_tdx("", "", "", "", register.hex())
    reference: Reference = parse_reference("org/repo@v1.0.0")
    assert reference.repo == "org/repo" and reference.tag == "v1.0.0" and reference.digest == ""
    assert PUBLIC_REGISTRY_ID
    nonce: bytes = random_nonce()
    assert len(nonce) == NONCE_SIZE
    verifier = Verifier(policy=Policy(pinned_registers=expected, freshness_max_age=timedelta(days=1)))
    assert verifier.pinned_registers == expected
    assert verifier.freshness_max_age == timedelta(days=1)
    verifier.check_pin_verifiability(Pin(repo="org/repo"))
    verifier.check_pin_verifiability(Pin(project="org/project@v1"))
    config_ref = EmbeddedConfigReference(
        digest="00" * 32, runtime=RuntimeReference(repo="tinfoilsh/cvmimage", tag="v1.0.0", digest="00" * 32)
    )
    configs: list[ConfigTrust] = [
        config_ref,
        EmbeddedConfig(data=b"x", name="/org/project/v1"),
        ConfigAuthorizer(authorize),
        Registries([PUBLIC_REGISTRY_ID]),
    ]
    assert len(configs) == 4
    artifacts: ArtifactTrust = EmbeddedArtifacts(runtime=b"x")
    assert isinstance(artifacts, EmbeddedArtifacts)
    keys: list[PublicKey] = []
    try:
        Verifier(ConfigSigningKeys(keys))
    except UsageError as err:
        assert err.message
        assert isinstance(err, ValueError)
    else:
        fail("an empty key list built a verifier")
    key: PublicKey = load_public_key(PEM)
    keyed = Verifier(
        ConfigSigningKeys([load_public_key(PEM)]), Policy(artifacts=EndorsedArtifacts(freshness_keys=[key]))
    )
    assert repr(keyed).startswith("Verifier(")
    keyed.check_pin_verifiability(Pin())
    try:
        parse_reference("not a reference")
    except UsageError as err:
        assert err.message
    else:
        fail("a malformed reference parsed")
    try:
        verifier.verify_v3_at(b"", nonce, Pin(project="org/project"), datetime.now(UTC))
    except VerificationError as err:
        layer: Layer = err.layer
        assert layer == LAYER_ENVELOPE
        assert isinstance(err, VerifyError)
        assert str(err) == f"{{layer}}: {{err.message}}"
        assert rejected(err)
        print(layer)
    else:
        fail("an empty document verified")


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


main()
'''


def test_consumer_probe_type_checks_and_runs(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(textwrap.dedent(PROBE).format(module=MODULE))
    checked = subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", "--no-error-summary", str(probe)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert checked.returncode == 0, checked.stdout + checked.stderr
    ran = subprocess.run([sys.executable, str(probe)], cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert ran.stdout.strip() == "envelope"
