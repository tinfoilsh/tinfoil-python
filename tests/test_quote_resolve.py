"""Quote resolution shared by both contracts: pin application, completion, the config contract and the legacy
contract over the policy fixture."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from tinfoil.verifier._document.document import CpuEvidence
from tinfoil.verifier._measurement import SEVSNP, TDX, ExpectedSEVSNP, ExpectedTDX
from tinfoil.verifier._policy import PLATFORM_SEV_SNP, PLATFORM_TDX, Artifact, Policy, Shape, parse
from tinfoil.verifier._quote import (
    AssemblyError,
    AuthenticatedSEVSNP,
    AuthenticatedTDX,
    ConfigReferenceValues,
    LegacyReferenceValues,
)
from tinfoil.verifier._quote.config import resolve_config
from tinfoil.verifier._quote.legacy import resolve_legacy
from tinfoil.verifier._quote.resolve import MR_CONFIG_ID_SIZE, apply_pins, complete, resolve_policy
from tinfoil.verifier._quote.sev.authenticate import Quote as SevQuote
from tinfoil.verifier._quote.tdx.authenticate import Quote as TdxQuote
from tinfoil.verifier._runtime import FORMAT_VERSION, Measurements, SNPLaunch, TDXLaunch

FIXTURE = Path(__file__).parent / "testdata" / "platform-endorsements.json"
REGISTER = bytes([0xAB]) * 48
OTHER = bytes([0xCD]) * 48
ZERO = bytes(48)
EVIDENCE = CpuEvidence(format="f", report=b"r")


def sev_quote(identity: str, launch: bytes = REGISTER) -> AuthenticatedSEVSNP:
    return AuthenticatedSEVSNP(
        identity=identity, measurement=SEVSNP(launch), evidence=EVIDENCE, quote=cast(SevQuote, None)
    )


def tdx_quote(identity: str, mrtd: bytes = REGISTER, rtmr0: bytes = REGISTER) -> AuthenticatedTDX:
    measurement = TDX(mrtd=mrtd, rtmr0=rtmr0, rtmr1=REGISTER, rtmr2=REGISTER, rtmr3=ZERO)
    return AuthenticatedTDX(identity=identity, measurement=measurement, evidence=EVIDENCE, quote=cast(TdxQuote, None))


def artifact() -> Artifact:
    return parse(FIXTURE.read_bytes())


def identity_for(endorsements: Artifact, platform: str) -> str:
    for identity, name in endorsements.machines.items():
        if endorsements.policies[name].platform == platform:
            return identity
    raise AssertionError(platform)


def with_policy(endorsements: Artifact, name: str, policy: Policy) -> Artifact:
    return dataclasses.replace(endorsements, policies={**endorsements.policies, name: policy})


# --- pins and completion -----------------------------------------------------------------


def test_pins_use_authenticated_platform() -> None:
    tdx_release = ExpectedTDX(rtmr1=REGISTER, rtmr2=REGISTER)
    sev_release = ExpectedSEVSNP(launch=REGISTER)
    got = apply_pins(tdx_release, PLATFORM_TDX, ExpectedTDX(rtmr3=REGISTER))
    assert got == ExpectedTDX(rtmr1=REGISTER, rtmr2=REGISTER, rtmr3=REGISTER), (
        "a pin fills a register the release leaves open"
    )
    assert apply_pins(sev_release, PLATFORM_SEV_SNP, ExpectedSEVSNP(launch=REGISTER)) == sev_release
    assert apply_pins(sev_release, PLATFORM_SEV_SNP, None) == sev_release
    with pytest.raises(AssemblyError, match="unsupported pinned measurement"):
        apply_pins(tdx_release, PLATFORM_TDX, cast(Any, "pins"))
    # Pins for the other platform reject in both directions, even when their value equals a fixed register.
    with pytest.raises(AssemblyError, match="pinned registers are for sev-snp, but the enclave is tdx"):
        apply_pins(tdx_release, PLATFORM_TDX, ExpectedSEVSNP(launch=REGISTER))
    with pytest.raises(AssemblyError, match="pinned registers are for tdx, but the enclave is sev-snp"):
        apply_pins(sev_release, PLATFORM_SEV_SNP, ExpectedTDX(rtmr1=REGISTER))


def test_config_bound_runtime_pins_cannot_override_measurements() -> None:
    measured = ExpectedTDX(mrtd=REGISTER, rtmr0=REGISTER, rtmr1=REGISTER, rtmr2=REGISTER, rtmr3=REGISTER)
    assert apply_pins(measured, PLATFORM_TDX, ExpectedTDX(rtmr1=REGISTER)) == measured
    with pytest.raises(AssemblyError, match="pinned RTMR1 does not match"):
        apply_pins(measured, PLATFORM_TDX, ExpectedTDX(rtmr1=OTHER))
    with pytest.raises(AssemblyError, match="pinned launch measurement does not match"):
        apply_pins(ExpectedSEVSNP(launch=REGISTER), PLATFORM_SEV_SNP, ExpectedSEVSNP(launch=OTHER))
    with pytest.raises(AssemblyError):
        apply_pins(measured, PLATFORM_TDX, ExpectedSEVSNP(launch=REGISTER))


def test_complete_requires_every_register() -> None:
    full = complete(ExpectedTDX(mrtd=REGISTER, rtmr0=REGISTER, rtmr1=REGISTER, rtmr2=REGISTER, rtmr3=REGISTER))
    assert full == TDX(mrtd=REGISTER, rtmr0=REGISTER, rtmr1=REGISTER, rtmr2=REGISTER, rtmr3=REGISTER)
    assert complete(ExpectedSEVSNP(launch=REGISTER)) == SEVSNP(launch=REGISTER)
    with pytest.raises(AssemblyError, match="nothing fixes the expected MRTD, RTMR0, RTMR3"):
        complete(ExpectedTDX(rtmr1=REGISTER, rtmr2=REGISTER))
    # Every register of the expected measurement is checked, under its upper-case label.
    every_label = ", ".join(field.name.upper() for field in dataclasses.fields(ExpectedTDX))
    with pytest.raises(AssemblyError, match=f"nothing fixes the expected {every_label}$"):
        complete(ExpectedTDX())
    with pytest.raises(AssemblyError, match="nothing fixes the expected launch measurement"):
        complete(ExpectedSEVSNP())
    with pytest.raises(AssemblyError, match="unsupported expected measurement"):
        complete(cast(Any, "expected"))


def test_resolve_policy_requires_an_endorsed_machine_of_the_platform() -> None:
    endorsements = artifact()
    sev_identity = identity_for(endorsements, PLATFORM_SEV_SNP)
    name, policy = resolve_policy(endorsements, sev_quote(sev_identity))
    assert policy.platform == PLATFORM_SEV_SNP
    assert endorsements.policies[name] == policy
    with pytest.raises(AssemblyError, match="is not endorsed"):
        resolve_policy(endorsements, sev_quote("ab" * 64))
    with pytest.raises(AssemblyError, match="evidence is"):
        resolve_policy(endorsements, tdx_quote(sev_identity))


# --- the config contract ------------------------------------------------------------------


@pytest.mark.parametrize("platform", [PLATFORM_SEV_SNP, PLATFORM_TDX])
def test_config_preparation_resolves_runtime_and_hash(platform: str) -> None:
    endorsements = artifact()
    identity = identity_for(endorsements, platform)
    quote = sev_quote(identity) if platform == PLATFORM_SEV_SNP else tdx_quote(identity)
    register = "ab" * 48
    zero = "0" * 96
    config_hash = hashlib.sha256(b"endorsed config bytes").digest()
    runtime = Measurements(
        format_version=FORMAT_VERSION,
        snp_launch=SNPLaunch(measurement=register),
        tdx_launch=TDXLaunch(mrtd=register, rtmr0=zero, rtmr1=zero, rtmr2=zero, rtmr3=zero),
    )
    refs = ConfigReferenceValues(endorsements=endorsements, runtime=runtime, hash=config_hash)
    with pytest.raises(AssemblyError, match="cannot be combined with platform"):
        resolve_config(refs, quote, None)
    name, policy = endorsements.policy_for(identity, platform)
    if platform == PLATFORM_SEV_SNP:
        assert policy.sev_snp is not None
        cleared = dataclasses.replace(policy, sev_snp=dataclasses.replace(policy.sev_snp, host_data=""))
    else:
        assert policy.tdx is not None
        cleared = dataclasses.replace(policy, tdx=dataclasses.replace(policy.tdx, platform_measurements=()))
    refs = dataclasses.replace(refs, endorsements=with_policy(endorsements, name, cleared))
    resolved = resolve_config(refs, quote, None)
    fixed = bytes.fromhex(register)
    if platform == PLATFORM_SEV_SNP:
        assert resolved.host_data == config_hash.hex()
        assert resolved.config_id == bytes(MR_CONFIG_ID_SIZE)
        want: Any = ExpectedSEVSNP(launch=fixed)
        assert endorsements.policies[name].sev_snp is not None
        assert endorsements.policies[name].sev_snp.host_data != "", "preparation must not modify platform endorsements"  # type: ignore[union-attr]
    else:
        assert resolved.host_data == ""
        assert resolved.config_id == config_hash + bytes(MR_CONFIG_ID_SIZE - 32)
        want = ExpectedTDX(mrtd=fixed, rtmr0=ZERO, rtmr1=ZERO, rtmr2=ZERO, rtmr3=ZERO)
    assert resolved.expected == want
    assert resolved.code == resolved.expected, "the runtime fixes every register"
    assert resolved.policy_name == name
    assert resolved.policy == cleared
    assert resolved.platform_measurement_name is None
    pins: Any = ExpectedSEVSNP(launch=OTHER) if platform == PLATFORM_SEV_SNP else ExpectedTDX(mrtd=OTHER)
    with pytest.raises(AssemblyError, match="does not match"):
        resolve_config(refs, quote, pins)
    assert resolve_config(refs, quote, want).expected == want
    with pytest.raises(AssemblyError, match="complete runtime endorsements are required"):
        resolve_config(dataclasses.replace(refs, runtime=None), quote, None)
    with pytest.raises(AssemblyError, match="config hash must be 32 bytes"):
        resolve_config(dataclasses.replace(refs, hash=b"short"), quote, None)
    bad_runtime = dataclasses.replace(
        runtime, snp_launch=SNPLaunch("zz"), tdx_launch=dataclasses.replace(runtime.tdx_launch, mrtd="zz")
    )
    with pytest.raises(AssemblyError, match=r"runtime (SNP launch measurement|TDX register 0)"):
        resolve_config(dataclasses.replace(refs, runtime=bad_runtime), quote, None)


# --- the legacy contract ------------------------------------------------------------------


def test_legacy_sev_takes_the_policy_host_data() -> None:
    endorsements = artifact()
    identity = identity_for(endorsements, PLATFORM_SEV_SNP)
    name, policy = endorsements.policy_for(identity, PLATFORM_SEV_SNP)
    assert policy.sev_snp is not None
    refs = LegacyReferenceValues(
        endorsements=endorsements,
        sevsnp=ExpectedSEVSNP(launch=REGISTER),
        tdx=ExpectedTDX(rtmr1=REGISTER, rtmr2=REGISTER),
        shape=None,
    )
    resolved = resolve_legacy(refs, sev_quote(identity), None)
    assert resolved.policy_name == name
    assert resolved.code == ExpectedSEVSNP(launch=REGISTER)
    assert resolved.expected == resolved.code
    assert resolved.host_data == policy.sev_snp.host_data
    assert resolved.platform_measurement_name is None
    assert resolved.config_id == bytes(MR_CONFIG_ID_SIZE)
    with pytest.raises(AssemblyError, match="pinned launch measurement does not match"):
        resolve_legacy(refs, sev_quote(identity), ExpectedSEVSNP(launch=OTHER))
    with pytest.raises(AssemblyError, match="is not endorsed"):
        resolve_legacy(refs, sev_quote("00" * 64), None)


def test_legacy_tdx_resolves_the_platform_registers_and_a_zero_rtmr3() -> None:
    endorsements = artifact()
    identity = identity_for(endorsements, PLATFORM_TDX)
    name, policy = endorsements.policy_for(identity, PLATFORM_TDX)
    assert policy.tdx is not None
    measurement_name = policy.tdx.platform_measurements[0]
    measurement = endorsements.measurements[measurement_name]
    assert measurement.shape is not None
    mrtd, rtmr0 = bytes.fromhex(measurement.mrtd), bytes.fromhex(measurement.rtmr0)
    refs = LegacyReferenceValues(
        endorsements=endorsements,
        sevsnp=ExpectedSEVSNP(launch=REGISTER),
        tdx=ExpectedTDX(rtmr1=REGISTER, rtmr2=REGISTER),
        shape=measurement.shape,
    )
    resolved = resolve_legacy(refs, tdx_quote(identity, mrtd, rtmr0), None)
    assert resolved.policy_name == name
    assert resolved.platform_measurement_name == measurement_name
    assert resolved.code == refs.tdx
    assert resolved.expected == ExpectedTDX(mrtd=mrtd, rtmr0=rtmr0, rtmr1=REGISTER, rtmr2=REGISTER, rtmr3=ZERO)
    assert resolved.host_data == ""
    assert resolved.config_id == bytes(MR_CONFIG_ID_SIZE)
    # Pins fill or must agree; a pinned RTMR3 replaces the zero default.
    pinned = resolve_legacy(refs, tdx_quote(identity, mrtd, rtmr0), ExpectedTDX(rtmr3=OTHER))
    assert pinned.expected == dataclasses.replace(resolved.expected, rtmr3=OTHER)
    assert resolve_legacy(refs, tdx_quote(identity, mrtd, rtmr0), ExpectedTDX(mrtd=mrtd)).expected == resolved.expected
    with pytest.raises(AssemblyError, match="pinned RTMR1 does not match"):
        resolve_legacy(refs, tdx_quote(identity, mrtd, rtmr0), ExpectedTDX(rtmr1=OTHER))
    # The quote's own platform registers must name an endorsed measurement for the required shape.
    with pytest.raises(AssemblyError, match="do not match any allowed configuration"):
        resolve_legacy(refs, tdx_quote(identity, OTHER, rtmr0), None)
    with pytest.raises(AssemblyError, match="required VM shape"):
        resolve_legacy(
            dataclasses.replace(refs, shape=Shape(cpus=1, memory_mb=1, disks=1, gpus=0)),
            tdx_quote(identity, mrtd, rtmr0),
            None,
        )
    with pytest.raises(AssemblyError, match="required VM shape is missing"):
        resolve_legacy(dataclasses.replace(refs, shape=None), tdx_quote(identity, mrtd, rtmr0), None)
    with pytest.raises(AssemblyError, match="pinned registers are for sev-snp"):
        resolve_legacy(refs, tdx_quote(identity, mrtd, rtmr0), ExpectedSEVSNP(launch=REGISTER))


def test_fixture_is_the_expected_shape() -> None:
    data = json.loads(FIXTURE.read_text())
    assert {p["platform"] for p in data["policies"].values()} == {PLATFORM_SEV_SNP, PLATFORM_TDX}
