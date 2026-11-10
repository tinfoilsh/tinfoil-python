"""Shared SEV-SNP material for the tests: the conformance vectors' documents, the public Turin captures, the policy
fixture and hand-built reports."""

from __future__ import annotations

import base64
import gzip
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.v3.vectors import find_vector, vector, vector_group
from tinfoil._v3.verifier._document import document
from tinfoil._v3.verifier._policy import ARTIFACT_FORMAT, Artifact, SEVSNPPolicy, parse
from tinfoil._v3.verifier._quote.sev.lib.abi import (
    GENOA_MODEL,
    REPORT_SIZE,
    SIGN_ECDSA_P384_SHA384,
    ZEN3_ZEN4_FAMILY,
    Report,
    fms_to_cpuid1_eax,
)
from tinfoil._v3.verifier._quote.sev.lib.chain import VcekExtensions
from tinfoil._v3.verifier._quote.sev.lib.tcb import TCB_STRUCT_VERSION_0, TCBVersionStruct

TESTDATA = Path(__file__).parent / "testdata"

# Real production identifiers (public by design in the endorsement artifact).
BOX3_GENOA_ID = (
    "cfdce31f5c40fc4e6eef803f6b5ed77e88b22603a91337bacab58446ab05fb8e"
    "f7bb5221611dced98dfa01d1eac114ca9a7952c262705977a36d81b0a53f856e"
)
BOX2_TURIN_ID = "6bb1229b7692b710" + "00" * 56

GENOA_TCB = 0x4814000000000007
"""The TCB of the synthetic Genoa vectors: bootloader 7, TEE 0, SNP 20, microcode 72."""
GENOA_HWID = b"\x11" * 64


@dataclass(frozen=True)
class VectorCase:
    """One quote vector, decoded."""

    fixture_id: str
    document: document.Document
    chain_pem: bytes | None
    """The injected ASK then ARK, in the KDS ``cert_chain`` layout; None selects the embedded roots."""
    now: datetime
    """The fixture's verification time, or the current time when it pins none."""
    accepted: bool


def _case(fixture: dict[str, Any]) -> VectorCase:
    data = fixture["input"]
    ask, ark = data.get("ask_pem", ""), data.get("amd_root_ca_pem", "")
    pinned = data.get("verification_time_unix", 0)
    return VectorCase(
        fixture_id=fixture["id"],
        document=document.decode_unbound(base64.b64decode(data["document_b64"])),
        chain_pem=f"{ask.strip()}\n{ark.strip()}\n".encode() if ask else None,
        now=datetime.fromtimestamp(pinned, UTC) if pinned else datetime.now(UTC),
        accepted=bool(fixture["expected"]["accepted"]),
    )


def sev_vector_params() -> list[Any]:
    """Every SEV quote vector: the quote-sev group, both frozen-time fixtures and the embedded-roots SEV fixture."""
    fixtures = vector_group("quote-sev") + vector_group("frozen-time")
    embedded = vector_group("embedded-roots")
    if embedded:
        fixtures.append(find_vector(embedded, "embedded-roots", "embedded-sev-rejects-synthetic"))
    if not fixtures:
        return [pytest.param(None, id="vectors-absent", marks=pytest.mark.skip(reason="conformance vectors not found"))]
    return [pytest.param(fixture, id=fixture["id"]) for fixture in fixtures]


def vector_case(group: str, fixture_id: str) -> VectorCase:
    return _case(vector(group, fixture_id))


def decode_case(fixture: dict[str, Any]) -> VectorCase:
    return _case(fixture)


def happy_case() -> VectorCase:
    return vector_case("quote-sev", "sev-happy")


def box2_turin_report() -> bytes:
    """A raw version 5 attestation report captured from production Turin hardware."""
    compressed = base64.b64decode((TESTDATA / "box2_turin_report.b64").read_text().strip())
    return gzip.decompress(compressed)


def box2_turin_vcek() -> bytes:
    """The DER VCEK that signed ``box2_turin_report``."""
    return base64.b64decode((TESTDATA / "box2_turin_vcek.b64").read_text().strip())


@dataclass(frozen=True)
class Capture:
    """A production Turin snapshot: the report, its VCEK, the policy that was selected and the capture time."""

    captured_at: datetime
    report: bytes
    vcek_der: bytes
    policy: SEVSNPPolicy


def production_capture(host: str) -> Capture:
    raw = json.loads((TESTDATA / f"{host}.json").read_text())
    report = base64.b64decode(raw["report_base64"])
    captured_at = datetime.fromisoformat(raw["captured_at"].replace("Z", "+00:00"))
    return Capture(
        captured_at=captured_at,
        report=report,
        vcek_der=base64.b64decode(raw["vcek_der_base64"]),
        policy=policy_from_json(raw["policy"], report[0x1A0:0x1E0].hex()),
    )


def endorsements() -> Artifact:
    """The platform-endorsements fixture."""
    return parse((TESTDATA / "platform-endorsements.json").read_bytes())


def sev_policy(identifier: str) -> SEVSNPPolicy:
    """The SEV-SNP policy that the endorsements fixture selects for a machine."""
    _, policy = endorsements().policy_for(identifier, "sev-snp")
    assert policy.sev_snp is not None
    return policy.sev_snp


def policy_from_json(policy: dict[str, Any], machine_id: str) -> SEVSNPPolicy:
    """Parse one policy object through the artifact parser, endorsing ``machine_id`` with it."""
    artifact = {"format": ARTIFACT_FORMAT, "measurements": {}, "machines": {machine_id: "p"}, "policies": {"p": policy}}
    _, parsed = parse(json.dumps(artifact).encode()).policy_for(machine_id, "sev-snp")
    assert parsed.sev_snp is not None
    return parsed.sev_snp


def make_report(**overrides: Any) -> Report:
    """A well-formed Genoa version 3 report shaped like the synthetic vectors, with fields overridden."""
    tcb = overrides.pop("tcb", GENOA_TCB)
    fields: dict[str, Any] = {
        "version": 3,
        "guest_svn": 0,
        "policy": 0x30000,
        "family_id": bytes(16),
        "image_id": bytes(16),
        "vmpl": 0,
        "signature_algo": SIGN_ECDSA_P384_SHA384,
        "current_tcb": tcb,
        "platform_info": 0,
        "signer_info": 0,
        "report_data": bytes(64),
        "measurement": bytes(48),
        "host_data": bytes(32),
        "id_key_digest": bytes(48),
        "author_key_digest": bytes(48),
        "report_id": bytes(32),
        "report_id_ma": bytes(32),
        "reported_tcb": tcb,
        "cpuid1_eax_fms": fms_to_cpuid1_eax(ZEN3_ZEN4_FAMILY, GENOA_MODEL, 0),
        "chip_id": GENOA_HWID,
        "committed_tcb": tcb,
        "current_build": 21,
        "current_minor": 55,
        "current_major": 1,
        "committed_build": 21,
        "committed_minor": 55,
        "committed_major": 1,
        "launch_tcb": tcb,
        "launch_mit_vector": 0,
        "current_mit_vector": 0,
        "signature": bytes(512),
        "raw": bytes(REPORT_SIZE),
    }
    fields.update(overrides)
    return Report(**fields)


def genoa_extensions(tcb: int = GENOA_TCB, hwid: bytes = GENOA_HWID) -> VcekExtensions:
    """VCEK extensions in the version 0 layout certifying ``tcb`` for ``hwid``."""
    return VcekExtensions(
        struct_version=TCB_STRUCT_VERSION_0,
        product_name="Genoa-B0",
        hwid=hwid,
        tcb=TCBVersionStruct(version=TCB_STRUCT_VERSION_0, tcb=tcb),
    )


def with_fields(report: Report, **overrides: Any) -> Report:
    return replace(report, **overrides)


def flip(data: bytes, index: int, mask: int = 1) -> bytes:
    """``data`` with bit ``mask`` of byte ``index`` toggled."""
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)
