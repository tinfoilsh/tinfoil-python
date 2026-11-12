"""Policy assembly: the document bindings, the dispatch to each platform's expectations, and assembly plus
validation of the golden quotes under both contracts."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from tests.vectors import document_collateral, vector
from tinfoil.verifier import _json
from tinfoil.verifier._document import document
from tinfoil.verifier._document.collateral.collateral import SIGSTORE_CODE_V1_FORMAT, SIGSTORE_PLATFORM_V1_FORMAT
from tinfoil.verifier._document.document import SEVSNP_REPORT_V1_FORMAT, TDX_QUOTE_V1_FORMAT, CpuEvidence
from tinfoil.verifier._endorsement.provenance import (
    measurements_from_statement,
    shape_from_predicate,
    signed_predicate,
)
from tinfoil.verifier._measurement import ExpectedSEVSNP, ExpectedTDX
from tinfoil.verifier._policy import PLATFORM_SEV_SNP, Artifact, parse
from tinfoil.verifier._quote import (
    AssembledSEVSNP,
    AssembledTDX,
    AssemblyError,
    Authenticated,
    AuthenticatedSEVSNP,
    AuthenticatedTDX,
    ConfigReferenceValues,
    LegacyReferenceValues,
    QuoteOptions,
    assemble,
    assemble_with,
    authenticate,
)
from tinfoil.verifier._quote.quote import TestOnlyRoots as Roots
from tinfoil.verifier._quote.resolve import AssemblyError as ResolveAssemblyError
from tinfoil.verifier._quote.sev.expectations import SevPolicyError
from tinfoil.verifier._quote.tdx.expectations import TdxPolicyError
from tinfoil.verifier._runtime import FORMAT_VERSION, Measurements, SNPLaunch, TDXLaunch
from tinfoil.verifier._sigstore import bundle as bm

OTHER = bytes([0xCD]) * 48


@dataclasses.dataclass(frozen=True)
class Golden:
    """A golden full-verify fixture taken apart: the bound document, its authenticated quote and the reference
    values read (unverified) from the document's own bundles."""

    doc: document.Document
    quote: Authenticated
    refs: LegacyReferenceValues

    @property
    def report_data(self) -> bytes:
        report_data = self.doc.expected_report_data()
        assert report_data is not None
        return report_data

    @property
    def artifact(self) -> Artifact:
        return self.refs.endorsements


def golden(group: str, fixture_id: str) -> Golden:
    fixture = vector(group, fixture_id)
    data = fixture["input"]
    doc = document.parse(base64.b64decode(data["document_b64"]), bytes.fromhex(data["nonce_hex"]))
    now = datetime.fromtimestamp(data["verification_time_unix"], UTC)
    ask, ark = data.get("ask_pem", ""), data.get("amd_root_ca_pem", "")
    roots = Roots(
        amd=f"{ask.strip()}\n{ark.strip()}\n".encode() if ask else None,
        intel=data["intel_sgx_root_pem"].encode() if data.get("intel_sgx_root_pem") else None,
    )
    quote = authenticate(doc.cpu_evidence(), doc.cpu_endorsements(), now, QuoteOptions(test_only_roots=roots))
    return Golden(doc=doc, quote=quote, refs=legacy_references(data["document_b64"]))


def legacy_references(document_b64: str) -> LegacyReferenceValues:
    """The code measurements and the platform artifact as the document's bundles carry them, without verifying
    the bundles: the quote tests exercise assembly, not provenance."""
    artifact: Artifact | None = None
    code: tuple[ExpectedSEVSNP, ExpectedTDX] | None = None
    shape: Any = None
    for entry in document_collateral(document_b64):
        format_ = _json.string(entry, "format")
        if format_ not in (SIGSTORE_PLATFORM_V1_FORMAT, SIGSTORE_CODE_V1_FORMAT):
            continue
        data = entry.get("data")
        assert isinstance(data, _json.JsonObject)
        payload = bm.parse_bundle(data["sigstore_bundle"]).envelope.payload
        if format_ == SIGSTORE_PLATFORM_V1_FORMAT:
            artifact = parse(signed_predicate(payload))
        else:
            statement = bm.parse_statement(payload)
            code = measurements_from_statement(statement)
            shape = shape_from_predicate(statement)
    assert artifact is not None
    assert code is not None
    return LegacyReferenceValues(endorsements=artifact, sevsnp=code[0], tdx=code[1], shape=shape)


def test_assembly_error_is_the_resolve_error() -> None:
    assert AssemblyError is ResolveAssemblyError


# --- the document bindings ------------------------------------------------------------------


def test_assemble_requires_a_parsed_document() -> None:
    fixture = vector("golden", "golden-happy")
    g = golden("golden", "golden-happy")
    unbound = document.decode_unbound(base64.b64decode(fixture["input"]["document_b64"]))
    with pytest.raises(AssemblyError, match=r"checked by document\.parse"):
        assemble(unbound, g.refs, None, g.quote)


def test_assemble_rejects_a_quote_from_another_document() -> None:
    g = golden("golden", "golden-happy")
    report = g.doc.cpu_evidence().report
    for name, evidence in {
        "other report": CpuEvidence(format=SEVSNP_REPORT_V1_FORMAT, report=report + b"\x00"),
        "other format": CpuEvidence(format=TDX_QUOTE_V1_FORMAT, report=report),
    }.items():
        with pytest.raises(AssemblyError, match="not this document's CPU evidence"):
            assemble(g.doc, g.refs, None, dataclasses.replace(g.quote, evidence=evidence))
        assert name
    # The quote authenticated from this document's own evidence passes the origin check and reaches the policy
    # inputs.
    unendorsed = dataclasses.replace(g.artifact, machines={})
    with pytest.raises(AssemblyError, match="is not endorsed") as info:
        assemble(g.doc, dataclasses.replace(g.refs, endorsements=unendorsed), None, g.quote)
    assert "not this document's CPU evidence" not in str(info.value)


# --- SEV-SNP -------------------------------------------------------------------------------


def test_golden_sev_assembles_and_validates() -> None:
    g = golden("golden", "golden-happy")
    assert isinstance(g.quote, AuthenticatedSEVSNP)
    assembled = assemble(g.doc, g.refs, None, g.quote)
    assert isinstance(assembled, AssembledSEVSNP)
    assert assembled.platform == PLATFORM_SEV_SNP
    assert assembled.code_measurement == g.refs.sevsnp
    assert assembled.policy_name == g.artifact.machines[g.quote.identity]
    assert assembled.quote == g.quote
    assembled.validate()
    assert assembled.expectations.options.report_data == g.report_data
    assert assembled.expectations.options.measurement == g.quote.measurement.launch

    # Wrong REPORT_DATA rejects even with a valid signature.
    wrong = bytes([g.report_data[0] ^ 0xFF]) + g.report_data[1:]
    with pytest.raises(SevPolicyError, match=r"(?i)report.?data"):
        assemble_with(g.refs, None, wrong, g.quote).validate()

    # A launch measurement differing from the code expectation rejects.
    other_code = dataclasses.replace(g.refs, sevsnp=ExpectedSEVSNP(launch=OTHER))
    with pytest.raises(SevPolicyError):
        assemble(g.doc, other_code, None, g.quote).validate()

    # SEV assembly does not consume the code artifact's VM shape.
    assemble(g.doc, dataclasses.replace(g.refs, shape=None), None, g.quote).validate()

    # A machine absent from the artifact rejects.
    with pytest.raises(AssemblyError, match="not endorsed"):
        assemble(
            g.doc, dataclasses.replace(g.refs, endorsements=dataclasses.replace(g.artifact, machines={})), None, g.quote
        )

    # The release leaves nothing open on SEV-SNP, so a pin must repeat the launch measurement.
    assemble(g.doc, g.refs, ExpectedSEVSNP(launch=g.quote.measurement.launch), g.quote).validate()
    with pytest.raises(AssemblyError, match="pinned launch measurement does not match"):
        assemble(g.doc, g.refs, ExpectedSEVSNP(launch=OTHER), g.quote)
    with pytest.raises(AssemblyError, match="pinned registers are for tdx, but the enclave is sev-snp"):
        assemble(g.doc, g.refs, ExpectedTDX(mrtd=g.quote.measurement.launch), g.quote)

    # A release that fixes nothing leaves the register to the pins, and nothing else fixes it.
    open_code = dataclasses.replace(g.refs, sevsnp=ExpectedSEVSNP())
    with pytest.raises(AssemblyError, match="nothing fixes the expected launch measurement"):
        assemble(g.doc, open_code, None, g.quote)
    assemble(g.doc, open_code, ExpectedSEVSNP(launch=g.quote.measurement.launch), g.quote).validate()


def test_golden_sev_under_the_config_contract_binds_host_data() -> None:
    g = golden("golden", "golden-happy")
    assert isinstance(g.quote, AuthenticatedSEVSNP)
    name, policy = g.artifact.policy_for(g.quote.identity, PLATFORM_SEV_SNP)
    assert policy.sev_snp is not None
    cleared = dataclasses.replace(policy, sev_snp=dataclasses.replace(policy.sev_snp, host_data=""))
    artifact = dataclasses.replace(g.artifact, policies={**g.artifact.policies, name: cleared})
    config_hash = hashlib.sha256(b"config").digest()
    runtime = Measurements(
        format_version=FORMAT_VERSION,
        snp_launch=SNPLaunch(measurement=g.quote.measurement.launch.hex()),
        tdx_launch=TDXLaunch(mrtd="ab" * 48, rtmr0="00" * 48, rtmr1="00" * 48, rtmr2="00" * 48, rtmr3="00" * 48),
    )
    refs = ConfigReferenceValues(endorsements=artifact, runtime=runtime, hash=config_hash)
    assembled = assemble(g.doc, refs, None, g.quote)
    assert isinstance(assembled, AssembledSEVSNP)
    assert assembled.code_measurement == ExpectedSEVSNP(launch=g.quote.measurement.launch)
    assert assembled.expectations.options.host_data == config_hash
    # The golden report's HOST_DATA is the policy's, not this config hash.
    with pytest.raises(SevPolicyError, match=r"(?i)host.?data"):
        assembled.validate()
    with pytest.raises(AssemblyError, match="cannot be combined with platform host_data"):
        assemble(g.doc, dataclasses.replace(refs, endorsements=g.artifact), None, g.quote)
    with pytest.raises(AssemblyError, match="unsupported reference values"):
        assemble_with(cast(Any, object()), None, g.report_data, g.quote)


# --- TDX -----------------------------------------------------------------------------------


def test_golden_tdx_assembles_and_validates() -> None:
    g = golden("golden-tdx", "tdx-golden-happy")
    assert isinstance(g.quote, AuthenticatedTDX)
    assembled = assemble(g.doc, g.refs, None, g.quote)
    assert isinstance(assembled, AssembledTDX)
    assert assembled.code_measurement == g.refs.tdx
    assert assembled.platform_measurement_name is not None
    assert assembled.platform_measurement_name in g.artifact.measurements
    assembled.validate()
    body = assembled.expectations.options.td_quote_body
    assert body.report_data == g.report_data
    assert body.mr_td == g.quote.measurement.mrtd
    assert body.rtmrs is not None
    assert body.rtmrs[3] == bytes(48), "an unpinned RTMR3 is expected to be zero"

    wrong = bytes([g.report_data[0] ^ 0xFF]) + g.report_data[1:]
    with pytest.raises(TdxPolicyError, match=r"(?i)report.?data"):
        assemble_with(g.refs, None, wrong, g.quote).validate()
    with pytest.raises(TdxPolicyError):
        assemble(
            g.doc, dataclasses.replace(g.refs, tdx=ExpectedTDX(rtmr1=OTHER, rtmr2=g.refs.tdx.rtmr2)), None, g.quote
        ).validate()
    with pytest.raises(AssemblyError, match="pinned registers are for sev-snp, but the enclave is tdx"):
        assemble(g.doc, g.refs, ExpectedSEVSNP(launch=g.quote.measurement.mrtd), g.quote)
    with pytest.raises(AssemblyError, match="pinned RTMR1 does not match"):
        assemble(g.doc, g.refs, ExpectedTDX(rtmr1=OTHER), g.quote)
    # A pinned RTMR3 replaces the zero default and is then enforced.
    with pytest.raises(TdxPolicyError):
        assemble(g.doc, g.refs, ExpectedTDX(rtmr3=OTHER), g.quote).validate()
    assemble(g.doc, g.refs, g.quote.measurement.expected(), g.quote).validate()
    with pytest.raises(AssemblyError, match="required VM shape is missing"):
        assemble(g.doc, dataclasses.replace(g.refs, shape=None), None, g.quote)
