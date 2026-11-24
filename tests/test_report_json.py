"""The report's JSON form against the golden files that every Tinfoil SDK shares.

The files in ``tests/testdata/report-json`` are copied unchanged from
tinfoil-go's ``verify/testdata/report-json`` (tinfoil-go#346), the reference
encoder of the common JSON form. Each holds a ``description``, the expected
``report`` and, for a case that comes from the conformance suite, the
``vector`` that it verifies, relative to the suite's ``vectors/`` directory.
A vector-backed case runs that vector through the conformance adapter, and so
through ``Verifier.verify_v3_at``; the other cases build the same input here
as the Go test that the description names builds it.

A report matches a golden one as JSON values, with every member compared
except the step messages, which are each SDK's own text, and ``metadata``,
which describes the run; whether a step has a message is compared. Times are
compared as instants, to the microsecond, which is as fine as a Python
``datetime`` holds.
"""

from __future__ import annotations

import dataclasses
import json
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import tinfoil_conformance as adapter
from tests import document_builder
from tests import verifier_fixtures as vf
from tests.conformance.conftest import fixtures_root
from tinfoil.verifier import (
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    SOURCE_EMBEDDED,
    SOURCE_ENDORSEMENT,
    STEP_PASSED,
    ArtifactVerification,
    ConfigVerification,
    ExpectedSEVSNP,
    Pin,
    SoftwareIdentity,
    Step,
    VerificationError,
    VerificationMetadata,
    VerificationReport,
    VerifiedFacts,
    Verifier,
)
from tinfoil.verifier._document.collateral.collateral import FORMAT_V3
from tinfoil.verifier._document.document import CryptoMaterialItem
from tinfoil.verifier._measurement import SEVSNP
from tinfoil.verifier._policy.artifact import ARTIFACT_FORMAT_V2
from tinfoil.verifier._report import LAYERS

_GOLDEN = Path(__file__).resolve().parent / "testdata" / "report-json"
_TIME_MEMBERS = frozenset({"approval_time", "signature_time", "freshness_expires_at", "verified_at"})
_RFC3339 = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")
# The instant of the Go tests that build the in-repo cases.
_GOLDEN_AT = datetime(2026, 1, 2, 2, 4, 5, tzinfo=UTC)


def _golden(name: str) -> dict[str, Any]:
    with (_GOLDEN / f"{name}.json").open("rb") as handle:
        data: dict[str, Any] = json.load(handle)
    return data


def _vector_cases() -> list[Any]:
    names = sorted(path.stem for path in _GOLDEN.glob("*.json") if "vector" in _golden(path.stem))
    return [pytest.param(name, id=name) for name in names]


def _instant(value: str) -> datetime:
    """An RFC 3339 time in UTC with ``Z``, to the microsecond."""
    match = _RFC3339.match(value)
    assert match is not None, f"{value!r} is not RFC 3339"
    whole, fraction, offset = match.groups()
    assert offset == "Z", f"{value!r} is not written in UTC with Z"
    micros = int(((fraction or "") + "000000")[:6])
    return datetime.fromisoformat(whole).replace(tzinfo=UTC, microsecond=micros)


def _comparable(value: Any, key: str = "") -> Any:
    """``value`` as the comparison sees it: no metadata, a step's message reduced to whether it has one, and times
    as instants."""
    if isinstance(value, dict):
        out = {k: _comparable(v, k) for k, v in value.items() if k != "metadata"}
        if key == "steps_item":
            out["message"] = "message" in value
        return out
    if isinstance(value, list):
        return [_comparable(item, "steps_item" if key == "steps" else "") for item in value]
    if key in _TIME_MEMBERS:
        return _instant(value)
    return value


def _assert_no_empty_member(value: Any, path: str = "$") -> None:
    """No member at any depth is None or ``""``: a fact that was not established is left out."""
    assert value is not None, f"{path} is null"
    assert value != "", f"{path} is empty"
    if isinstance(value, dict):
        for key, member in value.items():
            _assert_no_empty_member(member, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_empty_member(item, f"{path}[{index}]")


def assert_matches_golden(got: dict[str, Any], name: str) -> None:
    want = _golden(name)["report"]
    # Every SDK writes a well-formed metadata object; only its contents are the run's own.
    assert _instant(got["metadata"]["verified_at"])
    assert set(got["metadata"]) <= {"verified_at", "verifier"}
    _assert_no_empty_member(got)
    assert _comparable(got) == _comparable(want)


def test_every_golden_case_is_tested() -> None:
    vector_backed = {param.values[0] for param in _vector_cases()}
    built = {"acceptance-config-facts", "rejection-provenance-no-keys", "rejection-quote-skipped-provenance"}
    assert vector_backed | built == {path.stem for path in _GOLDEN.glob("*.json")}
    assert len(vector_backed) == 7


@pytest.mark.parametrize("name", _vector_cases())
def test_vector_report_matches_golden(name: str) -> None:
    """The adapter writes the report in the JSON form that ``VerificationReport.to_dict`` writes, and the report of
    the vector that the golden file names matches the golden report."""
    root = fixtures_root()
    if root is None:
        pytest.skip("conformance vectors not found")
    # The golden file names the vector relative to vectors/, and the root is vectors/v3.
    with (root.parent / _golden(name)["vector"]).open("rb") as handle:
        fixture = json.load(handle)
    result = adapter.run(fixture["stage"], fixture["input"])
    assert "report" in result.output, result.output
    assert_matches_golden(result.output["report"], name)


def _report_of(err: pytest.ExceptionInfo[VerificationError]) -> VerificationReport:
    report = err.value.report
    assert report is not None
    return report


def test_config_facts_report_matches_golden() -> None:
    """Go's ``goldenConfigFacts``: a config-based verification on SEV-SNP with every config and artifact record
    member, and times given in UTC-5 that the form writes in UTC. Go's times carry 500 nanoseconds, which a Python
    ``datetime`` can't hold, so the times here are whole seconds and compare equal to the microsecond."""
    west = timezone(timedelta(hours=-5))
    approved = datetime(2026, 9, 20, 3, 0, 0, tzinfo=west)
    launch = bytes([0xAB, 0xCD]) + bytes(46)
    facts = VerifiedFacts(
        config_repo="tinfoilsh/cvmimage",
        code_digest="0a" * 32,
        code_tag="v0.15.0",
        code_measurement=ExpectedSEVSNP(launch=launch),
        enclave_measurement=SEVSNP(launch=launch),
        config=ConfigVerification(
            source=SOURCE_ENDORSEMENT,
            name="/org/project/v1",
            digest="0c" * 32,
            reference="org/project@v1",
            signing_key_hint="hint",
            approval_time=approved,
            registry_id="registry",
            signature_time=approved + timedelta(minutes=1),
        ),
        runtime=ArtifactVerification(
            source=SOURCE_ENDORSEMENT,
            repo="tinfoilsh/cvmimage",
            tag="v0.15.0",
            digest="0a" * 32,
            name="runtime",
            commit="0e" * 20,
            approval_time=approved,
        ),
        platform=ArtifactVerification(source=SOURCE_EMBEDDED, digest="0f" * 32),
        crypto_material=(
            CryptoMaterialItem(id="tls", format=KEY_SPKI_FP_SHA256_V1_FORMAT, data="ab" * 32),
            CryptoMaterialItem(id="hpke", format=KEY_X25519_HPKE_V1_FORMAT, data="11" * 32),
        ),
        freshness_expires_at=datetime(2026, 10, 3, 7, 0, 0, tzinfo=west),
    )
    report = VerificationReport(
        steps=tuple(Step(layer, STEP_PASSED) for layer in LAYERS),
        verified_facts=facts,
        metadata=VerificationMetadata(verifier=SoftwareIdentity("tinfoil-python", "1.0.0"), verified_at=_GOLDEN_AT),
    )
    assert_matches_golden(report.to_dict(), "acceptance-config-facts")
    assert json.loads(report.to_json()) == report.to_dict()


def test_provenance_rejection_without_keys_report_matches_golden() -> None:
    """Go's ``TestReportJSONGoldenProvenanceRejectionWithoutKeys``: a document that endorses no keys and carries no
    config reference, verified with the default verifier and the project pin org/project. The envelope passes with
    ``"measured": {}``, and provenance fails."""
    nonce = bytes(32)
    _, raw = document_builder.build(nonce, crypto_items=[], collateral_entries=[], collateral_format=FORMAT_V3)
    with pytest.raises(VerificationError) as err:
        Verifier().verify_v3_at(raw, nonce, Pin(project="org/project"), _GOLDEN_AT)
    assert_matches_golden(_report_of(err).to_dict(), "rejection-provenance-no-keys")


def test_quote_rejection_after_skipped_provenance_report_matches_golden() -> None:
    """Go's ``TestReportJSONGoldenQuoteRejectionAfterSkippedProvenance``: a verifier that embeds every reference
    value, so provenance is skipped with its reason, and a dummy quote that isn't authentic. The document endorses no
    keys, as Go's embedded document does, and the embedded platform artifact has the bytes that Go encodes for an
    empty one, so that its digest is Go's."""
    nonce = document_builder.test_nonce()
    raw = document_builder.build_raw(nonce, crypto_items=[], collateral_entries=[], collateral_format=FORMAT_V3)
    platform = json.dumps({"format": ARTIFACT_FORMAT_V2, "machines": {}, "policies": {}}, separators=(",", ":"))
    verifier = vf.embedded_verifier(dataclasses.replace(vf.embedded_inputs(), platform=platform.encode()))
    with pytest.raises(VerificationError) as err:
        verifier.verify_v3_at(document_builder.encode(raw), nonce, Pin(), _GOLDEN_AT)
    assert_matches_golden(_report_of(err).to_dict(), "rejection-quote-skipped-provenance")
