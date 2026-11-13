"""TDX quote authentication: the conformance vectors at module level, and every rejection path on a synthetic
attestation."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tests import pki
from tests import tdx_builders as tb
from tests.vectors import vector, vector_params
from tinfoil.verifier._document import document
from tinfoil.verifier._quote.tdx.authenticate import (
    Evidence,
    Options,
    Quote,
    TdxAuthenticationError,
    authenticate,
    check_reserved_bytes,
    platform_measurements,
    trusted_root,
)
from tinfoil.verifier._quote.tdx.lib.abi import parse_quote
from tinfoil.verifier._quote.tdx.lib.chain import common_name
from tinfoil.verifier._quote.tdx.lib.collateral import TcbStatus
from tinfoil.verifier._quote.tdx.pcs import qe_identity_url

BASE = tb.Scenario()
ROOT = Options(test_only_root_pem=BASE.root_pem())


def run(scenario: tb.Scenario, now: datetime = tb.NOW, options: Options | None = ROOT) -> Quote:
    return authenticate(scenario.evidence(), now, options)


def rejects(scenario: tb.Scenario, match: str, now: datetime = tb.NOW, options: Options | None = ROOT) -> None:
    with pytest.raises(TdxAuthenticationError, match=match):
        run(scenario, now, options)


# --- conformance vectors ----------------------------------------------------------------


def evidence_from_fixture(fixture: dict[str, Any]) -> tuple[Evidence, datetime, Options | None]:
    """Build the stage's inputs the way the adapter would: the decoded document's CPU evidence and intel-pcs
    collateral, the pinned verification time or the current time, and the injected root when given."""
    raw = fixture["input"]
    doc = document.decode_unbound(base64.b64decode(raw["document_b64"]))
    endorsements = doc.cpu_endorsements()
    pcs = endorsements.intel_pcs.responses if endorsements.intel_pcs is not None else ()
    at = raw.get("verification_time_unix", 0)
    now = datetime.fromtimestamp(at, UTC) if at else datetime.now(UTC)
    root = raw.get("intel_sgx_root_pem", "")
    return Evidence(quote=doc.cpu_evidence().report, pcs=pcs), now, Options(root.encode()) if root else None


def assert_fixture(fixture: dict[str, Any]) -> None:
    evidence, now, options = evidence_from_fixture(fixture)
    expected = fixture["expected"]
    if not expected["accepted"]:
        assert expected["code"] == "QUOTE_REJECTED"
        with pytest.raises(TdxAuthenticationError):
            authenticate(evidence, now, options)
        return
    quote = authenticate(evidence, now, options)
    body = parse_quote(evidence.quote).td_quote_body
    assert quote.measurement.mrtd == body.mr_td
    assert (quote.measurement.rtmr0, quote.measurement.rtmr1, quote.measurement.rtmr2, quote.measurement.rtmr3) == (
        body.rtmrs
    )
    assert platform_measurements(quote) == (body.mr_td.hex(), body.rtmrs[0].hex())
    assert quote.identity == quote.pck_extensions.ppid
    assert len(quote.identity) == 32
    outputs = expected.get("outputs")
    if outputs and "enclave_measurement" in outputs:
        registers = [body.mr_td.hex(), *(r.hex() for r in body.rtmrs)]
        assert outputs["enclave_measurement"]["registers"] == registers


@pytest.mark.parametrize("fixture", vector_params("quote-tdx"))
def test_quote_tdx_vectors(fixture: dict[str, Any]) -> None:
    assert fixture["stage"] == "v3-authenticate-quote"
    assert_fixture(fixture)


def test_embedded_root_rejects_synthetic_vector() -> None:
    fixture = vector("embedded-roots", "embedded-tdx-rejects-synthetic")
    assert "intel_sgx_root_pem" not in fixture["input"]
    assert_fixture(fixture)


def test_vector_documents_are_well_formed() -> None:
    """The fixtures decode as documents with TDX evidence, so a verdict never comes from a decoding failure."""
    fixture = vector("quote-tdx", "tdx-happy")
    doc = document.decode_unbound(base64.b64decode(fixture["input"]["document_b64"]))
    assert doc.cpu_evidence().format == document.TDX_QUOTE_V1_FORMAT
    assert doc.cpu_endorsements().intel_pcs is not None
    assert json.loads(json.dumps(fixture["expected"])) == {"accepted": True}


# --- the embedded root ------------------------------------------------------------------


def test_embedded_intel_root_parses() -> None:
    assert common_name(trusted_root(None).subject) == "Intel SGX Root CA"
    assert common_name(trusted_root(Options()).subject) == "Intel SGX Root CA"


def test_root_pem_without_certificate_is_an_error() -> None:
    with pytest.raises(TdxAuthenticationError, match="Intel SGX root certificate"):
        trusted_root(Options(test_only_root_pem=b"not a pem\n"))


def test_embedded_root_rejects_the_synthetic_chain() -> None:
    rejects(BASE, "no verified path", options=None)


def test_wrong_injected_root_rejects() -> None:
    other = tb.intel_pki()
    rejects(BASE, "no verified path", options=Options(test_only_root_pem=other.pem(other.root)))


# --- the happy path -----------------------------------------------------------------------


def test_synthetic_attestation_authenticates() -> None:
    quote = run(BASE)
    assert quote.identity == tb.PPID.hex()
    assert quote.measurement.mrtd == tb.MR_TD
    assert (quote.measurement.rtmr0, quote.measurement.rtmr1, quote.measurement.rtmr2, quote.measurement.rtmr3) == (
        tb.RTMRS
    )
    assert quote.tcb_evaluation_data_number == 18
    assert quote.tcb_level.tcb_status == TcbStatus.UP_TO_DATE
    assert quote.pck_extensions.fmspc == tb.FMSPC
    assert quote.pck_extensions.pceid == tb.PCEID
    assert quote.pck_extensions.tcb.pce_svn == tb.PCE_SVN
    assert quote.pck_extensions.tcb.cpu_svn_components == tb.CPU_SVN_COMPONENTS
    assert platform_measurements(quote) == (tb.MR_TD.hex(), tb.RTMRS[0].hex())


def test_platform_measurements_read_the_quote_body() -> None:
    """The summary measurement is not consulted: a quote whose summary was swapped still reports its own body."""
    quote = run(BASE)
    other = tb.Scenario(body=tb.body_bytes(mr_td=bytes([0xEE]) * 48, rtmrs=(bytes([0xEE]) * 48, *tb.RTMRS[1:])))
    swapped = Quote(
        expires_at=quote.expires_at,
        identity=quote.identity,
        measurement=quote.measurement,
        tcb_evaluation_data_number=quote.tcb_evaluation_data_number,
        quote=parse_quote(other.quote()),
        pck_chain=quote.pck_chain,
        pck_extensions=quote.pck_extensions,
        collateral=quote.collateral,
        tcb_level=quote.tcb_level,
    )
    assert platform_measurements(swapped) == ((bytes([0xEE]) * 48).hex(), (bytes([0xEE]) * 48).hex())


def test_evaluation_number_is_the_lower_of_the_two() -> None:
    quote = run(
        BASE.with_(
            tcb_info=tb.tcb_info_object(evaluation_number=20), qe_identity=tb.qe_identity_object(evaluation_number=19)
        )
    )
    assert quote.tcb_evaluation_data_number == 19
    quote = run(
        BASE.with_(
            tcb_info=tb.tcb_info_object(evaluation_number=17), qe_identity=tb.qe_identity_object(evaluation_number=19)
        )
    )
    assert quote.tcb_evaluation_data_number == 17


def test_qe_vendor_id_is_not_checked_at_authentication() -> None:
    """The expected vendor id is a policy field; a quote from another vendor authenticates and fails validation."""
    quote = run(BASE.with_(header=tb.header_bytes(qe_vendor_id=bytes([0x01]) * 16)))
    assert quote.quote.header.qe_vendor_id == bytes([0x01]) * 16


# --- the verification time -------------------------------------------------------------------


def test_naive_verification_time_is_an_error() -> None:
    with pytest.raises(TdxAuthenticationError, match="verification time is required"):
        authenticate(BASE.evidence(), datetime(2026, 1, 15), ROOT)


def test_certificates_are_checked_at_the_verification_time() -> None:
    wide = (timedelta(days=-500), timedelta(days=500))
    scenario = BASE.with_(pck_crl_window=wide, root_crl_window=wide)
    rejects(scenario, "not valid at", now=tb.NOW + timedelta(days=400))
    rejects(scenario, "not valid at", now=tb.NOW - timedelta(days=400))


def test_a_scenario_anchored_at_another_time_authenticates_at_that_time() -> None:
    """Every default validity and signing time follows the scenario's ``now``, whether given at construction or
    changed afterwards; the given fields (here the PCK key) are kept."""
    later = tb.NOW + timedelta(days=400)
    for scenario in (tb.Scenario(now=later), BASE.with_(now=later)):
        options = Options(test_only_root_pem=scenario.root_pem())
        assert run(scenario, now=later, options=options).identity == tb.PPID.hex()
        rejects(scenario, "outside its validity window|not valid at", now=tb.NOW, options=options)
    assert BASE.with_(now=later).pck_key is BASE.pck_key
    assert BASE.with_(now=later).intel is not BASE.intel


# --- quote structure ---------------------------------------------------------------------------


def test_unsupported_quote_version_rejects() -> None:
    rejects(BASE.with_(header=tb.header_bytes(version=5)), "QuoteV5")
    rejects(BASE.with_(header=tb.header_bytes(version=3)), "Unsupported quote version")


def test_non_zero_reserved_header_bytes_reject() -> None:
    rejects(BASE.with_(header=tb.header_bytes(reserved=b"\x00\x01\x00\x00")), "non-zero reserved bytes")
    with pytest.raises(TdxAuthenticationError, match="reserved"):
        check_reserved_bytes(parse_quote(BASE.with_(header=tb.header_bytes(reserved=b"\x00\x00\x00\x01")).quote()))


def test_trailing_bytes_must_be_zero() -> None:
    assert run(BASE.with_(extra_bytes=bytes(16))).identity == tb.PPID.hex()
    rejects(BASE.with_(extra_bytes=bytes(15) + b"\x01"), "non-zero bytes after the signed data")


def test_quote_signature_must_verify() -> None:
    rejects(BASE.with_(quote_signature=bytes(64)), "unable to verify message digest")
    rejects(BASE.with_(quote_signature=bytes([0x01]) * 64), "unable to verify message digest")


def test_qe_report_must_bind_the_attestation_key() -> None:
    """The QE report's REPORT_DATA covers the attestation key and the auth data; changing the auth data breaks it."""
    good = BASE.with_(qe_auth_data=b"\x88" * 32)
    assert run(good).identity == tb.PPID.hex()
    broken = good.evidence()
    quote = bytearray(broken.quote)
    # The auth data sits right after the QE report and its signature inside the certification data.
    offset = 0x27C + 0x80 + 6 + 0x180 + 0x40 + 2
    assert quote[offset : offset + 32] == b"\x88" * 32
    quote[offset] ^= 0xFF
    with pytest.raises(TdxAuthenticationError, match="QE Report Data does not match"):
        authenticate(Evidence(quote=bytes(quote), pcs=broken.pcs), tb.NOW, ROOT)


def test_qe_report_signature_must_come_from_the_pck_key() -> None:
    other = pki.p256()
    evidence = BASE.with_(pck_key=other).evidence()
    # The chain still carries the PCK issued over the base key: the QE report was signed by another.
    chain = BASE.chain_pem()
    quote = tb.quote_bytes(other, chain)
    with pytest.raises(TdxAuthenticationError, match="QE report's signature verification"):
        authenticate(Evidence(quote=quote, pcs=evidence.pcs), tb.NOW, ROOT)


# --- the PCK chain -----------------------------------------------------------------------------


def test_chain_may_end_with_one_nul_byte() -> None:
    assert run(BASE.with_(chain_suffix=b"\x00")).identity == tb.PPID.hex()


def test_chain_with_two_nul_bytes_rejects() -> None:
    rejects(BASE.with_(chain_suffix=b"\x00\x00"), "PCK certificate chain")


def test_chain_with_trailing_blank_line_rejects() -> None:
    rejects(BASE.with_(chain_suffix=b"\n"), "unexpected trailing bytes")


def test_chain_with_text_after_the_blocks_rejects() -> None:
    rejects(BASE.with_(chain_suffix=b"trailer\n"), "PCK certificate chain")


def test_chain_must_hold_three_certificates() -> None:
    scenario = BASE
    chain = scenario.chain_pem()
    two = scenario.intel.pem(scenario.pck()) + scenario.intel.pem(scenario.intel.platform_ca)
    for pem in (two, chain + scenario.intel.pem(scenario.intel.root)):
        quote = tb.quote_bytes(scenario.pck_key, pem)
        with pytest.raises(TdxAuthenticationError, match="should contain 3 PEM certificates"):
            authenticate(Evidence(quote=quote, pcs=scenario.responses()), tb.NOW, ROOT)


def test_processor_ca_chain_rejects() -> None:
    """Only a PCK Platform CA intermediate is accepted.

    The PCK's issuer selects the processor CRL, which is fetched before the chain is validated.
    """
    processor = BASE.with_(intel=tb.intel_pki(platform_ca_cn=tb.PROCESSOR_CA_CN))
    rejects(processor, "no captured response for .*pckcrl\\?ca=processor")
    rejects(processor.with_(pck_crl_ca="processor"), "not expected in certificate's subject")


def test_pck_subject_must_be_the_pck_phrase() -> None:
    rejects(BASE.with_(pck_cn="Intel SGX PCK Cert"), "not expected in certificate's subject")


def test_revoked_pck_rejects() -> None:
    rejects(BASE.with_(pck_crl_revoked=(4,)), "PCK Leaf certificate in PCK certificate chain was revoked")
    assert run(BASE.with_(pck_crl_revoked=(5,))).identity == tb.PPID.hex()


def test_revoked_intermediate_rejects() -> None:
    rejects(BASE.with_(root_crl_revoked=(2,)), "intermediate certificate in PCK certificate chain was revoked")


def test_revoked_tcb_signing_certificate_rejects() -> None:
    rejects(BASE.with_(root_crl_revoked=(3,)), "signing certificate was revoked")


# --- CRL windows ---------------------------------------------------------------------------------


def test_pck_crl_window() -> None:
    rejects(BASE.with_(pck_crl_window=(timedelta(days=-2), timedelta(days=-1))), "outside its validity window")
    rejects(BASE.with_(pck_crl_window=(timedelta(hours=1), timedelta(days=1))), "outside its validity window")
    assert run(BASE.with_(pck_crl_window=(timedelta(0), timedelta(days=1)))).identity == tb.PPID.hex()
    assert run(BASE.with_(pck_crl_window=(timedelta(days=-1), timedelta(0)))).identity == tb.PPID.hex()


def test_root_crl_window() -> None:
    rejects(BASE.with_(root_crl_window=(timedelta(days=-2), timedelta(days=-1))), "outside its validity window")
    rejects(BASE.with_(root_crl_window=(timedelta(hours=1), timedelta(days=1))), "outside its validity window")


def test_missing_root_crl_rejects() -> None:
    rejects(BASE.with_(include_root_crl=False), "could not fetch root CRL")


def test_root_without_distribution_points_rejects() -> None:
    rejects(BASE.with_(intel=tb.intel_pki(root_crl_url=None)), "empty url found")


def test_header_root_with_exotic_distribution_point_names_rejects() -> None:
    """The QE Identity issuer root arrives with the document and its distribution points are read before it is
    verified: a root naming an x400Address or an ediPartyName beside the URI is rejected as an authentication
    error, the same way as any root other than the pinned one, rather than failing the read."""
    from tests.test_tdx_pcs import _context, root_with_distribution_points

    uri = _context(6, tb.INTEL_SGX_ROOT_CA_CRL_URL.encode(), constructed=False)
    for names in (_context(3, tb.sequence()) + uri, _context(5, _context(1, b"\x0c\x01x")) + uri):
        root_pem = root_with_distribution_points(names).public_bytes(serialization.Encoding.PEM)
        header = tb.issuer_chain_header(BASE.intel.pem(BASE.intel.tcb_signing), root_pem)
        rejects(BASE.with_(qe_identity_header=header), "unable to validate signing certificate")


# --- collateral validity -----------------------------------------------------------------------


def test_expired_tcb_info_rejects() -> None:
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(next_update=tb.NOW - timedelta(seconds=1))), "tcbInfo has expired")


def test_expired_qe_identity_rejects() -> None:
    rejects(
        BASE.with_(qe_identity=tb.qe_identity_object(next_update=tb.NOW - timedelta(seconds=1))),
        "QeIdentity has expired",
    )


def test_collateral_issued_after_the_verification_time_rejects() -> None:
    later = tb.NOW + timedelta(seconds=1)
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(issue_date=later)), "TCB Info is not yet valid")
    rejects(BASE.with_(qe_identity=tb.qe_identity_object(issue_date=later)), "QE Identity is not yet valid")
    assert (
        run(
            BASE.with_(
                tcb_info=tb.tcb_info_object(issue_date=tb.NOW), qe_identity=tb.qe_identity_object(issue_date=tb.NOW)
            )
        ).identity
        == tb.PPID.hex()
    )


def test_collateral_without_issue_date_rejects() -> None:
    info = tb.tcb_info_object()
    del info["issueDate"]
    rejects(BASE.with_(tcb_info=info), "issueDate was not observed")


def test_collateral_without_evaluation_number_rejects() -> None:
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(evaluation_number=None)), "tcbEvaluationDataNumber was not observed")
    rejects(
        BASE.with_(qe_identity=tb.qe_identity_object(evaluation_number=None)),
        "tcbEvaluationDataNumber was not observed",
    )


def test_tcb_info_signature_must_cover_the_member() -> None:
    evidence = BASE.evidence()
    tampered = []
    for response in evidence.pcs:
        if response.url.endswith("/tcb?fmspc=" + tb.FMSPC):
            body = response.body.replace(b'"tcbEvaluationDataNumber":18', b'"tcbEvaluationDataNumber":19')
            assert body != response.body
            tampered.append(tb.response(response.url, body, dict(response.headers)))
        else:
            tampered.append(response)
    with pytest.raises(TdxAuthenticationError, match="could not verify response body"):
        authenticate(Evidence(quote=evidence.quote, pcs=tuple(tampered)), tb.NOW, ROOT)


def test_duplicate_member_in_collateral_rejects() -> None:
    evidence = BASE.evidence()
    responses = []
    for response in evidence.pcs:
        if response.url == qe_identity_url():
            body = response.body.replace(b'{"id":"TD_QE",', b'{"id":"TD_QE","id":"TD_QE",')
            responses.append(tb.response(response.url, body, dict(response.headers)))
        else:
            responses.append(response)
    with pytest.raises(TdxAuthenticationError, match="duplicate"):
        authenticate(Evidence(quote=evidence.quote, pcs=tuple(responses)), tb.NOW, ROOT)


def test_unknown_members_and_absent_tcb_type_are_tolerated() -> None:
    info = tb.tcb_info_object()
    del info["tcbType"]
    info["futureMember"] = {"nested": [1, 2, 3]}
    assert run(BASE.with_(tcb_info=info)).identity == tb.PPID.hex()


def test_missing_pcs_response_rejects() -> None:
    evidence = BASE.evidence()
    without_tcb = tuple(r for r in evidence.pcs if "/tcb?" not in r.url)
    with pytest.raises(TdxAuthenticationError, match="no captured response for"):
        authenticate(Evidence(quote=evidence.quote, pcs=without_tcb), tb.NOW, ROOT)
    with pytest.raises(TdxAuthenticationError, match="no captured response for"):
        authenticate(Evidence(quote=evidence.quote, pcs=()), tb.NOW, ROOT)


def test_missing_issuer_chain_header_rejects() -> None:
    evidence = BASE.evidence()
    stripped = tuple(tb.response(r.url, r.body) for r in evidence.pcs)
    with pytest.raises(TdxAuthenticationError, match="is empty"):
        authenticate(Evidence(quote=evidence.quote, pcs=stripped), tb.NOW, ROOT)


def test_issuer_chain_header_with_trailing_newline_rejects() -> None:
    intel = BASE.intel
    header = tb.issuer_chain_header(intel.pem(intel.tcb_signing), intel.pem(intel.root), b"\n")
    rejects(BASE.with_(tcb_info_header=header), "unexpected trailing bytes")


def test_issuer_chain_header_repeated_under_another_case_rejects() -> None:
    """A second spelling of the issuer-chain header cannot stand in for, or hide behind, the first."""
    evidence = BASE.evidence()
    doubled = tuple(
        tb.response(r.url, r.body, {**dict(r.headers), "TCB-INFO-ISSUER-CHAIN": ("",)})
        if r.url.endswith("/tcb?fmspc=" + tb.FMSPC)
        else r
        for r in evidence.pcs
    )
    with pytest.raises(TdxAuthenticationError, match="repeated header 'Tcb-Info-Issuer-Chain'"):
        authenticate(Evidence(quote=evidence.quote, pcs=doubled), tb.NOW, ROOT)


def test_issuer_chain_header_must_hold_two_certificates() -> None:
    intel = BASE.intel
    one = tb.issuer_chain_header(intel.pem(intel.tcb_signing))
    three = tb.issuer_chain_header(intel.pem(intel.tcb_signing), intel.pem(intel.root), intel.pem(intel.root))
    rejects(BASE.with_(qe_identity_header=one), "should contain 2 PEM certificates")
    rejects(BASE.with_(qe_identity_header=three), "should contain 2 PEM certificates")


def test_issuer_chain_must_chain_to_the_trusted_root() -> None:
    other = tb.intel_pki()
    header = tb.issuer_chain_header(other.pem(other.tcb_signing), other.pem(other.root))
    rejects(BASE.with_(tcb_info_header=header), "unable to verify signing certificate")


# --- TCB status -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status", ["SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDate", "Revoked"]
)
def test_platform_tcb_status_must_be_up_to_date(status: str) -> None:
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(status=status)), "TCB Status is not 'UpToDate'")


def test_unknown_tcb_status_rejects() -> None:
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(status="Fine")), "unexpected tcb status")


def test_tcb_level_without_status_is_not_up_to_date() -> None:
    level = tb.tcb_level(list(tb.CPU_SVN_COMPONENTS), tb.PCE_SVN, tb.TDX_COMPONENTS)
    del level["tcbStatus"]
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(levels=[level])), "TCB Status is not 'UpToDate'")


def test_first_matching_level_decides() -> None:
    """Levels are tried in published order: a later up-to-date level does not rescue an earlier out-of-date match."""
    old = tb.tcb_level([0] * 16, 0, [0] * 16, "OutOfDate")
    current = tb.tcb_level(list(tb.CPU_SVN_COMPONENTS), tb.PCE_SVN, tb.TDX_COMPONENTS)
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(levels=[old, current])), "TCB Status is not 'UpToDate'")
    assert run(BASE.with_(tcb_info=tb.tcb_info_object(levels=[current, old]))).identity == tb.PPID.hex()


def test_pce_svn_below_every_level_rejects() -> None:
    rejects(
        BASE.with_(
            tcb_info=tb.tcb_info_object(levels=[tb.tcb_level(list(tb.CPU_SVN_COMPONENTS), 12, tb.TDX_COMPONENTS)])
        ),
        "no matching TCB level found",
    )


def test_tee_tcb_svn_below_a_level_rejects() -> None:
    higher = tb.TDX_COMPONENTS.copy()
    higher[2] = 6
    rejects(
        BASE.with_(tcb_info=tb.tcb_info_object(levels=[tb.tcb_level(list(tb.CPU_SVN_COMPONENTS), tb.PCE_SVN, higher)])),
        "no matching TCB level found",
    )


def test_module_identity_is_selected_by_hex_major_version() -> None:
    body = tb.body_bytes(tee_tcb_svn=bytes([0, 10, 5] + [0] * 13))
    rejects(BASE.with_(body=body), "could not find a TDX Module Identity \\('TDX_0a'\\)")
    rejects(BASE.with_(body=body, tcb_info=tb.tcb_info_object(module_id="TDX_10")), "'TDX_0a'")
    assert run(BASE.with_(body=body, tcb_info=tb.tcb_info_object(module_id="TDX_0a"))).identity == tb.PPID.hex()


def test_module_identities_are_not_consulted_for_major_version_zero() -> None:
    body = tb.body_bytes(tee_tcb_svn=bytes([0, 0, 5] + [0] * 13))
    # With the module version zero, every TEE TCB SVN component takes part in the level match.
    levels = [tb.tcb_level(list(tb.CPU_SVN_COMPONENTS), tb.PCE_SVN, [0, 0, 5] + [0] * 13)]
    info = tb.tcb_info_object(identities=[], levels=levels)
    assert run(BASE.with_(body=body, tcb_info=info)).identity == tb.PPID.hex()
    rejects(BASE.with_(body=body, tcb_info=tb.tcb_info_object(identities=[])), "no matching TCB level found")


def test_module_tcb_level_must_be_up_to_date() -> None:
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(module_status="OutOfDate")), "TDX Module TCB Status is not")
    rejects(
        BASE.with_(tcb_info=tb.tcb_info_object(module_isv_svn=1)),
        "could not find a TDX Module Identity TCB Level",
    )


def test_fmspc_and_pceid_compare_exactly() -> None:
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(fmspc=tb.FMSPC.upper())), "FMSPC from PCK Certificate")
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(fmspc="50806f000001")), "FMSPC from PCK Certificate")
    rejects(BASE.with_(tcb_info=tb.tcb_info_object(pceid="0001")), "PCEID from PCK Certificate")


def test_tdx_module_signer_and_attributes() -> None:
    rejects(BASE.with_(body=tb.body_bytes(mr_signer_seam=bytes([0xEE]) * 48)), "MRSIGNERSEAM")
    rejects(BASE.with_(body=tb.body_bytes(seam_attributes=bytes([0xFF]) * 8)), "AttributesMask value")
    # Bits outside the module's mask do not matter.
    masked = tb.tcb_info_object(attributes_mask=bytes([0x00]) + bytes([0xFF]) * 7)
    assert run(BASE.with_(body=tb.body_bytes(seam_attributes=b"\x80" + bytes(7)), tcb_info=masked)).identity


def test_tdx_module_attributes_outside_the_mask_reject() -> None:
    """The module's published attributes are compared unmasked against the masked quote value."""
    info = tb.tcb_info_object(attributes=b"\x80" + bytes(7), attributes_mask=bytes([0x00]) + bytes([0xFF]) * 7)
    rejects(BASE.with_(body=tb.body_bytes(seam_attributes=b"\x80" + bytes(7)), tcb_info=info), "AttributesMask value")


# --- QE identity -----------------------------------------------------------------------------------


def test_qe_mrsigner_must_match() -> None:
    rejects(BASE.with_(qe_report_kwargs={"mr_signer": bytes([0xEE]) * 32}), "MRSIGNER value")


def test_qe_isv_prod_id_must_match() -> None:
    rejects(BASE.with_(qe_report_kwargs={"isv_prod_id": 3}), "ISV PRODID value")


def test_qe_isv_svn_below_every_level_rejects() -> None:
    rejects(BASE.with_(qe_report_kwargs={"isv_svn": 7}), "it is now OutOfDate")
    assert run(BASE.with_(qe_report_kwargs={"isv_svn": 9})).identity == tb.PPID.hex()


@pytest.mark.parametrize("status", ["SWHardeningNeeded", "OutOfDate", "Revoked"])
def test_qe_tcb_status_must_be_up_to_date(status: str) -> None:
    rejects(BASE.with_(qe_identity=tb.qe_identity_object(status=status)), "TCB Status is not 'UpToDate'")


def test_qe_attributes_outside_the_mask_are_ignored() -> None:
    attributes = bytearray(tb.QE_ATTRIBUTES)
    attributes[9] = 0xFF
    assert run(BASE.with_(qe_report_kwargs={"attributes": bytes(attributes)})).identity == tb.PPID.hex()
    attributes = bytearray(tb.QE_ATTRIBUTES)
    attributes[1] = 0x01
    rejects(BASE.with_(qe_report_kwargs={"attributes": bytes(attributes)}), "AttributesMask value")


def test_qe_identity_attributes_outside_the_mask_reject() -> None:
    """The published attributes are compared unmasked: a bit the mask hides can never be matched."""
    attributes = bytearray(tb.QE_ATTRIBUTES)
    attributes[9] = 0x01
    rejects(BASE.with_(qe_identity=tb.qe_identity_object(attributes=bytes(attributes))), "AttributesMask value")


def test_qe_miscselect_under_the_mask() -> None:
    assert (
        run(
            BASE.with_(
                qe_report_kwargs={"misc_select": 0x80000000},
                qe_identity=tb.qe_identity_object(miscselect_mask=bytes.fromhex("ffffff7f")),
            )
        ).identity
        == tb.PPID.hex()
    )
    rejects(BASE.with_(qe_report_kwargs={"misc_select": 0x80000000}), "MISCSELECT value")
    rejects(BASE.with_(qe_identity=tb.qe_identity_object(miscselect=bytes(3))), "MISCSELECT field size")
    rejects(BASE.with_(qe_identity=tb.qe_identity_object(miscselect_mask=bytes(5))), "MISCSELECTMask field size")


# --- PCK extensions -------------------------------------------------------------------------------


def test_pck_extension_count_must_be_six() -> None:
    scenario = BASE
    pck = tb.pck_certificate(
        scenario.intel.platform_ca,
        scenario.pck_key,
        now=tb.NOW,
        extra_extensions=((x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False),),
    )
    chain = (
        scenario.intel.pem(pck)
        + scenario.intel.pem(scenario.intel.platform_ca)
        + scenario.intel.pem(scenario.intel.root)
    )
    quote = tb.quote_bytes(scenario.pck_key, chain)
    with pytest.raises(TdxAuthenticationError, match="extensions length found 7"):
        authenticate(Evidence(quote=quote, pcs=scenario.responses()), tb.NOW, ROOT)


def test_pck_key_usage_must_allow_digital_signatures() -> None:
    """The PCK key authenticates the QE report, so a keyUsage extension on the leaf must allow digitalSignature."""
    scenario = BASE
    pck = tb.pck_certificate(scenario.intel.platform_ca, scenario.pck_key, now=tb.NOW, key_usage=tb.ENCIPHERMENT_USAGE)
    chain = (
        scenario.intel.pem(pck)
        + scenario.intel.pem(scenario.intel.platform_ca)
        + scenario.intel.pem(scenario.intel.root)
    )
    quote = tb.quote_bytes(scenario.pck_key, chain)
    with pytest.raises(TdxAuthenticationError, match="key usage does not allow digital signatures"):
        authenticate(Evidence(quote=quote, pcs=scenario.responses()), tb.NOW, ROOT)


def test_missing_fmspc_selects_no_tcb_info() -> None:
    value = tb.sequence(
        tb.attribute(f"{tb._SGX_OID}.1", tb.octet_string(tb.PPID)),
        tb.tcb_attribute(),
        tb.attribute(f"{tb._SGX_OID}.3", tb.octet_string(bytes.fromhex(tb.PCEID))),
        tb.attribute(f"{tb._SGX_OID}.9", tb.octet_string(b"")),
    )
    rejects(BASE.with_(extension_value=value), "no captured response for .*tcb\\?fmspc=$")


def test_pck_tcb_below_every_level_rejects() -> None:
    lower = bytearray(tb.CPU_SVN_COMPONENTS)
    lower[0] = 4
    rejects(BASE.with_(extension_value=tb.sgx_extension(tcb=tb.tcb_attribute(components=bytes(lower)))), "no matching")
    rejects(BASE.with_(extension_value=tb.sgx_extension(tcb=tb.tcb_attribute(pce_svn=10))), "no matching TCB level")


@pytest.mark.parametrize("source", ["tcb", "qe", "root_crl", "pck_crl", "pck"])
def test_verified_collateral_bounds_quote_lifetime(source: str) -> None:
    lifetime = timedelta(hours=1)
    deadline = tb.NOW + lifetime
    variants: dict[str, dict[str, Any]] = {
        "tcb": {"tcb_info": tb.tcb_info_object(next_update=deadline)},
        "qe": {"qe_identity": tb.qe_identity_object(next_update=deadline)},
        "root_crl": {"root_crl_window": (timedelta(days=-1), lifetime)},
        "pck_crl": {"pck_crl_window": (timedelta(days=-1), lifetime)},
        "pck": {},
    }
    scenario = BASE.with_(**variants[source])
    evidence = scenario.evidence()
    if source == "pck":
        pck = scenario.pck()
        short = pki.reissue(pki.load(pck.der), pck.key, scenario.intel.platform_ca, not_after=deadline)
        chain = b"".join(scenario.intel.pem(cert) for cert in (short, scenario.intel.platform_ca, scenario.intel.root))
        evidence = Evidence(quote=tb.quote_bytes(scenario.pck_key, chain), pcs=scenario.responses())
    assert authenticate(evidence, tb.NOW, ROOT).expires_at == deadline
    assert authenticate(evidence, deadline, ROOT).expires_at == deadline
    with pytest.raises(TdxAuthenticationError):
        authenticate(evidence, deadline + timedelta(seconds=1), ROOT)
