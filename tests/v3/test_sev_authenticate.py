"""SEV-SNP authentication: every quote vector through the platform dispatch, the pinned-root path on production Turin
captures, and the single rules of each step."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.v3 import sev_fixtures as fx
from tinfoil._v3.verifier._document.collateral.collateral import CPUEndorsements
from tinfoil._v3.verifier._document.collateral.sev import AMDCRL, AMDVCEK
from tinfoil._v3.verifier._document.document import SEVSNP_REPORT_V1_FORMAT, TDX_QUOTE_V1_FORMAT, CpuEvidence
from tinfoil._v3.verifier._measurement import SEVSNP
from tinfoil._v3.verifier._quote import quote, sev
from tinfoil._v3.verifier._quote.sev import expectations
from tinfoil._v3.verifier._quote.sev.authenticate import (
    SevAuthenticationError,
    decode_cert_chain,
    parse_crl,
    parse_report_bytes,
    product_from_report,
    reject_masked_chip_id,
    trusted_roots,
    verify_signature,
)
from tinfoil._v3.verifier._quote.sev.lib import abi, chain
from tinfoil._v3.verifier._quote.sev.lib.abi import REPORT_SIZE, fms_to_cpuid1_eax, parse_report
from tinfoil._v3.verifier._x509.certificate import parse_certificate

PINNED_TURIN_TIME = datetime(2026, 8, 18, tzinfo=UTC)


def options_for(case: fx.VectorCase) -> quote.QuoteOptions:
    return quote.QuoteOptions(test_only_roots=quote.TestOnlyRoots(amd=case.chain_pem))


def sev_evidence(case: fx.VectorCase) -> sev.Evidence:
    endorsements = case.document.cpu_endorsements()
    assert endorsements.amd_vcek is not None
    assert endorsements.amd_crl is not None
    return sev.Evidence(
        report=case.document.cpu_evidence().report,
        vcek_der=endorsements.amd_vcek.vcek_der,
        cert_chain_pem=endorsements.amd_vcek.cert_chain_pem,
        crl_der=endorsements.amd_crl.crl_der,
    )


@pytest.mark.parametrize("fixture", fx.sev_vector_params())
def test_sev_vectors(fixture: dict[str, Any]) -> None:
    """Every vector: the fixture's verdict through the platform dispatch, and on accept the identity and the launch
    measurement read from the report."""
    case = fx.decode_case(fixture)
    doc = case.document
    if case.accepted:
        result = quote.authenticate(doc.cpu_evidence(), doc.cpu_endorsements(), case.now, options_for(case))
        assert isinstance(result, quote.AuthenticatedSEVSNP)
        report = parse_report(doc.cpu_evidence().report)
        assert result.identity == report.chip_id.hex()
        assert result.measurement.launch == report.measurement
        assert result.platform == "sev-snp"
        assert result.evidence == doc.cpu_evidence()
        assert result.quote.product_line == sev.PRODUCT_GENOA
    else:
        with pytest.raises(quote.QuoteError):
            quote.authenticate(doc.cpu_evidence(), doc.cpu_endorsements(), case.now, options_for(case))


def test_happy_vector_through_the_sev_entry_point() -> None:
    case = fx.happy_case()
    assert case.chain_pem is not None
    verified = sev.authenticate(sev_evidence(case), case.now, sev.Options(test_only_root_pem=case.chain_pem))
    assert verified.identity == fx.GENOA_HWID.hex()
    assert verified.chain.vcek == parse_certificate(sev_evidence(case).vcek_der)
    assert chain.common_name(verified.chain.ask.subject) == "SEV-Genoa"
    assert chain.common_name(verified.chain.ark.subject) == "ARK-Genoa"


def test_dispatch_rejects_missing_collateral_and_unknown_formats() -> None:
    case = fx.happy_case()
    evidence = case.document.cpu_evidence()
    endorsements = case.document.cpu_endorsements()
    with pytest.raises(quote.QuoteError, match="no amd-vcek endorsement collateral"):
        quote.authenticate(evidence, replace(endorsements, amd_vcek=None), case.now, options_for(case))
    with pytest.raises(quote.QuoteError, match="no amd-crl endorsement collateral"):
        quote.authenticate(evidence, replace(endorsements, amd_crl=None), case.now, options_for(case))
    tdx_evidence = CpuEvidence(format=TDX_QUOTE_V1_FORMAT, report=evidence.report)
    with pytest.raises(quote.QuoteError, match="no intel-pcs endorsement collateral"):
        quote.authenticate(tdx_evidence, CPUEndorsements(), case.now, options_for(case))
    other = CpuEvidence(format="https://example.invalid/format", report=evidence.report)
    with pytest.raises(quote.QuoteError, match="unsupported cpu_evidence format"):
        quote.authenticate(other, endorsements, case.now, options_for(case))


def test_dispatch_rejects_the_synthetic_chain_under_the_embedded_roots() -> None:
    case = fx.happy_case()
    doc = case.document
    with pytest.raises(quote.QuoteError, match="error verifying VCEK certificate"):
        quote.authenticate(doc.cpu_evidence(), doc.cpu_endorsements(), case.now, quote.QuoteOptions())
    with pytest.raises(quote.QuoteError, match="error verifying VCEK certificate"):
        quote.authenticate(doc.cpu_evidence(), doc.cpu_endorsements(), case.now, None)


def test_dispatch_passes_empty_collateral_to_the_platform_checks() -> None:
    case = fx.happy_case()
    doc = case.document
    endorsements = doc.cpu_endorsements()
    assert endorsements.amd_vcek is not None
    chain_pem = endorsements.amd_vcek.cert_chain_pem
    empty_vcek = replace(endorsements, amd_vcek=AMDVCEK(vcek_der=b"", cert_chain_pem=chain_pem))
    with pytest.raises(quote.QuoteError, match="empty VCEK"):
        quote.authenticate(doc.cpu_evidence(), empty_vcek, case.now, options_for(case))
    empty_crl = replace(endorsements, amd_crl=AMDCRL(crl_der=b""))
    with pytest.raises(quote.QuoteError, match="empty CRL"):
        quote.authenticate(doc.cpu_evidence(), empty_crl, case.now, options_for(case))


def test_report_size_must_be_exact() -> None:
    for size in (REPORT_SIZE - 1, REPORT_SIZE + 1):
        with pytest.raises(SevAuthenticationError, match="must be exactly"):
            parse_report_bytes(bytes(size))


def test_authenticate_requires_an_aware_verification_time() -> None:
    case = fx.happy_case()
    naive = datetime(2025, 1, 1)
    with pytest.raises(SevAuthenticationError, match="verification time is required"):
        sev.authenticate(sev_evidence(case), naive, sev.Options(test_only_root_pem=case.chain_pem))


def test_trusted_roots_select_the_product() -> None:
    for product_line in (sev.PRODUCT_GENOA, sev.PRODUCT_TURIN):
        roots = trusted_roots(product_line, None)
        assert roots.product_line == product_line
        assert chain.common_name(roots.ask.subject) == f"SEV-{product_line}"
        assert chain.common_name(roots.ark.subject) == f"ARK-{product_line}"
    with pytest.raises(SevAuthenticationError, match="unsupported SEV product line"):
        trusted_roots("Milan", None)


def test_trusted_roots_reject_a_malformed_replacement() -> None:
    case = fx.happy_case()
    assert case.chain_pem is not None
    one_block = case.chain_pem.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
    with pytest.raises(SevAuthenticationError, match="got 1 blocks"):
        trusted_roots(sev.PRODUCT_GENOA, one_block)
    with pytest.raises(SevAuthenticationError, match="not ASCII"):
        trusted_roots(sev.PRODUCT_GENOA, b"\xff")
    not_certificates = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" * 2
    with pytest.raises(SevAuthenticationError, match="parsing embedded AMD Genoa root certificates"):
        trusted_roots(sev.PRODUCT_GENOA, not_certificates)


def test_product_from_report() -> None:
    unknown = fx.make_report(version=abi.REPORT_VERSION_5, cpuid1_eax_fms=fms_to_cpuid1_eax(0xFF, 0xFF, 0))
    with pytest.raises(SevAuthenticationError, match="unsupported SEV product"):
        product_from_report(unknown)
    with pytest.raises(SevAuthenticationError, match="no CPUID product identity"):
        product_from_report(fx.make_report(version=2, cpuid1_eax_fms=0))
    assert product_from_report(fx.make_report()) == sev.PRODUCT_GENOA
    turin = fms_to_cpuid1_eax(abi.ZEN5_FAMILY, abi.TURIN_MODEL, 1)
    assert product_from_report(fx.make_report(cpuid1_eax_fms=turin)) == sev.PRODUCT_TURIN
    milan = fms_to_cpuid1_eax(abi.ZEN3_ZEN4_FAMILY, abi.MILAN_MODEL, 1)
    with pytest.raises(SevAuthenticationError, match="unsupported SEV product"):
        product_from_report(fx.make_report(cpuid1_eax_fms=milan))


def test_box2_turin_signature_under_the_pinned_roots() -> None:
    report = parse_report(fx.box2_turin_report())
    vcek = parse_certificate(fx.box2_turin_vcek())
    assert product_from_report(report) == sev.PRODUCT_TURIN
    roots = trusted_roots(sev.PRODUCT_TURIN, None)
    extensions = chain.validate_vcek_certificate(vcek, roots.product_line)
    assert extensions.struct_version == 1
    assert len(extensions.hwid) == 8
    chain.validate_vcek_issuer(vcek, roots.product_line)
    chain.verify_vcek_chain(vcek, roots.ask, roots.ark, PINNED_TURIN_TIME)
    chain.verify_report_signature(report, vcek)
    assert report.chip_id.hex() == fx.BOX2_TURIN_ID


def test_box2_turin_signature_fails_under_the_genoa_roots_and_when_tampered() -> None:
    vcek = parse_certificate(fx.box2_turin_vcek())
    genoa = trusted_roots(sev.PRODUCT_GENOA, None)
    with pytest.raises(chain.ChainError, match="different TCB formats"):
        chain.validate_vcek_certificate(vcek, genoa.product_line)
    with pytest.raises(chain.ChainError, match="issuer common name"):
        chain.validate_vcek_issuer(vcek, genoa.product_line)
    with pytest.raises(chain.ChainError, match="error verifying VCEK certificate"):
        chain.verify_vcek_chain(vcek, genoa.ask, genoa.ark, PINNED_TURIN_TIME)
    tampered = parse_report(fx.flip(fx.box2_turin_report(), 0x90))
    with pytest.raises(chain.ChainError, match="report signature verification error"):
        chain.verify_report_signature(tampered, vcek)


@pytest.mark.parametrize("host", ["inf17", "inf18"])
def test_production_turin_captures(host: str) -> None:
    """Captured version 5 reports verify under the pinned Turin roots at capture time and satisfy the selected
    policy; an exact PLATFORM_INFO bit is enforced, not permitted."""
    capture = fx.production_capture(host)
    report = parse_report(capture.report)
    assert report.version == 5
    assert report.platform_info == 0x64
    vcek = parse_certificate(capture.vcek_der)
    roots = trusted_roots(product_from_report(report), None)
    assert roots.product_line == sev.PRODUCT_TURIN
    chain.validate_vcek_certificate(vcek, roots.product_line)
    chain.validate_vcek_issuer(vcek, roots.product_line)
    chain.verify_vcek_chain(vcek, roots.ask, roots.ark, capture.captured_at)
    chain.verify_report_signature(report, vcek)
    verified = sev.Quote(
        identity=report.chip_id.hex(),
        measurement=SEVSNP(launch=report.measurement),
        product_line=roots.product_line,
        report=report,
        chain=chain.CertificateChain(ark=roots.ark, ask=roots.ask, vcek=vcek),
    )
    assert expectations.expected_platform_info(capture.policy) == abi.SnpPlatformInfo(
        ecc_enabled=True, alias_check_complete=True, iommu_write_safe=True
    )
    expected = sev.assemble(capture.policy, verified, report.measurement, report.report_data)
    sev.validate(expected, verified)

    wrong = replace(capture.policy, platform_info=replace(capture.policy.platform_info, ecc_enabled=False))
    expected = sev.assemble(wrong, verified, report.measurement, report.report_data)
    with pytest.raises(sev.SevPolicyError, match="PLATFORM_INFO does not match"):
        sev.validate(expected, verified)


def test_decode_cert_chain() -> None:
    empty = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
    with pytest.raises(SevAuthenticationError, match="empty CERTIFICATE block"):
        decode_cert_chain(empty + empty)
    case = fx.happy_case()
    endorsements = case.document.cpu_endorsements()
    assert endorsements.amd_vcek is not None
    good = endorsements.amd_vcek.cert_chain_pem
    ask_der, ark_der = decode_cert_chain(good)
    assert chain.common_name(parse_certificate(ask_der).subject) == "SEV-Genoa"
    assert chain.common_name(parse_certificate(ark_der).subject) == "ARK-Genoa"
    one = good.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    with pytest.raises(SevAuthenticationError, match="got 1 blocks"):
        decode_cert_chain(one)
    with pytest.raises(SevAuthenticationError, match="got 3 blocks"):
        decode_cert_chain(good + one)
    with pytest.raises(SevAuthenticationError, match="not a CERTIFICATE"):
        decode_cert_chain(good.replace("CERTIFICATE", "PUBLIC KEY", 2))
    with pytest.raises(SevAuthenticationError, match="text outside PEM blocks"):
        decode_cert_chain(good + "trailing\n")


def test_parse_crl_window_is_inclusive() -> None:
    case = fx.happy_case()
    endorsements = case.document.cpu_endorsements()
    assert endorsements.amd_crl is not None
    crl_der = endorsements.amd_crl.crl_der
    crl = parse_crl(crl_der, case.now)
    parse_crl(crl_der, crl.this_update)
    parse_crl(crl_der, crl.next_update)
    with pytest.raises(SevAuthenticationError, match="outside its validity window"):
        parse_crl(crl_der, crl.this_update - timedelta(seconds=1))
    with pytest.raises(SevAuthenticationError, match="outside its validity window"):
        parse_crl(crl_der, crl.next_update + timedelta(seconds=1))
    with pytest.raises(SevAuthenticationError, match="parsing amd-crl collateral"):
        parse_crl(crl_der + b"\x00", case.now)


def test_masked_chip_id_is_rejected_after_the_signature_check() -> None:
    masked = abi.compose_signer_info(abi.SignerInfo(abi.ReportSigner.VCEK, mask_chip_key=True, author_key_en=False))
    with pytest.raises(SevAuthenticationError, match="masks CHIP_ID"):
        reject_masked_chip_id(fx.make_report(signer_info=masked))
    reject_masked_chip_id(fx.make_report())


def test_non_vcek_signers_are_rejected() -> None:
    case = fx.happy_case()
    assert case.chain_pem is not None
    roots = trusted_roots(sev.PRODUCT_GENOA, case.chain_pem)
    crl = parse_crl(sev_evidence(case).crl_der, case.now)
    for key in (abi.ReportSigner.VLEK, abi.ReportSigner.NONE):
        info = abi.compose_signer_info(abi.SignerInfo(key, mask_chip_key=False, author_key_en=False))
        report = fx.make_report(signer_info=info)
        with pytest.raises(SevAuthenticationError, match=f"missing {key} certificate"):
            verify_signature(report, sev_evidence(case), roots, crl, case.now)


def test_report_layout_fixes_the_measurement_size() -> None:
    assert len(parse_report(fx.happy_case().document.cpu_evidence().report).measurement) == 48


def test_evidence_format_constant_matches_the_document() -> None:
    assert fx.happy_case().document.cpu_evidence().format == SEVSNP_REPORT_V1_FORMAT
