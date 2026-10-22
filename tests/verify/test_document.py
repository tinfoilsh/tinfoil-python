from types import MappingProxyType

import pytest

from tinfoil.verify import _formats
from tinfoil.verify.collateral import (
    AmdCrl,
    AmdVcek,
    CPUEndorsements,
    Freshness,
    IntelPcs,
    PcsResponse,
    SigstoreRef,
    _Collateral,
)
from tinfoil.verify.document import (
    SEV_SNP_REPORT_V1_FORMAT,
    TDX_QUOTE_V1_FORMAT,
    CPUEvidence,
    CryptoMaterialItem,
    Document,
)

VCEK = AmdVcek(b"vcek", "chain")
CRL = AmdCrl(b"crl")
PCS = IntelPcs([PcsResponse("https://api.trustedservices.intel.com/tdx", {"Issuer": ["chain"]}, b"body")])
PLATFORM = SigstoreRef(repo="tinfoilsh/cvmimage", tag="platform-v1.0.0", digest="ab" * 32, bundle=b"{}")


def document(
    evidence_format: str = SEV_SNP_REPORT_V1_FORMAT,
    collateral: _Collateral | None = None,
    collateral_format: str | None = None,
) -> Document:
    return Document._create(
        evidence=CPUEvidence(evidence_format, b"report"),
        crypto_material=(CryptoMaterialItem("tls", "fmt", "aa"), CryptoMaterialItem("hpke", "fmt", "bb")),
        device_evidence=(),
        collateral=collateral or _Collateral(),
        collateral_format=collateral_format,
        report_data=bytes(64),
    )


def test_documents_come_only_from_parse():
    with pytest.raises(TypeError, match="parse"):
        Document()


@pytest.mark.parametrize(
    ("evidence_format", "expected"),
    [
        (SEV_SNP_REPORT_V1_FORMAT, CPUEndorsements(amd_vcek=VCEK, amd_crl=CRL)),
        (TDX_QUOTE_V1_FORMAT, CPUEndorsements(intel_pcs=PCS)),
        ("https://example.com/unknown", CPUEndorsements()),
    ],
)
def test_cpu_endorsements_follow_the_evidence_format(evidence_format, expected):
    collateral = _Collateral(cpu=CPUEndorsements(amd_vcek=VCEK, amd_crl=CRL, intel_pcs=PCS))
    assert document(evidence_format, collateral).cpu_endorsements == expected


def test_collateral_format_defaults_to_legacy():
    assert document().collateral_format == _formats.COLLATERAL_V2
    assert document(collateral_format=_formats.COLLATERAL_V3).collateral_format == _formats.COLLATERAL_V3


def test_lookups_return_none_when_absent():
    parsed = document(collateral=_Collateral(freshness=MappingProxyType({"code-freshness": Freshness("f", b"{}")})))
    assert parsed.crypto_material_item("hpke") == CryptoMaterialItem("hpke", "fmt", "bb")
    assert parsed.crypto_material_item("ssh") is None
    assert parsed.freshness("code-freshness") == Freshness("f", b"{}")
    assert parsed.freshness("platform-freshness") is None
    assert parsed.sigstore_code is None
    assert parsed.config_endorsement is None
    assert parsed.runtime is None
    assert parsed.config_platform() is None


def test_config_platform_must_be_unambiguous():
    unique = _Collateral(platform_entries=1, config_platform=PLATFORM)
    assert document(collateral=unique).config_platform() == PLATFORM
    for ambiguous in (_Collateral(platform_entries=2, config_platform=PLATFORM), _Collateral(platform_entries=1)):
        with pytest.raises(ValueError, match="conflicting platform collateral"):
            document(collateral=ambiguous).config_platform()


def test_pcs_headers_are_read_only():
    headers = PCS.responses[0].headers
    assert headers["Issuer"] == ("chain",)
    with pytest.raises(TypeError):
        headers["Issuer"] = ("other",)  # type: ignore[index]
