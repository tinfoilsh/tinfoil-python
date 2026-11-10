"""The SEV-SNP report ABI: field decoding, the bit fields, the CPUID product identity and the reserved ranges."""

from __future__ import annotations

import pytest

from tests.v3 import sev_fixtures as fx
from tinfoil._v3.verifier._quote.sev.lib import abi
from tinfoil._v3.verifier._x509 import der


def happy_report_bytes() -> bytes:
    return fx.happy_case().document.cpu_evidence().report


class TestBitFields:
    def test_policy_round_trips(self) -> None:
        policy = abi.SnpPolicy(abi_major=1, abi_minor=51, smt=True, single_socket=True, page_swap_disable=True)
        assert abi.parse_snp_policy(abi.snp_policy_to_int(policy)) == policy
        assert abi.snp_policy_to_int(abi.SnpPolicy()) == 1 << abi.POLICY_RESERVED_1_BIT

    def test_policy_reserved_bits(self) -> None:
        with pytest.raises(abi.AbiError, match=r"policy\[17\] is reserved, must be 1, got 0"):
            abi.parse_snp_policy(0)
        with pytest.raises(abi.AbiError, match=r"mbz range policy\[0x1a:0x3f\] not all zero"):
            abi.parse_snp_policy((1 << 17) | (1 << 26))
        with pytest.raises(abi.AbiError, match="not all zero"):
            abi.parse_snp_policy((1 << 17) | (1 << 63))

    def test_signer_info(self) -> None:
        info = abi.SignerInfo(abi.ReportSigner.VLEK, mask_chip_key=True, author_key_en=True)
        assert abi.compose_signer_info(info) == 0b111
        assert abi.parse_signer_info(0b111) == info
        assert abi.parse_signer_info(7 << 2).signing_key == abi.ReportSigner.NONE
        for reserved in range(2, 7):
            with pytest.raises(abi.AbiError, match="signing_key values 2-6 are reserved"):
                abi.parse_signer_info(reserved << 2)
        with pytest.raises(abi.AbiError, match=r"mbz range data\[0x48:0x4C\]\[0x5:0x1f\]"):
            abi.parse_signer_info(1 << 5)
        assert str(abi.ReportSigner.VCEK) == "VCEK"

    def test_platform_info(self) -> None:
        assert abi.parse_snp_platform_info(0xFF) == abi.SnpPlatformInfo(*([True] * 8))
        assert abi.parse_snp_platform_info(1 << 6).iommu_write_safe
        with pytest.raises(abi.AbiError, match="unrecognized platform info bit"):
            abi.parse_snp_platform_info(1 << 8)


class TestProductIdentity:
    def test_fms_round_trips(self) -> None:
        for family, model, stepping in ((0x19, 0x11, 0), (0x1A, 0x02, 1), (0x0F, 0x00, 0xF), (0xFF, 0xFF, 0x3)):
            assert abi.fms_from_cpuid1_eax(abi.fms_to_cpuid1_eax(family, model, stepping)) == (family, model, stepping)
        assert abi.fms_to_cpuid1_eax(0x19, 0x11, 0) == 0x00A10F10
        assert abi.fms_to_cpuid1_eax(0x1A, 0x02, 0) == 0x00B00F20
        assert abi.fms_to_cpuid1_eax(0x19, 0x01, 0) == 0x00A00F10

    def test_products(self) -> None:
        assert abi.sev_product_from_cpuid1_eax(0x00A10F11) == abi.SevProduct(abi.PRODUCT_GENOA, 1)
        assert abi.sev_product_from_cpuid1_eax(0x00B00F21) == abi.SevProduct(abi.PRODUCT_TURIN, 1)
        assert abi.sev_product_from_cpuid1_eax(0x00A00F11) == abi.SevProduct(abi.PRODUCT_MILAN, 1)
        # An unknown product reveals nothing about the stepping.
        assert abi.sev_product_from_cpuid1_eax(abi.fms_to_cpuid1_eax(0x19, 0x22, 3)) == abi.SevProduct("Unknown", 0)
        assert abi.sev_product_from_cpuid1_eax(0) == abi.SevProduct("Unknown", 0)

    def test_product_lines(self) -> None:
        assert abi.product_line_from_fms(abi.fms_to_cpuid1_eax(0x19, 0x11, 0)) == abi.PRODUCT_GENOA
        assert abi.product_line_from_fms(abi.fms_to_cpuid1_eax(0x19, 0x01, 0)) == abi.PRODUCT_MILAN
        assert abi.product_line_from_fms(abi.fms_to_cpuid1_eax(0x19, 0xA0, 0)) == abi.PRODUCT_SIENA
        assert abi.product_line_from_fms(abi.fms_to_cpuid1_eax(0x1A, 0x02, 0)) == abi.PRODUCT_TURIN
        assert abi.product_line_from_fms(abi.fms_to_cpuid1_eax(0x1A, 0x12, 0)) == abi.PRODUCT_TURIN
        assert abi.product_line_from_fms(abi.fms_to_cpuid1_eax(0x1A, 0x22, 0)) == abi.PRODUCT_UNKNOWN
        assert abi.product_line_from_fms(0) == abi.PRODUCT_UNKNOWN


class TestParseReport:
    def test_happy_vector_fields(self) -> None:
        report = abi.parse_report(happy_report_bytes())
        assert report.version == 3
        assert report.policy == 0x30000
        assert report.cpuid1_eax_fms == abi.fms_to_cpuid1_eax(0x19, 0x11, 0)
        assert report.current_tcb == report.reported_tcb == report.committed_tcb == report.launch_tcb == fx.GENOA_TCB
        assert (report.current_major, report.current_minor, report.current_build) == (1, 55, 21)
        assert report.chip_id == fx.GENOA_HWID
        assert report.signer_info == 0
        assert report.signature_algo == abi.SIGN_ECDSA_P384_SHA384
        assert report.raw == happy_report_bytes()
        assert len(report.signature) == abi.SIGNATURE_SIZE
        assert abi.signed_component(report.raw) == report.raw[: abi.SIGNATURE_OFFSET]

    def test_size_must_be_exact(self) -> None:
        with pytest.raises(abi.AbiError, match="array size is 0x49f"):
            abi.parse_report(happy_report_bytes()[:-1])
        with pytest.raises(abi.AbiError, match="array size is 0x4a1"):
            abi.parse_report(happy_report_bytes() + b"\x00")

    @pytest.mark.parametrize(
        ("offset", "message"),
        [
            (0x0A, "malformed guest policy"),
            (0x4C, r"mbz range \[0x4c:0x50\]"),
            (0x18B, r"mbz range \[0x18b:0x1a0\]"),
            (0x1EB, r"mbz range \[0x1eb:0x1ec\]"),
            (0x1EF, r"mbz range \[0x1ef:0x1f0\]"),
            (0x208, r"mbz range \[0x208:0x2a0\]"),
            (0x29F, r"mbz range \[0x208:0x2a0\]"),
            (0x2A0 + 144, r"mbz range \[0x330:0x4a0\]"),
            (0x49F, r"mbz range \[0x330:0x4a0\]"),
        ],
    )
    def test_reserved_ranges(self, offset: int, message: str) -> None:
        with pytest.raises(abi.AbiError, match=message):
            abi.parse_report(fx.flip(happy_report_bytes(), offset, 0x02))

    def test_signer_info_is_checked(self) -> None:
        with pytest.raises(abi.AbiError, match="reserved"):
            abi.parse_report(fx.flip(happy_report_bytes(), 0x48, 0x08))
        with pytest.raises(abi.AbiError, match="mbz range"):
            abi.parse_report(fx.flip(happy_report_bytes(), 0x48, 0x20))

    def test_version_2_reserves_the_cpuid_bytes(self) -> None:
        raw = bytearray(happy_report_bytes())
        raw[0] = 2
        with pytest.raises(abi.AbiError, match=r"mbz range \[0x188:0x1a0\]"):
            abi.parse_report(bytes(raw))
        raw[0x188:0x18B] = bytes(3)
        assert abi.parse_report(bytes(raw)).cpuid1_eax_fms == 0

    def test_stepping_must_fit_four_bits(self) -> None:
        raw = bytearray(happy_report_bytes())
        raw[0x18A] = 0x0F
        assert abi.parse_report(bytes(raw)).cpuid1_eax_fms & 0xF == 0xF
        raw[0x18A] = 0x10
        with pytest.raises(abi.AbiError, match="stepping 0x10 does not fit four bits"):
            abi.parse_report(bytes(raw))

    def test_mitigation_vectors_are_read_for_every_version(self) -> None:
        raw = bytearray(happy_report_bytes())
        raw[0x1F8] = 0x03
        raw[0x200] = 0x01
        report = abi.parse_report(bytes(raw))
        assert (report.launch_mit_vector, report.current_mit_vector) == (3, 1)

    def test_unknown_signature_algorithms_leave_the_tail_unchecked(self) -> None:
        raw = bytearray(happy_report_bytes())
        raw[0x34] = 2
        raw[0x49F] = 1
        report = abi.parse_report(bytes(raw))
        with pytest.raises(abi.AbiError, match="unknown signature algorithm: 2"):
            abi.report_signature_der(report)

    def test_report_format(self) -> None:
        abi.validate_report_format(happy_report_bytes())
        raw = bytearray(happy_report_bytes())
        raw[0] = 6
        with pytest.raises(abi.AbiError, match=r"report version is: 6\. Expected between 2 and 5"):
            abi.validate_report_format(bytes(raw))
        raw[0] = 1
        with pytest.raises(abi.AbiError, match="report version is: 1"):
            abi.validate_report_format(bytes(raw))
        with pytest.raises(abi.AbiError, match="report size is 10 bytes"):
            abi.validate_report_format(bytes(10))

    def test_signature_der_is_minimal(self) -> None:
        report = abi.parse_report(happy_report_bytes())
        signature = abi.report_signature_der(report)
        r = int.from_bytes(report.signature[:72], "little")
        s = int.from_bytes(report.signature[72:144], "little")
        assert der.ecdsa_signature_to_raw(signature, 48) == r.to_bytes(48, "big") + s.to_bytes(48, "big")
        assert der.raw_signature_to_der(der.ecdsa_signature_to_raw(signature, 48), 48) == signature


class TestMbz:
    def test_ranges(self) -> None:
        abi.mbz(bytes(4), 0, 4)
        with pytest.raises(abi.AbiError, match=r"mbz range \[0x1:0x3\] not all zero: 0001"):
            abi.mbz(b"\x00\x00\x01\x00", 1, 3)
        abi.mbz64(0xFF, "x", 15, 8)
        with pytest.raises(abi.AbiError, match=r"mbz range x\[0x8:0xf\] not all zero: 100"):
            abi.mbz64(0x100, "x", 15, 8)
