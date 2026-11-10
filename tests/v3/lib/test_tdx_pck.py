"""PCK certificate extension parsing."""

from __future__ import annotations

import pytest

from tests.v3 import pki
from tests.v3 import tdx_builders as tb
from tinfoil._v3.verifier._quote.tdx.lib.pck import (
    CPU_SVN_SIZE,
    FMSPC_SIZE,
    OID_FMSPC,
    OID_PCEID,
    OID_PPID,
    OID_SGX_EXTENSION,
    OID_TCB,
    PCEID_SIZE,
    PPID_SIZE,
    TCB_COMPONENTS_COUNT,
    TCB_EXTENSION_SIZE,
    PckCertTCB,
    PckExtensionError,
    PckExtensions,
    extract_pck_extensions,
)

SGX = tb._SGX_OID
PLATFORM_CA = tb.intel_pki().platform_ca


def parse(value: bytes) -> PckExtensions:
    return extract_pck_extensions(pki.load(tb.pck_certificate(PLATFORM_CA, extension_value=value).der))


class TestConstants:
    def test_oids(self) -> None:
        assert OID_SGX_EXTENSION == "1.2.840.113741.1.13.1"
        assert OID_PPID == "1.2.840.113741.1.13.1.1"
        assert OID_TCB == "1.2.840.113741.1.13.1.2"
        assert OID_PCEID == "1.2.840.113741.1.13.1.3"
        assert OID_FMSPC == "1.2.840.113741.1.13.1.4"

    def test_sizes(self) -> None:
        assert (PPID_SIZE, CPU_SVN_SIZE, FMSPC_SIZE, PCEID_SIZE) == (16, 16, 6, 2)
        assert TCB_COMPONENTS_COUNT == 16
        assert TCB_EXTENSION_SIZE == 18


class TestExtractPckExtensions:
    def test_profile(self) -> None:
        ext = parse(tb.sgx_extension())
        assert ext == PckExtensions(
            ppid=tb.PPID.hex(),
            tcb=PckCertTCB(pce_svn=tb.PCE_SVN, cpu_svn=tb.CPU_SVN_COMPONENTS, cpu_svn_components=tb.CPU_SVN_COMPONENTS),
            pceid=tb.PCEID,
            fmspc=tb.FMSPC,
        )

    def test_hex_is_lowercase(self) -> None:
        ext = parse(tb.sgx_extension(ppid=bytes([0xAB]) * 16, fmspc="50806F000000"))
        assert ext.ppid == "ab" * 16
        assert ext.fmspc == "50806f000000"

    def test_requires_six_extensions(self) -> None:
        without_sgx = pki.certificate("leaf", pki.p256(), PLATFORM_CA, key_usage=pki.SIGNING_USAGE)
        with pytest.raises(PckExtensionError, match="extensions length found 2"):
            extract_pck_extensions(pki.load(without_sgx.der))

    def test_requires_the_sgx_extension(self) -> None:
        from cryptography import x509

        cert = tb.pck_certificate(PLATFORM_CA)
        loaded = pki.load(cert.der)
        extras: list[tuple[x509.ExtensionType, bool]] = [
            (loaded.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value, False),
            (loaded.extensions.get_extension_for_class(x509.CRLDistributionPoints).value, False),
            (loaded.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value, False),
            (x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.840.113741.1.13.2"), b"\x04\x00"), False),
        ]
        six = pki.certificate(tb.PCK_CN, pki.p256(), PLATFORM_CA, key_usage=pki.SIGNING_USAGE, extra=extras)
        with pytest.raises(PckExtensionError, match="could not find SGX extension"):
            extract_pck_extensions(pki.load(six.der))

    def test_requires_four_attributes(self) -> None:
        three = tb.sequence(
            tb.attribute(f"{SGX}.1", tb.octet_string(tb.PPID)),
            tb.attribute(f"{SGX}.3", tb.octet_string(bytes(2))),
            tb.attribute(f"{SGX}.4", tb.octet_string(bytes(6))),
        )
        with pytest.raises(PckExtensionError, match="minimum length of 4"):
            parse(three)

    def test_absent_attributes_keep_zero_values(self) -> None:
        unknown = tuple(tb.attribute(f"{SGX}.{i}", tb.octet_string(b"x")) for i in (7, 8, 9, 10))
        ext = parse(tb.sequence(*unknown))
        assert ext == PckExtensions()
        assert ext.tcb.cpu_svn_components == b""

    def test_value_must_be_a_sequence(self) -> None:
        with pytest.raises(PckExtensionError, match="must be a SEQUENCE"):
            parse(tb.octet_string(b"\x00" * 8))
        with pytest.raises(PckExtensionError, match="could not parse SGX extension"):
            parse(tb.sgx_extension() + b"\x00")

    def test_attribute_pair_shape(self) -> None:
        with pytest.raises(PckExtensionError, match="must hold an OID and a value"):
            parse(tb.sequence(tb.sequence(tb.oid(f"{SGX}.1")), *[tb.attribute(f"{SGX}.9", tb.octet_string(b""))] * 3))
        # Elements after the value are tolerated.
        longer = tb.sequence(
            tb.sequence(tb.oid(f"{SGX}.1"), tb.octet_string(tb.PPID), tb.octet_string(b"extra")),
            tb.tcb_attribute(),
            tb.attribute(f"{SGX}.3", tb.octet_string(bytes(2))),
            tb.attribute(f"{SGX}.4", tb.octet_string(bytes(6))),
        )
        assert parse(longer).ppid == tb.PPID.hex()

    def test_octet_string_sizes(self) -> None:
        with pytest.raises(PckExtensionError, match="PPID"):
            parse(tb.sgx_extension(ppid=bytes(15)))
        with pytest.raises(PckExtensionError, match="FMSPC"):
            parse(tb.sgx_extension(fmspc="50806f0000"))
        with pytest.raises(PckExtensionError, match="PCEID"):
            parse(tb.sgx_extension(pceid="000000"))

    def test_nested_octet_string_is_unwrapped(self) -> None:
        nested = tb.sequence(
            tb.attribute(f"{SGX}.1", tb.octet_string(tb.octet_string(tb.PPID))),
            tb.tcb_attribute(),
            tb.attribute(f"{SGX}.3", tb.octet_string(bytes(2))),
            tb.attribute(f"{SGX}.4", tb.octet_string(bytes(6))),
        )
        assert parse(nested).ppid == tb.PPID.hex()
        wrong = tb.sequence(
            tb.attribute(f"{SGX}.1", tb.octet_string(tb.integer(1) + bytes(12))),
            tb.tcb_attribute(),
            tb.attribute(f"{SGX}.3", tb.octet_string(bytes(2))),
            tb.attribute(f"{SGX}.4", tb.octet_string(bytes(6))),
        )
        with pytest.raises(PckExtensionError, match="could not parse PPID extension as an octet string"):
            parse(wrong)

    def test_octet_string_attribute_with_critical_flag(self) -> None:
        flagged = tb.sequence(
            tb.sequence(tb.oid(f"{SGX}.1"), tb.tlv(0x01, b"\xff"), tb.octet_string(tb.PPID)),
            tb.tcb_attribute(),
            tb.attribute(f"{SGX}.3", tb.octet_string(bytes(2))),
            tb.attribute(f"{SGX}.4", tb.octet_string(bytes(6))),
        )
        assert parse(flagged).ppid == tb.PPID.hex()

    def test_octet_string_attribute_value_type(self) -> None:
        with pytest.raises(PckExtensionError, match="PPID attribute value is not an OCTET STRING"):
            parse(tb.sgx_extension(ppid=tb.PPID).replace(tb.octet_string(tb.PPID), tb.tlv(0x0C, tb.PPID)))

    def test_tcb_shape(self) -> None:
        with pytest.raises(PckExtensionError, match="of size 3, expected 2"):
            parse(tb.sgx_extension(tcb=tb.sequence(tb.oid(f"{SGX}.2"), tb.sequence(), tb.sequence())))
        entries = tb.tcb_attribute()
        short = tb.sequence(
            tb.oid(f"{SGX}.2"), tb.sequence(*[tb.attribute(f"{SGX}.2.{i + 1}", tb.integer(0)) for i in range(17)])
        )
        with pytest.raises(PckExtensionError, match="TCB extension is of size 17, expected 18"):
            parse(tb.sgx_extension(tcb=short))
        assert entries

    def test_tcb_values(self) -> None:
        components = bytes(range(16))
        ext = parse(tb.sgx_extension(tcb=tb.tcb_attribute(components=components, pce_svn=65535, cpu_svn=bytes(16))))
        assert ext.tcb == PckCertTCB(pce_svn=65535, cpu_svn=bytes(16), cpu_svn_components=components)

    def test_tcb_component_ranges(self) -> None:
        pairs = [tb.attribute(f"{SGX}.2.{i + 1}", tb.integer(0)) for i in range(16)]
        pairs[3] = tb.attribute(f"{SGX}.2.4", tb.integer(256))
        tcb = tb.sequence(
            tb.oid(f"{SGX}.2"),
            tb.sequence(
                *pairs,
                tb.attribute(f"{SGX}.2.17", tb.integer(0)),
                tb.attribute(f"{SGX}.2.18", tb.octet_string(bytes(16))),
            ),
        )
        with pytest.raises(PckExtensionError, match="sgxTcbComponent4 is out of range: 256"):
            parse(tb.sgx_extension(tcb=tcb))
        with pytest.raises(PckExtensionError, match="PCESvn is out of range"):
            parse(tb.sgx_extension(tcb=tb.tcb_attribute(pce_svn=65536)))
        with pytest.raises(PckExtensionError, match="not an INTEGER"):
            parse(tb.sgx_extension(tcb=tb.tcb_attribute(pce_svn=1).replace(tb.integer(1), tb.octet_string(b"\x01"))))

    def test_cpu_svn_shape(self) -> None:
        with pytest.raises(PckExtensionError, match="CPUSVN component in TCB extension is of size 15"):
            parse(tb.sgx_extension(tcb=tb.tcb_attribute(cpu_svn=bytes(15))))
        wrong_type = tb.tcb_attribute(cpu_svn=bytes(16)).replace(
            tb.octet_string(bytes(16)), tb.tlv(0x03, b"\x00" + bytes(15))
        )
        with pytest.raises(PckExtensionError, match="not an OCTET STRING"):
            parse(tb.sgx_extension(tcb=wrong_type))

    def test_unknown_tcb_entries_are_ignored_and_missing_ones_are_zero(self) -> None:
        pairs = [tb.attribute(f"{SGX}.2.{i + 1}", tb.integer(7)) for i in range(15)]
        pairs.append(tb.attribute(f"{SGX}.2.99", tb.octet_string(b"?")))
        pairs.append(tb.attribute(f"{SGX}.2.17", tb.integer(3)))
        pairs.append(tb.attribute(f"{SGX}.2.18", tb.octet_string(bytes(16))))
        ext = parse(tb.sgx_extension(tcb=tb.sequence(tb.oid(f"{SGX}.2"), tb.sequence(*pairs))))
        assert ext.tcb.cpu_svn_components == bytes([7] * 15 + [0])
        assert ext.tcb.pce_svn == 3

    def test_absent_tcb_components_leave_the_components_empty(self) -> None:
        pairs = [tb.attribute(f"{SGX}.2.99", tb.integer(i)) for i in range(18)]
        ext = parse(tb.sgx_extension(tcb=tb.sequence(tb.oid(f"{SGX}.2"), tb.sequence(*pairs))))
        assert ext.tcb == PckCertTCB(pce_svn=0, cpu_svn=b"", cpu_svn_components=bytes(16))

    def test_nested_encodings_are_validated(self) -> None:
        non_minimal = tb.sgx_extension(extra=(tb.attribute(f"{SGX}.9", tb.tlv(0x02, b"\x00\x01")),))
        with pytest.raises(PckExtensionError, match="could not parse SGX extension"):
            parse(non_minimal)
