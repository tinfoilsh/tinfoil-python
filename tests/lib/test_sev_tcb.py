"""The SEV-SNP TCB version: the two layouts, packing and unpacking, and the component-wise order."""

from __future__ import annotations

import pytest

from tinfoil.verifier._quote.sev.lib import tcb

TURIN_BOX2 = 0x5200000004010101


def test_layout_by_product_line() -> None:
    assert tcb.tcb_struct_version("Genoa") == tcb.TCB_STRUCT_VERSION_0
    assert tcb.tcb_struct_version("milan") == tcb.TCB_STRUCT_VERSION_0
    assert tcb.tcb_struct_version("Siena") == tcb.TCB_STRUCT_VERSION_0
    assert tcb.tcb_struct_version("TURIN") == tcb.TCB_STRUCT_VERSION_1
    with pytest.raises(tcb.TcbError, match="invalid product line 'Unknown'"):
        tcb.tcb_struct_version("Unknown")
    with pytest.raises(tcb.TcbError, match="invalid product line ''"):
        tcb.new_tcb_version_struct("", 0)


def test_version_0_unpacks_every_level() -> None:
    parts = tcb.new_tcb_version_struct("Genoa", 0x4814_0706_0504_0207).to_parts()
    assert parts == tcb.TCBParts(
        version=0, bl_spl=7, tee_spl=2, spl4=4, spl5=5, spl6=6, spl7=7, snp_spl=0x14, ucode_spl=0x48
    )
    assert parts.to_version_struct() == tcb.TCBVersionStruct(0, 0x4814_0706_0504_0207)
    assert str(parts) == "{BlSpl:7 TeeSpl:2 Spl4:4 Spl5:5 Spl6:6 Spl7:7 SnpSpl:20 UcodeSpl:72}"
    assert str(parts.to_version_struct()) == "Milan or Genoa TCB: 0x4814070605040207"


def test_version_1_unpacks_the_turin_levels() -> None:
    parts = tcb.new_tcb_version_struct("Turin", TURIN_BOX2).to_parts()
    assert parts == tcb.TCBParts(version=1, fmc_spl=1, bl_spl=1, tee_spl=1, snp_spl=4, ucode_spl=0x52)
    assert parts.to_version_struct().tcb == TURIN_BOX2
    assert str(parts) == "{FmcSpl:1 BlSpl:1 TeeSpl:1 SnpSpl:4 UcodeSpl:82}"
    assert str(parts.to_version_struct()) == "Turin TCB: 0x5200000004010101"
    with pytest.raises(tcb.TcbError, match="non-zero reserved bits in Turin TCB: 0x100000000"):
        tcb.new_tcb_version_struct("Turin", TURIN_BOX2 | (1 << 32)).to_parts()
    with pytest.raises(tcb.TcbError, match="unknown TCB version: 2"):
        tcb.TCBVersionStruct(2, 0).to_parts()
    assert str(tcb.TCBVersionStruct(2, 0)) == "Unknown TCB"


def test_packing_rejects_levels_outside_the_layout() -> None:
    with pytest.raises(tcb.TcbError, match=r"SnpSpl TCB part is 128\. Expect 0-127"):
        tcb.TCBParts(snp_spl=128).to_version_struct()
    assert tcb.TCBParts(ucode_spl=255).to_version_struct().tcb == 255 << 56
    with pytest.raises(tcb.TcbError, match=r"UcodeSpl TCB part is 256\. Expect 0-255"):
        tcb.TCBParts(ucode_spl=256).to_version_struct()
    with pytest.raises(tcb.TcbError, match=r"BlSpl TCB part is -1\. Expect 0-127"):
        tcb.TCBParts(bl_spl=-1).to_version_struct()
    with pytest.raises(tcb.TcbError, match=r"UcodeSpl TCB part is -1\. Expect 0-255"):
        tcb.TCBParts(version=1, ucode_spl=-1).to_version_struct()
    with pytest.raises(tcb.TcbError, match=r"FmcSpl TCB part is 128\. Expect 0-127"):
        tcb.TCBParts(version=1, fmc_spl=128).to_version_struct()
    with pytest.raises(tcb.TcbError, match="FmcSpl is not defined for TCB struct version 0"):
        tcb.TCBParts(fmc_spl=1).to_version_struct()
    with pytest.raises(tcb.TcbError, match="reserved Turin TCB components must be zero"):
        tcb.TCBParts(version=1, spl5=1).to_version_struct()
    with pytest.raises(tcb.TcbError, match="unsupported TCB struct version: 3"):
        tcb.TCBParts(version=3).to_version_struct()


def test_new_tcb_parts_tags_and_checks() -> None:
    parts = tcb.new_tcb_parts("Turin", tcb.TCBParts(fmc_spl=1, bl_spl=1, tee_spl=1, snp_spl=4, ucode_spl=82))
    assert parts.version == 1
    with pytest.raises(tcb.TcbError, match="FmcSpl is not defined"):
        tcb.new_tcb_parts("Genoa", tcb.TCBParts(fmc_spl=1))
    with pytest.raises(tcb.TcbError, match="invalid product line"):
        tcb.new_tcb_parts("Milano", tcb.TCBParts())


def test_component_wise_order() -> None:
    lower = tcb.TCBParts(bl_spl=1, snp_spl=2, ucode_spl=3)
    assert tcb.tcb_parts_le(lower, lower)
    assert tcb.tcb_parts_le(lower, tcb.TCBParts(bl_spl=1, snp_spl=3, ucode_spl=3))
    assert not tcb.tcb_parts_le(lower, tcb.TCBParts(bl_spl=0, snp_spl=9, ucode_spl=9))
    assert not tcb.tcb_parts_le(lower, tcb.TCBParts(version=1, bl_spl=1, snp_spl=2, ucode_spl=3))
    assert not tcb.tcb_parts_le(tcb.TCBParts(spl4=1), tcb.TCBParts())
    assert not tcb.tcb_parts_le(tcb.TCBParts(version=1, fmc_spl=1), tcb.TCBParts(version=1))
