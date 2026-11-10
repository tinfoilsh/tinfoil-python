"""TDX module identity matching against synthetic TEE_TCB_SVN values."""

from __future__ import annotations

import pytest

from tinfoil._v3.verifier._quote.tdx.lib.collateral import (
    CollateralError,
    Tcb,
    TcbLevel,
    TcbStatus,
    TdxModuleIdentity,
    get_matching_tdx_module_tcb_level,
)


def identity(module_id: str, isv_svn: int = 3, status: TcbStatus | None = TcbStatus.UP_TO_DATE) -> TdxModuleIdentity:
    return TdxModuleIdentity(
        id=module_id,
        mrsigner=bytes(48),
        attributes=bytes(8),
        attributes_mask=bytes([0xFF]) * 8,
        tcb_levels=(TcbLevel(tcb=Tcb(isv_svn=isv_svn), tcb_status=status),),
    )


def svn(minor: int, major: int) -> bytes:
    """TEE_TCB_SVN: byte 0 is the module's ISV SVN, byte 1 its major version; the rest are other components."""
    return bytes([minor, major]) + bytes(14)


class TestModuleIdentityMatching:
    def test_major_version_selects_the_identity_in_hex(self) -> None:
        identities = (identity("TDX_01"), identity("TDX_03"), identity("TDX_0a"))
        assert get_matching_tdx_module_tcb_level(identities, svn(3, 3)) == identities[1].tcb_levels[0]
        assert get_matching_tdx_module_tcb_level(identities, svn(3, 1)) == identities[0].tcb_levels[0]
        assert get_matching_tdx_module_tcb_level(identities, svn(3, 10)) == identities[2].tcb_levels[0]
        assert get_matching_tdx_module_tcb_level((identity("TDX_ff"),), svn(3, 255)) is not None

    def test_decimal_ids_do_not_match(self) -> None:
        with pytest.raises(CollateralError, match="could not find a TDX Module Identity \\('TDX_0a'\\)"):
            get_matching_tdx_module_tcb_level((identity("TDX_10"),), svn(3, 10))

    def test_unknown_major_version(self) -> None:
        with pytest.raises(CollateralError, match="'TDX_02'"):
            get_matching_tdx_module_tcb_level((identity("TDX_01"), identity("TDX_03")), svn(3, 2))
        with pytest.raises(CollateralError, match="'TDX_03'"):
            get_matching_tdx_module_tcb_level((), svn(3, 3))

    def test_minor_version_selects_the_first_reachable_level(self) -> None:
        levels = (
            TcbLevel(tcb=Tcb(isv_svn=5), tcb_status=TcbStatus.UP_TO_DATE),
            TcbLevel(tcb=Tcb(isv_svn=3), tcb_status=TcbStatus.OUT_OF_DATE),
        )
        module = TdxModuleIdentity(id="TDX_03", tcb_levels=levels)
        assert get_matching_tdx_module_tcb_level((module,), svn(5, 3)) == levels[0]
        assert get_matching_tdx_module_tcb_level((module,), svn(9, 3)) == levels[0]
        assert get_matching_tdx_module_tcb_level((module,), svn(4, 3)) == levels[1]
        with pytest.raises(CollateralError, match="TCB Level matching the TDX Module's ISVSVN \\(2\\)"):
            get_matching_tdx_module_tcb_level((module,), svn(2, 3))

    def test_first_identity_with_the_id_decides(self) -> None:
        """A second identity with the same id is never consulted, even when the first has no reachable level."""
        identities = (identity("TDX_03", isv_svn=5), identity("TDX_03", isv_svn=0))
        with pytest.raises(CollateralError, match="ISVSVN \\(1\\)"):
            get_matching_tdx_module_tcb_level(identities, svn(1, 3))

    def test_tee_tcb_svn_too_short_for_a_module_version_rejects(self) -> None:
        """A one-byte value would otherwise name the module ``TDX_`` from its missing second byte, and an empty one
        has no ISV SVN at all; neither may select a level."""
        identities = (identity("TDX_"), identity("TDX_03"))
        for short in (b"", b"\x03"):
            with pytest.raises(CollateralError, match=r"TEE TCB SVN of [01] bytes is too short to name a TDX module"):
                get_matching_tdx_module_tcb_level(identities, short)
        assert get_matching_tdx_module_tcb_level(identities, bytes([3, 3])) == identities[1].tcb_levels[0]

    def test_returns_the_level_with_its_status(self) -> None:
        level = get_matching_tdx_module_tcb_level((identity("TDX_03", status=TcbStatus.OUT_OF_DATE),), svn(3, 3))
        assert level.tcb_status == TcbStatus.OUT_OF_DATE
        level = get_matching_tdx_module_tcb_level((identity("TDX_03", status=None),), svn(3, 3))
        assert level.tcb_status is None
