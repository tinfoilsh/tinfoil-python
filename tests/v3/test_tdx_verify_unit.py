"""Unit tests for the tricky DCAP internals: raw r||s ECDSA verification and
attestation-key point validation (der.py), TCB level matching including the
versioned-module skip-2 rule (verify.py), and the exact raw-member JSON
extraction the Intel signature covers (pcs.py)."""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization

from tinfoil.v3.tdx.der import ecdsa_p256_public_key, verify_raw_signature
from tinfoil.v3.tdx.pcs import (
    Tcb,
    TcbComponent,
    TcbLevel,
    TdxModuleIdentity,
    raw_top_level_member,
)
from tinfoil.v3.tdx.quote import TDQuoteBody
from tinfoil.v3.tdx.verify import (
    _check_qe_tcb_status,
    _get_matching_tcb_level,
    _get_matching_tdx_module_tcb_level,
    _is_tdx_tcb_svn_higher_or_equal,
)


# --- DER <-> raw r||s and point validation ------------------------------------


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, spki


def _sign_raw(priv, message: bytes) -> bytes:
    der = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_raw_signature_roundtrip():
    priv, spki = _keypair()
    msg = b"header and body bytes"
    sig = _sign_raw(priv, msg)
    assert verify_raw_signature(msg, sig, spki)
    assert not verify_raw_signature(msg + b"x", sig, spki)


def test_raw_signature_bitflip_rejects():
    priv, spki = _keypair()
    msg = b"m"
    sig = bytearray(_sign_raw(priv, msg))
    sig[10] ^= 0xFF
    assert not verify_raw_signature(msg, bytes(sig), spki)


def test_raw_signature_wrong_length_rejects():
    priv, spki = _keypair()
    sig = _sign_raw(priv, b"m")
    assert not verify_raw_signature(b"m", sig[:63], spki)
    assert not verify_raw_signature(b"m", sig + b"\x00", spki)


def test_raw_signature_zero_rs_rejects():
    _, spki = _keypair()
    assert not verify_raw_signature(b"m", bytes(64), spki)


def test_attestation_key_roundtrip():
    priv, spki = _keypair()
    nums = priv.public_key().public_numbers()
    xy = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    assert ecdsa_p256_public_key(xy) == spki


def test_attestation_key_not_on_curve_rejects():
    with pytest.raises(ValueError):
        ecdsa_p256_public_key(b"\x01" * 64)


def test_attestation_key_wrong_size_rejects():
    with pytest.raises(ValueError, match="unexpected size"):
        ecdsa_p256_public_key(b"\x01" * 63)


# --- TCB level matching ---------------------------------------------------------


def _components(svns: list[int]) -> list[TcbComponent]:
    return [TcbComponent(svn=s, category="", type="") for s in svns]


def _level(sgx=None, pcesvn=0, tdx=None, isvsvn=0, status="UpToDate") -> TcbLevel:
    return TcbLevel(
        tcb=Tcb(
            sgx_tcbcomponents=_components(sgx if sgx is not None else [0] * 16),
            pcesvn=pcesvn,
            tdx_tcbcomponents=_components(tdx if tdx is not None else [0] * 16),
            isvsvn=isvsvn,
        ),
        tcb_date="",
        tcb_status=status,
    )


def _td_body(tee_tcb_svn: bytes) -> TDQuoteBody:
    z48 = bytes(48)
    return TDQuoteBody(
        tee_tcb_svn=tee_tcb_svn,
        mr_seam=z48,
        mr_signer_seam=z48,
        seam_attributes=bytes(8),
        td_attributes=bytes(8),
        xfam=bytes(8),
        mr_td=z48,
        mr_config_id=z48,
        mr_owner=z48,
        mr_owner_config=z48,
        rtmrs=[z48] * 4,
        report_data=bytes(64),
    )


def test_tdx_svn_versioned_module_skips_first_two_bytes():
    # byte[1] > 0: bytes 0 and 1 are excluded from the component comparison.
    svn = b"\x00\x03\x05" + b"\x00" * 13
    comps = [99, 99, 5] + [0] * 13  # would fail bytes 0-1 if compared
    assert _is_tdx_tcb_svn_higher_or_equal(svn, _components(comps))
    comps_high = [0, 0, 6] + [0] * 13
    assert not _is_tdx_tcb_svn_higher_or_equal(svn, _components(comps_high))


def test_tdx_svn_unversioned_module_compares_all_bytes():
    svn = b"\x01\x00" + b"\x00" * 14
    assert not _is_tdx_tcb_svn_higher_or_equal(svn, _components([2] + [0] * 15))
    assert _is_tdx_tcb_svn_higher_or_equal(svn, _components([1] + [0] * 15))


def test_tdx_svn_length_mismatch_is_false():
    assert not _is_tdx_tcb_svn_higher_or_equal(b"\x00" * 16, _components([0] * 15))


def test_get_matching_tcb_level_first_match_wins_and_pcesvn_floors():
    body = _td_body(b"\x00\x03\x05" + b"\x00" * 13)
    cpu_svn = bytes([5] * 4 + [0] * 12)
    high = _level(sgx=[6] * 4 + [0] * 12, pcesvn=10, tdx=[0, 0, 5] + [0] * 13, status="UpToDate")
    match = _level(sgx=[5] * 4 + [0] * 12, pcesvn=11, tdx=[0, 0, 5] + [0] * 13, status="OutOfDate")
    got = _get_matching_tcb_level([high, match], body, 11, cpu_svn)
    assert got is match  # cpu svn too low for `high`, pcesvn 11 >= 11 for `match`
    with pytest.raises(ValueError, match="no matching TCB level found"):
        _get_matching_tcb_level([high, match], body, 10, cpu_svn)  # pcesvn below both


def test_module_identity_matching_by_id_and_isvsvn():
    identities = [
        TdxModuleIdentity(
            id="TDX_03",
            mrsigner=b"",
            attributes=b"",
            attributes_mask=b"",
            tcb_levels=[_level(isvsvn=5, status="OutOfDate"), _level(isvsvn=0, status="UpToDate")],
        )
    ]
    # tee_tcb_svn[1] = 3 selects TDX_03; isvsvn = byte[0].
    got = _get_matching_tdx_module_tcb_level(identities, b"\x07\x03" + b"\x00" * 14)
    assert got.tcb_status == "OutOfDate"  # first level with isvsvn 5 <= 7
    got = _get_matching_tdx_module_tcb_level(identities, b"\x02\x03" + b"\x00" * 14)
    assert got.tcb_status == "UpToDate"  # falls through to isvsvn 0
    with pytest.raises(ValueError, match="TDX Module Identity TCB Level"):
        _get_matching_tdx_module_tcb_level(
            [
                TdxModuleIdentity(
                    id="TDX_03",
                    mrsigner=b"",
                    attributes=b"",
                    attributes_mask=b"",
                    tcb_levels=[_level(isvsvn=9)],
                )
            ],
            b"\x02\x03" + b"\x00" * 14,
        )
    with pytest.raises(ValueError, match="could not find a TDX Module Identity "):
        _get_matching_tdx_module_tcb_level(identities, b"\x00\x04" + b"\x00" * 14)


def test_check_qe_tcb_status():
    levels = [_level(isvsvn=8, status="UpToDate"), _level(isvsvn=0, status="OutOfDate")]
    _check_qe_tcb_status(levels, 8)  # matches first, UpToDate
    with pytest.raises(ValueError, match='TCB Status is not "UpToDate"'):
        _check_qe_tcb_status(levels, 7)  # falls to the OutOfDate level
    with pytest.raises(ValueError, match="OutOfDate"):
        _check_qe_tcb_status([_level(isvsvn=9, status="UpToDate")], 8)  # nothing <= 8


# --- exact raw member extraction -------------------------------------------------


def test_raw_top_level_member_exact_bytes():
    body = b'{"tcbInfo": {"a": 1, "s": "x\\"y"} , "signature":"ab"}'
    assert raw_top_level_member(body, "tcbInfo") == b'{"a": 1, "s": "x\\"y"}'
    assert raw_top_level_member(body, "signature") == b'"ab"'
    assert raw_top_level_member(body, "missing") is None


def test_raw_top_level_member_last_duplicate_wins():
    body = b'{"k": 1, "k": {"x":[1,2]}}'
    assert raw_top_level_member(body, "k") == b'{"x":[1,2]}'


def test_raw_top_level_member_rejects_non_object():
    with pytest.raises(ValueError):
        raw_top_level_member(b"[1,2]", "k")
