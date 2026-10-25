import hashlib

import pytest

from tinfoil.v3.measurement import (
    RTMR3_ZERO,
    SEV_GUEST_V2,
    SNP_TDX_MULTI_PLATFORM_V1,
    TDX_GUEST_V2,
    HardwareMeasurement,
    Measurement,
    fingerprint,
)


def test_sev_single_register_returned_directly():
    m = Measurement(type=SEV_GUEST_V2, registers=["aa" * 48])
    assert fingerprint(m, None, SEV_GUEST_V2) == "aa" * 48


def test_multiplatform_to_sev():
    m = Measurement(type=SNP_TDX_MULTI_PLATFORM_V1, registers=["s0", "r1", "r2"])
    assert fingerprint(m, None, SEV_GUEST_V2) == "s0"


def test_multiplatform_to_tdx_requires_hardware():
    m = Measurement(type=SNP_TDX_MULTI_PLATFORM_V1, registers=["s0", "r1", "r2"])
    with pytest.raises(ValueError, match="hardware measurement required"):
        fingerprint(m, None, TDX_GUEST_V2)
    hw = HardwareMeasurement(id="p@d", mrtd="mm", rtmr0="rr")
    want = hashlib.sha256(
        (SNP_TDX_MULTI_PLATFORM_V1 + "mm" + "rr" + "r1" + "r2" + RTMR3_ZERO).encode()
    ).hexdigest()
    assert fingerprint(m, hw, TDX_GUEST_V2) == want


def test_tdx_runtime_hashes_five_registers():
    regs = ["a", "b", "c", "d", "e"]
    m = Measurement(type=TDX_GUEST_V2, registers=regs)
    want = hashlib.sha256((TDX_GUEST_V2 + "abcde").encode()).hexdigest()
    assert fingerprint(m, None, TDX_GUEST_V2) == want


def test_unsupported_types_reject():
    m = Measurement(type="x", registers=["a"])
    with pytest.raises(ValueError, match="unsupported measurement type"):
        fingerprint(m, None, SEV_GUEST_V2)
    mp = Measurement(type=SNP_TDX_MULTI_PLATFORM_V1, registers=["a", "b", "c"])
    with pytest.raises(ValueError, match="unsupported target type"):
        fingerprint(mp, None, SNP_TDX_MULTI_PLATFORM_V1)
