import pytest

from tinfoil.verifier._measurement import (
    REGISTER_SIZE,
    SEVSNP,
    TDX,
    ExpectedSEVSNP,
    ExpectedTDX,
    parse_expected_sevsnp,
    parse_expected_tdx,
    parse_register,
)


def register(first: int, *rest: int) -> bytes:
    value = bytes([first, *rest])
    return value + bytes(REGISTER_SIZE - len(value))


def test_parse_register_accepts_either_case() -> None:
    want = register(0xAB, 0xCD)
    lower = "abcd" + "00" * (REGISTER_SIZE - 2)
    for text in (lower, lower.upper()):
        assert parse_register(text) == want
    assert want.hex() == lower, "the text form is lowercase"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("zz" * REGISTER_SIZE, "not hex"),
        ("ab" * (REGISTER_SIZE - 1), "96 hex characters"),
        ("ab" * (REGISTER_SIZE + 1), "96 hex characters"),
        # The length is checked before decoding.
        ("zz" * (REGISTER_SIZE + 1), "96 hex characters"),
        ("", "96 hex characters"),
    ],
)
def test_parse_register_rejects(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_register(text)


def test_parse_expected() -> None:
    tdx = TDX(mrtd=register(1), rtmr0=register(2), rtmr1=register(3), rtmr2=register(4), rtmr3=register(5))
    every = parse_expected_tdx(tdx.mrtd.hex(), tdx.rtmr0.hex(), tdx.rtmr1.hex(), tdx.rtmr2.hex(), tdx.rtmr3.hex())
    assert every == tdx.expected(), "arguments are in register order"
    sparse = parse_expected_tdx("", "", "", "", tdx.rtmr3.hex().upper())
    assert sparse == ExpectedTDX(rtmr3=tdx.rtmr3), '"" leaves a register unconstrained'

    sev = SEVSNP(launch=register(1))
    assert parse_expected_sevsnp(sev.launch.hex()) == sev.expected()
    assert parse_expected_sevsnp("") == ExpectedSEVSNP()

    with pytest.raises(ValueError, match="rtmr2: register must be 96 hex characters"):
        parse_expected_tdx("", "", "", "abcd", "")
    with pytest.raises(ValueError, match="launch: register is not hex"):
        parse_expected_sevsnp("zz" * REGISTER_SIZE)


def test_expected_pins_every_register() -> None:
    tdx = TDX(mrtd=register(1), rtmr0=register(2), rtmr1=register(3), rtmr2=register(4), rtmr3=register(5))
    assert tdx.expected() == ExpectedTDX(
        mrtd=tdx.mrtd, rtmr0=tdx.rtmr0, rtmr1=tdx.rtmr1, rtmr2=tdx.rtmr2, rtmr3=tdx.rtmr3
    )
    sev = SEVSNP(launch=register(1))
    assert sev.expected() == ExpectedSEVSNP(launch=sev.launch)


def test_str() -> None:
    value = register(0xAB)
    assert str(SEVSNP(launch=value)) == "SEV-SNP\nlaunch " + value.hex()
    assert (
        str(ExpectedTDX(rtmr1=value))
        == "TDX\nmrtd   any\nrtmr0  any\nrtmr1  " + value.hex() + "\nrtmr2  any\nrtmr3  any"
    )


def test_registers_must_be_the_register_size() -> None:
    with pytest.raises(ValueError, match="launch: register must be 48 bytes, got 2"):
        SEVSNP(launch=b"\xab\xcd")
    with pytest.raises(ValueError, match="rtmr3: register must be 48 bytes, got 0"):
        ExpectedTDX(rtmr3=b"")
    with pytest.raises(ValueError, match="mrtd: register must be 48 bytes, got 49"):
        TDX(mrtd=bytes(49), rtmr0=register(0), rtmr1=register(0), rtmr2=register(0), rtmr3=register(0))


def test_registers_must_be_bytes() -> None:
    """A register of another type is a ValueError naming the type, never a TypeError from measuring its length."""
    with pytest.raises(ValueError, match="launch: register must be bytes, not str"):
        SEVSNP(launch="ab" * REGISTER_SIZE)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="rtmr0: register must be bytes, not int"):
        ExpectedTDX(rtmr0=0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="mrtd: register must be bytes, not bytearray"):
        ExpectedTDX(mrtd=bytearray(REGISTER_SIZE))  # type: ignore[arg-type]


def test_parse_register_rejects_whitespace_and_prefixes() -> None:
    body = "ab" * (REGISTER_SIZE - 1)
    for text in (" " + body + " ", body + "\n0", "0x" + body):
        assert len(text) == 2 * REGISTER_SIZE
        with pytest.raises(ValueError, match="not hex"):
            parse_register(text)


def test_measurements_require_every_register() -> None:
    with pytest.raises(ValueError, match="launch: register is required"):
        SEVSNP(launch=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="rtmr1: register is required"):
        TDX(mrtd=register(0), rtmr0=register(0), rtmr1=None, rtmr2=register(0), rtmr3=register(0))  # type: ignore[arg-type]
    assert ExpectedSEVSNP(launch=None).launch is None
