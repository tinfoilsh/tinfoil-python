import dataclasses

import pytest

from tinfoil.verify.measurement import Measurement, PredicateType


def test_registers_are_copied_into_a_tuple():
    registers = ["aa", "bb"]
    measurement = Measurement(PredicateType.SNP_TDX_MULTIPLATFORM_V1, registers)
    registers[0] = "changed"
    assert measurement.registers == ("aa", "bb")


def test_measurement_is_immutable():
    measurement = Measurement(PredicateType.SEV_GUEST_V2, ["aa"])
    with pytest.raises(dataclasses.FrozenInstanceError):
        measurement.type = PredicateType.TDX_GUEST_V2  # type: ignore[misc]


def test_measurements_compare_by_value():
    assert Measurement(PredicateType.SEV_GUEST_V2, ["aa"]) == Measurement(PredicateType.SEV_GUEST_V2, ("aa",))
    assert Measurement(PredicateType.SEV_GUEST_V2, ["aa"]) == Measurement(str(PredicateType.SEV_GUEST_V2), ["aa"])


def test_str_labels_registers():
    measurement = Measurement(PredicateType.TDX_GUEST_V2, ["00", "01", "02", "03", "04"])
    assert str(measurement) == "\n".join(
        [
            "https://tinfoil.sh/predicate/tdx-guest/v2",
            "MRTD  00",
            "RTMR0 01",
            "RTMR1 02",
            "RTMR2 03",
            "RTMR3 04",
        ]
    )


def test_str_numbers_registers_of_unknown_types():
    assert str(Measurement("https://example.com/other", ["aa"])) == "https://example.com/other\n[0] aa"
