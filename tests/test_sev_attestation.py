import pytest
from tinfoil.attestation.attestation import verify_attestation_json, PredicateType


def test_sev_verify():
    cases = [
        {
            "attestation": '{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v2","body":"H4sIAAAAAAAA/2JmgAEEixBgZGBg4AKzxEPU0eQETrU6V/UVB3t6X/nzPHnDqkuB7Ge7tj5ZEHio29Wfkc1uX9Sclq9brfxurj5f8/1vsLnEKWGd+VvbrZlW1uopNP7g1X277qF1y53Evj/F31o35j7JULPg0r0S+zF28d3utXtmKJ26X/2ndOpEHVfxXfmrpYMOEO1oGgGNBec2/VR6lX2Gl0OiQHRZX6rfLIn+iuYbKf+jFB4bqZ34TwDAwlFSkBGr+VIfV+XIhzFXsbbMitzRGPOTM8J+9sr3+qxGEkfMP1svbH7yRHSD5eb6JlZVrovx3R0LFq+9+eVA44HyWR5vlUTM+1xg5muYMzKAMIxPxyCiCHQ6e7XWK8xY82mR/JozTx04Vy5l8FSb5PHojvm2wD2bL32f4PhFweCczqKfEgb9gr/XG+Iy57HDxR1FBzhUzT5FZUW/TOHzX/fB7uei0kcHzO5v62TjbzG4Zxh1YsrdgwmpTrsN8vatoq8vRwEuAAgAAP//tiY3daAEAAA="}',
            "expected_format": PredicateType.SEV_GUEST_V2,
            "expected_tls_public_key": "10ca85437a8e7353494bd4fce763b0aad25107cd8ab5e4a051c28b454f01063e",
            "expected_hpke_public_key": "be5a9c84f5b53a4ed9abcf7cf7fd533718ca132c9fb5873b02a97d2e2081f80d",
            "expected_measurement_registers": [
                "2dedaee13b84dc618efc73f685b16de46826380a2dd45df15da3dd8badbc9822cadf7bfc7595912c4517ba6fab1b52c0"
            ],
        },
    ]

    for case in cases:
        verification = verify_attestation_json(case["attestation"])
        assert case["expected_format"] == verification.measurement.type
        assert case["expected_tls_public_key"] == verification.public_key_fp
        assert case["expected_hpke_public_key"] == verification.hpke_public_key
        assert case["expected_measurement_registers"] == verification.measurement.registers


if __name__ == "__main__":
    pytest.main()
