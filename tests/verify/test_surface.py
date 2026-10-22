"""The public surface applications program against (SDK_SURFACE_SPEC.md)."""

import importlib

import pytest

PUBLIC = {
    "tinfoil.verify": {
        "Error",
        "Layer",
        "UsageError",
        "VerificationError",
    },
    "tinfoil.verify.measurement": {"Measurement", "PredicateType"},
}


@pytest.mark.parametrize("module_name", sorted(PUBLIC))
def test_public_names(module_name):
    module = importlib.import_module(module_name)
    assert set(module.__all__) == PUBLIC[module_name]
    for name in module.__all__:
        assert hasattr(module, name), name
