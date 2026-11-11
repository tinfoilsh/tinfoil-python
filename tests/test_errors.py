"""The error types: their messages, and that they survive copying and pickling."""

from __future__ import annotations

import copy
import pickle

import pytest

from tinfoil.verifier._errors import LAYER_QUOTE, UsageError, VerificationError, VerifyError


def test_verification_error_carries_its_layer_and_message() -> None:
    err = VerificationError(LAYER_QUOTE, "signature does not verify")
    assert err.layer == LAYER_QUOTE
    assert err.message == "signature does not verify"
    assert str(err) == "quote: signature does not verify"
    assert err.args == (LAYER_QUOTE, "signature does not verify")
    assert isinstance(err, VerifyError)


def test_usage_error_is_a_value_error_with_a_bare_message() -> None:
    err = UsageError("nonce must be 32 bytes")
    assert err.message == "nonce must be 32 bytes"
    assert str(err) == "nonce must be 32 bytes"
    assert isinstance(err, ValueError)
    assert isinstance(err, VerifyError)


@pytest.mark.parametrize(
    "err", [VerificationError(LAYER_QUOTE, "signature does not verify"), UsageError("nonce must be 32 bytes")]
)
def test_errors_survive_pickling_and_copying(err: VerifyError) -> None:
    # Exceptions are rebuilt from ``args``, so a round trip must give back the same type, attributes and text.
    for clone in (pickle.loads(pickle.dumps(err)), copy.copy(err), copy.deepcopy(err)):
        assert type(clone) is type(err)
        assert clone.args == err.args
        assert str(clone) == str(err)
        assert vars(clone) == vars(err)
