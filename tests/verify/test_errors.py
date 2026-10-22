import pickle

import pytest

from tinfoil.verify import Error, Layer, UsageError, VerificationError
from tinfoil.verify._errors import as_rejection, as_usage_error, prefixed


def test_verification_error_names_its_layer():
    err = VerificationError(Layer.QUOTE, "report signature is invalid")
    assert str(err) == "verification error: quote: report signature is invalid"
    assert err.layer is Layer.QUOTE
    assert isinstance(err, Error)


def test_usage_error_message():
    err = UsageError("expected nonce must be 32 bytes, got 31")
    assert str(err) == "usage error: expected nonce must be 32 bytes, got 31"
    assert isinstance(err, Error)
    assert not isinstance(err, VerificationError)


def test_layers_are_lowercase_words():
    # The gomobile bridge parses "verification error: <layer>: <detail>", so a
    # layer value must be one lowercase word without a colon.
    assert [str(layer) for layer in Layer] == ["envelope", "provenance", "quote", "policy"]
    assert Layer("policy") is Layer.POLICY


@pytest.mark.parametrize("err", [UsageError("bad nonce"), VerificationError(Layer.ENVELOPE, "bad hash")])
def test_errors_survive_pickling(err):
    restored = pickle.loads(pickle.dumps(err))
    assert type(restored) is type(err)
    assert str(restored) == str(err)


def test_as_rejection_assigns_the_layer_and_keeps_the_cause():
    cause = ValueError("nonce mismatch")
    with pytest.raises(VerificationError) as caught:
        with as_rejection(Layer.ENVELOPE):
            raise cause
    assert caught.value.layer is Layer.ENVELOPE
    assert caught.value.__cause__ is cause
    assert str(caught.value) == "verification error: envelope: nonce mismatch"


@pytest.mark.parametrize(
    "err",
    [UsageError("caller mistake"), VerificationError(Layer.PROVENANCE, "authorizer"), NotImplementedError()],
)
@pytest.mark.parametrize("context", [lambda: as_rejection(Layer.POLICY), as_usage_error, lambda: prefixed("step")])
def test_classified_and_unimplemented_errors_pass_through(context, err):
    with pytest.raises(type(err)) as caught:
        with context():
            raise err
    assert caught.value is err


def test_as_usage_error_wraps_other_errors():
    with pytest.raises(UsageError) as caught:
        with as_usage_error():
            raise ValueError("invalid release reference")
    assert str(caught.value) == "usage error: invalid release reference"
    assert isinstance(caught.value.__cause__, ValueError)


def test_prefixed_adds_context():
    with pytest.raises(ValueError, match="^verifying code freshness: witness is stale$"):
        with prefixed("verifying code freshness"):
            raise RuntimeError("witness is stale")
