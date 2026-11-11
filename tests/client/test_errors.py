"""The client's error hierarchy: three categories under one abstract base, the bare message that pickles, the
cause chain and the helper that finds a client error behind a caller's own."""

from __future__ import annotations

import pickle

import httpx
import httpx2
import openai
import pytest

from tinfoil._errors import (
    AttestationError,
    ConfigurationError,
    NetworkError,
    TinfoilError,
    attestation_error,
    configuration_error,
    from_verify,
    network_error,
    tinfoil_error,
    wrap_attestation,
    wrap_network,
)
from tinfoil.verifier import LAYER_POLICY, UsageError, VerificationError


@pytest.mark.parametrize(
    ("category", "cls"),
    [("configuration", ConfigurationError), ("network", NetworkError), ("attestation", AttestationError)],
)
def test_error_contract(category: str, cls: type[TinfoilError]) -> None:
    cause = httpx.ConnectTimeout("timed out")
    err = cls(str(cause))
    err.__cause__ = cause
    assert isinstance(err, TinfoilError)
    assert err.category == category
    assert err.message == "timed out"
    assert str(err) == "timed out", "the message carries no category prefix"
    assert err.args == ("timed out",)
    for other in (ConfigurationError, NetworkError, AttestationError):
        assert isinstance(err, other) == (other is cls), "an error has one category"
    assert err.__cause__ is cause
    assert not isinstance(err, httpx.HTTPError), "client errors are not the HTTP stack's own transport errors"


@pytest.mark.parametrize("cls", [ConfigurationError, NetworkError, AttestationError])
def test_errors_pickle_round_trip(cls: type[TinfoilError]) -> None:
    err = cls("what went wrong")
    restored = pickle.loads(pickle.dumps(err))
    assert type(restored) is cls
    assert restored.category == err.category
    assert restored.message == "what went wrong"
    assert str(restored) == "what went wrong"
    assert restored.args == err.args


def test_base_class_is_abstract() -> None:
    with pytest.raises(TypeError, match="abstract"):
        TinfoilError("x")
    assert not hasattr(TinfoilError, "category"), "the category belongs to the three subclasses"
    for cls in (ConfigurationError, NetworkError, AttestationError):
        assert isinstance(cls("x"), TinfoilError)


def test_wrap_keeps_classified_errors() -> None:
    cause = httpx.ConnectError("refused")
    for wrap, cls in ((wrap_network, NetworkError), (wrap_attestation, AttestationError)):
        wrapped = wrap(cause)
        assert isinstance(wrapped, cls)
        assert wrapped.__cause__ is cause
        for classified in (ConfigurationError("x"), network_error(cause), attestation_error("y")):
            assert wrap(classified) is classified, "do not reclassify or double-wrap client errors"
        outer = RuntimeError("context")
        outer.__cause__ = classified
        assert wrap(outer) is outer, "an error whose cause chain holds a client error keeps its category"


def test_from_verify_classifies_by_type() -> None:
    usage = UsageError("bad input")
    assert isinstance(from_verify(usage), ConfigurationError)
    assert from_verify(usage).__cause__ is usage
    rejected = VerificationError(LAYER_POLICY, "measurement mismatch")
    classified = from_verify(rejected)
    assert isinstance(classified, AttestationError)
    assert not isinstance(classified, ConfigurationError)
    assert classified.__cause__ is rejected
    assert "measurement mismatch" in str(classified)


def test_tinfoil_error_follows_the_cause_chain() -> None:
    inner = configuration_error("bad option")
    request = httpx2.Request("GET", "https://enclave.example")
    library = openai.APIConnectionError(request=request)
    library.__cause__ = inner
    assert tinfoil_error(library) is inner
    assert tinfoil_error(inner) is inner
    assert tinfoil_error(RuntimeError("unrelated")) is None
    looped = RuntimeError("a")
    looped.__context__ = looped
    assert tinfoil_error(looped) is None, "a cycle in the chain ends the search"
    assert (
        tinfoil_error(openai.RateLimitError("429", response=httpx2.Response(429, request=request), body=None)) is None
    )


def test_tinfoil_error_follows_the_chain_the_traceback_shows() -> None:
    """A caller's own exception raised while handling a client error points at it through ``__context__``, or
    through ``__cause__`` with ``from err``; ``from None`` hides it, as it does in the traceback."""
    failure = AttestationError("channel binding failed")

    def handle(suppress: bool) -> None:
        try:
            raise failure
        except AttestationError:
            if suppress:
                raise RuntimeError("handled") from None
            raise RuntimeError("handled")  # noqa: B904 - the implicit context is what the test exercises

    with pytest.raises(RuntimeError) as implicit:
        handle(False)
    assert implicit.value.__context__ is failure
    assert tinfoil_error(implicit.value) is failure, "an implicit context is the chain the traceback shows"
    with pytest.raises(RuntimeError) as suppressed:
        handle(True)
    assert suppressed.value.__context__ is failure
    assert tinfoil_error(suppressed.value) is None, "'from None' suppresses the context in the traceback and here"
    explicit = RuntimeError("wrapped")
    explicit.__cause__ = failure
    explicit.__context__ = ConfigurationError("not this one")
    explicit.__suppress_context__ = True
    assert tinfoil_error(explicit) is failure, "a cause is followed before a context"


def test_api_errors_are_not_client_errors() -> None:
    request = httpx2.Request("GET", "https://enclave.example")
    api_error = openai.RateLimitError("429", response=httpx2.Response(429, request=request), body=None)
    assert not isinstance(api_error, TinfoilError)

    def handled() -> bool:
        try:
            raise api_error
        except TinfoilError:  # pragma: no cover - the point is that this handler does not run
            return True
        except openai.RateLimitError:
            return False

    assert handled() is False, "a handler for client errors must not catch an API error"
