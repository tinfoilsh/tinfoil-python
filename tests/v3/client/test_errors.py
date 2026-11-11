"""The client's error hierarchy: three categories under one base, the message prefix, the cause chain and the
helper that finds a client error behind a library's."""

from __future__ import annotations

import httpx
import httpx2
import openai
import pytest

from tinfoil._v3._errors import (
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
from tinfoil._v3.verifier import LAYER_POLICY, UsageError, VerificationError


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
    assert str(err) == f"{category} error: timed out"
    for other in (ConfigurationError, NetworkError, AttestationError):
        assert isinstance(err, other) == (other is cls), "an error has one category"
    assert err.__cause__ is cause
    assert not isinstance(err, httpx.HTTPError), "client errors are not the HTTP stack's own transport errors"


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
