"""The client package's surface: every exported name is importable, ``__all__`` is pinned and sorted, nothing
private leaks, and the version comes from the installed package."""

from __future__ import annotations

import importlib

import openai

import tinfoil._v3 as surface
from tinfoil._sdkinfo import sdk_version

EXPECTED_ALL = (
    "DEFAULT_GATEWAY_URL",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TRANSPORT_MODE",
    "APIConnectionError",
    "APIError",
    "APIResponseValidationError",
    "APIStatusError",
    "APITimeoutError",
    "AsyncClient",
    "AsyncEnclaveHTTPClient",
    "AsyncEnclaveOpenAIClient",
    "AsyncGatewayHTTPClient",
    "AsyncGatewayOpenAIClient",
    "AsyncRouterHTTPClient",
    "AsyncRouterOpenAIClient",
    "AttestationError",
    "AuthenticationError",
    "BadRequestError",
    "Catalog",
    "CatalogEntry",
    "Client",
    "ConfigurationError",
    "ConflictError",
    "EnclaveHTTPClient",
    "EnclaveOpenAIClient",
    "GatewayHTTPClient",
    "GatewayOpenAIClient",
    "InternalServerError",
    "ModelPin",
    "NetworkError",
    "NotFoundError",
    "OpenAIError",
    "PermissionDeniedError",
    "RateLimitError",
    "ReplicaVerification",
    "RouterHTTPClient",
    "RouterOpenAIClient",
    "TimeoutTypes",
    "TinfoilError",
    "TransportMode",
    "UnprocessableEntityError",
    "VerificationCheck",
    "__version__",
    "create_async_client",
    "create_client",
    "fetch_catalog",
    "fetch_catalog_async",
    "tinfoil_error",
)

EXPERIMENTAL = {
    "DEFAULT_GATEWAY_URL",
    "AsyncGatewayHTTPClient",
    "AsyncGatewayOpenAIClient",
    "Catalog",
    "CatalogEntry",
    "GatewayHTTPClient",
    "GatewayOpenAIClient",
    "ModelPin",
    "ReplicaVerification",
    "fetch_catalog",
    "fetch_catalog_async",
}


def test_all_is_pinned() -> None:
    assert tuple(surface.__all__) == EXPECTED_ALL


def test_every_name_is_importable_and_nothing_private_leaks() -> None:
    for name in surface.__all__:
        assert hasattr(surface, name), name
        assert not name.startswith("_") or name == "__version__"
    assert set(surface.__all__) >= EXPERIMENTAL


def test_openai_errors_are_the_library_s_own() -> None:
    for name in ("APIError", "RateLimitError", "APIConnectionError", "APITimeoutError", "OpenAIError"):
        assert getattr(surface, name) is getattr(openai, name)


def test_version_comes_from_the_package() -> None:
    assert surface.__version__ == sdk_version()
    assert surface.__version__ not in ("", "unknown")


def test_submodules_import() -> None:
    for name in (
        "_clients",
        "_openai",
        "_gateway",
        "_router",
        "_transport",
        "_tls",
        "_ehbp",
        "_chain",
        "_cachesecret",
        "_fetch",
        "_enclave",
        "_errors",
        "_url",
        "_types",
        "_keys",
    ):
        importlib.import_module(f"tinfoil._v3.{name}")
