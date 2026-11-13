"""Attested HTTP and OpenAI clients for Tinfoil's enclaves.

The enclave and router clients verify before the constructor returns;
gateway clients verify each model's replica on its first request. The
asynchronous clients are built with ``await Cls.create(...)``, which is
where they verify, since their constructor raises. Every request is bound
to the keys of the current verification. The verifier that appraises the
attestation documents is the ``verifier`` subpackage; its records and
errors are not re-exported here. ``pin_tls_key`` and ``connection_cert_fp``
check that a TLS connection that the caller opens presents the key that a
verification endorses. The client modules load on first use, so that
importing the ``verifier`` subpackage alone stays light.
"""

import importlib
from typing import TYPE_CHECKING

from tinfoil._sdkinfo import sdk_version

if TYPE_CHECKING:
    from openai import (
        APIConnectionError,
        APIError,
        APIResponseValidationError,
        APIStatusError,
        APITimeoutError,
        AuthenticationError,
        BadRequestError,
        ConflictError,
        InternalServerError,
        NotFoundError,
        OpenAIError,
        PermissionDeniedError,
        RateLimitError,
        UnprocessableEntityError,
    )

    from tinfoil._clients import (
        AsyncEnclaveHTTPClient,
        AsyncGatewayHTTPClient,
        AsyncRouterHTTPClient,
        EnclaveHTTPClient,
        GatewayHTTPClient,
        RouterHTTPClient,
    )
    from tinfoil._errors import AttestationError, ConfigurationError, NetworkError, TinfoilError, tinfoil_error
    from tinfoil._gateway import (
        DEFAULT_GATEWAY_URL,
        Catalog,
        CatalogEntry,
        ModelPin,
        ReplicaVerification,
        fetch_catalog,
        fetch_catalog_async,
    )
    from tinfoil._openai import (
        AsyncClient,
        AsyncEnclaveOpenAIClient,
        AsyncGatewayOpenAIClient,
        AsyncOpenAICopyOptions,
        AsyncOpenAIOptions,
        AsyncRouterOpenAIClient,
        Client,
        EnclaveOpenAIClient,
        GatewayOpenAIClient,
        OpenAICopyOptions,
        OpenAIOptions,
        RouterOpenAIClient,
        create_async_client,
        create_client,
    )
    from tinfoil._pin import connection_cert_fp, pin_tls_key
    from tinfoil._types import (
        DEFAULT_HTTP_TIMEOUT,
        DEFAULT_TRANSPORT_MODE,
        TimeoutTypes,
        TransportMode,
        VerificationCheck,
    )

__version__ = sdk_version()
"""The version of this package, as installed."""

__all__ = [
    "DEFAULT_GATEWAY_URL",
    "DEFAULT_HTTP_TIMEOUT",
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
    "AsyncOpenAICopyOptions",
    "AsyncOpenAIOptions",
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
    "OpenAICopyOptions",
    "OpenAIError",
    "OpenAIOptions",
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
    "connection_cert_fp",
    "create_async_client",
    "create_client",
    "fetch_catalog",
    "fetch_catalog_async",
    "pin_tls_key",
    "tinfoil_error",
]

_MODULE_OF: dict[str, str] = {
    name: module
    for module, names in (
        (
            "openai",
            (
                "APIConnectionError",
                "APIError",
                "APIResponseValidationError",
                "APIStatusError",
                "APITimeoutError",
                "AuthenticationError",
                "BadRequestError",
                "ConflictError",
                "InternalServerError",
                "NotFoundError",
                "OpenAIError",
                "PermissionDeniedError",
                "RateLimitError",
                "UnprocessableEntityError",
            ),
        ),
        (
            "tinfoil._clients",
            (
                "AsyncEnclaveHTTPClient",
                "AsyncGatewayHTTPClient",
                "AsyncRouterHTTPClient",
                "EnclaveHTTPClient",
                "GatewayHTTPClient",
                "RouterHTTPClient",
            ),
        ),
        (
            "tinfoil._errors",
            ("AttestationError", "ConfigurationError", "NetworkError", "TinfoilError", "tinfoil_error"),
        ),
        (
            "tinfoil._gateway",
            (
                "DEFAULT_GATEWAY_URL",
                "Catalog",
                "CatalogEntry",
                "ModelPin",
                "ReplicaVerification",
                "fetch_catalog",
                "fetch_catalog_async",
            ),
        ),
        (
            "tinfoil._openai",
            (
                "AsyncClient",
                "AsyncEnclaveOpenAIClient",
                "AsyncGatewayOpenAIClient",
                "AsyncOpenAICopyOptions",
                "AsyncOpenAIOptions",
                "AsyncRouterOpenAIClient",
                "Client",
                "EnclaveOpenAIClient",
                "GatewayOpenAIClient",
                "OpenAICopyOptions",
                "OpenAIOptions",
                "RouterOpenAIClient",
                "create_async_client",
                "create_client",
            ),
        ),
        ("tinfoil._pin", ("connection_cert_fp", "pin_tls_key")),
        (
            "tinfoil._types",
            ("DEFAULT_HTTP_TIMEOUT", "DEFAULT_TRANSPORT_MODE", "TimeoutTypes", "TransportMode", "VerificationCheck"),
        ),
    )
    for name in names
}
"""The module that defines each exported name, for the import on first use."""

# The type checker sees the imports above and resolves every name from them, so it keeps reporting a name that
# the package does not export; these two hooks exist for the interpreter alone.
if not TYPE_CHECKING:

    def __getattr__(name: str) -> object:
        """Imports the module that defines ``name`` and binds the attribute here, so that later accesses are plain
        attribute reads."""
        try:
            module = _MODULE_OF[name]
        except KeyError:
            raise AttributeError(f"module 'tinfoil' has no attribute {name!r}") from None
        value = getattr(importlib.import_module(module), name)
        globals()[name] = value
        return value

    def __dir__() -> list[str]:
        return sorted(set(__all__) | set(globals()))
