"""Attested HTTP and OpenAI clients for Tinfoil's enclaves.

The enclave and router clients verify before the constructor returns;
gateway clients verify each model's replica on its first request. The
asynchronous clients are built with ``await Cls.create(...)``, which is
where they verify, since their constructor raises. Every request is bound
to the keys of the current verification. The verifier that appraises the
attestation documents is the ``verifier`` subpackage; its records and
errors are not re-exported here.
"""

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
from tinfoil._sdkinfo import sdk_version
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
    "create_async_client",
    "create_client",
    "fetch_catalog",
    "fetch_catalog_async",
    "tinfoil_error",
]
