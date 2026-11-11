"""The v3 client: attested HTTP and OpenAI clients for Tinfoil's enclaves.

Every client verifies its enclave before it returns and binds each request
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

from tinfoil._sdkinfo import sdk_version
from tinfoil._v3._clients import (
    AsyncEnclaveHTTPClient,
    AsyncGatewayHTTPClient,
    AsyncRouterHTTPClient,
    EnclaveHTTPClient,
    GatewayHTTPClient,
    RouterHTTPClient,
)
from tinfoil._v3._errors import AttestationError, ConfigurationError, NetworkError, TinfoilError, tinfoil_error
from tinfoil._v3._gateway import (
    DEFAULT_GATEWAY_URL,
    Catalog,
    CatalogEntry,
    ModelPin,
    ReplicaVerification,
    fetch_catalog,
    fetch_catalog_async,
)
from tinfoil._v3._openai import (
    AsyncClient,
    AsyncEnclaveOpenAIClient,
    AsyncGatewayOpenAIClient,
    AsyncRouterOpenAIClient,
    Client,
    EnclaveOpenAIClient,
    GatewayOpenAIClient,
    RouterOpenAIClient,
    create_async_client,
    create_client,
)
from tinfoil._v3._types import DEFAULT_TIMEOUT, DEFAULT_TRANSPORT_MODE, TimeoutTypes, TransportMode, VerificationCheck

__version__ = sdk_version()
"""The version of this package, as installed."""

__all__ = [
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
]
