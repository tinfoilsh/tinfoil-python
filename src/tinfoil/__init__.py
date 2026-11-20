"""Attested HTTP and OpenAI clients for Tinfoil's enclaves.

The HTTP clients are the core of the package. ``OpenAIClient`` and
``AsyncOpenAIClient`` build ``openai`` clients on top of them, and ``Client``
is the drop-in one over the router; they and the re-exported ``openai`` errors
need the optional ``openai`` dependency, ``pip install 'tinfoil[openai]'``.

The enclave and router clients verify before the constructor returns;
gateway clients verify each model's replica on its first request. The
asynchronous clients are built with ``await Cls.create(...)``, which is
where they verify, since their constructor raises. Every request is bound
to the keys of the current verification. The enclave clients take a trust
argument, ``Trust``, which names who vouches for the enclave's config. The
verifier that appraises the attestation documents is the ``verifier``
subpackage, which defines the ``Policy`` that every client takes. The
client modules load on first use, so that importing the ``verifier``
subpackage alone stays light.
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
        AsyncAttestedHTTPClient,
        AsyncEnclaveHTTPClient,
        AsyncGatewayHTTPClient,
        AsyncRouterHTTPClient,
        AttestedHTTPClient,
        EnclaveHTTPClient,
        GatewayHTTPClient,
        RouterHTTPClient,
    )
    from tinfoil._errors import AttestationError, ConfigurationError, NetworkError, TinfoilError, tinfoil_error
    from tinfoil._fetchers import (
        AsyncAttestationFetcher,
        AsyncRouterListFetcher,
        AttestationFetcher,
        AttestationRelay,
        RouterListFetcher,
        RouterListRelay,
    )
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
        AsyncOpenAIClient,
        AsyncOpenAICopyOptions,
        AsyncOpenAIOptions,
        Client,
        OpenAIClient,
        OpenAICopyOptions,
        OpenAIOptions,
        create_async_client,
        create_client,
    )
    from tinfoil._trust import AuthorizedBy, EitherPin, EmbeddedConfig, ProjectPin, RepoPin, SignedBy, Trust
    from tinfoil._types import DEFAULT_HTTP_TIMEOUT, EHBP, TLS, TimeoutTypes, Transport, VerificationCheck

_OPENAI_EXTRA = "install it with `pip install 'tinfoil[openai]'`"
"""How to install the optional ``openai`` dependency, which the OpenAI clients and the re-exported ``openai`` errors
need."""

__version__ = sdk_version()
"""The version of this package, as installed."""

__all__ = [
    "DEFAULT_GATEWAY_URL",
    "DEFAULT_HTTP_TIMEOUT",
    "EHBP",
    "TLS",
    "APIConnectionError",
    "APIError",
    "APIResponseValidationError",
    "APIStatusError",
    "APITimeoutError",
    "AsyncAttestationFetcher",
    "AsyncAttestedHTTPClient",
    "AsyncClient",
    "AsyncEnclaveHTTPClient",
    "AsyncGatewayHTTPClient",
    "AsyncOpenAIClient",
    "AsyncOpenAICopyOptions",
    "AsyncOpenAIOptions",
    "AsyncRouterHTTPClient",
    "AsyncRouterListFetcher",
    "AttestationError",
    "AttestationFetcher",
    "AttestationRelay",
    "AttestedHTTPClient",
    "AuthenticationError",
    "AuthorizedBy",
    "BadRequestError",
    "Catalog",
    "CatalogEntry",
    "Client",
    "ConfigurationError",
    "ConflictError",
    "EitherPin",
    "EmbeddedConfig",
    "EnclaveHTTPClient",
    "GatewayHTTPClient",
    "InternalServerError",
    "ModelPin",
    "NetworkError",
    "NotFoundError",
    "OpenAIClient",
    "OpenAICopyOptions",
    "OpenAIError",
    "OpenAIOptions",
    "PermissionDeniedError",
    "ProjectPin",
    "RateLimitError",
    "ReplicaVerification",
    "RepoPin",
    "RouterHTTPClient",
    "RouterListFetcher",
    "RouterListRelay",
    "SignedBy",
    "TimeoutTypes",
    "TinfoilError",
    "Transport",
    "Trust",
    "UnprocessableEntityError",
    "VerificationCheck",
    "__version__",
    "create_async_client",
    "create_client",
    "fetch_catalog",
    "fetch_catalog_async",
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
                "AsyncAttestedHTTPClient",
                "AsyncEnclaveHTTPClient",
                "AsyncGatewayHTTPClient",
                "AsyncRouterHTTPClient",
                "AttestedHTTPClient",
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
            "tinfoil._fetchers",
            (
                "AsyncAttestationFetcher",
                "AsyncRouterListFetcher",
                "AttestationFetcher",
                "AttestationRelay",
                "RouterListFetcher",
                "RouterListRelay",
            ),
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
                "AsyncOpenAIClient",
                "AsyncOpenAICopyOptions",
                "AsyncOpenAIOptions",
                "Client",
                "OpenAIClient",
                "OpenAICopyOptions",
                "OpenAIOptions",
                "create_async_client",
                "create_client",
            ),
        ),
        (
            "tinfoil._types",
            ("DEFAULT_HTTP_TIMEOUT", "EHBP", "TLS", "TimeoutTypes", "Transport", "VerificationCheck"),
        ),
        (
            "tinfoil._trust",
            ("AuthorizedBy", "EitherPin", "EmbeddedConfig", "ProjectPin", "RepoPin", "SignedBy", "Trust"),
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
        try:
            loaded = importlib.import_module(module)
        except ModuleNotFoundError as err:
            if err.name != "openai":
                raise
            raise ModuleNotFoundError(
                f"tinfoil.{name} requires the openai package: {_OPENAI_EXTRA}", name="openai"
            ) from err
        value = getattr(loaded, name)
        globals()[name] = value
        return value

    def __dir__() -> list[str]:
        return sorted(set(__all__) | set(globals()))
