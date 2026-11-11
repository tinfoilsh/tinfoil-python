"""The client package's surface: every exported name is importable, ``__all__`` is pinned and sorted, nothing
private leaks, the version comes from the installed package, and a consumer's misspelled or misplaced option is
a type error under strict mypy."""

from __future__ import annotations

import importlib
import subprocess
import sys
import textwrap
from pathlib import Path

import openai
import pytest

import tinfoil as surface
from tinfoil._sdkinfo import sdk_version

REPO_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_ALL = (
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


OPENAI_ERRORS = (
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
)
"""The ``openai`` package's errors that the surface re-exports, so that a caller catches them from one import."""

CLIENT_ERRORS = ("AttestationError", "ConfigurationError", "NetworkError", "TinfoilError")


def _isort_key(name: str) -> tuple[int, str]:
    """The linter's isort-style order for ``__all__``: SCREAMING_SNAKE_CASE names, then CamelCase, then the rest,
    each alphabetically."""
    return (0 if name.isupper() else 1 if name[0].isupper() else 2, name)


def test_all_is_pinned_and_sorted() -> None:
    assert tuple(surface.__all__) == EXPECTED_ALL
    assert list(EXPECTED_ALL) == sorted(EXPECTED_ALL, key=_isort_key)
    assert len(set(EXPECTED_ALL)) == len(EXPECTED_ALL)


def test_every_name_is_importable_and_nothing_private_leaks() -> None:
    for name in surface.__all__:
        assert hasattr(surface, name), name
        assert not name.startswith("_") or name == "__version__"
    assert set(surface.__all__) >= EXPERIMENTAL


def test_openai_errors_are_the_library_s_own() -> None:
    errors = tuple(name for name in EXPECTED_ALL if name.endswith("Error") and name not in CLIENT_ERRORS)
    assert errors == OPENAI_ERRORS, "every re-exported error is listed here"
    for name in OPENAI_ERRORS:
        assert getattr(surface, name) is getattr(openai, name), name
    for name in CLIENT_ERRORS:
        assert not hasattr(openai, name), "the client's own errors are not the library's"


def test_version_comes_from_the_package() -> None:
    assert surface.__version__ == sdk_version()
    assert surface.__version__ not in ("", "unknown")


PROBE = '''
"""A consumer of the OpenAI clients' options: every option is named by keyword and checked by the type checker."""

import httpx

from tinfoil import (
    AsyncClient,
    AsyncOpenAIOptions,
    Client,
    EnclaveOpenAIClient,
    GatewayOpenAIClient,
    OpenAICopyOptions,
    OpenAIOptions,
    RouterOpenAIClient,
    create_client,
)


def key() -> str:
    return "k"


async def async_key() -> str:
    return "k"


options: OpenAIOptions = {{
    "api_key": key,
    "timeout": httpx.Timeout(10.0),
    "max_retries": 0,
    "websocket_base_url": httpx.URL("wss://enclave.example/v1/"),
}}
async_options: AsyncOpenAIOptions = {{"api_key": async_key, "default_headers": {{"X-Trace": "1"}}}}
overrides: OpenAICopyOptions = {{"set_default_headers": {{}}, "timeout": 1.0}}


async def consume() -> None:
    enclave = EnclaveOpenAIClient("enclave.example", "org/repo", transport_mode="ehbp", http_timeout=5.0, **options)
    router = RouterOpenAIClient(user_cache_secret="s", api_key="k", organization="o", project="p")
    gateway = GatewayOpenAIClient(url="https://gateway.example/v1/", api_key="k", max_retries=1)
    drop_in: Client = create_client(**options)
    again: Client = drop_in.with_options(**overrides).copy(max_retries=2, set_default_query={{"v": 1}})
    async_drop_in = await AsyncClient.create(**async_options)
    for client in (enclave, router, gateway, drop_in, again):
        client.close()
    await async_drop_in.close()
    {mistakes}
'''

MISTAKES = (
    'EnclaveOpenAIClient("enclave.example", "org/repo", api_key="k", max_retires=0)',
    'create_client(api_key="k", transport_mode="ehbp")',
    'RouterOpenAIClient(api_key="k", http_client=httpx.Client())',
    'EnclaveOpenAIClient("enclave.example", api_key="k")',
    'GatewayOpenAIClient(api_key="k").with_options(base_url="https://elsewhere.example/")',
    "create_client(api_key=async_key)",
)
"""Consumer mistakes, one per line of the probe: a misspelled option, a route option on the drop-in client, the
fixed ``http_client`` and ``base_url``, a missing ``repo`` and an awaitable key on a synchronous client."""


def _mypy(probe: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", "--no-error-summary", str(probe)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("mistakes", [(), MISTAKES], ids=["valid consumer", "each mistake is an error"])
def test_consumer_probe_type_checks(tmp_path: Path, mistakes: tuple[str, ...]) -> None:
    """A consumer written against the surface type-checks under strict mypy, and each mistake is an error on
    its own line and nothing else is."""
    source = textwrap.dedent(PROBE).format(mistakes="\n    ".join(mistakes))
    probe = tmp_path / "probe.py"
    probe.write_text(source)
    checked = _mypy(probe)
    if not mistakes:
        assert checked.returncode == 0, checked.stdout + checked.stderr
        return
    assert checked.returncode != 0
    lines = source.splitlines()
    reported = sorted({int(line.split(":")[1]) for line in checked.stdout.splitlines() if ": error:" in line})
    expected = sorted(index + 1 for index, line in enumerate(lines) if line.strip() in mistakes)
    assert reported == expected, checked.stdout


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
        importlib.import_module(f"tinfoil.{name}")
