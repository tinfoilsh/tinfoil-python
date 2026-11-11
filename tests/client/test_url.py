"""The URL rules: origins, base URLs, loopback hosts and the trailing slash."""

from __future__ import annotations

import pytest

from tinfoil._errors import ConfigurationError
from tinfoil._url import (
    QUERY_OR_FRAGMENT_REFUSED,
    USERINFO_REFUSED,
    allowed_origins,
    enclave_url_header_value,
    has_query_or_fragment,
    is_loopback,
    origin_of,
    validate_base_url,
    validate_tls_base_url,
    with_trailing_slash,
)


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("https://enclave.example.com:443/v1", "https://enclave.example.com"),
        ("http://proxy.example.com:80/v1", "http://proxy.example.com"),
        ("https://enclave.example.com:8443/v1", "https://enclave.example.com:8443"),
        ("http://[::1]:80/v1", "http://[::1]"),
        ("http://[::1]:8080/v1", "http://[::1]:8080"),
        ("HTTPS://Enclave.Example/v1", "https://enclave.example"),
    ],
)
def test_origin_of_normalizes(raw: str, want: str) -> None:
    assert origin_of(raw) == want


@pytest.mark.parametrize(
    "raw",
    ["/v1/", "enclave.example", "ftp://enclave.example/v1", "https://", "", "https://:443/v1", "https://:8443"],
)
def test_origin_of_rejects_relative_hostless_and_other_schemes(raw: str) -> None:
    with pytest.raises(ValueError, match="URL must"):
        origin_of(raw)


def test_hostless_authority_is_a_configuration_error() -> None:
    with pytest.raises(ValueError, match="must name a host"):
        origin_of("https://:443/v1")
    with pytest.raises(ConfigurationError, match="invalid base URL: URL must name a host"):
        validate_base_url("https://:443/v1")
    with pytest.raises(ValueError, match="must name a host"):
        allowed_origins("", "https://:443/v1/")


def test_origin_of_refuses_userinfo_without_echoing_it() -> None:
    with pytest.raises(ValueError, match="user information") as err:
        origin_of("https://user:hunter2@enclave.example/v1")
    assert str(err.value) == USERINFO_REFUSED
    assert "hunter2" not in str(err.value)
    with pytest.raises(ConfigurationError) as refused:
        validate_base_url("https://user:hunter2@proxy.example/v1/")
    assert "hunter2" not in str(refused.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "https://proxy.example/v1/",
        "http://localhost:8080/v1/",
        "http://LOCALHOST/v1/",
        "http://127.0.0.1:8080/v1/",
        "http://127.1.2.3/v1/",
        "http://[::1]:8080/v1/",
    ],
)
def test_validate_base_url_accepts(base_url: str) -> None:
    assert validate_base_url(base_url) == base_url


@pytest.mark.parametrize(
    "base_url",
    [
        "http://proxy.example/v1/",
        "http://app.localhost/v1/",
        "http://localhost.example/v1/",
        "http://0.0.0.0:8080/v1/",
        "http://10.0.0.1/v1/",
        "/v1/",
        "ftp://localhost/v1/",
        "",
        "https://proxy.example:port/v1/",
        "https://:443/v1/",
        "https://proxy.example/v1/?api-version=1",
        "https://proxy.example/v1/#fragment",
        "http://localhost:8080/v1?x=1",
        "https://proxy.example/v1/?",
        "https://proxy.example/v1/#",
    ],
)
def test_validate_base_url_rejects(base_url: str) -> None:
    with pytest.raises(ConfigurationError, match="invalid base URL"):
        validate_base_url(base_url)


def test_validate_base_url_names_a_query_or_fragment() -> None:
    """A query or a fragment is refused by name, including a bare delimiter, which parses as no component and
    would otherwise be dropped with the trailing slash."""
    for base_url in (
        "https://proxy.example/v1/?x=1",
        "https://proxy.example/v1/#f",
        "https://proxy.example/v1?x",
        "https://proxy.example/v1/?",
        "https://proxy.example/v1/#",
    ):
        assert has_query_or_fragment(base_url), base_url
        with pytest.raises(ConfigurationError) as err:
            validate_base_url(base_url)
        assert str(err.value) == QUERY_OR_FRAGMENT_REFUSED
    assert not has_query_or_fragment("https://proxy.example/v1/")


def test_validate_base_url_normalizes_the_trailing_slash() -> None:
    assert validate_base_url("https://proxy.example/v1") == "https://proxy.example/v1/"
    assert validate_base_url("https://proxy.example") == "https://proxy.example/"
    assert with_trailing_slash("https://proxy.example/v1?x=1") == "https://proxy.example/v1/?x=1"


def test_validate_tls_base_url() -> None:
    validate_tls_base_url("", "enclave.example.com")
    validate_tls_base_url("https://enclave.example.com/custom/v1", "enclave.example.com")
    validate_tls_base_url("https://enclave.example.com:443/custom/v1", "enclave.example.com")
    with pytest.raises(ConfigurationError) as proxy:
        validate_tls_base_url("https://proxy.example.com/v1", "enclave.example.com")
    assert "verified enclave origin" in str(proxy.value)
    assert '"ehbp"' in str(proxy.value), "the error names the mode a proxy needs"
    with pytest.raises(ConfigurationError, match="verified enclave origin"):
        validate_tls_base_url("http://enclave.example.com/v1", "enclave.example.com")


@pytest.mark.parametrize(
    ("host", "want"),
    [("localhost", True), ("LocalHost", True), ("127.0.0.1", True), ("127.1.2.3", True), ("::1", True)],
)
def test_is_loopback_accepts(host: str, want: bool) -> None:
    assert is_loopback(host) is want


@pytest.mark.parametrize("host", ["app.localhost", "0.0.0.0", "10.0.0.1", "example.com", "", "::"])
def test_is_loopback_rejects(host: str) -> None:
    assert is_loopback(host) is False


def test_allowed_origins() -> None:
    assert allowed_origins("enclave.example", "") == {"https://enclave.example"}
    assert allowed_origins("enclave.example", "http://proxy.example/v1/") == {
        "https://enclave.example",
        "http://proxy.example",
    }
    assert allowed_origins("", "https://gateway.example/v1/") == {"https://gateway.example"}


@pytest.mark.parametrize(
    ("base_url", "enclave", "want"),
    [
        ("https://proxy.example.com/", "enclave.example.com", "https://enclave.example.com"),
        ("https://proxy.example.com/api/v1/", "enclave.example.com", "https://enclave.example.com"),
        ("https://enclave.example.com/v1/", "enclave.example.com", None),
        ("https://enclave.example.com:443/v1/", "enclave.example.com", None),
        ("", "enclave.example.com", None),
        ("https://proxy.example.com/", "", None),
    ],
)
def test_enclave_url_header_value(base_url: str, enclave: str, want: str | None) -> None:
    assert enclave_url_header_value(base_url, enclave) == want
