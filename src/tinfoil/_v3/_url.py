"""The URL rules of the client: origins, base URLs and loopback hosts."""

from __future__ import annotations

import ipaddress
from urllib.parse import SplitResult, urlsplit, urlunsplit

from tinfoil._v3._errors import ConfigurationError

USERINFO_REFUSED = "URL must not contain user information"
"""The message for a URL with a user name or password. The URL itself is never echoed."""


def origin_of(raw_url: str) -> str:
    """The normalized origin of an absolute http or https URL with a host and without user information. Raises
    ValueError otherwise, without echoing a URL that carries user information."""
    parts = _split(raw_url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"URL must be absolute: {raw_url!r}")
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError(f"URL must use http or https: {raw_url!r}")
    if not parts.hostname:
        raise ValueError(f"URL must name a host: {raw_url!r}")
    return normalized_origin(parts)


def normalized_origin(parts: SplitResult) -> str:
    """The lowercased scheme and host of ``parts`` with an explicit default port dropped, so that origins compare
    equal regardless of how a URL spells them (``https://host`` and ``https://host:443``)."""
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    port = parts.port
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if port is not None:
        return f"{scheme}://{hostname}:{port}"
    return f"{scheme}://{hostname}"


def request_origin(raw_url: str) -> str:
    """``origin_of`` for a request URL: a ValueError names the reason without echoing the URL."""
    parts = _split(raw_url)
    return normalized_origin(parts)


def validate_base_url(base_url: str) -> str:
    """Checks that ``base_url`` is an absolute URL that keeps request headers private on the way to the enclave or
    proxy: HTTPS, or HTTP to a loopback host, whose traffic never leaves the machine. Returns the URL with its path
    ending in a slash. Raises ConfigurationError."""
    try:
        origin = origin_of(base_url)
    except ValueError as err:
        raise ConfigurationError(f"invalid base URL: {err}") from None
    if not origin.startswith("https://") and not is_loopback(urlsplit(base_url).hostname or ""):
        raise ConfigurationError(
            "invalid base URL: HTTP is allowed only for localhost or a loopback IP address; "
            "use HTTPS to protect request headers"
        )
    return with_trailing_slash(base_url)


def validate_tls_base_url(base_url: str, enclave: str) -> None:
    """Checks that a TLS base URL uses the enclave's own origin, since a pinned connection cannot pass through a
    proxy. Raises ConfigurationError."""
    if not base_url:
        return
    try:
        base_origin = origin_of(base_url)
    except ValueError as err:
        raise ConfigurationError(f"invalid base URL: {err}") from None
    enclave_origin = origin_of(f"https://{enclave}")
    if base_origin != enclave_origin:
        raise ConfigurationError(
            f'a base URL off the verified enclave origin "{enclave_origin}" is a proxy, '
            'which requires the "ehbp" transport mode'
        )


def is_loopback(host: str) -> bool:
    """Whether ``host``, as written, is localhost or a loopback IP address. Other names are not resolved, so DNS
    cannot make a remote host pass."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def allowed_origins(enclave: str, base_url: str) -> frozenset[str]:
    """The origins requests may go to: the enclave's HTTPS origin and the base URL's. Either may be empty."""
    origins: set[str] = set()
    if enclave:
        origins.add(origin_of(f"https://{enclave}"))
    if base_url:
        origins.add(origin_of(base_url))
    return frozenset(origins)


def enclave_url_header_value(base_url: str, enclave: str) -> str | None:
    """The ``X-Tinfoil-Enclave-Url`` value for requests through ``base_url``, or None when it is not a proxy on
    another origin than ``enclave``."""
    if not base_url or not enclave:
        return None
    enclave_url = f"https://{enclave}"
    try:
        proxy_origin = origin_of(base_url)
        enclave_origin = origin_of(enclave_url)
    except ValueError:
        return None
    if proxy_origin == enclave_origin:
        return None
    return enclave_url


def with_trailing_slash(url: str) -> str:
    """``url`` with its path ending in a slash, so that relative paths join under it."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit(parts._replace(path=path))


def _split(raw_url: str) -> SplitResult:
    parts = urlsplit(raw_url)
    if parts.username is not None or parts.password is not None:
        raise ValueError(USERINFO_REFUSED)
    try:
        parts.port  # noqa: B018 - a port that does not parse raises
    except ValueError:
        raise ValueError(f"invalid port in URL: {raw_url!r}") from None
    return parts


__all__ = [
    "USERINFO_REFUSED",
    "allowed_origins",
    "enclave_url_header_value",
    "is_loopback",
    "normalized_origin",
    "origin_of",
    "request_origin",
    "validate_base_url",
    "validate_tls_base_url",
    "with_trailing_slash",
]
