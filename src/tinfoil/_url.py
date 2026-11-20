"""The URL rules of the client: origins, base URLs and loopback hosts."""

from __future__ import annotations

import ipaddress
from urllib.parse import SplitResult, urlsplit, urlunsplit

from tinfoil._errors import ConfigurationError

USERINFO_REFUSED = "URL must not contain user information"
"""The message for a URL with a user name or password. The URL itself is never echoed."""
QUERY_OR_FRAGMENT_REFUSED = "invalid proxy URL: a proxy URL must not carry a query or a fragment"
"""The message for a proxy URL with a query or a fragment: request paths join under a proxy URL, so neither has a
place there."""


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


def validate_proxy_url(proxy_url: str, name: str = "proxy URL") -> str:
    """Checks that ``proxy_url``, a route URL that ``name`` describes, such as a proxy or a relay, is an absolute URL
    that keeps request headers private on the way there: HTTPS, or HTTP to a loopback host, whose traffic never
    leaves the machine. A query or a fragment is refused, since request paths join under the URL. Returns the URL
    with its path ending in a slash. Raises ConfigurationError."""
    if not isinstance(proxy_url, str):
        raise ConfigurationError(f"invalid {name}: want a string, not {type(proxy_url).__name__}")
    try:
        origin = origin_of(proxy_url)
    except ValueError as err:
        raise ConfigurationError(f"invalid {name}: {err}") from None
    parts = urlsplit(proxy_url)
    if not origin.startswith("https://") and not is_loopback(parts.hostname or ""):
        raise ConfigurationError(
            f"invalid {name}: HTTP is allowed only for localhost or a loopback IP address; "
            "use HTTPS to protect request headers"
        )
    if has_query_or_fragment(proxy_url):
        raise ConfigurationError(QUERY_OR_FRAGMENT_REFUSED.replace("proxy URL", name))
    return with_trailing_slash(proxy_url)


def refuse_enclave_origin_proxy(proxy_url: str, enclave: str) -> None:
    """Refuses a proxy URL on the enclave's own origin, which would send requests directly to the enclave under the
    name of a proxy. Raises ConfigurationError."""
    if not proxy_url:
        return
    try:
        proxy_origin = origin_of(proxy_url)
        enclave_origin = origin_of(f"https://{enclave}")
    except ValueError as err:
        raise ConfigurationError(f"invalid proxy URL: {err}") from None
    if proxy_origin == enclave_origin:
        raise ConfigurationError(
            f'invalid proxy URL: "{enclave_origin}" is the enclave\'s own origin; leave proxy_url unset to connect '
            "directly"
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


def has_query_or_fragment(url: str) -> bool:
    """Whether ``url`` carries a query or a fragment, even an empty one. ``urlsplit`` parses a bare ``?`` or
    ``#`` as no component at all and ``urlunsplit`` then drops it, so the delimiters are looked for in the URL
    as written as well as in its parsed components."""
    parts = urlsplit(url)
    return bool(parts.query or parts.fragment) or "?" in url or "#" in url


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
    "QUERY_OR_FRAGMENT_REFUSED",
    "USERINFO_REFUSED",
    "allowed_origins",
    "enclave_url_header_value",
    "has_query_or_fragment",
    "is_loopback",
    "normalized_origin",
    "origin_of",
    "refuse_enclave_origin_proxy",
    "request_origin",
    "validate_proxy_url",
    "with_trailing_slash",
]
