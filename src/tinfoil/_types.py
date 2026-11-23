"""The types shared by the client modules: timeouts, the verification check and the ``Transport`` option."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeAlias, final

import httpx

from tinfoil.verifier import VerifiedFacts

TimeoutTypes: TypeAlias = float | tuple[float | None, float | None, float | None, float | None] | httpx.Timeout | None
"""A timeout as ``httpx.Client`` accepts it: seconds for every operation, None for no limit, a
``(connect, read, write, pool)`` tuple or an ``httpx.Timeout``."""

DEFAULT_HTTP_TIMEOUT: httpx.Timeout = httpx.Timeout(600.0, connect=5.0)
"""The timeout a client applies when none is given: five seconds to connect and ten minutes for each read, write
and pool wait, which is what the ``openai`` package applies to inference requests by default. It is the
``httpx`` timeout of ``http_client``, whose requests may stream a long completion, and of the client's own
attestation fetches, which are also bounded as a whole: an attestation document and the router list within
30 seconds, the gateway catalog within 10 seconds."""

VerificationCheck: TypeAlias = Callable[[VerifiedFacts], None]
"""A caller's check of a verification that passed the verifier, called before the client uses the enclave's keys.
Raising rejects the enclave; the exception becomes the cause of an AttestationError and is not retried."""


@final
@dataclass(frozen=True, slots=True)
class TLS:
    """Pins each connection to the attested TLS key. It protects the whole request and response, and needs a direct
    connection to the enclave, so it takes no URL: requests go to the enclave's own HTTPS origin. It is the default
    transport."""


@final
@dataclass(frozen=True, slots=True)
class EHBP:
    """Seals request and response bodies to the attested HPKE key, so that they stay private through a proxy. The
    method, URL and headers are not sealed, and neither is a request without a body or its response. It refuses
    protocol upgrades, such as WebSockets, and CONNECT tunnels, because nothing after the handshake would be
    sealed.

    ``proxy_url``, when set, is a proxy that forwards requests to the
    enclave, and requests are sent to it; None or ``""`` sends them directly
    to the enclave. Its path, if any, is where the proxy is mounted, not the
    API path: an ``OpenAIClient`` joins its ``api_path``, ``/v1/`` by
    default, under it. Requests to the proxy carry
    ``X-Tinfoil-Enclave-Url`` so that it can forward them. The proxy must
    use HTTPS, since EHBP does not seal headers such as the API key;
    ``http://`` is accepted only when its host is localhost or a loopback IP
    address, for a local development proxy or a sidecar. Request paths join
    under it, so a ``proxy_url`` with user information, a query or a
    fragment, even an empty one, is a ConfigurationError. An enclave client
    also refuses a ``proxy_url`` on the enclave's own origin, which is no
    proxy; leave it unset to connect directly.
    """

    proxy_url: str | None = None


Transport: TypeAlias = TLS | EHBP
"""How a client protects its traffic to an enclave: ``TLS()`` or ``EHBP(proxy_url=...)``. None, where a
``Transport`` is optional, selects ``TLS()``, the stronger transport."""

__all__ = [
    "DEFAULT_HTTP_TIMEOUT",
    "EHBP",
    "TLS",
    "TimeoutTypes",
    "Transport",
    "VerificationCheck",
]
