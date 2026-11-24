"""The types shared by the client modules: timeouts, the verification check and callback, and the ``Transport``
option."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeAlias, final

import httpx

from tinfoil._errors import TinfoilError
from tinfoil.verifier import VerificationReport, VerifiedFacts

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
"""A caller's check of the verified facts of a verification that passed the verifier, called before the client uses
the enclave's keys. Raising rejects the enclave; the exception becomes the cause of an AttestationError and is not
retried. It never sees a report or partial facts: it decides about trust, so it sees only facts that were
verified."""

LastVerification: TypeAlias = tuple[VerificationReport | None, TinfoilError | None]
"""The outcome of a client's most recent verification attempt, as ``(report, error)``: the report and None when
the attempt passed, None and the client error that it reported when it failed, and ``(None, None)`` before the
first attempt. When the verifier rejected the document, the verifier's ``VerificationError``, whose ``report``
shows the failed step and the partial facts, is the error's ``__cause__``. A failed fetch, a
``verification_check`` rejection and a document whose keys the client cannot use come after or before the
verifier, so no report is reachable from them."""

OnVerification: TypeAlias = Callable[[str, VerificationReport | None, TinfoilError | None], None]
"""A caller's callback that a client calls once for every verification attempt, after the attempt's outcome is decided,
with the host of the enclave that it verified and the attempt's ``(report, error)``, as ``last_verification`` returns
them: the first verification, a retry, a refresh after expiry or a key rotation, an explicit ``reverify``, each
router that discovery tries and each gateway replica. A verification that concurrent requests share is one attempt.
The client holds none of its locks while it calls it, so the callback may call the client, for example
``last_verification``. It returns nothing and cannot change the outcome: an ``Exception`` that it raises is logged to
the ``tinfoil`` logger and otherwise ignored, so that it never turns a verification into a failure or makes discovery
or the gateway skip a router or replica. A decision about trust belongs in the ``verification_check``. A callback
that blocks or raises is a bug in the caller's code."""


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
    "LastVerification",
    "OnVerification",
    "TimeoutTypes",
    "Transport",
    "VerificationCheck",
]
