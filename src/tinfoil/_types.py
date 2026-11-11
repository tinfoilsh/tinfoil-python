"""Type aliases shared by the client modules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, TypeAlias

import httpx

from tinfoil.verifier import Verification

TimeoutTypes: TypeAlias = float | tuple[float | None, float | None, float | None, float | None] | httpx.Timeout | None
"""A timeout as ``httpx.Client`` accepts it: seconds for every operation, None for no limit, a
``(connect, read, write, pool)`` tuple or an ``httpx.Timeout``."""

DEFAULT_HTTP_TIMEOUT: httpx.Timeout = httpx.Timeout(600.0, connect=5.0)
"""The timeout a client applies when none is given: five seconds to connect and ten minutes for each read, write
and pool wait, which is what the ``openai`` package applies to inference requests by default. It is the
``httpx`` timeout of ``http_client``, whose requests may stream a long completion, and of the client's own
attestation fetches, which are also bounded as a whole: an attestation document and the router list within
30 seconds, the gateway catalog within 10 seconds."""

VerificationCheck: TypeAlias = Callable[[Verification], None]
"""A caller's check of a verification that passed the verifier, called before the client uses the enclave's keys.
Raising rejects the enclave; the exception becomes the cause of an AttestationError and is not retried."""

TransportMode: TypeAlias = Literal["tls", "ehbp"]
"""How a client protects its traffic to an enclave.

``"tls"`` pins each connection to the attested TLS key. It protects the
whole request and response, and needs a direct connection. ``"ehbp"``
seals request and response bodies to the attested HPKE key, so they stay
private through a proxy. The method, URL and headers are not sealed, and
neither is a request without a body or its response. It refuses protocol
upgrades, such as WebSockets, and CONNECT tunnels, because nothing after
the handshake would be sealed.
"""

DEFAULT_TRANSPORT_MODE: TransportMode = "tls"
"""The transport mode a client uses when none is given: the stronger one. A proxy base URL requires ``"ehbp"``."""

__all__ = [
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_TRANSPORT_MODE",
    "TimeoutTypes",
    "TransportMode",
    "VerificationCheck",
]
