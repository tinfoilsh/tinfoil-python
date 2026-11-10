"""Type aliases shared by the client modules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, TypeAlias

import httpx

from tinfoil._v3.verifier import Verification

TimeoutTypes: TypeAlias = float | tuple[float | None, float | None, float | None, float | None] | httpx.Timeout | None
"""A timeout as ``httpx.Client`` accepts it: seconds for every operation, None for no limit, a
``(connect, read, write, pool)`` tuple or an ``httpx.Timeout``."""

DEFAULT_TIMEOUT: httpx.Timeout = httpx.Timeout(5.0)
"""The timeout a client applies when none is given: five seconds for each connect, read, write and pool wait, as
``httpx.Client`` applies by default."""

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
    "DEFAULT_TIMEOUT",
    "DEFAULT_TRANSPORT_MODE",
    "TimeoutTypes",
    "TransportMode",
    "VerificationCheck",
]
