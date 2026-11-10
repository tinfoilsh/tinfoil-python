"""RFC 3161 timestamp responses: decoding, the imprint check and verification against the trusted root's timestamp
authorities at the token's own genTime.

The CMS decode and signature check are delegated to ``rfc3161-client``;
the checks that it does not make (status, policy, TSTInfo version, size
bounds, the authority's validity window at genTime) are made here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._sigstore.bundle import MAX_STATEMENT_SIZE as MAX_STATEMENT_SIZE
from tinfoil._v3.verifier._sigstore.bundle import MAX_TIMESTAMP_SIZE as MAX_TIMESTAMP_SIZE
from tinfoil._v3.verifier._sigstore.trusted_root import TrustedRoot

SIGSTORE_TIMESTAMP_POLICY = "1.3.6.1.4.1.57264.2"
STATUS_GRANTED = 0
TST_INFO_VERSION = 1
OID_SHA256 = "2.16.840.1.101.3.4.2.1"


class TimestampError(ValueError):
    """A timestamp response that fails to decode, does not match its input or no authority authenticated."""


@dataclass(frozen=True, slots=True)
class TimestampResponse:
    """A decoded TimeStampResp."""

    status: int
    policy: str
    gen_time: datetime
    hash_algorithm: str
    """The message imprint's hash algorithm OID."""
    hashed_message: bytes
    tst_info_version: int
    serial_number: int
    nonce: int | None
    raw: bytes


def timestamp_input(domain: bytes, core: _json.JsonValue) -> bytes:
    """The bytes that an approval timestamps: ``domain`` followed by the RFC 8785 canonical form of ``core``."""
    raise NotImplementedError


def parse_timestamp_response(response: bytes) -> TimestampResponse:
    """Decode a DER TimeStampResp.

    Rejects a response outside (0, MAX_TIMESTAMP_SIZE], a status other
    than STATUS_GRANTED (a token granted with modifications is rejected
    too), a TSTInfo version other than 1, a genTime that is not
    GeneralizedTime with ``Z`` and a message imprint that is not SHA-256.
    """
    raise NotImplementedError


def check_imprint(response: TimestampResponse, data: bytes) -> None:
    """Check that the response's message imprint is SHA-256 over ``data``, with ``data`` within MAX_STATEMENT_SIZE."""
    raise NotImplementedError


def verify_timestamp(
    root: TrustedRoot, response: bytes, data: bytes, *, policy: str = SIGSTORE_TIMESTAMP_POLICY
) -> datetime:
    """Verify a timestamp over ``data`` and return its genTime.

    The response is decoded and its imprint checked; the token's policy
    OID must equal ``policy``. Then each timestamp
    authority whose window contains the genTime is tried: the token's
    signing certificate must chain to the authority at the genTime with
    the time-stamping EKU and the CMS signature must verify. The first
    authority that authenticates the token decides; when none does, the
    timestamp is rejected.
    """
    raise NotImplementedError
