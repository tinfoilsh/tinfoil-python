"""Attestation document transport (Go: envelope.Fetch / envelope.RandomNonce).
The fetched bytes are untrusted until verify_document_v3 accepts them."""

from __future__ import annotations

import httpx

from .envelope import ATTESTATION_ENDPOINT, NONCE_SIZE, random_nonce

__all__ = ["NONCE_SIZE", "fetch_attestation", "random_nonce"]

# Matches Go util.Get's client timeout.
_FETCH_TIMEOUT_SECONDS = 10


def fetch_attestation(host: str, nonce: bytes) -> bytes:
    """GET https://<host>/.well-known/tinfoil-attestation?nonce=<hex>; host
    may already carry a port. Non-2xx responses raise (Go: envelope.Fetch)."""
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    url = f"https://{host}{ATTESTATION_ENDPOINT}?nonce={nonce.hex()}"
    # Go http.Get follows redirects; httpx does not by default.
    resp = httpx.get(url, timeout=_FETCH_TIMEOUT_SECONDS, follow_redirects=True)
    if resp.status_code < 200 or resp.status_code >= 300:
        raise RuntimeError(f"fetching attestation from {host}: HTTP {resp.status_code}")
    return resp.content
