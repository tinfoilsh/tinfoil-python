"""PPID extraction from a verified TDX quote's PCK leaf certificate, a 1:1
port of Go verifier/quote/tdx/identity.go. The PPID is authenticated because
the PCK chain is validated up to the Intel SGX root during quote
verification; callers must only invoke this after verification succeeds.
All errors are ValueError; the authenticate wrapper assigns the layer."""

from __future__ import annotations

import json

from ..bytesutil import decode_hex
from .der import Certificate, bytes_to_latin1, parse_certificate, pem_decode
from .pcs import pck_certificate_extensions
from .quote import QuoteV4


def identity(quote: QuoteV4) -> str:
    """Extract the machines-map lookup key (the 16-byte PPID, lowercase hex)
    from the PCK leaf certificate embedded in the quote."""
    leaf = _pck_leaf_certificate(quote)
    try:
        ppid_hex = pck_certificate_extensions(leaf).ppid
    except ValueError as e:
        raise ValueError(f"parsing PCK certificate extensions: {e}") from None
    try:
        ppid = decode_hex(ppid_hex)
    except ValueError:
        ppid = b""
    if len(ppid) != 16:
        raise ValueError(f"PCK certificate carries malformed PPID {json.dumps(ppid_hex)}")
    # Re-encode rather than returning the parsed string: the machines-map
    # lookup is case-sensitive and this guarantees canonical lowercase hex.
    return ppid.hex()


def _pck_leaf_certificate(quote: QuoteV4) -> Certificate:
    chain_data = (
        quote.signed_data.certification_data.qe_report_certification_data.pck_certificate_chain_data
    )
    if len(chain_data.pck_cert_chain) == 0:
        raise ValueError("quote carries no PCK certificate chain (certification data type 5)")
    block = pem_decode(bytes_to_latin1(chain_data.pck_cert_chain))
    if block is None or block.type != "CERTIFICATE":
        raise ValueError("PCK certificate chain is not PEM")
    try:
        return parse_certificate(block.der)
    except ValueError as e:
        raise ValueError(f"parsing PCK leaf certificate: {e}") from None
