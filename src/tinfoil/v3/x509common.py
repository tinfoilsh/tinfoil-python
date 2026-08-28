"""X.509 primitives shared by the SEV and TDX verification slices: PEM
decoding with Go encoding/pem semantics (\\r?\\n line endings tolerated, junk
before a block skipped), the certificate validity window, and the
basic-constraints / key-usage / CRL-distribution-points extension accessors.
sev/x509.py and tdx/der.py keep thin shapers where their Go call sites expect
different return shapes. All errors are ValueError; callers assign the
rejection layer."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from .bytesutil import decode_base64

# Go encoding/pem.Decode subset: first block + rest.
_PEM_RE = re.compile(
    r"-----BEGIN ([^-]+)-----\r?\n([A-Za-z0-9+/=\r\n]*)-----END \1-----(?:\r?\n)?"
)


@dataclass
class PEMBlock:
    type: str
    der: bytes
    rest: str


def pem_decode(text: str) -> Optional[PEMBlock]:
    """Decode the first PEM block, returning its DER and the remaining text
    (Go pem.Decode: junk before a block is skipped; None when nothing
    parses)."""
    m = _PEM_RE.search(text)
    if m is None:
        return None
    try:
        der = decode_base64(m.group(2))
    except ValueError:
        return None
    return PEMBlock(type=m.group(1), der=der, rest=text[m.end() :])


def pem_decode_all(text: str) -> tuple[list[PEMBlock], str]:
    """Decode consecutive PEM blocks (Go pem.Decode loop semantics); the
    trailing rest after the last block is returned for the caller's
    trailing-data checks."""
    blocks: list[PEMBlock] = []
    rest = text
    while True:
        block = pem_decode(rest)
        if block is None:
            return blocks, rest
        blocks.append(block)
        rest = block.rest


def check_validity(not_before: datetime, not_after: datetime, now: datetime) -> bool:
    """Whether now falls inside the certificate validity window (Go x509
    isValid's window check against opts.Now)."""
    return not_before <= now <= not_after


def basic_constraints_ext(cert: x509.Certificate) -> Optional[x509.BasicConstraints]:
    """The BasicConstraints extension value, or None when absent."""
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        return None


def key_usage_ext(cert: x509.Certificate) -> Optional[x509.KeyUsage]:
    """The KeyUsage extension value, or None when absent."""
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return None


def crl_distribution_point_uris(cert: x509.Certificate) -> list[str]:
    """The URI GeneralNames of the CRL Distribution Points extension."""
    try:
        dps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return []
    out: list[str] = []
    for dp in dps:
        for gn in dp.full_name or []:
            if isinstance(gn, x509.UniformResourceIdentifier):
                out.append(gn.value)
    return out
