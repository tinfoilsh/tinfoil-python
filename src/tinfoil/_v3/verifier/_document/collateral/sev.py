"""AMD SEV-SNP endorsement collateral: the VCEK chain and the KDS CRL."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._canonical import EncodingError, decode_base64
from tinfoil._v3.verifier._document.collateral.entry import Entry, unmarshal_data

MAX_VCEK_DER_SIZE = 64 * 1024
"""The largest VCEK DER accepted; a production VCEK is about 1.4 KiB."""
MAX_CERT_CHAIN_PEM_SIZE = 64 * 1024
"""The largest ``cert_chain_pem`` accepted, in characters; the ASK and ARK PEM together are about 5 KiB."""
MAX_CRL_DER_SIZE = 1024 * 1024
"""The largest CRL DER accepted; the KDS product revocation lists are under 1 KiB."""


@dataclass(frozen=True, slots=True)
class AMDVCEK:
    """Decoded amd-vcek collateral."""

    vcek_der: bytes
    cert_chain_pem: str
    """The ASK then the ARK certificate."""


@dataclass(frozen=True, slots=True)
class AMDCRL:
    """Decoded amd-crl collateral."""

    crl_der: bytes


_VCEK_MEMBERS = ("vcek_der_base64", "cert_chain_pem")
_CRL_MEMBERS = ("crl_der_base64",)


def decode_amd_vcek(entry: Entry) -> AMDVCEK:
    """Decode an amd-vcek entry, bounding the VCEK DER and the chain PEM before either is parsed."""
    data = unmarshal_data(entry, "amd-vcek", _VCEK_MEMBERS)
    try:
        der = decode_base64("vcek_der_base64", _json.string(data, "vcek_der_base64"))
    except EncodingError as err:
        raise EncodingError(f"amd-vcek collateral entry {entry.id!r}: {err}") from err
    if len(der) > MAX_VCEK_DER_SIZE:
        raise EncodingError(
            f"amd-vcek collateral entry {entry.id!r}: vcek_der_base64 exceeds {MAX_VCEK_DER_SIZE} bytes"
        )
    pem = _json.string(data, "cert_chain_pem")
    if len(pem) > MAX_CERT_CHAIN_PEM_SIZE:
        raise EncodingError(
            f"amd-vcek collateral entry {entry.id!r}: cert_chain_pem exceeds {MAX_CERT_CHAIN_PEM_SIZE} characters"
        )
    return AMDVCEK(vcek_der=der, cert_chain_pem=pem)


def decode_amd_crl(entry: Entry) -> AMDCRL:
    """Decode an amd-crl entry, bounding the CRL DER before it is parsed."""
    data = unmarshal_data(entry, "amd-crl", _CRL_MEMBERS)
    try:
        der = decode_base64("crl_der_base64", _json.string(data, "crl_der_base64"))
    except EncodingError as err:
        raise EncodingError(f"amd-crl collateral entry {entry.id!r}: {err}") from err
    if len(der) > MAX_CRL_DER_SIZE:
        raise EncodingError(f"amd-crl collateral entry {entry.id!r}: crl_der_base64 exceeds {MAX_CRL_DER_SIZE} bytes")
    return AMDCRL(crl_der=der)
