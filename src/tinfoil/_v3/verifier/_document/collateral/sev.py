"""AMD SEV-SNP endorsement collateral: the VCEK chain and the KDS CRL."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._canonical import EncodingError, decode_base64
from tinfoil._v3.verifier._document.collateral.entry import Entry, unmarshal_data


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
    data = unmarshal_data(entry, "amd-vcek", _VCEK_MEMBERS)
    try:
        der = decode_base64("vcek_der_base64", _json.string(data, "vcek_der_base64"))
    except EncodingError as err:
        raise EncodingError(f"amd-vcek collateral entry {entry.id!r}: {err}") from err
    return AMDVCEK(vcek_der=der, cert_chain_pem=_json.string(data, "cert_chain_pem"))


def decode_amd_crl(entry: Entry) -> AMDCRL:
    data = unmarshal_data(entry, "amd-crl", _CRL_MEMBERS)
    try:
        der = decode_base64("crl_der_base64", _json.string(data, "crl_der_base64"))
    except EncodingError as err:
        raise EncodingError(f"amd-crl collateral entry {entry.id!r}: {err}") from err
    return AMDCRL(crl_der=der)
