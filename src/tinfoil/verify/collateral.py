"""Collateral a v3 attestation document carries, as decoded by parsing.

Collateral is unendorsed transport: every entry is authenticated by its own
signature chain during verification, so a decoded entry is not trusted and a
tampered one can only cause rejection.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

__all__ = [
    "AmdCrl",
    "AmdVcek",
    "CPUEndorsements",
    "Freshness",
    "IntelPcs",
    "PcsResponse",
    "SigstoreRef",
]


@dataclass(frozen=True, slots=True)
class AmdVcek:
    """Decoded amd-vcek collateral: the chip's VCEK and the chain it issues through."""

    vcek_der: bytes
    # The ASK then the ARK certificate, PEM-encoded.
    cert_chain_pem: str


@dataclass(frozen=True, slots=True)
class AmdCrl:
    """Decoded amd-crl collateral: the AMD KDS revocation list for the product line."""

    crl_der: bytes


@dataclass(frozen=True, slots=True)
class PcsResponse:
    """One captured Intel PCS response.

    Headers are kept because Intel delivers issuer chains in response headers.
    """

    url: str
    headers: Mapping[str, tuple[str, ...]]
    body: bytes

    def __post_init__(self) -> None:
        headers = {name: tuple(values) for name, values in self.headers.items()}
        object.__setattr__(self, "headers", MappingProxyType(headers))


@dataclass(frozen=True, slots=True)
class IntelPcs:
    """Decoded intel-pcs collateral: Intel PCS responses captured for offline replay."""

    responses: tuple[PcsResponse, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "responses", tuple(self.responses))


@dataclass(frozen=True, slots=True, kw_only=True)
class CPUEndorsements:
    """Vendor collateral that chains CPU evidence to its vendor root.

    Which members are required depends on the evidence format; CPU evidence
    authentication rejects evidence missing one.
    """

    amd_vcek: AmdVcek | None = None
    amd_crl: AmdCrl | None = None
    intel_pcs: IntelPcs | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class SigstoreRef:
    """A Sigstore reference-values entry: a bundle and the release it names.

    ``repo`` and ``tag`` are hints; trust comes from verifying ``bundle``
    against the expected signing identity and ``digest``.
    """

    repo: str | None
    tag: str | None
    digest: str
    # The Sigstore bundle, as JSON.
    bundle: bytes


@dataclass(frozen=True, slots=True)
class Freshness:
    """A freshness witness for a reference-values artifact."""

    format: str
    # The signed bundle, as JSON.
    bundle: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class _Collateral:
    """Decoded collateral: for each purpose the verifier knows, the first entry serving it."""

    # Endorsement collateral for the reserved CPU subject, of every platform.
    cpu: CPUEndorsements = CPUEndorsements()
    sigstore_code: SigstoreRef | None = None
    sigstore_platform: SigstoreRef | None = None
    # Freshness witnesses by entry ID.
    freshness: Mapping[str, Freshness] = field(default_factory=lambda: MappingProxyType({}))


def _decode(entries: list[Any]) -> _Collateral:
    """Check every entry's shape and decode every entry of a known role and format."""
    raise NotImplementedError
