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
    "ConfigEndorsement",
    "Freshness",
    "IntelPcs",
    "PcsResponse",
    "Runtime",
    "RuntimeReference",
    "SigstoreRef",
]


@dataclass(frozen=True, slots=True)
class AmdVcek:
    """Decoded amd-vcek collateral: the chip's VCEK and the chain it issues through."""

    vcek_der: bytes
    cert_chain_pem: str
    """The ASK then the ARK certificate, PEM-encoded."""


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
    bundle: bytes
    """The Sigstore bundle, as JSON."""


@dataclass(frozen=True, slots=True)
class Freshness:
    """A freshness witness or approval for a reference-values artifact."""

    format: str
    bundle: bytes
    """The signed bundle, as JSON."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigEndorsement:
    """Untrusted config material decoded from a document.

    Plain config collateral has no ``reference`` or ``bundle`` and needs a
    caller's config authorizer. A signed reference must match the
    independently verified endorsement.
    """

    config: bytes
    reference: str | None = None
    bundle: bytes | None = None
    """The approval bundle, as JSON."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeReference:
    """The runtime manifest release an endorsed config pins."""

    repo: str
    tag: str
    digest: str

    def validate(self) -> None:
        """Raise ValueError unless this names a canonical cvmimage release."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True, kw_only=True)
class Runtime:
    """Decoded runtime collateral: the manifest and its provenance bundle."""

    reference: RuntimeReference
    manifest: bytes
    bundle: bytes
    """The Sigstore bundle, as JSON."""


@dataclass(frozen=True, slots=True, kw_only=True)
class _Collateral:
    """Decoded collateral: for each purpose the verifier knows, the first entry serving it."""

    cpu: CPUEndorsements = CPUEndorsements()
    """Endorsement collateral for the reserved CPU subject, of every platform."""
    sigstore_code: SigstoreRef | None = None
    sigstore_platform: SigstoreRef | None = None
    config: ConfigEndorsement | None = None
    runtime: Runtime | None = None
    freshness: Mapping[str, Freshness] = field(default_factory=lambda: MappingProxyType({}))
    """Freshness witnesses and approvals by entry ID."""
    platform_entries: int = 0
    """How many entries claim the platform ID or the sigstore-platform format."""
    config_platform: SigstoreRef | None = None
    """The sigstore-platform entry with the reserved platform ID."""

    def unambiguous_config_platform(self) -> SigstoreRef | None:
        """The platform reference config verification uses, or None when absent.

        Raises ValueError when more than one entry could serve as it.
        """
        if self.platform_entries == 0:
            return None
        if self.platform_entries != 1 or self.config_platform is None:
            raise ValueError("conflicting platform collateral for config verification")
        return self.config_platform


def _decode(entries: list[Any]) -> _Collateral:
    """Check every entry's shape and decode every entry of a known role and format."""
    raise NotImplementedError
