"""The legacy repository-release contract: the release fixes the code registers and the platform endorsements
supply the rest."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tinfoil._v3.verifier._measurement import Expected, ExpectedSEVSNP, ExpectedTDX
from tinfoil._v3.verifier._policy import Artifact, Shape
from tinfoil._v3.verifier._quote.resolve import ResolvedValues

if TYPE_CHECKING:
    from tinfoil._v3.verifier._quote.quote import Authenticated


@dataclass(frozen=True, slots=True)
class LegacyReferenceValues:
    endorsements: Artifact
    sevsnp: ExpectedSEVSNP
    """The registers the release fixes on SEV-SNP."""
    tdx: ExpectedTDX
    """The registers the release fixes on TDX: RTMR1 and RTMR2 are set, the other registers are left
    unconstrained and are resolved from the platform endorsements and the pins."""
    shape: Shape | None
    """The VM shape the release declares; selects the TDX platform measurement."""


def resolve_legacy(refs: LegacyReferenceValues, quote: Authenticated, pins: Expected | None) -> ResolvedValues:
    """Resolve the legacy contract for a quote.

    Looks up the endorsed policy and takes the release's registers for the
    quote's platform, then applies the pins. On SEV-SNP the policy's
    ``host_data`` is the expectation. On TDX the release fixes only RTMR1
    and RTMR2: the platform endorsements resolve MRTD and RTMR0 from the
    quote's own values and the required shape, and an unpinned RTMR3 must
    be zero.
    """
    raise NotImplementedError
