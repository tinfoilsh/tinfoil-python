"""The runtime v1 and config-endorsement v1 contract: the runtime manifest fixes the launch registers and the config
hash binds HOST_DATA (SEV-SNP) or MR_CONFIG_ID (TDX)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tinfoil._v3.verifier._measurement import Expected
from tinfoil._v3.verifier._policy import Artifact
from tinfoil._v3.verifier._quote.resolve import ResolvedValues
from tinfoil._v3.verifier._runtime import Measurements

if TYPE_CHECKING:
    from tinfoil._v3.verifier._quote.quote import Authenticated


@dataclass(frozen=True, slots=True)
class ConfigReferenceValues:
    endorsements: Artifact
    runtime: Measurements | None
    """The manifest's measurements; both launches are required at resolution."""
    hash: bytes
    """SHA-256 of the exact config bytes."""


def resolve_config(refs: ConfigReferenceValues, quote: Authenticated, pins: Expected | None) -> ResolvedValues:
    """Resolve the config contract for a quote.

    Requires complete runtime measurements (both launches). Looks up the
    endorsed policy. On SEV-SNP the policy may not set ``host_data`` (the
    config hash takes its place) and the code is the manifest's launch
    measurement; on TDX the policy may not list ``platform_measurements``,
    the config hash becomes MR_CONFIG_ID and the code is the manifest's
    five registers. Then the pins apply.
    """
    raise NotImplementedError
