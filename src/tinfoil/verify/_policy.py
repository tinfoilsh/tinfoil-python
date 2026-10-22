"""The platform-endorsements artifact: what a verified quote is appraised against.

The artifact names which machines are endorsed, which platform
configurations they may run, and the policy each must satisfy. It must come
from a verified reference-values source; this module performs no
cryptography. Parsing is fail-closed: unknown members, malformed identifiers,
dangling references or platform mismatches reject, so a policy that cannot
be fully enforced is never partially applied.
"""

from __future__ import annotations

from dataclasses import dataclass

ARTIFACT_FORMAT = "https://tinfoil.sh/predicate/platform-endorsements/v1"

PLATFORM_SEV_SNP = "sev-snp"
PLATFORM_TDX = "tdx"


@dataclass(frozen=True, slots=True, kw_only=True)
class Shape:
    """The launch dimensions of a VM that determine its platform measurement.

    ``disks`` counts every attached disk. ``gpus`` is None when a measured
    configuration does not record it; a code artifact always declares it.
    """

    cpus: int
    memory_mb: int
    disks: int
    gpus: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Artifact:
    """A parsed platform-endorsements artifact."""

    format: str
