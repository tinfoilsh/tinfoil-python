"""The collateral format registry and the decoded set: for each purpose that the verifier knows, the first entry that
serves it."""

from __future__ import annotations

from dataclasses import dataclass, field

from tinfoil.verifier._document.collateral.config import (
    CONFIG_FORMATS,
    CONFIG_ID,
    ConfigEndorsement,
    decode_config_endorsement,
)
from tinfoil.verifier._document.collateral.entry import (
    ROLE_ENDORSEMENT,
    ROLE_REFERENCE_VALUES,
    SUBJECT_CPU,
    Entry,
    validate,
)
from tinfoil.verifier._document.collateral.runtime import (
    PLATFORM_ID,
    RUNTIME_ID,
    RUNTIME_V1_FORMAT,
    Runtime,
    decode_runtime,
)
from tinfoil.verifier._document.collateral.sev import AMDCRL, AMDVCEK, decode_amd_crl, decode_amd_vcek
from tinfoil.verifier._document.collateral.sigstore import (
    Freshness,
    SigstoreRef,
    decode_freshness,
    decode_sigstore_ref,
)
from tinfoil.verifier._document.collateral.tdx import IntelPCS, decode_intel_pcs

# Collateral format registry (v3).
FORMAT_V2 = "https://tinfoil.sh/predicate/attestation-collaterals/v2"
"""Legacy GitHub workload-release collateral."""
FORMAT_V3 = "https://tinfoil.sh/predicate/attestation-collaterals/v3"
"""Config, runtime and platform collateral."""

AMD_VCEK_V1_FORMAT = "https://tinfoil.sh/collateral/amd-vcek/v1"
"""{vcek_der_base64, cert_chain_pem}."""
AMD_CRL_V1_FORMAT = "https://tinfoil.sh/collateral/amd-crl/v1"
"""{crl_der_base64}: the AMD KDS CRL for the product line, for offline VCEK revocation checking."""
INTEL_PCS_V1_FORMAT = "https://tinfoil.sh/collateral/intel-pcs/v1"
"""Captured Intel PCS responses (TCB info, QE identity, CRLs) for offline TDX quote verification."""
NVIDIA_GPU_V1_FORMAT = "https://tinfoil.sh/collateral/nvidia-gpu/v1"
"""NVIDIA cert chains / RIM material."""
SIGSTORE_CODE_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-code/v1"
"""The code-provenance Sigstore bundle {repo, tag, digest, sigstore_bundle}."""
SIGSTORE_PLATFORM_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-platform/v1"
"""The platform-endorsements Sigstore bundle {repo, tag, digest, sigstore_bundle}."""
SIGSTORE_FRESHNESS_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-freshness/v1"
"""A freshness witness for a Sigstore reference-values artifact."""
ARTIFACT_FRESHNESS_V1_FORMAT = "https://tinfoil.sh/collateral/artifact-freshness/v1"
"""A Tinfoil-signed release approval."""

# Freshness entry ids associate each witness with the reference-values entry that it refreshes.
FRESHNESS_ID_CODE = "code-freshness"
FRESHNESS_ID_PLATFORM = "platform-freshness"
FRESHNESS_ID_RUNTIME = "runtime-freshness"


class NotFoundError(LookupError):
    """A document carries no collateral entry for the requested purpose.

    Malformed collateral never reaches the document's accessors, because
    decoding rejects it. Verification classifies missing required collateral
    as a verification error while preserving this cause.
    """


class ConflictError(ValueError):
    """Collateral entries that contend for one reserved purpose."""


@dataclass(frozen=True, slots=True)
class CPUEndorsements:
    """The decoded vendor collateral that chains CPU evidence to its vendor root.

    None means no such collateral; which fields are required depends on the
    evidence format, and CPU-evidence authentication rejects evidence that
    is missing one.
    """

    amd_vcek: AMDVCEK | None = None
    amd_crl: AMDCRL | None = None
    intel_pcs: IntelPCS | None = None


@dataclass(frozen=True, slots=True)
class Set:
    """Decoded collateral: for each purpose the verifier knows, the first entry serving it."""

    cpu: CPUEndorsements = CPUEndorsements()
    """The endorsement collateral for SUBJECT_CPU, of every platform."""
    sigstore_code: SigstoreRef | None = None
    sigstore_platform: SigstoreRef | None = None
    config: ConfigEndorsement | None = None
    runtime: Runtime | None = None
    freshness: dict[str, Freshness] = field(default_factory=dict)
    """The freshness witnesses by entry id."""
    platform_count: int = 0
    config_platform_ref: SigstoreRef | None = None

    def config_platform(self) -> SigstoreRef:
        """The one platform reference that config verification requires."""
        if self.platform_count == 0:
            raise NotFoundError("no platform reference-values entry")
        if self.platform_count != 1 or self.config_platform_ref is None:
            raise ConflictError("conflicting platform collateral for config verification")
        return self.config_platform_ref


def decode(entries: tuple[Entry, ...]) -> Set:
    """Check the entries' shape and decode every entry of a known role and format.

    A malformed entry fails whether or not verification would read it.

    An entry whose role and format have no decoder (an unknown format, a
    known format under another role) is checked for shape only and not
    retained. Config and runtime entries require their reserved ids, formats
    and roles. An endorsement entry serves the CPU only when its subjects
    include SUBJECT_CPU.
    """
    validate(entries)
    amd_vcek: AMDVCEK | None = None
    amd_crl: AMDCRL | None = None
    intel_pcs: IntelPCS | None = None
    sigstore_code: SigstoreRef | None = None
    sigstore_platform: SigstoreRef | None = None
    config: ConfigEndorsement | None = None
    runtime: Runtime | None = None
    freshness: dict[str, Freshness] = {}
    platform_count = 0
    config_platform_ref: SigstoreRef | None = None

    for entry in entries:
        cpu = SUBJECT_CPU in entry.subjects
        if entry.id == PLATFORM_ID or entry.format == SIGSTORE_PLATFORM_V1_FORMAT:
            platform_count += 1
        if entry.id == CONFIG_ID or entry.format in CONFIG_FORMATS:
            if entry.id != CONFIG_ID or entry.format not in CONFIG_FORMATS or entry.role != ROLE_REFERENCE_VALUES:
                raise ConflictError(f"conflicting collateral entry for {CONFIG_ID!r}")
            config = decode_config_endorsement(entry)
        elif entry.id == RUNTIME_ID or entry.format == RUNTIME_V1_FORMAT:
            if entry.id != RUNTIME_ID or entry.format != RUNTIME_V1_FORMAT or entry.role != ROLE_REFERENCE_VALUES:
                raise ConflictError(f"conflicting collateral entry for {RUNTIME_ID!r}")
            runtime = decode_runtime(entry)
        elif entry.format == ARTIFACT_FRESHNESS_V1_FORMAT or entry.id == FRESHNESS_ID_RUNTIME:
            if (
                entry.id not in (FRESHNESS_ID_PLATFORM, FRESHNESS_ID_RUNTIME)
                or entry.format != ARTIFACT_FRESHNESS_V1_FORMAT
                or entry.role != ROLE_REFERENCE_VALUES
            ):
                raise ConflictError(f"conflicting artifact freshness collateral {entry.id!r}")
            freshness[entry.id] = decode_freshness(entry)
        elif entry.role == ROLE_ENDORSEMENT and entry.format == AMD_VCEK_V1_FORMAT:
            decoded_vcek = decode_amd_vcek(entry)
            if cpu and amd_vcek is None:
                amd_vcek = decoded_vcek
        elif entry.role == ROLE_ENDORSEMENT and entry.format == AMD_CRL_V1_FORMAT:
            decoded_crl = decode_amd_crl(entry)
            if cpu and amd_crl is None:
                amd_crl = decoded_crl
        elif entry.role == ROLE_ENDORSEMENT and entry.format == INTEL_PCS_V1_FORMAT:
            decoded_pcs = decode_intel_pcs(entry)
            if cpu and intel_pcs is None:
                intel_pcs = decoded_pcs
        elif entry.role == ROLE_REFERENCE_VALUES and entry.format == SIGSTORE_CODE_V1_FORMAT:
            decoded_ref = decode_sigstore_ref(entry)
            if sigstore_code is None:
                sigstore_code = decoded_ref
        elif entry.role == ROLE_REFERENCE_VALUES and entry.format == SIGSTORE_PLATFORM_V1_FORMAT:
            decoded_ref = decode_sigstore_ref(entry)
            if sigstore_platform is None:
                sigstore_platform = decoded_ref
            if entry.id == PLATFORM_ID:
                config_platform_ref = decoded_ref
        elif entry.role == ROLE_REFERENCE_VALUES and entry.format == SIGSTORE_FRESHNESS_V1_FORMAT:
            # validate already rejected duplicate ids.
            freshness[entry.id] = decode_freshness(entry)

    return Set(
        cpu=CPUEndorsements(amd_vcek=amd_vcek, amd_crl=amd_crl, intel_pcs=intel_pcs),
        sigstore_code=sigstore_code,
        sigstore_platform=sigstore_platform,
        config=config,
        runtime=runtime,
        freshness=freshness,
        platform_count=platform_count,
        config_platform_ref=config_platform_ref,
    )
