"""What a verified quote is appraised against: which machines are endorsed, which platform configurations they may
run, and the policy that each must satisfy."""

from tinfoil.verifier._policy._common import PolicyError
from tinfoil.verifier._policy.artifact import (
    ARTIFACT_FORMAT,
    ARTIFACT_FORMAT_V2,
    PLATFORM_SEV_SNP,
    PLATFORM_TDX,
    Artifact,
    PlatformMeasurement,
    Policy,
    parse,
)
from tinfoil.verifier._policy.sev import TCB, GuestPolicy, SEVSNPPolicy, SNPPlatform
from tinfoil.verifier._policy.shape import Shape, Stack, satisfies
from tinfoil.verifier._policy.tdx import TDXPolicy

__all__ = [
    "ARTIFACT_FORMAT",
    "ARTIFACT_FORMAT_V2",
    "PLATFORM_SEV_SNP",
    "PLATFORM_TDX",
    "TCB",
    "Artifact",
    "GuestPolicy",
    "PlatformMeasurement",
    "Policy",
    "PolicyError",
    "SEVSNPPolicy",
    "SNPPlatform",
    "Shape",
    "Stack",
    "TDXPolicy",
    "parse",
    "satisfies",
]
