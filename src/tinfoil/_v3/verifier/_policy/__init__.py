"""What a verified quote is appraised against: which machines are endorsed, which platform configurations they may
run, and the policy that each must satisfy."""

from tinfoil._v3.verifier._policy.artifact import (
    ARTIFACT_FORMAT,
    ARTIFACT_FORMAT_V2,
    PLATFORM_SEV_SNP,
    PLATFORM_TDX,
    Artifact,
    PlatformMeasurement,
    Policy,
    parse,
)
from tinfoil._v3.verifier._policy.sev import TCB, GuestPolicy, SEVSNPPolicy, SNPPlatform, validate_policy_version
from tinfoil._v3.verifier._policy.shape import Shape, Stack, format_shape, satisfies
from tinfoil._v3.verifier._policy.tdx import PolicyError, TDXPolicy, decode_hex, validate_policy_hex

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
    "decode_hex",
    "format_shape",
    "parse",
    "satisfies",
    "validate_policy_hex",
    "validate_policy_version",
]
