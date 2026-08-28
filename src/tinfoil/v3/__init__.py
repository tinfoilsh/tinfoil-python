"""v3 attestation verifier, a 1:1 port of tinfoil-go feat/v3 (see PORTING.md).

Foundation surface: errors, strict JSON, envelope, measurement, policy, and
the embedded production trust anchors. The provenance, sev, tdx, and
integration modules extend this package per the module map in PORTING.md.
"""

from .errors import (
    ENVELOPE_REJECTED,
    POLICY_REJECTED,
    PROVENANCE_REJECTED,
    QUOTE_REJECTED,
    CollateralNotFoundError,
    VerificationError,
)
from .envelope import NONCE_SIZE, check, parse_document, random_nonce
from .measurement import (
    SEV_GUEST_V2,
    SNP_TDX_MULTI_PLATFORM_V1,
    TDX_GUEST_V2,
    Measurement,
)
from .policy import Artifact, Policy, Shape, parse_artifact, policy_for
from .quote import (
    AssembledPolicy,
    Authenticated,
    assemble_and_validate,
    assembled_validate,
    quote_assemble,
    quote_authenticate,
)
from .client import (
    VerifiedDocumentV3,
    hpke_public_key,
    tls_public_key_fp,
    verify_document_v3,
)
from .fetch import fetch_attestation

__all__ = [
    "ENVELOPE_REJECTED",
    "PROVENANCE_REJECTED",
    "QUOTE_REJECTED",
    "POLICY_REJECTED",
    "VerificationError",
    "CollateralNotFoundError",
    "NONCE_SIZE",
    "parse_document",
    "check",
    "random_nonce",
    "Measurement",
    "SEV_GUEST_V2",
    "TDX_GUEST_V2",
    "SNP_TDX_MULTI_PLATFORM_V1",
    "Artifact",
    "Policy",
    "Shape",
    "parse_artifact",
    "policy_for",
    "Authenticated",
    "AssembledPolicy",
    "quote_authenticate",
    "quote_assemble",
    "assembled_validate",
    "assemble_and_validate",
    "VerifiedDocumentV3",
    "verify_document_v3",
    "tls_public_key_fp",
    "hpke_public_key",
    "fetch_attestation",
]
