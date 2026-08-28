"""AMD SEV-SNP quote verification (Go: verifier/quote/sev + the configured
subset of the forked tinfoilsh/go-sev-guest). Authentication failures raise
VerificationError("QUOTE_REJECTED"); policy-comparison failures
VerificationError("POLICY_REJECTED")."""

from .authenticate import (
    PRODUCT_GENOA,
    PRODUCT_TURIN,
    SevQuote,
    decode_cert_chain,
    sev_authenticate,
)
from .expectations import SevExpectations, sev_assemble, sev_validate
from .identity import identity

__all__ = [
    "PRODUCT_GENOA",
    "PRODUCT_TURIN",
    "SevQuote",
    "SevExpectations",
    "decode_cert_chain",
    "identity",
    "sev_authenticate",
    "sev_assemble",
    "sev_validate",
]
