"""AMD SEV-SNP: authenticate a report against the pinned AMD roots and assemble complete validation expectations
from an endorsed policy."""

from tinfoil._v3.verifier._quote.sev.authenticate import (
    PRODUCT_GENOA,
    PRODUCT_TURIN,
    Evidence,
    Options,
    Quote,
    SevAuthenticationError,
)
from tinfoil._v3.verifier._quote.sev.expectations import Expectations, SevPolicyError, assemble
from tinfoil._v3.verifier._quote.sev.identity import CHIP_ID_SIZE

__all__ = [
    "CHIP_ID_SIZE",
    "PRODUCT_GENOA",
    "PRODUCT_TURIN",
    "Evidence",
    "Expectations",
    "Options",
    "Quote",
    "SevAuthenticationError",
    "SevPolicyError",
    "assemble",
]
