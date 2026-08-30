"""Intel TDX quote verification for v3 documents: full DCAP quote-v4
authentication against the pinned Intel SGX root over replayed PCS collateral
(Go: verifier/quote/tdx + the go-tdx-guest subset its configuration
exercises), plus policy expectation assembly and validation."""

from .authenticate import TdxQuote, tdx_authenticate
from .expectations import CodeRegisters, TdxExpectations, tdx_assemble, tdx_validate

__all__ = [
    "TdxQuote",
    "tdx_authenticate",
    "CodeRegisters",
    "TdxExpectations",
    "tdx_assemble",
    "tdx_validate",
]
