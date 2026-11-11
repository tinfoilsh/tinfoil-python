"""Intel TDX: authenticate a quote against the pinned Intel SGX root by replaying the document's captured PCS
collateral, and assemble complete validation expectations from an endorsed policy."""

from tinfoil.verifier._quote.tdx.authenticate import (
    Evidence,
    Options,
    Quote,
    TdxAuthenticationError,
    platform_measurements,
)
from tinfoil.verifier._quote.tdx.expectations import Expectations, TdxPolicyError, assemble
from tinfoil.verifier._quote.tdx.identity import PPID_SIZE
from tinfoil.verifier._quote.tdx.pcs import PCSReplay, PCSReplayError

__all__ = [
    "PPID_SIZE",
    "Evidence",
    "Expectations",
    "Options",
    "PCSReplay",
    "PCSReplayError",
    "Quote",
    "TdxAuthenticationError",
    "TdxPolicyError",
    "assemble",
    "platform_measurements",
]
