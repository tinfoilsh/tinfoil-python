"""The machine identity of a TDX quote: the PPID from its PCK certificate."""

from __future__ import annotations

from tinfoil._v3.verifier._quote.tdx.lib.abi import QuoteV4
from tinfoil._v3.verifier._quote.tdx.lib.pck import PPID_SIZE as PPID_SIZE
from tinfoil._v3.verifier._x509.certificate import Certificate


def identity(quote: QuoteV4) -> str:
    """The machines-map lookup key: the 16-byte PPID from the PCK leaf's SGX extension, as lowercase hex.

    The PPID is authenticated because the PCK chain is verified to the
    Intel root during quote verification; call this only after that
    succeeds. A malformed PPID is an error.
    """
    raise NotImplementedError


def pck_leaf_certificate(quote: QuoteV4) -> Certificate:
    """The first certificate of the quote's PCK chain (certification data type 5 inside type 6); a quote without a
    PEM chain is an error."""
    raise NotImplementedError
