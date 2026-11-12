"""The machine identity of a TDX quote: the PPID from its PCK certificate."""

from __future__ import annotations

from tinfoil.verifier._quote.tdx.lib.abi import QuoteV4
from tinfoil.verifier._quote.tdx.lib.chain import TdxVerificationError, extract_pck_cert_chain
from tinfoil.verifier._quote.tdx.lib.pck import PPID_SIZE as PPID_SIZE
from tinfoil.verifier._quote.tdx.lib.pck import PckExtensionError, extract_pck_extensions
from tinfoil.verifier._x509.certificate import Certificate


class IdentityError(ValueError):
    """A quote whose PCK certificate carries no well-formed PPID."""


def identity(quote: QuoteV4) -> str:
    """The machines-map lookup key: the 16-byte PPID from the PCK leaf's SGX extension, as lowercase hex.

    The PPID is authenticated because the PCK chain is verified to the
    Intel root during quote verification; call this only after that
    succeeds. A malformed PPID is an error.
    """
    leaf = pck_leaf_certificate(quote)
    try:
        ext = extract_pck_extensions(leaf)
    except PckExtensionError as err:
        raise IdentityError(f"parsing PCK certificate extensions: {err}") from err
    try:
        ppid = bytes.fromhex(ext.ppid)
    except ValueError:
        ppid = b""
    if len(ppid) != PPID_SIZE:
        raise IdentityError(f"PCK certificate carries malformed PPID {ext.ppid!r}")
    # Re-encoded so that the lookup key is canonical lowercase hex whatever
    # the extension parser produced.
    return ppid.hex()


def pck_leaf_certificate(quote: QuoteV4) -> Certificate:
    """The first certificate of the quote's PCK chain (certification data type 5 inside type 6); a quote without a
    PEM chain is an error."""
    try:
        return extract_pck_cert_chain(quote).pck_cert
    except TdxVerificationError as err:
        raise IdentityError(f"PCK certificate chain: {err}") from err
