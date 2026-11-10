"""The PPID identity of a TDX quote."""

from __future__ import annotations

import pytest

from tests.v3 import pki
from tests.v3 import tdx_builders as tb
from tinfoil._v3.verifier._quote.tdx.identity import PPID_SIZE, IdentityError, identity, pck_leaf_certificate
from tinfoil._v3.verifier._quote.tdx.lib.abi import parse_quote
from tinfoil._v3.verifier._quote.tdx.lib.chain import common_name


def test_identity_is_the_lowercase_hex_ppid() -> None:
    quote = parse_quote(tb.Scenario().quote())
    assert PPID_SIZE == 16
    assert identity(quote) == tb.PPID.hex()
    assert common_name(pck_leaf_certificate(quote).subject) == tb.PCK_CN


def test_identity_requires_a_sixteen_byte_ppid() -> None:
    short = tb.sgx_extension(ppid=bytes(15), extra=(tb.attribute(f"{tb._SGX_OID}.9", tb.octet_string(b"")),))
    with pytest.raises(IdentityError, match="PPID"):
        identity(parse_quote(tb.Scenario(extension_value=short).quote()))
    without = tb.sequence(
        tb.tcb_attribute(),
        tb.attribute(f"{tb._SGX_OID}.3", tb.octet_string(bytes(2))),
        tb.attribute(f"{tb._SGX_OID}.4", tb.octet_string(bytes(6))),
        tb.attribute(f"{tb._SGX_OID}.9", tb.octet_string(b"")),
    )
    with pytest.raises(IdentityError, match="malformed PPID ''"):
        identity(parse_quote(tb.Scenario(extension_value=without).quote()))


def test_quote_without_a_chain_is_an_error() -> None:
    quote = parse_quote(tb.quote_bytes(pki.p256(), b"garbage"))
    with pytest.raises(IdentityError, match="PCK certificate chain"):
        identity(quote)
