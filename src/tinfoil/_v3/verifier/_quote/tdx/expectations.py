"""Translation of an endorsed TDX policy into complete validation expectations, and their one application."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier._measurement import TDX
from tinfoil._v3.verifier._policy import TDXPolicy
from tinfoil._v3.verifier._quote.tdx.authenticate import Quote
from tinfoil._v3.verifier._quote.tdx.lib.validate import PolicyOptions

MR_CONFIG_ID_SIZE = 48
MR_OWNER_SIZE = 48
MR_OWNER_CONFIG_SIZE = 48
REPORT_DATA_SIZE = 64


class TdxPolicyError(ValueError):
    """A policy that cannot be translated, or a quote that does not satisfy it."""


@dataclass(frozen=True, slots=True)
class Expectations:
    """The fully translated TDX expected state, resolved at assembly so that validation performs no translation and
    no lookups. The collateral floor is separate because it is not a quote field."""

    options: PolicyOptions
    minimum_tcb_evaluation_data_number: int


def assemble(policy: TDXPolicy, measurement: TDX, report_data: bytes, config_id: bytes) -> Expectations:
    """Translate complete reference values into validation options: the policy's fields, the five registers of
    ``measurement``, the 64-byte ``report_data`` and the 48-byte ``config_id``."""
    raise NotImplementedError


def validate(expectations: Expectations, quote: Quote) -> None:
    """Compare a quote against the assembled expected state: the library validation plus the collateral floor
    (the quote's evaluation number must reach the policy minimum). This is the only TDX enforcement entry point,
    so no subset of the policy can be applied."""
    raise NotImplementedError


def _options(policy: TDXPolicy) -> PolicyOptions:
    """Translate the policy block into validation options.

    The policy must validate; the QE vendor id, minimum TEE TCB SVN,
    MR_SEAM, TD attributes and XFAM decode from hex to their sizes.
    MR_OWNER and MR_OWNER_CONFIG are pinned to zero; MR_CONFIG_ID is set
    at assembly. The header's QE and PCE SVN minimums are left unset: those
    bytes are reserved in quote v4 and pinned to zero at authentication.
    """
    raise NotImplementedError
