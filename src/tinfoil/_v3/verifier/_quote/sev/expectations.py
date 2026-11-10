"""Translation of an endorsed SEV-SNP policy into complete validation expectations, and their one application."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier._policy import TCB, SEVSNPPolicy
from tinfoil._v3.verifier._quote.sev.authenticate import Quote
from tinfoil._v3.verifier._quote.sev.lib.abi import Report, SnpPlatformInfo, SnpPolicy
from tinfoil._v3.verifier._quote.sev.lib.tcb import TCBParts
from tinfoil._v3.verifier._quote.sev.lib.validate import ValidationOptions

REPORT_DATA_SIZE = 64
HOST_DATA_SIZE = 32
FAMILY_ID_SIZE = 16
IMAGE_ID_SIZE = 16


class SevPolicyError(ValueError):
    """A policy that cannot be translated for the quote's product line, or a report that does not satisfy it."""


@dataclass(frozen=True, slots=True)
class Expectations:
    """The fully translated SEV-SNP expected state, resolved at assembly so that validation performs no translation
    and no lookups.

    ``options`` holds the bounds and equalities that the library applies;
    the ``want_*`` fields are compared by strict equality on top, since
    the library treats the guest policy and platform info as maximum
    masks. The library records are mutable; callers must not mutate them.
    """

    options: ValidationOptions
    want_guest_policy: SnpPolicy
    want_platform_info: SnpPlatformInfo
    minimum_launch_mitigation_vector: int
    minimum_current_mitigation_vector: int


def assemble(policy: SEVSNPPolicy, quote: Quote, launch: bytes, report_data: bytes) -> Expectations:
    """Combine the policy with the launch measurement, REPORT_DATA and the authenticated CHIP_ID.

    ``launch`` is 48 bytes and ``report_data`` 64; the CHIP_ID comes from
    ``quote.identity``.
    """
    raise NotImplementedError


def validate(expectations: Expectations, quote: Quote) -> None:
    """Compare a quote against the assembled expected state: the library validation plus the strict-equality
    companions and the signer check. This is the only SEV enforcement entry point, so no subset of the policy
    can be applied.

    The guest policy is compared with the ABI version taken from the
    report (the version is a floor, enforced by the options); PLATFORM_INFO
    is compared exactly; the report must be launched without an author key
    or ID block.
    """
    raise NotImplementedError


def check_signer(report: Report) -> None:
    """Reject a report with an author key, a non-zero ID key digest or a non-zero author key digest: ID-block
    launches are unsupported. (A masked CHIP_ID is rejected at authentication.)"""
    raise NotImplementedError


def expected_guest_policy(policy: SEVSNPPolicy) -> SnpPolicy:
    """The guest policy bits the policy requires, with the ABI version left at zero."""
    raise NotImplementedError


def expected_platform_info(policy: SEVSNPPolicy) -> SnpPlatformInfo:
    """The PLATFORM_INFO bits the policy requires."""
    raise NotImplementedError


def _options(policy: SEVSNPPolicy, product_line: str) -> ValidationOptions:
    """Translate the policy block into validation options for ``product_line``.

    The policy must validate. Genoa forbids ``fmc_spl`` and
    ``iommu_write_safe``; Turin requires both. The API and ABI versions
    parse as ``maj.min``; the TCBs translate per product line; the hex
    fields decode to their sizes; the ABI floor rides in the guest policy.
    """
    raise NotImplementedError


def tcb_parts(field: str, product_line: str, tcb: TCB) -> TCBParts:
    """Translate a policy TCB into the product line's TCB layout; ``field`` names it in errors."""
    raise NotImplementedError


def parse_version(name: str, version: str) -> int:
    """``maj.min`` as ``maj << 8 | min``."""
    raise NotImplementedError


def parse_version_parts(name: str, version: str) -> tuple[int, int]:
    """``maj.min`` as two decimal uint8 values; anything else is an error naming ``name``."""
    raise NotImplementedError
