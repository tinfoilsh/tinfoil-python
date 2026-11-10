"""CPU evidence verification in three phases.

1. Authenticate: verify the quote's signature chain up to the pinned vendor
   root from document-carried collateral only. Authenticated, not yet
   appraised.
2. Assemble: resolve the complete policy, every value the quote must
   attest, as one object. Entries differ only in which verified source
   resolves them (policy artifact, code provenance, document); that
   distinction ends here. Assembly fails if any entry cannot be resolved.
3. Validate: one comparison of the quote against the assembled policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TypeAlias

from tinfoil._v3.verifier._document.collateral.collateral import CPUEndorsements
from tinfoil._v3.verifier._document.document import CpuEvidence, Document
from tinfoil._v3.verifier._measurement import SEVSNP, TDX, Expected, ExpectedSEVSNP, ExpectedTDX
from tinfoil._v3.verifier._policy import PLATFORM_SEV_SNP, PLATFORM_TDX
from tinfoil._v3.verifier._quote.config import ConfigReferenceValues
from tinfoil._v3.verifier._quote.legacy import LegacyReferenceValues
from tinfoil._v3.verifier._quote.sev.authenticate import Quote as SevQuote
from tinfoil._v3.verifier._quote.sev.expectations import Expectations as SevExpectations
from tinfoil._v3.verifier._quote.tdx.authenticate import Quote as TdxQuote
from tinfoil._v3.verifier._quote.tdx.expectations import Expectations as TdxExpectations

ReferenceValues: TypeAlias = LegacyReferenceValues | ConfigReferenceValues
"""Authenticated inputs for one verification contract; each resolves every workload expectation before assembly."""


class QuoteError(ValueError):
    """Hardware evidence that does not authenticate, or evidence of an unsupported format."""


class AssemblyError(ValueError):
    """A policy that cannot be completed for the quote: an unendorsed machine, a pin conflict, an open register."""


@dataclass(frozen=True, slots=True)
class TestOnlyRoots:
    """Replacement vendor anchors for the conformance harness; None keeps the embedded anchor for that platform.

    A supplied anchor destroys the guarantee that evidence chains to AMD or
    Intel, so the public verifier never exposes this.
    """

    amd: bytes | None = None
    """An AMD KDS ``cert_chain`` PEM (ASK then ARK)."""
    intel: bytes | None = None
    """An Intel SGX root certificate PEM."""


@dataclass(frozen=True, slots=True)
class QuoteOptions:
    """Per-authentication overrides. None, and the default value, select the embedded vendor roots."""

    test_only_roots: TestOnlyRoots | None = None


@dataclass(frozen=True, slots=True)
class AuthenticatedSEVSNP:
    """A signature-verified SEV-SNP report, not yet compared against any expected value."""

    identity: str
    """The authenticated machine identifier: CHIP_ID, lowercase hex."""
    measurement: SEVSNP
    """The authenticated launch measurement."""
    evidence: CpuEvidence
    """The evidence that was authenticated, so that assembly can check it came from the document being appraised."""
    quote: SevQuote

    @property
    def platform(self) -> str:
        return PLATFORM_SEV_SNP


@dataclass(frozen=True, slots=True)
class AuthenticatedTDX:
    """A signature-verified TDX quote, not yet compared against any expected value."""

    identity: str
    """The authenticated machine identifier: PPID, lowercase hex."""
    measurement: TDX
    """The authenticated MRTD and RTMRs."""
    evidence: CpuEvidence
    quote: TdxQuote

    @property
    def platform(self) -> str:
        return PLATFORM_TDX


Authenticated: TypeAlias = AuthenticatedSEVSNP | AuthenticatedTDX
"""A signature-verified quote of either platform; callers distinguish them by type."""


@dataclass(frozen=True, slots=True)
class AssembledSEVSNP:
    """The complete expected state of an SEV-SNP quote, resolved before validation and bound to that quote."""

    code_measurement: ExpectedSEVSNP
    """The registers the release fixes."""
    policy_name: str
    """The matched policy name."""
    quote: AuthenticatedSEVSNP
    expectations: SevExpectations

    @property
    def platform(self) -> str:
        return PLATFORM_SEV_SNP

    def validate(self) -> None:
        """Compare the captured quote against the assembled policy in one call: no lookups, no translation."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class AssembledTDX:
    """The complete expected state of a TDX quote, resolved before validation and bound to that quote."""

    code_measurement: ExpectedTDX
    """The registers the release fixes."""
    policy_name: str
    """The matched policy name."""
    platform_measurement_name: str | None
    """The resolved platform configuration under the legacy contract; None under the config contract."""
    quote: AuthenticatedTDX
    expectations: TdxExpectations

    @property
    def platform(self) -> str:
        return PLATFORM_TDX

    def validate(self) -> None:
        """Compare the captured quote against the assembled policy in one call: no lookups, no translation."""
        raise NotImplementedError


AssembledPolicy: TypeAlias = AssembledSEVSNP | AssembledTDX
"""An assembled policy of either platform; callers distinguish them by type."""


def authenticate(
    evidence: CpuEvidence, endorsements: CPUEndorsements, now: datetime, options: QuoteOptions | None = None
) -> Authenticated:
    """Verify the evidence's signature chain up to the pinned vendor root from the supplied collateral alone.

    SEV-SNP evidence requires the amd-vcek and amd-crl collateral; TDX
    evidence requires the intel-pcs collateral; missing collateral is
    rejected, never fetched. Certificate and CRL windows are appraised at
    ``now``. Any other evidence format is rejected.
    """
    raise NotImplementedError


def assemble(doc: Document, refs: ReferenceValues, pins: Expected | None, quote: Authenticated) -> AssembledPolicy:
    """Combine endorsed machine policy, release measurements, caller pins and the REPORT_DATA that ``doc`` binds.

    ``doc`` must come from ``document.parse`` so that its expected
    REPORT_DATA was recomputed from the caller's nonce, and ``quote`` must
    have been authenticated from ``doc``'s own CPU evidence; either
    failing is an error. Then ``assemble_with``.
    """
    raise NotImplementedError


def assemble_with(
    refs: ReferenceValues, pins: Expected | None, report_data: bytes, quote: Authenticated
) -> AssembledPolicy:
    """``assemble`` against an explicit 64-byte REPORT_DATA.

    The reference values resolve the policy and the expected registers for
    the quote's platform; pins fill unset registers or must agree with the
    resolved value; every register must end up fixed; then the platform's
    ``assemble`` translates the policy into its expectations.
    """
    raise NotImplementedError
