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
from tinfoil._v3.verifier._measurement import Expected, Measurement
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
class Authenticated:
    """A signature-verified quote, not yet compared against any expected value."""

    platform: str
    """PLATFORM_SEV_SNP or PLATFORM_TDX."""
    identity: str
    """The authenticated machine identifier (SEV CHIP_ID or TDX PPID), lowercase hex."""
    measurement: Measurement
    """The authenticated launch measurement (SEV-SNP) or MRTD and RTMRs (TDX)."""
    evidence: CpuEvidence
    """The evidence that was authenticated, so that assembly can check it came from the document being appraised."""
    sev: SevQuote | None = None
    tdx: TdxQuote | None = None


@dataclass(frozen=True, slots=True)
class AssembledPolicy:
    """The complete expected state of a quote, resolved before validation and bound to the quote it was built for."""

    code_measurement: Expected
    """The registers the release fixes on the quote's platform."""
    policy_name: str
    """The matched policy name."""
    platform_measurement_name: str
    """The resolved TDX platform configuration; "" for SEV-SNP."""
    quote: Authenticated
    sev: SevExpectations | None = None
    tdx: TdxExpectations | None = None

    def validate(self) -> None:
        """Compare the captured quote against the assembled policy in one platform call: no lookups, no
        translation."""
        raise NotImplementedError


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
