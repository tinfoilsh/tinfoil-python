"""Policy assembly and validation (block B4).

Assembly resolves the complete expected state of a quote as one object:
endorsed machine policy, release measurements, caller register pins and the
REPORT_DATA the document binds. Validation compares the authenticated quote
against it in one step, with no lookups.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import _policy
from ..document import Document
from ..measurement import Measurement
from .authenticate import AuthenticatedQuote


@dataclass(frozen=True, slots=True, kw_only=True)
class LegacyReferenceValues:
    """Reference values of the legacy repository-release contract."""

    endorsements: _policy.Artifact
    code: Measurement
    shape: _policy.Shape


class AssembledPolicy:
    """The complete expected state of one quote, resolved before validation.

    It captures the quote it was assembled for, so it cannot be applied to
    any other quote.
    """

    @property
    def code_measurement(self) -> Measurement:
        """The release measurement the policy was assembled from."""
        raise NotImplementedError

    def validate(self) -> None:
        """Compare the captured quote against the policy; raise on any mismatch."""
        raise NotImplementedError


def validate_pins(pins: Measurement) -> None:
    """Raise ValueError unless ``pins`` are well-formed caller register pins."""
    raise NotImplementedError


def assemble(
    document: Document, references: LegacyReferenceValues, pins: Measurement | None, quote: AuthenticatedQuote
) -> AssembledPolicy:
    """Assemble the policy ``quote`` must satisfy.

    ``document`` must come from parse(), and ``quote`` must be authenticated
    from that document's own CPU evidence.
    """
    raise NotImplementedError
