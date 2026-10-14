"""v3 rejection model: every verification failure raises a VerificationError
tagged with the layer that rejected. The conformance adapter maps the layer to
the wire rejection code; MALFORMED_INPUT is adapter-level and never a
VerificationError layer."""

ENVELOPE_REJECTED = "ENVELOPE_REJECTED"
PROVENANCE_REJECTED = "PROVENANCE_REJECTED"
QUOTE_REJECTED = "QUOTE_REJECTED"
POLICY_REJECTED = "POLICY_REJECTED"

LAYERS = (ENVELOPE_REJECTED, PROVENANCE_REJECTED, QUOTE_REJECTED, POLICY_REJECTED)


class VerificationError(Exception):
    """A verification failure attributed to one rejection layer."""

    def __init__(self, layer: str, message: str):
        super().__init__(message)
        self.layer = layer


class CollateralNotFoundError(VerificationError):
    """The document carries no collateral entry of the requested role and
    format (Go: envelope.ErrCollateralNotFound)."""
