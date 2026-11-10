"""The Intel TDX policy block."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier._policy._common import PolicyError, validate_policy_hex


@dataclass(frozen=True, slots=True)
class TDXPolicy:
    """The standard Intel TDX policy block.

    ``platform_measurements`` names the measurements-map entries that the
    machine is endorsed to run; the quote's own MRTD/RTMR0 select exactly one
    of them. It is empty in a v2 artifact, where runtime endorsements supply
    the measurements instead. ``minimum_tcb_evaluation_data_number`` is None
    when the member is absent, which ``validate`` rejects.
    """

    qe_vendor_id: str
    minimum_tee_tcb_svn: str
    mr_seam: str
    td_attributes: str
    xfam: str
    minimum_tcb_evaluation_data_number: int | None
    platform_measurements: tuple[str, ...] = ()

    def validate(self) -> None:
        """Reject a block with any absent or malformed required member."""
        if self.qe_vendor_id == "":
            raise PolicyError("qe_vendor_id is required")
        if self.minimum_tee_tcb_svn == "":
            raise PolicyError("minimum_tee_tcb_svn is required")
        if self.mr_seam == "":
            raise PolicyError("mr_seam is required")
        if self.td_attributes == "":
            raise PolicyError("td_attributes is required")
        if self.xfam == "":
            raise PolicyError("xfam is required")
        if self.minimum_tcb_evaluation_data_number is None:
            raise PolicyError("minimum_tcb_evaluation_data_number is required")
        if self.minimum_tcb_evaluation_data_number < 0:
            # A negative minimum would pass for any collateral, silently
            # disabling the freshness floor.
            raise PolicyError("minimum_tcb_evaluation_data_number must not be negative")
        validate_policy_hex("qe_vendor_id", self.qe_vendor_id, 16)
        validate_policy_hex("minimum_tee_tcb_svn", self.minimum_tee_tcb_svn, 16)
        validate_policy_hex("mr_seam", self.mr_seam, 48)
        validate_policy_hex("td_attributes", self.td_attributes, 8)
        validate_policy_hex("xfam", self.xfam, 8)
