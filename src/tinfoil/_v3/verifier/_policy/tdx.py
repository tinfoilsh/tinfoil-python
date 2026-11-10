"""The Intel TDX policy block, and the hex field checks that every policy block shares."""

from __future__ import annotations

import re
from dataclasses import dataclass


class PolicyError(ValueError):
    """A policy artifact that cannot be fully enforced."""


_HEX = re.compile(r"[0-9a-fA-F]*")


def decode_hex(name: str, value: str, want_len: int) -> bytes:
    """Decode a required hex policy value of an exact byte length, in either case."""
    if not _HEX.fullmatch(value):
        raise PolicyError(f"{name} is not hex: invalid byte in hex string")
    if len(value) % 2:
        raise PolicyError(f"{name} is not hex: odd length hex string")
    decoded = bytes.fromhex(value)
    if len(decoded) != want_len:
        raise PolicyError(f"{name} must be {want_len} bytes, got {len(decoded)}")
    return decoded


def validate_policy_hex(name: str, value: str, byte_len: int) -> None:
    """Require exactly ``2 * byte_len`` lowercase hex characters."""
    if len(value) != 2 * byte_len:
        raise PolicyError(f"{name} must be {2 * byte_len} hex chars, got {len(value)}")
    if value != value.lower():
        raise PolicyError(f"{name} must be lowercase hex")
    decode_hex(name, value, byte_len)


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
