"""The machine identity of an SEV-SNP report."""

from __future__ import annotations

CHIP_ID_SIZE = 64


def identity(chip_id: bytes) -> str:
    """The machines-map lookup key for a verified report's CHIP_ID: the 64 bytes as lowercase hex.

    Turin hardware delivers its 8-byte hwID zero-padded, which is exactly
    the endorsed form, so no product-specific handling is needed. Any other
    length is an error.
    """
    raise NotImplementedError
