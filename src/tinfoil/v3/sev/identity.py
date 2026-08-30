"""SEV-SNP platform identity (Go: verifier/quote/sev/identity.go)."""

from __future__ import annotations


def identity(chip_id: bytes) -> str:
    """The machines-map lookup key for a verified SEV-SNP report's CHIP_ID
    field. The field is always 64 bytes; Turin hardware delivers its 8-byte
    hwID zero-padded, which is exactly the endorsed form, so no
    product-specific handling is needed. ValueError; the caller assigns the
    rejection layer."""
    if len(chip_id) != 64:
        raise ValueError(f"SEV CHIP_ID must be 64 bytes, got {len(chip_id)}")
    return chip_id.hex()
