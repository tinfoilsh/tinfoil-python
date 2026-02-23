"""
Shared utility functions for attestation modules.

This module has no intra-package dependencies, so any module
can import from it without risk of circular imports.
"""

import gzip
import io

MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024  # 10 MiB


def safe_gzip_decompress(data: bytes, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    """Decompress gzip data with a size limit to prevent gzip bombs.

    Args:
        data: Gzip-compressed bytes
        max_size: Maximum allowed decompressed size

    Returns:
        Decompressed bytes

    Raises:
        ValueError: If decompressed data exceeds max_size or decompression fails
    """
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            result = f.read(max_size + 1)
    except (OSError, EOFError) as e:
        raise ValueError(f"Gzip decompression failed: {e}") from e
    if len(result) > max_size:
        raise ValueError(
            f"Decompressed attestation exceeds maximum size ({max_size} bytes)"
        )
    return result
