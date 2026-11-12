"""The repositories whose releases the verifier recognizes, named once for every module that checks them."""

from __future__ import annotations

from typing import Final

CVMIMAGE_REPO: Final = "tinfoilsh/cvmimage"
"""The repository that releases the IGVM runtime (``v*`` tags) and the platform endorsements (``platform-v*``
tags)."""

__all__ = ["CVMIMAGE_REPO"]
