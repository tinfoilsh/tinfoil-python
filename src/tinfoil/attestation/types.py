"""
Shared types, errors, and protocol constants for attestation.

This module is the canonical source for types used across TDX and SEV
attestation modules. It has no intra-package dependencies, so any module
can import from it without risk of circular imports.
"""

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


# =============================================================================
# Protocol-level constants (shared across TDX and SEV)
# =============================================================================

TLS_KEY_FP_SIZE = 32   # SHA-256 TLS public key fingerprint (bytes)
HPKE_KEY_SIZE = 32     # HPKE public key (bytes)

# RTMR3 should always be zeros (48 bytes = 96 hex chars)
RTMR3_ZERO = "0" * 96

# Register layout constants per platform
TDX_REGISTER_COUNT = 5           # [mrtd, rtmr0, rtmr1, rtmr2, rtmr3]
TDX_MRTD_IDX = 0
TDX_RTMR0_IDX = 1
TDX_RTMR1_IDX = 2
TDX_RTMR2_IDX = 3
TDX_RTMR3_IDX = 4
SEV_REGISTER_COUNT = 1           # [snp_measurement]
MULTIPLATFORM_REGISTER_COUNT = 3 # [snp_measurement, rtmr1, rtmr2]
MULTIPLATFORM_SNP_IDX = 0
MULTIPLATFORM_RTMR1_IDX = 1
MULTIPLATFORM_RTMR2_IDX = 2

# Shared decompression constants
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
    import gzip
    import io

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


# =============================================================================
# Predicate types
# =============================================================================

class PredicateType(str, Enum):
    """Predicate types for attestation"""
    SEV_GUEST_V2 = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
    TDX_GUEST_V2 = "https://tinfoil.sh/predicate/tdx-guest/v2"
    SNP_TDX_MULTIPLATFORM_v1 = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
    HARDWARE_MEASUREMENTS_V1 = "https://tinfoil.sh/predicate/hardware-measurements/v1"


TDX_TYPES = (PredicateType.TDX_GUEST_V2,)


# =============================================================================
# Errors
# =============================================================================

class AttestationError(Exception):
    """Base class for attestation errors"""
    pass

class FormatMismatchError(AttestationError):
    """Raised when attestation formats don't match"""
    pass

class MeasurementMismatchError(AttestationError):
    """Raised when measurements don't match"""
    pass

class Rtmr3NotZeroError(AttestationError):
    """Raised when RTMR3 is not zeros"""
    pass

class HardwareMeasurementError(AttestationError):
    """Raised when hardware measurement verification fails"""
    pass


# =============================================================================
# Data types
# =============================================================================

@dataclass
class HardwareMeasurement:
    """Represents hardware platform measurements (MRTD and RTMR0 for TDX)"""
    id: str  # platform@digest
    mrtd: str
    rtmr0: str

@dataclass
class Measurement:
    """Represents measurement data"""
    type: PredicateType
    registers: List[str]

    def fingerprint(self) -> str:
        """
        Computes the SHA-256 hash of the predicate type and all measurement
        registers.  Always returns a 64-char hex digest regardless of the
        number of registers, so callers get a uniform format.
        """
        if not self.registers:
            raise ValueError("Cannot compute fingerprint: no measurement registers")

        all_data = self.type.value + "".join(self.registers)
        return hashlib.sha256(all_data.encode()).hexdigest()

    def assert_equal(self, other: 'Measurement') -> None:
        """
        Checks if this measurement equals another measurement with multi-platform support
        Raises appropriate error if they don't match
        """
        # Direct comparison for same types
        if self.type == other.type:
            if len(self.registers) != len(other.registers) or self.registers != other.registers:
                raise MeasurementMismatchError()
            return

        # Multi-platform comparison support
        if self.type == PredicateType.SNP_TDX_MULTIPLATFORM_v1:
            if other.type == PredicateType.TDX_GUEST_V2 and len(other.registers) == TDX_REGISTER_COUNT:
                if (len(self.registers) != MULTIPLATFORM_REGISTER_COUNT or
                    self.registers[MULTIPLATFORM_RTMR1_IDX] != other.registers[TDX_RTMR1_IDX] or
                    self.registers[MULTIPLATFORM_RTMR2_IDX] != other.registers[TDX_RTMR2_IDX]):
                    raise MeasurementMismatchError()
                if other.registers[TDX_RTMR3_IDX] != RTMR3_ZERO:
                    raise Rtmr3NotZeroError(f"RTMR3 must be zeros, got {other.registers[TDX_RTMR3_IDX]}")
                return
            elif other.type == PredicateType.SEV_GUEST_V2 and len(other.registers) == SEV_REGISTER_COUNT:
                if (len(self.registers) != MULTIPLATFORM_REGISTER_COUNT or
                    self.registers[MULTIPLATFORM_SNP_IDX] != other.registers[0]):
                    raise MeasurementMismatchError()
                return

        # Reverse comparisons
        if other.type == PredicateType.SNP_TDX_MULTIPLATFORM_v1:
            try:
                other.assert_equal(self)
                return
            except (FormatMismatchError, MeasurementMismatchError):
                raise

        # If we get here, the formats are incompatible
        raise FormatMismatchError()

    def __str__(self) -> str:
        """Returns a human-readable string representation of the measurement"""
        if self.type == PredicateType.SEV_GUEST_V2 and len(self.registers) == SEV_REGISTER_COUNT:
            return f"Measurement(type={self.type.value}, snp_measurement={self.registers[0][:16]}...)"

        elif self.type == PredicateType.TDX_GUEST_V2 and len(self.registers) == TDX_REGISTER_COUNT:
            labels = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
            parts = [f"{label}={reg[:16]}..." for label, reg in zip(labels, self.registers)]
            return f"Measurement(type={self.type.value}, {', '.join(parts)})"

        elif self.type == PredicateType.SNP_TDX_MULTIPLATFORM_v1 and len(self.registers) == MULTIPLATFORM_REGISTER_COUNT:
            labels = ["snp_measurement", "rtmr1", "rtmr2"]
            parts = [f"{label}={reg[:16]}..." for label, reg in zip(labels, self.registers)]
            return f"Measurement(type={self.type.value}, {', '.join(parts)})"

        return f"Measurement(type={self.type.value}, registers={len(self.registers)} items)"

@dataclass
class Verification:
    """Represents verification results"""
    measurement: Measurement
    public_key_fp: str
    hpke_public_key: Optional[str] = None
