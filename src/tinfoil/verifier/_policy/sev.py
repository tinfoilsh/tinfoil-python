"""The AMD SEV-SNP policy block."""

from __future__ import annotations

import json
from dataclasses import dataclass

from tinfoil.verifier._policy._common import PolicyError, validate_policy_hex


@dataclass(frozen=True, slots=True)
class TCB:
    """AMD security patch levels. ``fmc_spl`` applies only to family 1Ah (Turin) parts.

    Each level is None when its member is absent; ``validate`` rejects an
    absent required level.
    """

    bl_spl: int | None = None
    tee_spl: int | None = None
    snp_spl: int | None = None
    ucode_spl: int | None = None
    fmc_spl: int | None = None

    def validate(self) -> None:
        if self.bl_spl is None:
            raise PolicyError("bl_spl is required")
        if self.tee_spl is None:
            raise PolicyError("tee_spl is required")
        if self.snp_spl is None:
            raise PolicyError("snp_spl is required")
        if self.ucode_spl is None:
            raise PolicyError("ucode_spl is required")


@dataclass(frozen=True, slots=True)
class GuestPolicy:
    """The SNP guest policy bits enforced at verification.

    All bits are compared: a bit absent from the policy JSON is False and the
    report must have it clear.
    """

    debug: bool = False
    smt: bool = False
    migrate_ma: bool = False
    single_socket: bool = False
    cxl_allowed: bool = False
    mem_aes256_xts: bool = False
    rapl_dis: bool = False
    ciphertext_hiding_dram: bool = False
    page_swap_disable: bool = False


@dataclass(frozen=True, slots=True)
class SNPPlatform:
    """The SNP PLATFORM_INFO expectations.

    All fields are compared by strict equality against the report, so
    machines with different host configurations need distinct policies.
    """

    smt_enabled: bool = False
    tsme_enabled: bool = False
    ecc_enabled: bool = False
    rapl_disabled: bool = False
    ciphertext_hiding_dram: bool = False
    alias_check_complete: bool = False
    iommu_write_safe: bool = False
    tio_enabled: bool = False


@dataclass(frozen=True, slots=True)
class SEVSNPPolicy:
    """The standard SEV-SNP policy block.

    ``host_data`` is supplied by the platform for legacy releases, or derived
    from the endorsed config; it is empty in a v2 artifact. Numeric members
    are None when absent so that an absent member is told from a meaningful
    zero; ``validate`` rejects any absent required member.
    """

    minimum_build: int | None
    minimum_api_version: str
    """Floors the firmware version (maj.min)."""
    minimum_abi_version: str
    """Floors the guest policy's ABI version (maj.min)."""
    minimum_guest_svn: int | None
    minimum_tcb: TCB
    minimum_launch_tcb: TCB
    guest_policy: GuestPolicy
    platform_info: SNPPlatform
    permit_provisional_firmware: bool
    vmpl: int | None
    host_data: str
    image_id: str
    family_id: str
    require_author_key: bool
    require_id_block: bool
    minimum_launch_mitigation_vector: int | None
    minimum_current_mitigation_vector: int | None

    def validate(self) -> None:
        """Reject a block with any absent required member or an unsupported setting."""
        if self.minimum_build is None:
            raise PolicyError("minimum_build is required")
        if self.minimum_api_version == "":
            raise PolicyError("minimum_api_version is required")
        if self.minimum_abi_version == "":
            raise PolicyError("minimum_abi_version is required")
        if self.minimum_guest_svn is None:
            raise PolicyError("minimum_guest_svn is required")
        if self.vmpl is None:
            raise PolicyError("vmpl is required")
        if self.vmpl < 0 or self.vmpl > 3:
            raise PolicyError("vmpl must be between 0 and 3")
        if self.image_id == "":
            raise PolicyError("image_id is required")
        if self.family_id == "":
            raise PolicyError("family_id is required")
        if self.minimum_launch_mitigation_vector is None:
            raise PolicyError("minimum_launch_mitigation_vector is required")
        if self.minimum_current_mitigation_vector is None:
            raise PolicyError("minimum_current_mitigation_vector is required")
        if self.require_author_key or self.require_id_block:
            raise PolicyError(
                "require_author_key and require_id_block are not supported (no trusted key material is modeled)"
            )
        try:
            self.minimum_tcb.validate()
        except PolicyError as err:
            raise PolicyError(f"minimum_tcb: {err}") from err
        try:
            self.minimum_launch_tcb.validate()
        except PolicyError as err:
            raise PolicyError(f"minimum_launch_tcb: {err}") from err
        validate_policy_version("minimum_api_version", self.minimum_api_version)
        validate_policy_version("minimum_abi_version", self.minimum_abi_version)
        if self.host_data != "":
            validate_policy_hex("host_data", self.host_data, 32)
        validate_policy_hex("image_id", self.image_id, 16)
        validate_policy_hex("family_id", self.family_id, 16)


def validate_policy_version(name: str, version: str) -> None:
    """Require ``maj.min`` with each component a decimal uint8."""
    major, dot, minor = version.partition(".")
    if dot == "" or not _decimal_digits(major) or not _decimal_digits(minor):
        raise PolicyError(f"{name} {_quote(version)} is not maj.min")
    # A uint8 has at most three digits, so the length check keeps a
    # pathologically long component away from the integer conversion.
    if len(major) > 3 or int(major) > 255:
        raise PolicyError(f"{name} major: value out of range")
    if len(minor) > 3 or int(minor) > 255:
        raise PolicyError(f"{name} minor: value out of range")


def _decimal_digits(value: str) -> bool:
    return value != "" and all("0" <= digit <= "9" for digit in value)


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
