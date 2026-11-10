"""The platform-endorsements artifact: which machines are endorsed, which platform configurations they may run, and the
policy that each must satisfy.

Parsing is fail-closed: unknown members, malformed identifiers, dangling
references, or platform mismatches are errors. A policy that cannot be fully
enforced is never partially applied. Inputs must come from a verified
reference-values source; this package performs no cryptography.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._policy._common import PolicyError, validate_policy_hex
from tinfoil._v3.verifier._policy.sev import TCB, GuestPolicy, SEVSNPPolicy, SNPPlatform
from tinfoil._v3.verifier._policy.shape import Shape, Stack, format_shape, satisfies
from tinfoil._v3.verifier._policy.tdx import TDXPolicy

ARTIFACT_FORMAT = "https://tinfoil.sh/predicate/platform-endorsements/v1"
ARTIFACT_FORMAT_V2 = "https://tinfoil.sh/predicate/platform-endorsements/v2"
"""Machine policy without workload measurements."""

PLATFORM_SEV_SNP = "sev-snp"
"""Labels AMD SEV-SNP policies."""
PLATFORM_TDX = "tdx"
"""Labels Intel TDX policies."""

_SEV_IDENTIFIER_HEX_LEN = 128
_TDX_IDENTIFIER_HEX_LEN = 32
_LOWER_HEX = re.compile(r"[0-9a-f]+")


@dataclass(frozen=True, slots=True)
class PlatformMeasurement:
    """One TDX platform configuration's expected registers, annotated with the VM shape that it was measured for and,
    optionally, the host stack that produced it."""

    mrtd: str
    rtmr0: str
    shape: Shape | None = None
    stack: Stack | None = None
    """Informational and never checked."""


@dataclass(frozen=True, slots=True)
class Policy:
    """A named appraisal policy. Exactly one platform block is set, matching ``platform``."""

    platform: str
    sev_snp: SEVSNPPolicy | None = None
    tdx: TDXPolicy | None = None


@dataclass(frozen=True, slots=True)
class Artifact:
    """The parsed policy document: named platform measurements, named policies, and the machines map keying both by
    hardware identity."""

    format: str
    measurements: Mapping[str, PlatformMeasurement]
    machines: Mapping[str, str]
    """A machine's hardware identifier to its policy name.

    SEV-SNP machines are keyed by the 64-byte CHIP_ID (128 lowercase hex
    chars), TDX machines by the 16-byte PPID (32 lowercase hex chars).
    """
    policies: Mapping[str, Policy]

    def policy_for(self, identifier_hex: str, platform: str) -> tuple[str, Policy]:
        """The appraisal policy, and its name, for an authenticated platform identifier (lowercase hex) extracted from
        verified evidence, asserting that the policy's platform matches the evidence platform.

        An identifier absent from the machines map is an error: the machine is
        not endorsed.
        """
        name = self.machines.get(identifier_hex)
        if name is None:
            raise PolicyError(f"platform identifier {_trunc_id(identifier_hex)}... is not endorsed")
        policy = self.policies.get(name)
        found = policy.platform if policy is not None else ""
        if policy is None or found != platform:
            raise PolicyError(f"policy {_quote(name)} is for platform {_quote(found)}, evidence is {_quote(platform)}")
        return name, policy

    def resolve_platform_measurement(
        self, policy: TDXPolicy, required: Shape | None, mrtd_hex: str, rtmr0_hex: str
    ) -> tuple[str, PlatformMeasurement]:
        """The single measurements-map entry that the policy allows whose MRTD/RTMR0 equal the quote's authenticated
        values, and its name.

        Only entries measured for the required VM shape are candidates, so a
        quote from a machine-endorsed but wrong-shaped VM resolves nothing.
        The measurement inputs must come from a verified quote.
        """
        if required is None:
            raise PolicyError("required VM shape is missing")
        any_shape_match = False
        for ref in policy.platform_measurements:
            measurement = self.measurements.get(ref)
            if measurement is None or not satisfies(measurement.shape, required):
                continue
            any_shape_match = True
            if measurement.mrtd == mrtd_hex and measurement.rtmr0 == rtmr0_hex:
                return ref, measurement
        if not any_shape_match:
            raise PolicyError(
                f"no endorsed platform measurement matches the required VM shape {format_shape(required)}"
            )
        raise PolicyError(
            f"platform measurements (mrtd {_trunc_id(mrtd_hex)}...) do not match any allowed configuration"
        )


def parse(data: bytes) -> Artifact:
    """Strictly decode and validate a policy artifact.

    Unknown members anywhere in the document are rejected case-sensitively,
    as are duplicate member names.
    """
    try:
        artifact = _decode_artifact(_json.strict_parse(data))
    except _json.JsonError as err:
        raise PolicyError(f"parsing policy artifact: {err}") from err
    if artifact.format not in (ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2):
        raise PolicyError(f"unsupported artifact format {_quote(artifact.format)}")
    _validate(artifact)
    return artifact


# --- decoding ----------------------------------------------------------------

_ARTIFACT_MEMBERS = ("format", "measurements", "machines", "policies")
_MEASUREMENT_MEMBERS = ("mrtd", "rtmr0", "shape", "stack")
_SHAPE_MEMBERS = ("cpus", "memory_mb", "gpus", "disks")
_STACK_MEMBERS = ("qemu", "ovmf")
_POLICY_MEMBERS = ("platform", "sev_snp", "tdx")
_SEV_SNP_MEMBERS = (
    "minimum_build",
    "minimum_api_version",
    "minimum_abi_version",
    "minimum_guest_svn",
    "minimum_tcb",
    "minimum_launch_tcb",
    "guest_policy",
    "platform_info",
    "permit_provisional_firmware",
    "vmpl",
    "host_data",
    "image_id",
    "family_id",
    "require_author_key",
    "require_id_block",
    "minimum_launch_mitigation_vector",
    "minimum_current_mitigation_vector",
)
_TCB_MEMBERS = ("fmc_spl", "bl_spl", "tee_spl", "snp_spl", "ucode_spl")
_GUEST_POLICY_MEMBERS = (
    "debug",
    "smt",
    "migrate_ma",
    "single_socket",
    "cxl_allowed",
    "mem_aes256_xts",
    "rapl_dis",
    "ciphertext_hiding_dram",
    "page_swap_disable",
)
_PLATFORM_INFO_MEMBERS = (
    "smt_enabled",
    "tsme_enabled",
    "ecc_enabled",
    "rapl_disabled",
    "ciphertext_hiding_dram",
    "alias_check_complete",
    "iommu_write_safe",
    "tio_enabled",
)
_TDX_MEMBERS = (
    "qe_vendor_id",
    "minimum_tee_tcb_svn",
    "mr_seam",
    "td_attributes",
    "xfam",
    "minimum_tcb_evaluation_data_number",
    "platform_measurements",
)


def _decode_artifact(value: _json.JsonValue) -> Artifact:
    obj = _json.object_(value, "policy artifact", _ARTIFACT_MEMBERS)
    return Artifact(
        format=_json.string(obj, "format"),
        measurements=MappingProxyType(_json.mapping(obj, "measurements", _decode_measurement)),
        machines=MappingProxyType(_json.mapping(obj, "machines", _decode_policy_name)),
        policies=MappingProxyType(_json.mapping(obj, "policies", _decode_policy)),
    )


def _decode_measurement(value: _json.JsonValue, name: str) -> PlatformMeasurement:
    obj = _json.object_(value, f"measurement {_quote(name)}", _MEASUREMENT_MEMBERS)
    shape = _json.opt_struct(obj, "shape", _SHAPE_MEMBERS)
    stack = _json.opt_struct(obj, "stack", _STACK_MEMBERS)
    return PlatformMeasurement(
        mrtd=_json.string(obj, "mrtd"),
        rtmr0=_json.string(obj, "rtmr0"),
        shape=None if shape is None else _decode_shape(shape),
        stack=None if stack is None else Stack(qemu=_json.string(stack, "qemu"), ovmf=_json.string(stack, "ovmf")),
    )


def _decode_shape(obj: _json.JsonObject) -> Shape:
    return Shape(
        cpus=_int_or_zero(obj, "cpus"),
        memory_mb=_int_or_zero(obj, "memory_mb"),
        disks=_int_or_zero(obj, "disks"),
        gpus=_json.int64(obj, "gpus"),
    )


def _int_or_zero(obj: _json.JsonObject, key: str) -> int:
    value = _json.int64(obj, key)
    return 0 if value is None else value


def _decode_policy_name(value: _json.JsonValue, name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise _json.JsonError(f"cannot unmarshal JSON value into string within machine {_quote(name)}")
    return value


def _decode_policy(value: _json.JsonValue, name: str) -> Policy:
    obj = _json.object_(value, f"policy {_quote(name)}", _POLICY_MEMBERS)
    sev_snp = _json.opt_struct(obj, "sev_snp", _SEV_SNP_MEMBERS)
    tdx = _json.opt_struct(obj, "tdx", _TDX_MEMBERS)
    return Policy(
        platform=_json.string(obj, "platform"),
        sev_snp=None if sev_snp is None else _decode_sev_snp(sev_snp),
        tdx=None if tdx is None else _decode_tdx(tdx),
    )


def _decode_sev_snp(obj: _json.JsonObject) -> SEVSNPPolicy:
    guest = _json.struct(obj, "guest_policy", _GUEST_POLICY_MEMBERS)
    platform = _json.struct(obj, "platform_info", _PLATFORM_INFO_MEMBERS)
    return SEVSNPPolicy(
        minimum_build=_json.uint(obj, "minimum_build", 8),
        minimum_api_version=_json.string(obj, "minimum_api_version"),
        minimum_abi_version=_json.string(obj, "minimum_abi_version"),
        minimum_guest_svn=_json.uint(obj, "minimum_guest_svn", 32),
        minimum_tcb=_decode_tcb(_json.struct(obj, "minimum_tcb", _TCB_MEMBERS)),
        minimum_launch_tcb=_decode_tcb(_json.struct(obj, "minimum_launch_tcb", _TCB_MEMBERS)),
        guest_policy=GuestPolicy(
            debug=_json.boolean(guest, "debug"),
            smt=_json.boolean(guest, "smt"),
            migrate_ma=_json.boolean(guest, "migrate_ma"),
            single_socket=_json.boolean(guest, "single_socket"),
            cxl_allowed=_json.boolean(guest, "cxl_allowed"),
            mem_aes256_xts=_json.boolean(guest, "mem_aes256_xts"),
            rapl_dis=_json.boolean(guest, "rapl_dis"),
            ciphertext_hiding_dram=_json.boolean(guest, "ciphertext_hiding_dram"),
            page_swap_disable=_json.boolean(guest, "page_swap_disable"),
        ),
        platform_info=SNPPlatform(
            smt_enabled=_json.boolean(platform, "smt_enabled"),
            tsme_enabled=_json.boolean(platform, "tsme_enabled"),
            ecc_enabled=_json.boolean(platform, "ecc_enabled"),
            rapl_disabled=_json.boolean(platform, "rapl_disabled"),
            ciphertext_hiding_dram=_json.boolean(platform, "ciphertext_hiding_dram"),
            alias_check_complete=_json.boolean(platform, "alias_check_complete"),
            iommu_write_safe=_json.boolean(platform, "iommu_write_safe"),
            tio_enabled=_json.boolean(platform, "tio_enabled"),
        ),
        permit_provisional_firmware=_json.boolean(obj, "permit_provisional_firmware"),
        vmpl=_json.int64(obj, "vmpl"),
        host_data=_json.string(obj, "host_data"),
        image_id=_json.string(obj, "image_id"),
        family_id=_json.string(obj, "family_id"),
        require_author_key=_json.boolean(obj, "require_author_key"),
        require_id_block=_json.boolean(obj, "require_id_block"),
        minimum_launch_mitigation_vector=_json.uint(obj, "minimum_launch_mitigation_vector", 64),
        minimum_current_mitigation_vector=_json.uint(obj, "minimum_current_mitigation_vector", 64),
    )


def _decode_tcb(obj: _json.JsonObject) -> TCB:
    return TCB(
        bl_spl=_json.uint(obj, "bl_spl", 8),
        tee_spl=_json.uint(obj, "tee_spl", 8),
        snp_spl=_json.uint(obj, "snp_spl", 8),
        ucode_spl=_json.uint(obj, "ucode_spl", 8),
        fmc_spl=_json.uint(obj, "fmc_spl", 8),
    )


def _decode_tdx(obj: _json.JsonObject) -> TDXPolicy:
    return TDXPolicy(
        qe_vendor_id=_json.string(obj, "qe_vendor_id"),
        minimum_tee_tcb_svn=_json.string(obj, "minimum_tee_tcb_svn"),
        mr_seam=_json.string(obj, "mr_seam"),
        td_attributes=_json.string(obj, "td_attributes"),
        xfam=_json.string(obj, "xfam"),
        minimum_tcb_evaluation_data_number=_json.int64(obj, "minimum_tcb_evaluation_data_number"),
        platform_measurements=_json.string_array(obj, "platform_measurements") or (),
    )


# --- validation --------------------------------------------------------------


def _validate(artifact: Artifact) -> None:
    if artifact.format == ARTIFACT_FORMAT_V2 and len(artifact.measurements) != 0:
        raise PolicyError("platform endorsement v2 excludes workload measurements")
    for name, policy in artifact.policies.items():
        _validate_policy(artifact, name, policy)

    for name, measurement in artifact.measurements.items():
        shape = measurement.shape
        if shape is None:
            raise PolicyError(f"measurement {_quote(name)}: shape is required")
        if shape.cpus <= 0 or shape.memory_mb <= 0 or shape.disks <= 0:
            raise PolicyError(f"measurement {_quote(name)}: cpus, memory_mb, and disks must be positive")
        if shape.gpus is not None and shape.gpus < 0:
            raise PolicyError(f"measurement {_quote(name)}: gpus must be non-negative")
        try:
            validate_policy_hex("mrtd", measurement.mrtd, 48)
            validate_policy_hex("rtmr0", measurement.rtmr0, 48)
        except PolicyError as err:
            raise PolicyError(f"measurement {_quote(name)}: {err}") from err

    for identifier, policy_name in artifact.machines.items():
        named = artifact.policies.get(policy_name)
        prefix = f"machine {_trunc_id(identifier)}..."
        if named is None:
            raise PolicyError(f"{prefix}: unknown policy {_quote(policy_name)}")
        if not _LOWER_HEX.fullmatch(identifier):
            raise PolicyError(f"{prefix}: identifier is not lowercase hex")
        if named.platform == PLATFORM_SEV_SNP and len(identifier) != _SEV_IDENTIFIER_HEX_LEN:
            raise PolicyError(
                f"{prefix}: sev-snp identifier must be {_SEV_IDENTIFIER_HEX_LEN} hex chars, got {len(identifier)}"
            )
        if named.platform == PLATFORM_TDX and len(identifier) != _TDX_IDENTIFIER_HEX_LEN:
            raise PolicyError(
                f"{prefix}: tdx identifier must be {_TDX_IDENTIFIER_HEX_LEN} hex chars, got {len(identifier)}"
            )


def _validate_policy(artifact: Artifact, name: str, policy: Policy) -> None:
    prefix = f"policy {_quote(name)}"
    v1 = artifact.format == ARTIFACT_FORMAT
    if policy.platform == PLATFORM_SEV_SNP:
        if policy.sev_snp is None or policy.tdx is not None:
            raise PolicyError(f"{prefix}: platform sev-snp requires exactly the sev_snp block")
        if v1 != (policy.sev_snp.host_data != ""):
            raise PolicyError(f"{prefix}: host_data is required in v1 and excluded in v2")
        try:
            policy.sev_snp.validate()
        except PolicyError as err:
            raise PolicyError(f"{prefix}: {err}") from err
    elif policy.platform == PLATFORM_TDX:
        if policy.tdx is None or policy.sev_snp is not None:
            raise PolicyError(f"{prefix}: platform tdx requires exactly the tdx block")
        if v1 != (len(policy.tdx.platform_measurements) != 0):
            raise PolicyError(f"{prefix}: platform_measurements are required in v1 and excluded in v2")
        try:
            policy.tdx.validate()
        except PolicyError as err:
            raise PolicyError(f"{prefix}: {err}") from err
        for ref in policy.tdx.platform_measurements:
            if ref not in artifact.measurements:
                raise PolicyError(f"{prefix}: platform_measurements ref {_quote(ref)} not in measurements")
    else:
        raise PolicyError(f"{prefix}: unsupported platform {_quote(policy.platform)}")


def _trunc_id(identifier: str) -> str:
    return identifier[:16] if len(identifier) > 16 else identifier


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
