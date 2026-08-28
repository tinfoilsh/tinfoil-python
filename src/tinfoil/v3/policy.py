"""What a verified quote is appraised against (Go: verifier/policy): which
machines are endorsed, which platform configurations they may run, and the
policy each must satisfy. Inputs must come from a verified reference-values
source; this module performs no cryptography.

Parsing is fail-closed: unknown members, malformed identifiers, dangling
references, or platform mismatches are errors. A policy that cannot be fully
enforced is never partially applied. Parse/validate errors carry
PROVENANCE_REJECTED (the artifact arrives inside platform-endorsements
authentication); appraisal lookups carry POLICY_REJECTED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .errors import POLICY_REJECTED, PROVENANCE_REJECTED, VerificationError
from . import strictjson
from .strictjson import (
    BOOL,
    STR,
    array_of,
    field,
    int_schema,
    map_of,
    opt_struct_of,
    struct_of,
    uint_schema,
)

# Required format URI of the artifact.
ARTIFACT_FORMAT = "https://tinfoil.sh/predicate/platform-endorsements/v1"

PLATFORM_SEV_SNP = "sev-snp"
PLATFORM_TDX = "tdx"

_SEV_IDENTIFIER_HEX_LEN = 128
_TDX_IDENTIFIER_HEX_LEN = 32

_LOWER_HEX_RE = re.compile(r"^[0-9a-f]+$")


@dataclass
class Shape:
    """Canonical VM shape descriptor: the launch dimensions that determine a
    platform measurement. disks counts every attached disk (root, config,
    external config, one per model). gpus is None when the dimension is
    unknown for a measured slug; a code artifact always declares it."""

    cpus: int
    memory_mb: int
    gpus: Optional[int]
    disks: int

    def satisfies(self, required: Optional["Shape"]) -> bool:
        """Whether a measured slug shape satisfies the shape a code artifact
        requires. gpus is compared only when the slug declares it."""
        if required is None:
            return False
        if (
            self.cpus != required.cpus
            or self.memory_mb != required.memory_mb
            or self.disks != required.disks
        ):
            return False
        if self.gpus is not None and required.gpus is not None and self.gpus != required.gpus:
            return False
        return True


def shape_satisfies(s: Optional[Shape], required: Optional[Shape]) -> bool:
    if s is None or required is None:
        return False
    return s.satisfies(required)


@dataclass
class Stack:
    """Host software that produced a measurement. Informational."""

    qemu: str
    ovmf: str


@dataclass
class PlatformMeasurement:
    """One TDX platform configuration's expected registers, annotated with
    the VM shape it was measured for and, optionally, the host stack that
    produced it (informational, never checked)."""

    mrtd: str
    rtmr0: str
    shape: Optional[Shape]
    stack: Optional[Stack]


@dataclass
class TCB:
    """AMD security patch levels. fmc_spl applies only to family 1Ah (Turin)
    parts. None means the member was absent."""

    fmc_spl: Optional[int]
    bl_spl: Optional[int]
    tee_spl: Optional[int]
    snp_spl: Optional[int]
    ucode_spl: Optional[int]


@dataclass
class GuestPolicy:
    """SNP guest policy bits enforced at verification. All bits are compared:
    a bit absent from the policy JSON is False and the report must have it
    clear."""

    debug: bool
    smt: bool
    migrate_ma: bool
    single_socket: bool
    cxl_allowed: bool
    mem_aes256_xts: bool
    rapl_dis: bool
    ciphertext_hiding_dram: bool
    page_swap_disable: bool


@dataclass
class SNPPlatform:
    """SNP PLATFORM_INFO expectations. All fields are compared by strict
    equality against the report, so machines with different host
    configurations need distinct policies."""

    smt_enabled: bool
    tsme_enabled: bool
    ecc_enabled: bool
    rapl_disabled: bool
    ciphertext_hiding_dram: bool
    alias_check_complete: bool
    iommu_write_safe: bool
    tio_enabled: bool


@dataclass
class SEVSNPPolicy:
    """Standard SEV-SNP policy block. Every field is required and checked.
    Numeric members are None when absent so parsing can tell an absent member
    from a meaningful zero — validate rejects any absent member."""

    minimum_build: Optional[int]
    minimum_api_version: str  # floors the firmware version (maj.min)
    minimum_abi_version: str  # floors the guest policy's ABI version (maj.min)
    minimum_guest_svn: Optional[int]
    minimum_tcb: TCB
    minimum_launch_tcb: TCB
    guest_policy: GuestPolicy
    platform_info: SNPPlatform
    permit_provisional_firmware: bool
    vmpl: Optional[int]
    host_data: str
    image_id: str
    family_id: str
    require_author_key: bool
    require_id_block: bool
    minimum_launch_mitigation_vector: Optional[int]
    minimum_current_mitigation_vector: Optional[int]


@dataclass
class TDXPolicy:
    """Standard Intel TDX policy block. platform_measurements names the
    measurements-map entries the machine is endorsed to run; the quote's own
    MRTD/RTMR0 select exactly one of them at policy assembly."""

    qe_vendor_id: str
    minimum_tee_tcb_svn: str
    mr_seam: str
    td_attributes: str
    xfam: str
    minimum_tcb_evaluation_data_number: Optional[int]
    platform_measurements: Optional[list[str]]


@dataclass
class Policy:
    """A named appraisal policy. Exactly one platform block is set, matching
    platform."""

    platform: str
    sev_snp: Optional[SEVSNPPolicy]
    tdx: Optional[TDXPolicy]


@dataclass
class Artifact:
    """Parsed policy document: named platform measurements, named policies,
    and the machines map keying both by hardware identity. SEV-SNP machines
    are keyed by the 64-byte CHIP_ID (128 lowercase hex chars), TDX machines
    by the 16-byte PPID (32 lowercase hex chars)."""

    format: str
    measurements: dict[str, PlatformMeasurement]
    machines: dict[str, str]
    policies: dict[str, Policy]


# --- strict schema -----------------------------------------------------------

SHAPE_SCHEMA = opt_struct_of(
    {
        "cpus": field("cpus", int_schema()),
        "memory_mb": field("memory_mb", int_schema()),
        "gpus": field("gpus", int_schema(pointer=True)),
        "disks": field("disks", int_schema()),
    },
    cls=Shape,
)

_TCB_SCHEMA = struct_of(
    {
        "fmc_spl": field("fmc_spl", uint_schema(8, pointer=True)),
        "bl_spl": field("bl_spl", uint_schema(8, pointer=True)),
        "tee_spl": field("tee_spl", uint_schema(8, pointer=True)),
        "snp_spl": field("snp_spl", uint_schema(8, pointer=True)),
        "ucode_spl": field("ucode_spl", uint_schema(8, pointer=True)),
    },
    cls=TCB,
)

_GUEST_POLICY_SCHEMA = struct_of(
    {
        "debug": field("debug", BOOL),
        "smt": field("smt", BOOL),
        "migrate_ma": field("migrate_ma", BOOL),
        "single_socket": field("single_socket", BOOL),
        "cxl_allowed": field("cxl_allowed", BOOL),
        "mem_aes256_xts": field("mem_aes256_xts", BOOL),
        "rapl_dis": field("rapl_dis", BOOL),
        "ciphertext_hiding_dram": field("ciphertext_hiding_dram", BOOL),
        "page_swap_disable": field("page_swap_disable", BOOL),
    },
    cls=GuestPolicy,
)

_SNP_PLATFORM_SCHEMA = struct_of(
    {
        "smt_enabled": field("smt_enabled", BOOL),
        "tsme_enabled": field("tsme_enabled", BOOL),
        "ecc_enabled": field("ecc_enabled", BOOL),
        "rapl_disabled": field("rapl_disabled", BOOL),
        "ciphertext_hiding_dram": field("ciphertext_hiding_dram", BOOL),
        "alias_check_complete": field("alias_check_complete", BOOL),
        "iommu_write_safe": field("iommu_write_safe", BOOL),
        "tio_enabled": field("tio_enabled", BOOL),
    },
    cls=SNPPlatform,
)

_SEV_SNP_POLICY_SCHEMA = opt_struct_of(
    {
        "minimum_build": field("minimum_build", uint_schema(8, pointer=True)),
        "minimum_api_version": field("minimum_api_version", STR),
        "minimum_abi_version": field("minimum_abi_version", STR),
        "minimum_guest_svn": field("minimum_guest_svn", uint_schema(32, pointer=True)),
        "minimum_tcb": field("minimum_tcb", _TCB_SCHEMA),
        "minimum_launch_tcb": field("minimum_launch_tcb", _TCB_SCHEMA),
        "guest_policy": field("guest_policy", _GUEST_POLICY_SCHEMA),
        "platform_info": field("platform_info", _SNP_PLATFORM_SCHEMA),
        "permit_provisional_firmware": field("permit_provisional_firmware", BOOL),
        "vmpl": field("vmpl", int_schema(pointer=True)),
        "host_data": field("host_data", STR),
        "image_id": field("image_id", STR),
        "family_id": field("family_id", STR),
        "require_author_key": field("require_author_key", BOOL),
        "require_id_block": field("require_id_block", BOOL),
        "minimum_launch_mitigation_vector": field(
            "minimum_launch_mitigation_vector", uint_schema(64, pointer=True)
        ),
        "minimum_current_mitigation_vector": field(
            "minimum_current_mitigation_vector", uint_schema(64, pointer=True)
        ),
    },
    cls=SEVSNPPolicy,
)

_TDX_POLICY_SCHEMA = opt_struct_of(
    {
        "qe_vendor_id": field("qe_vendor_id", STR),
        "minimum_tee_tcb_svn": field("minimum_tee_tcb_svn", STR),
        "mr_seam": field("mr_seam", STR),
        "td_attributes": field("td_attributes", STR),
        "xfam": field("xfam", STR),
        "minimum_tcb_evaluation_data_number": field(
            "minimum_tcb_evaluation_data_number", int_schema(pointer=True)
        ),
        "platform_measurements": field("platform_measurements", array_of(STR)),
    },
    cls=TDXPolicy,
)

_ARTIFACT_SCHEMA = struct_of(
    {
        "format": field("format", STR),
        "measurements": field(
            "measurements",
            map_of(
                struct_of(
                    {
                        "mrtd": field("mrtd", STR),
                        "rtmr0": field("rtmr0", STR),
                        "shape": field("shape", SHAPE_SCHEMA),
                        "stack": field(
                            "stack",
                            opt_struct_of(
                                {
                                    "qemu": field("qemu", STR),
                                    "ovmf": field("ovmf", STR),
                                },
                                cls=Stack,
                            ),
                        ),
                    },
                    cls=PlatformMeasurement,
                )
            ),
        ),
        "machines": field("machines", map_of(STR)),
        "policies": field(
            "policies",
            map_of(
                struct_of(
                    {
                        "platform": field("platform", STR),
                        "sev_snp": field("sev_snp", _SEV_SNP_POLICY_SCHEMA),
                        "tdx": field("tdx", _TDX_POLICY_SCHEMA),
                    },
                    cls=Policy,
                )
            ),
        ),
    },
    cls=Artifact,
)


def _provenance_error(message: str) -> VerificationError:
    return VerificationError(PROVENANCE_REJECTED, message)


def _policy_error(message: str) -> VerificationError:
    return VerificationError(POLICY_REJECTED, message)


def parse_artifact(artifact_json: bytes) -> Artifact:
    """Strictly decode and validate a policy artifact (Go: policy.Parse).
    Unknown members anywhere in the document are rejected case-sensitively,
    as are duplicate member names."""
    try:
        a: Artifact = strictjson.unmarshal(artifact_json, _ARTIFACT_SCHEMA)
    except ValueError as e:
        raise _provenance_error(f"parsing policy artifact: {e}") from None
    if a.format != ARTIFACT_FORMAT:
        raise _provenance_error(f"unsupported artifact format {a.format!r}")
    _validate_artifact(a)
    return a


def _validate_artifact(a: Artifact) -> None:
    for name, p in a.policies.items():
        if p.platform == PLATFORM_SEV_SNP:
            if p.sev_snp is None or p.tdx is not None:
                raise _provenance_error(
                    f"policy {name!r}: platform sev-snp requires exactly the sev_snp block"
                )
            err = validate_sev_snp_policy(p.sev_snp)
            if err is not None:
                raise _provenance_error(f"policy {name!r}: {err}")
        elif p.platform == PLATFORM_TDX:
            if p.tdx is None or p.sev_snp is not None:
                raise _provenance_error(
                    f"policy {name!r}: platform tdx requires exactly the tdx block"
                )
            err = validate_tdx_policy(p.tdx)
            if err is not None:
                raise _provenance_error(f"policy {name!r}: {err}")
            for ref in p.tdx.platform_measurements or []:
                if ref not in a.measurements:
                    raise _provenance_error(
                        f"policy {name!r}: platform_measurements ref {ref!r} not in measurements"
                    )
        else:
            raise _provenance_error(
                f"policy {name!r}: unsupported platform {p.platform!r}"
            )

    for name, m in a.measurements.items():
        if m.shape is None:
            raise _provenance_error(f"measurement {name!r}: shape is required")

    for identifier, policy_name in a.machines.items():
        p = a.policies.get(policy_name)
        if p is None:
            raise _provenance_error(
                f"machine {_trunc_id(identifier)}...: unknown policy {policy_name!r}"
            )
        if _LOWER_HEX_RE.fullmatch(identifier) is None:
            raise _provenance_error(
                f"machine {_trunc_id(identifier)}...: identifier is not lowercase hex"
            )
        if p.platform == PLATFORM_SEV_SNP and len(identifier) != _SEV_IDENTIFIER_HEX_LEN:
            raise _provenance_error(
                f"machine {_trunc_id(identifier)}...: sev-snp identifier must be "
                f"{_SEV_IDENTIFIER_HEX_LEN} hex chars, got {len(identifier)}"
            )
        if p.platform == PLATFORM_TDX and len(identifier) != _TDX_IDENTIFIER_HEX_LEN:
            raise _provenance_error(
                f"machine {_trunc_id(identifier)}...: tdx identifier must be "
                f"{_TDX_IDENTIFIER_HEX_LEN} hex chars, got {len(identifier)}"
            )


def validate_sev_snp_policy(p: SEVSNPPolicy) -> Optional[str]:
    """Reject a block with any absent required member or an unsupported
    setting (Go: SEVSNPPolicy.Validate). Returns an error string or None."""
    if p.minimum_build is None:
        return "minimum_build is required"
    if p.minimum_api_version == "":
        return "minimum_api_version is required"
    if p.minimum_abi_version == "":
        return "minimum_abi_version is required"
    if p.minimum_guest_svn is None:
        return "minimum_guest_svn is required"
    if p.vmpl is None:
        return "vmpl is required"
    if p.vmpl < 0 or p.vmpl > 3:
        return "vmpl must be between 0 and 3"
    if p.host_data == "":
        return "host_data is required"
    if p.image_id == "":
        return "image_id is required"
    if p.family_id == "":
        return "family_id is required"
    if p.minimum_launch_mitigation_vector is None:
        return "minimum_launch_mitigation_vector is required"
    if p.minimum_current_mitigation_vector is None:
        return "minimum_current_mitigation_vector is required"
    if p.require_author_key or p.require_id_block:
        return (
            "require_author_key and require_id_block are not supported "
            "(no trusted key material is modeled)"
        )
    err = _validate_tcb(p.minimum_tcb)
    if err is not None:
        return f"minimum_tcb: {err}"
    err = _validate_tcb(p.minimum_launch_tcb)
    if err is not None:
        return f"minimum_launch_tcb: {err}"
    err = _validate_policy_version("minimum_api_version", p.minimum_api_version)
    if err is not None:
        return err
    err = _validate_policy_version("minimum_abi_version", p.minimum_abi_version)
    if err is not None:
        return err
    for name, (value, byte_len) in {
        "host_data": (p.host_data, 32),
        "image_id": (p.image_id, 16),
        "family_id": (p.family_id, 16),
    }.items():
        err = _validate_policy_hex(name, value, byte_len)
        if err is not None:
            return err
    return None


def _validate_tcb(t: TCB) -> Optional[str]:
    if t.bl_spl is None:
        return "bl_spl is required"
    if t.tee_spl is None:
        return "tee_spl is required"
    if t.snp_spl is None:
        return "snp_spl is required"
    if t.ucode_spl is None:
        return "ucode_spl is required"
    return None


def _validate_policy_version(name: str, version: str) -> Optional[str]:
    major, sep, minor = version.partition(".")
    if sep == "" or not _decimal_digits(major) or not _decimal_digits(minor):
        return f"{name} {version!r} is not maj.min"
    # strconv.ParseUint(..., 10, 8) range semantics.
    if int(major) > 0xFF:
        return f"{name} major: value out of range"
    if int(minor) > 0xFF:
        return f"{name} minor: value out of range"
    return None


def _decimal_digits(value: str) -> bool:
    return value != "" and all("0" <= d <= "9" for d in value)


def validate_tdx_policy(p: TDXPolicy) -> Optional[str]:
    """Reject a block with any absent or malformed required member (Go:
    TDXPolicy.Validate). Returns an error string or None."""
    if p.qe_vendor_id == "":
        return "qe_vendor_id is required"
    if p.minimum_tee_tcb_svn == "":
        return "minimum_tee_tcb_svn is required"
    if p.mr_seam == "":
        return "mr_seam is required"
    if p.td_attributes == "":
        return "td_attributes is required"
    if p.xfam == "":
        return "xfam is required"
    if p.minimum_tcb_evaluation_data_number is None:
        return "minimum_tcb_evaluation_data_number is required"
    if p.minimum_tcb_evaluation_data_number < 0:
        # A negative minimum would pass for any collateral, silently
        # disabling the freshness floor.
        return "minimum_tcb_evaluation_data_number must not be negative"
    if not p.platform_measurements:
        return "platform_measurements must not be empty"
    for name, (value, byte_len) in {
        "qe_vendor_id": (p.qe_vendor_id, 16),
        "minimum_tee_tcb_svn": (p.minimum_tee_tcb_svn, 16),
        "mr_seam": (p.mr_seam, 48),
        "td_attributes": (p.td_attributes, 8),
        "xfam": (p.xfam, 8),
    }.items():
        err = _validate_policy_hex(name, value, byte_len)
        if err is not None:
            return err
    return None


def _validate_policy_hex(name: str, value: str, byte_len: int) -> Optional[str]:
    if value != value.lower():
        return f"{name} must be lowercase hex"
    try:
        decode_hex(name, value, byte_len)
    except ValueError as e:
        return str(e)
    return None


def decode_hex(name: str, value: str, want_len: int) -> bytes:
    """Decode a required hex policy value of an exact byte length (Go:
    policy.DecodeHex — either case, even length). Raises ValueError; the
    caller assigns the rejection layer."""
    if re.fullmatch(r"[0-9a-fA-F]*", value) is None or len(value) % 2 != 0:
        raise ValueError(f"{name} is not hex: invalid hex string")
    b = bytes.fromhex(value)
    if len(b) != want_len:
        raise ValueError(f"{name} must be {want_len} bytes, got {len(b)}")
    return b


def _trunc_id(id_: str) -> str:
    return id_[:16] if len(id_) > 16 else id_


def policy_for(a: Artifact, identifier_hex: str, platform: str) -> tuple[str, Policy]:
    """Look up the appraisal policy for an authenticated platform identifier
    (lowercase hex) extracted from verified evidence, asserting the policy's
    platform matches the evidence platform. An identifier absent from the
    machines map is an error: the machine is not endorsed. Errors carry
    POLICY_REJECTED."""
    name = a.machines.get(identifier_hex)
    if name is None:
        raise _policy_error(
            f"platform identifier {_trunc_id(identifier_hex)}... is not endorsed"
        )
    p = a.policies[name]
    if p.platform != platform:
        raise _policy_error(
            f"policy {name!r} is for platform {p.platform!r}, evidence is {platform!r}"
        )
    return name, p


def resolve_platform_measurement(
    a: Artifact,
    p: TDXPolicy,
    required: Optional[Shape],
    mrtd_hex: str,
    rtmr0_hex: str,
) -> tuple[str, PlatformMeasurement]:
    """Select the single measurements-map entry the policy allows whose
    MRTD/RTMR0 equal the quote's authenticated values, returning its name.
    Only entries measured for the required VM shape are candidates, so a
    quote from a machine-endorsed but wrong-shaped VM resolves nothing. The
    measurement inputs must come from a verified quote. Errors carry
    POLICY_REJECTED."""
    if required is None:
        raise _policy_error("required VM shape is missing")
    any_shape_match = False
    for ref in p.platform_measurements or []:
        m = a.measurements[ref]
        if m.shape is None or not m.shape.satisfies(required):
            continue
        any_shape_match = True
        if m.mrtd == mrtd_hex and m.rtmr0 == rtmr0_hex:
            return ref, m
    if not any_shape_match:
        raise _policy_error(
            f"no endorsed platform measurement matches the required VM shape {required}"
        )
    raise _policy_error(
        f"platform measurements (mrtd {_trunc_id(mrtd_hex)}...) do not match any "
        "allowed configuration"
    )
