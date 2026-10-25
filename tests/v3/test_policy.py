"""Policy artifact fail-closed parsing and appraisal lookups (Go: policy_test)."""

import copy
import json

import pytest

from tinfoil.v3 import policy
from tinfoil.v3.errors import POLICY_REJECTED, PROVENANCE_REJECTED, VerificationError

SEV_ID = "ab" * 64  # 128 hex chars
TDX_ID = "cd" * 16  # 32 hex chars

SEV_POLICY = {
    "platform": "sev-snp",
    "sev_snp": {
        "minimum_build": 21,
        "minimum_api_version": "1.55",
        "minimum_abi_version": "1.0",
        "minimum_guest_svn": 0,
        "minimum_tcb": {"bl_spl": 10, "tee_spl": 0, "snp_spl": 25, "ucode_spl": 84},
        "minimum_launch_tcb": {"bl_spl": 10, "tee_spl": 0, "snp_spl": 25, "ucode_spl": 84},
        "guest_policy": {"smt": True},
        "platform_info": {"smt_enabled": True, "alias_check_complete": True},
        "permit_provisional_firmware": False,
        "vmpl": 0,
        "host_data": "00" * 32,
        "image_id": "00" * 16,
        "family_id": "00" * 16,
        "minimum_launch_mitigation_vector": 1,
        "minimum_current_mitigation_vector": 18446744073709551615,  # u64 max, > 2^53
    },
}

TDX_POLICY = {
    "platform": "tdx",
    "tdx": {
        "qe_vendor_id": "939a7233f79c4ca9940a0db3957f0607",
        "minimum_tee_tcb_svn": "06010300000000000000000000000000",
        "mr_seam": "ff" * 48,
        "td_attributes": "0000001000000000",
        "xfam": "e702060000000000",
        "minimum_tcb_evaluation_data_number": 18,
        "platform_measurements": ["m1"],
    },
}

ARTIFACT = {
    "format": policy.ARTIFACT_FORMAT,
    "measurements": {
        "m1": {
            "mrtd": "11" * 48,
            "rtmr0": "22" * 48,
            "shape": {"cpus": 4, "memory_mb": 16384, "gpus": 1, "disks": 3},
            "stack": {"qemu": "9.0", "ovmf": "edk2"},
        }
    },
    "machines": {SEV_ID: "sev", TDX_ID: "tdx"},
    "policies": {"sev": SEV_POLICY, "tdx": TDX_POLICY},
}


def parse(obj) -> policy.Artifact:
    return policy.parse_artifact(json.dumps(obj).encode())


def variant(mutate):
    a = copy.deepcopy(ARTIFACT)
    mutate(a)
    return a


def assert_parse_rejects(obj, match=None):
    with pytest.raises(VerificationError, match=match) as ei:
        parse(obj)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_happy_artifact():
    a = parse(ARTIFACT)
    assert a.format == policy.ARTIFACT_FORMAT
    assert a.machines[SEV_ID] == "sev"
    p = a.policies["sev"]
    assert p.sev_snp.minimum_build == 21
    assert p.sev_snp.minimum_current_mitigation_vector == 2**64 - 1  # exact
    assert p.sev_snp.guest_policy.smt is True
    assert p.sev_snp.guest_policy.debug is False  # absent bit is False
    assert p.sev_snp.platform_info.iommu_write_safe is False
    m = a.measurements["m1"]
    assert m.shape.gpus == 1 and m.stack.qemu == "9.0"
    t = a.policies["tdx"].tdx
    assert t.minimum_tcb_evaluation_data_number == 18


def test_wrong_format_rejects():
    assert_parse_rejects(
        variant(lambda a: a.update(format="x")), match="unsupported artifact format"
    )


def test_unknown_member_rejects():
    assert_parse_rejects(
        variant(lambda a: a["policies"]["sev"]["sev_snp"].update(bogus=1)),
        match="unknown object member",
    )


def test_platform_block_pairing():
    def swap(a):
        a["policies"]["sev"]["tdx"] = copy.deepcopy(TDX_POLICY["tdx"])

    assert_parse_rejects(variant(swap), match="requires exactly the sev_snp block")

    def drop(a):
        del a["policies"]["tdx"]["tdx"]

    assert_parse_rejects(variant(drop), match="requires exactly the tdx block")

    def unknown(a):
        a["policies"]["sev"]["platform"] = "riscv"

    assert_parse_rejects(variant(unknown), match="unsupported platform")


def test_absent_required_members_reject():
    for member in ("minimum_build", "vmpl", "minimum_launch_mitigation_vector"):
        assert_parse_rejects(
            variant(lambda a, m=member: a["policies"]["sev"]["sev_snp"].pop(m)),
            match=f"{member} is required",
        )
    assert_parse_rejects(
        variant(lambda a: a["policies"]["sev"]["sev_snp"]["minimum_tcb"].pop("bl_spl")),
        match="minimum_tcb: bl_spl is required",
    )


def test_meaningful_zero_is_not_absent():
    a = parse(variant(lambda a: a["policies"]["sev"]["sev_snp"].update(minimum_build=0)))
    assert a.policies["sev"].sev_snp.minimum_build == 0


def test_vmpl_range():
    assert_parse_rejects(
        variant(lambda a: a["policies"]["sev"]["sev_snp"].update(vmpl=4)),
        match="vmpl must be between 0 and 3",
    )


def test_author_key_id_block_unsupported():
    assert_parse_rejects(
        variant(lambda a: a["policies"]["sev"]["sev_snp"].update(require_id_block=True)),
        match="not supported",
    )


def test_version_format():
    for bad in ("1", "1.", ".5", "a.b", "1.5.1", "256.0", "-1.0"):
        assert_parse_rejects(
            variant(lambda a, b=bad: a["policies"]["sev"]["sev_snp"].update(minimum_api_version=b)),
            match="minimum_api_version",
        )
    parse(variant(lambda a: a["policies"]["sev"]["sev_snp"].update(minimum_api_version="255.255")))


def test_policy_hex_validation():
    assert_parse_rejects(
        variant(lambda a: a["policies"]["sev"]["sev_snp"].update(host_data="AB" * 32)),
        match="must be lowercase hex",
    )
    assert_parse_rejects(
        variant(lambda a: a["policies"]["sev"]["sev_snp"].update(image_id="00" * 15)),
        match="must be 16 bytes",
    )
    assert_parse_rejects(
        variant(lambda a: a["policies"]["tdx"]["tdx"].update(xfam="00" * 7)),
        match="xfam must be 8 bytes",
    )


def test_tdx_required_members():
    assert_parse_rejects(
        variant(lambda a: a["policies"]["tdx"]["tdx"].update(minimum_tcb_evaluation_data_number=-1)),
        match="must not be negative",
    )
    assert_parse_rejects(
        variant(lambda a: a["policies"]["tdx"]["tdx"].update(platform_measurements=[])),
        match="platform_measurements must not be empty",
    )
    assert_parse_rejects(
        variant(lambda a: a["policies"]["tdx"]["tdx"].update(platform_measurements=["ghost"])),
        match="not in measurements",
    )


def test_measurement_shape_required():
    assert_parse_rejects(
        variant(lambda a: a["measurements"]["m1"].pop("shape")), match="shape is required"
    )


def test_machine_identifier_validation():
    assert_parse_rejects(
        variant(lambda a: a["machines"].update({"ff" * 64: "ghost"})), match="unknown policy"
    )
    assert_parse_rejects(
        variant(lambda a: a["machines"].update({"AB" * 64: "sev"})),
        match="identifier is not lowercase hex",
    )
    assert_parse_rejects(
        variant(lambda a: a["machines"].update({"ab" * 63: "sev"})),
        match="sev-snp identifier must be 128 hex chars",
    )
    assert_parse_rejects(
        variant(lambda a: a["machines"].update({"ab" * 17: "tdx"})),
        match="tdx identifier must be 32 hex chars",
    )


def test_duplicate_member_rejects():
    data = json.dumps(ARTIFACT).encode()
    dup = data[:-1] + b',"format":"x"}'
    with pytest.raises(VerificationError, match="duplicate object member") as ei:
        policy.parse_artifact(dup)
    assert ei.value.layer == PROVENANCE_REJECTED


def test_policy_for():
    a = parse(ARTIFACT)
    name, p = policy.policy_for(a, SEV_ID, policy.PLATFORM_SEV_SNP)
    assert name == "sev" and p.platform == policy.PLATFORM_SEV_SNP

    with pytest.raises(VerificationError) as ei:
        policy.policy_for(a, "ee" * 64, policy.PLATFORM_SEV_SNP)
    assert ei.value.layer == POLICY_REJECTED

    with pytest.raises(VerificationError, match="is for platform"):
        policy.policy_for(a, SEV_ID, policy.PLATFORM_TDX)


def test_resolve_platform_measurement():
    a = parse(ARTIFACT)
    t = a.policies["tdx"].tdx
    required = policy.Shape(cpus=4, memory_mb=16384, gpus=1, disks=3)
    name, m = policy.resolve_platform_measurement(a, t, required, "11" * 48, "22" * 48)
    assert name == "m1" and m.mrtd == "11" * 48

    # Wrong registers: shape matched but no configuration.
    with pytest.raises(VerificationError, match="do not match any allowed"):
        policy.resolve_platform_measurement(a, t, required, "33" * 48, "22" * 48)

    # Wrong shape: nothing is a candidate.
    other = policy.Shape(cpus=8, memory_mb=16384, gpus=1, disks=3)
    with pytest.raises(VerificationError, match="required VM shape"):
        policy.resolve_platform_measurement(a, t, other, "11" * 48, "22" * 48)

    with pytest.raises(VerificationError, match="required VM shape is missing"):
        policy.resolve_platform_measurement(a, t, None, "11" * 48, "22" * 48)


def test_shape_gpus_compared_only_when_declared():
    slug = policy.Shape(cpus=4, memory_mb=1, gpus=None, disks=1)
    req = policy.Shape(cpus=4, memory_mb=1, gpus=2, disks=1)
    assert slug.satisfies(req)
    slug2 = policy.Shape(cpus=4, memory_mb=1, gpus=1, disks=1)
    assert not slug2.satisfies(req)
    assert policy.shape_satisfies(None, req) is False
