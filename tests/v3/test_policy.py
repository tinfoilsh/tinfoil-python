"""The policy artifact: parsing and validation, policy lookup, platform-measurement resolution, and the per-platform
policy validators.

Inputs are JSON text: a hand-written object, or the fixture decoded, mutated
as a plain tree, and re-encoded. Where a test builds a record directly it
uses the dataclasses and ``dataclasses.replace``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from tinfoil._v3.verifier._policy import (
    ARTIFACT_FORMAT,
    ARTIFACT_FORMAT_V2,
    PLATFORM_SEV_SNP,
    PLATFORM_TDX,
    TCB,
    Artifact,
    PlatformMeasurement,
    PolicyError,
    SEVSNPPolicy,
    Shape,
    TDXPolicy,
    parse,
    satisfies,
)
from tinfoil._v3.verifier._policy.sev import GuestPolicy, SNPPlatform, validate_policy_version

FIXTURE = Path(__file__).parent / "testdata" / "platform-endorsements.json"

# Real production identifiers (public by design in the endorsement artifact).
BOX2_TURIN_ID = "6bb1229b7692b710" + "0" * 112
INF7_PPID = "3b064a0f58d5dd3688780aeb40e0b5d2"

Tree = dict[str, Any]


def fixture_text() -> str:
    return FIXTURE.read_text()


def fixture_tree() -> Tree:
    tree: Tree = json.loads(fixture_text())
    return tree


def render(tree: Tree) -> bytes:
    return json.dumps(tree, separators=(",", ":")).encode()


def load_fixture() -> Artifact:
    return parse(fixture_text().encode())


def mutated(mutate: Callable[[Tree], None]) -> bytes:
    tree = fixture_tree()
    mutate(tree)
    return render(tree)


def sev_block(tree: Tree) -> Tree:
    block: Tree = tree["policies"]["amd-turin-prod"]["sev_snp"]
    return block


def tdx_block(tree: Tree) -> Tree:
    block: Tree = tree["policies"]["tdx-h200-prod"]["tdx"]
    return block


# --- parse -------------------------------------------------------------------


def test_parse_artifact_fixture() -> None:
    artifact = load_fixture()
    assert len(artifact.machines) == 12
    assert len(artifact.policies) == 6
    assert len(artifact.measurements) == 16


def measurement_spec() -> Tree:
    return {"mrtd": "ab" * 48, "rtmr0": "cd" * 48, "shape": {"cpus": 1, "memory_mb": 1, "disks": 1}}


def set_gpus(value: int) -> Callable[[Tree], None]:
    def mutate(m: Tree) -> None:
        m["shape"]["gpus"] = value

    return mutate


def set_shape(key: str, value: int) -> Callable[[Tree], None]:
    def mutate(m: Tree) -> None:
        m["shape"][key] = value

    return mutate


def set_field(key: str, value: str) -> Callable[[Tree], None]:
    def mutate(m: Tree) -> None:
        m[key] = value

    return mutate


def set_upper(key: str) -> Callable[[Tree], None]:
    def mutate(m: Tree) -> None:
        m[key] = m[key].upper()

    return mutate


def drop_shape(m: Tree) -> None:
    m["shape"] = None


@pytest.mark.parametrize(
    ("name", "mutate", "want"),
    [
        ("optional GPUs", lambda m: None, ""),
        ("zero GPUs", set_gpus(0), ""),
        ("positive GPUs", set_gpus(1), ""),
        ("missing shape", drop_shape, "shape is required"),
        ("zero CPUs", set_shape("cpus", 0), "must be positive"),
        ("negative CPUs", set_shape("cpus", -1), "must be positive"),
        ("zero memory", set_shape("memory_mb", 0), "must be positive"),
        ("negative memory", set_shape("memory_mb", -1), "must be positive"),
        ("zero disks", set_shape("disks", 0), "must be positive"),
        ("negative disks", set_shape("disks", -1), "must be positive"),
        ("negative GPUs", set_gpus(-1), "gpus must be non-negative"),
        ("missing MRTD", set_field("mrtd", ""), "mrtd"),
        ("short MRTD", set_field("mrtd", "ab" * 47), "mrtd"),
        ("oversized MRTD", set_field("mrtd", "AB" * (1 << 19)), "mrtd must be 96 hex chars"),
        ("nonhex MRTD", set_field("mrtd", "z" * 96), "mrtd"),
        ("uppercase MRTD", set_upper("mrtd"), "mrtd"),
        ("missing RTMR0", set_field("rtmr0", ""), "rtmr0"),
        ("short RTMR0", set_field("rtmr0", "ab" * 47), "rtmr0"),
        ("oversized RTMR0", set_field("rtmr0", "AB" * (1 << 19)), "rtmr0 must be 96 hex chars"),
        ("nonhex RTMR0", set_field("rtmr0", "z" * 96), "rtmr0"),
        ("uppercase RTMR0", set_upper("rtmr0"), "rtmr0"),
    ],
    ids=lambda value: value if isinstance(value, str) and " " in value else None,
)
def test_parse_platform_measurement_validation(name: str, mutate: Callable[[Tree], None], want: str) -> None:
    m = measurement_spec()
    mutate(m)
    # Even an entry unused by any policy must be well formed.
    data = render({"format": ARTIFACT_FORMAT, "measurements": {"test": m}, "machines": None, "policies": None})
    if want == "":
        parse(data)
    else:
        with pytest.raises(PolicyError, match=want):
            parse(data)


def test_parse_artifact_fail_closed() -> None:
    data = fixture_text()

    wrong_format = data.replace("platform-endorsements/v1", "platform-endorsements/v9", 1)
    with pytest.raises(PolicyError, match="unsupported artifact format"):
        parse(wrong_format.encode())

    dangling_ref = data.replace('"amd-genoa-prod"', '"no-such-policy"', 1)
    with pytest.raises(PolicyError, match="unknown policy"):
        parse(dangling_ref.encode())

    # A negative minimum would let any observed collateral satisfy the floor.
    negative_min = data.replace(
        '"minimum_tcb_evaluation_data_number": 19', '"minimum_tcb_evaluation_data_number": -1', 1
    )
    assert negative_min != data
    with pytest.raises(PolicyError, match="must not be negative"):
        parse(negative_min.encode())


def test_policy_lookup() -> None:
    artifact = load_fixture()

    name, policy = artifact.policy_for(BOX2_TURIN_ID, PLATFORM_SEV_SNP)
    assert name == "amd-turin-prod"
    assert policy.sev_snp is not None

    name, policy = artifact.policy_for(INF7_PPID, PLATFORM_TDX)
    assert name == "tdx-h200-prod"
    assert policy.tdx is not None

    # Platform mismatch: TDX identifier presented as SEV evidence.
    with pytest.raises(PolicyError, match="is for platform"):
        artifact.policy_for(INF7_PPID, PLATFORM_SEV_SNP)

    # Unknown machine: unconditional rejection.
    with pytest.raises(PolicyError, match="not endorsed"):
        artifact.policy_for("ab" * 64, PLATFORM_SEV_SNP)


def test_resolve_platform_measurement_shape_filter() -> None:
    shape_a = Shape(cpus=8, memory_mb=65536, gpus=1, disks=4)
    shape_b = Shape(cpus=32, memory_mb=524288, gpus=2, disks=5)
    artifact = Artifact(
        format="",
        measurements={
            "one-disk": PlatformMeasurement(mrtd="aa", rtmr0="bb", shape=shape_a),
            "two-disk": PlatformMeasurement(mrtd="cc", rtmr0="dd", shape=shape_b),
            "no-gpus": PlatformMeasurement(mrtd="11", rtmr0="22", shape=Shape(cpus=8, memory_mb=65536, disks=4)),
            "legacy": PlatformMeasurement(mrtd="ee", rtmr0="ff"),
        },
        machines={},
        policies={},
    )
    policy = TDXPolicy(
        qe_vendor_id="",
        minimum_tee_tcb_svn="",
        mr_seam="",
        td_attributes="",
        xfam="",
        minimum_tcb_evaluation_data_number=None,
        platform_measurements=("one-disk", "two-disk", "no-gpus", "legacy"),
    )

    # The required shape is not optional.
    with pytest.raises(PolicyError, match="required VM shape is missing"):
        artifact.resolve_platform_measurement(policy, None, "ee", "ff")

    # The shape filter restricts candidates before the measurement lookup.
    name, measurement = artifact.resolve_platform_measurement(policy, shape_a, "aa", "bb")
    assert name == "one-disk"
    assert measurement.shape == shape_a

    # A slug without a GPU count satisfies any required GPU count.
    name, _ = artifact.resolve_platform_measurement(policy, shape_a, "11", "22")
    assert name == "no-gpus"

    # A quote from an endorsed but differently-shaped VM must not resolve.
    with pytest.raises(PolicyError, match="do not match any allowed configuration"):
        artifact.resolve_platform_measurement(policy, shape_a, "cc", "dd")

    # Entries without shape metadata are never candidates under a filter.
    with pytest.raises(PolicyError, match="do not match any allowed configuration"):
        artifact.resolve_platform_measurement(policy, shape_a, "ee", "ff")

    # A shape no endorsed entry was measured for reports the shape itself.
    with pytest.raises(PolicyError, match="required VM shape"):
        artifact.resolve_platform_measurement(policy, Shape(cpus=1, memory_mb=0, disks=0), "aa", "bb")


# --- v2 artifacts ------------------------------------------------------------


def v2_tree() -> Tree:
    """The fixture as a v2 artifact: no measurements map, no SEV host_data, no TDX platform_measurements."""
    tree = fixture_tree()
    tree["format"] = ARTIFACT_FORMAT_V2
    del tree["measurements"]
    for policy in tree["policies"].values():
        if "sev_snp" in policy:
            del policy["sev_snp"]["host_data"]
        else:
            del policy["tdx"]["platform_measurements"]
    return tree


def expected_v2() -> Artifact:
    artifact = load_fixture()
    policies = {}
    for name, policy in artifact.policies.items():
        if policy.sev_snp is not None:
            policies[name] = replace(policy, sev_snp=replace(policy.sev_snp, host_data=""))
        else:
            assert policy.tdx is not None
            policies[name] = replace(policy, tdx=replace(policy.tdx, platform_measurements=()))
    return Artifact(format=ARTIFACT_FORMAT_V2, measurements={}, machines=artifact.machines, policies=policies)


def test_platform_policy_without_workload_measurements() -> None:
    data = render(v2_tree())
    assert b'"measurements"' not in data
    assert parse(data) == expected_v2()


def restore_v1(tree: Tree) -> None:
    tree["format"] = ARTIFACT_FORMAT
    original = fixture_tree()["policies"]
    for name, policy in tree["policies"].items():
        if "sev_snp" in policy:
            policy["sev_snp"]["host_data"] = original[name]["sev_snp"]["host_data"]
        else:
            policy["tdx"]["platform_measurements"] = original[name]["tdx"]["platform_measurements"]


def add_host_data(tree: Tree) -> None:
    for policy in tree["policies"].values():
        if "sev_snp" in policy:
            policy["sev_snp"]["host_data"] = "00" * 32


def add_platform_measurements(tree: Tree) -> None:
    for policy in tree["policies"].values():
        if "tdx" in policy:
            policy["tdx"]["platform_measurements"] = ["legacy"]


def add_measurement_map(tree: Tree) -> None:
    tree["measurements"] = {"legacy": {"mrtd": "", "rtmr0": "", "shape": None}}


@pytest.mark.parametrize(
    "mutate",
    [restore_v1, add_host_data, add_platform_measurements, add_measurement_map],
    ids=[
        "v1 requires workload measurements",
        "v2 excludes host_data",
        "v2 excludes platform_measurements",
        "v2 excludes measurement map",
    ],
)
def test_v2_rejects_v1_members(mutate: Callable[[Tree], None]) -> None:
    data = render(v2_tree())
    changed = v2_tree()
    mutate(changed)
    encoded = render(changed)
    assert encoded != data
    with pytest.raises(PolicyError):
        parse(encoded)


@pytest.mark.parametrize("block", ["sev_snp", "tdx"])
def test_v2_rejects_config_binding(block: str) -> None:
    marked = v2_tree()
    for policy in marked["policies"].values():
        if block in policy:
            policy[block]["config_binding"] = "sha256"
    with pytest.raises(PolicyError, match="config_binding"):
        parse(render(marked))


# --- SEVSNPPolicy.validate ---------------------------------------------------


def valid_sevsnp_policy() -> SEVSNPPolicy:
    tcb = TCB(bl_spl=0, tee_spl=0, snp_spl=0, ucode_spl=0)
    return SEVSNPPolicy(
        minimum_build=0,
        minimum_api_version="1.55",
        minimum_abi_version="0.31",
        minimum_guest_svn=0,
        minimum_tcb=tcb,
        minimum_launch_tcb=tcb,
        guest_policy=GuestPolicy(),
        platform_info=SNPPlatform(),
        permit_provisional_firmware=False,
        vmpl=0,
        host_data="ab" * 32,
        image_id="cd" * 16,
        family_id="ef" * 16,
        require_author_key=False,
        require_id_block=False,
        minimum_launch_mitigation_vector=0,
        minimum_current_mitigation_vector=0,
    )


def test_sevsnp_policy_validate_accepts_valid() -> None:
    valid_sevsnp_policy().validate()


@pytest.mark.parametrize(
    ("name", "changes"),
    [
        ("malformed api version", {"minimum_api_version": "1.2.3"}),
        ("version component overflow", {"minimum_abi_version": "256.0"}),
        ("uppercase hex", {"host_data": ("ab" * 32).upper()}),
        ("short hex", {"image_id": ("cd" * 16)[:-2]}),
        ("non-hex", {"family_id": "z" * 32}),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_sevsnp_policy_validate_encoded_fields(name: str, changes: dict[str, Any]) -> None:
    bad = replace(valid_sevsnp_policy(), **changes)
    with pytest.raises(PolicyError):
        bad.validate()


@pytest.mark.parametrize(
    ("version", "match"),
    [
        ("1.55", ""),
        ("0.0", ""),
        ("255.255", ""),
        ("256.0", r"minimum_api_version major: value out of range"),
        ("0.256", r"minimum_api_version minor: value out of range"),
        ("1" * 10_000 + ".0", r"minimum_api_version major: value out of range"),
        ("0." + "9" * 10_000, r"minimum_api_version minor: value out of range"),
        ("1", r'minimum_api_version "1" is not maj.min'),
        ("1.", r"is not maj.min"),
        (".1", r"is not maj.min"),
        ("1.2.3", r"is not maj.min"),
        ("-1.0", r"is not maj.min"),
        ("1.0 ", r"is not maj.min"),
        ("１.0", r"is not maj.min"),
    ],
)
def test_validate_policy_version(version: str, match: str) -> None:
    if match == "":
        validate_policy_version("minimum_api_version", version)
    else:
        with pytest.raises(PolicyError, match=match):
            validate_policy_version("minimum_api_version", version)


def test_long_version_component_in_artifact() -> None:
    raises_parse(mutated(set_sev("minimum_api_version", "1" * 10_000 + ".0")), r"major: value out of range")


# --- TDXPolicy.validate ------------------------------------------------------


def valid_tdx_policy() -> TDXPolicy:
    return TDXPolicy(
        qe_vendor_id="ab" * 16,
        minimum_tee_tcb_svn="00" * 16,
        mr_seam="cd" * 48,
        td_attributes="00" * 8,
        xfam="00" * 8,
        minimum_tcb_evaluation_data_number=0,
        platform_measurements=("sample",),
    )


def test_tdx_policy_validate_accepts_valid() -> None:
    valid_tdx_policy().validate()


@pytest.mark.parametrize(
    ("name", "changes"),
    [
        ("uppercase", {"qe_vendor_id": ("ab" * 16).upper()}),
        ("odd length", {"mr_seam": ("cd" * 48)[:-1]}),
        ("non-hex", {"xfam": "z" * 16}),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_tdx_policy_validate_hex_fields(name: str, changes: dict[str, Any]) -> None:
    bad = replace(valid_tdx_policy(), **changes)
    with pytest.raises(PolicyError):
        bad.validate()


# --- Shape.satisfies ---------------------------------------------------------


def test_shape_satisfies_none() -> None:
    shape = Shape(cpus=4, memory_mb=4096, disks=3)
    assert shape.satisfies(None) is False
    assert satisfies(None, shape) is False


# --- decode semantics --------------------------------------------------------


def set_sev(key: str, value: Any) -> Callable[[Tree], None]:
    def mutate(tree: Tree) -> None:
        sev_block(tree)[key] = value

    return mutate


def raises_parse(data: bytes, match: str) -> None:
    with pytest.raises(PolicyError, match=match):
        parse(data)


def test_rerendered_fixture_parses() -> None:
    parse(mutated(lambda tree: None))


@pytest.mark.parametrize(
    ("value", "match"),
    [
        (256, r"parsing policy artifact: .*256 overflows uint8"),
        (-1, r"parsing policy artifact: .*JSON number -1 is negative"),
        (1.0, r"parsing policy artifact: .*1\.0 is not an integer"),
        ("0", r'parsing policy artifact: .*JSON string into number within "/minimum_build"'),
        (None, r'policy "amd-turin-prod": minimum_build is required'),
    ],
)
def test_minimum_build_literals(value: Any, match: str) -> None:
    raises_parse(mutated(set_sev("minimum_build", value)), match)


def test_minimum_build_accepts_zero() -> None:
    parse(mutated(set_sev("minimum_build", 0)))


def test_uint64_mitigation_vector_bounds() -> None:
    artifact = parse(mutated(set_sev("minimum_launch_mitigation_vector", (1 << 64) - 1)))
    sev_snp = artifact.policies["amd-turin-prod"].sev_snp
    assert sev_snp is not None
    assert sev_snp.minimum_launch_mitigation_vector == (1 << 64) - 1
    raises_parse(
        mutated(set_sev("minimum_launch_mitigation_vector", 1 << 64)),
        r"parsing policy artifact: .*18446744073709551616 overflows uint64",
    )


def test_uint32_guest_svn_overflow() -> None:
    raises_parse(
        mutated(set_sev("minimum_guest_svn", 1 << 32)), r"parsing policy artifact: .*4294967296 overflows uint32"
    )


def test_int_cpus_literals() -> None:
    def fractional(tree: Tree) -> None:
        tree["measurements"]["mini_0d"]["shape"]["cpus"] = 1.5

    def overflow(tree: Tree) -> None:
        tree["measurements"]["mini_0d"]["shape"]["cpus"] = 1 << 63

    raises_parse(mutated(fractional), r"parsing policy artifact: .*1\.5 is not an integer")
    raises_parse(mutated(overflow), r"parsing policy artifact: .*9223372036854775808 overflows int64")


@pytest.mark.parametrize("value", [4, -1])
def test_vmpl_range(value: int) -> None:
    raises_parse(mutated(set_sev("vmpl", value)), r'policy "amd-turin-prod": vmpl must be between 0 and 3')


def test_vmpl_accepts_three() -> None:
    sev_snp = parse(mutated(set_sev("vmpl", 3))).policies["amd-turin-prod"].sev_snp
    assert sev_snp is not None
    assert sev_snp.vmpl == 3


def test_unknown_members_reject_at_every_depth() -> None:
    def in_guest_policy(tree: Tree) -> None:
        sev_block(tree)["guest_policy"]["extra"] = True

    def in_tcb(tree: Tree) -> None:
        sev_block(tree)["minimum_tcb"]["extra"] = 0

    def in_shape(tree: Tree) -> None:
        tree["measurements"]["mini_0d"]["shape"]["extra"] = 0

    def at_top(tree: Tree) -> None:
        tree["extra"] = 0

    for mutate in (in_guest_policy, in_tcb, in_shape, at_top):
        raises_parse(mutated(mutate), r'^parsing policy artifact: .*unknown object member name "extra"')


def test_null_members() -> None:
    def null_shape(tree: Tree) -> None:
        tree["measurements"]["mini_0d"]["shape"] = None

    def null_stack(tree: Tree) -> None:
        tree["measurements"]["mini_0d"]["stack"] = None

    def null_sev(tree: Tree) -> None:
        tree["policies"]["amd-turin-prod"]["sev_snp"] = None

    def null_tdx(tree: Tree) -> None:
        tree["policies"]["tdx-h200-prod"]["tdx"] = None

    def null_measurements(tree: Tree) -> None:
        tree["measurements"] = None

    def null_machines(tree: Tree) -> None:
        tree["machines"] = None

    def null_policies(tree: Tree) -> None:
        tree["policies"] = None

    def null_platform_measurements(tree: Tree) -> None:
        tdx_block(tree)["platform_measurements"] = None

    def null_policy_name(tree: Tree) -> None:
        tree["machines"][INF7_PPID] = None

    raises_parse(mutated(null_shape), r'measurement "mini_0d": shape is required')
    assert parse(mutated(null_stack)).measurements["mini_0d"].stack is None
    raises_parse(mutated(null_sev), r'policy "amd-turin-prod": platform sev-snp requires exactly the sev_snp block')
    raises_parse(mutated(null_tdx), r'policy "tdx-h200-prod": platform tdx requires exactly the tdx block')
    raises_parse(mutated(null_measurements), r'platform_measurements ref ".*" not in measurements')
    assert len(parse(mutated(null_machines)).machines) == 0
    raises_parse(mutated(null_policies), r'^machine [0-9a-f]{16}\.\.\.: unknown policy "')
    # A null guest_policy reads as the policy with every bit false.
    sev_snp = parse(mutated(set_sev("guest_policy", None))).policies["amd-turin-prod"].sev_snp
    assert sev_snp is not None
    assert sev_snp.guest_policy == GuestPolicy()
    raises_parse(mutated(set_sev("minimum_tcb", None)), r'policy "amd-turin-prod": minimum_tcb: bl_spl is required')
    raises_parse(
        mutated(null_platform_measurements),
        r'policy "tdx-h200-prod": platform_measurements are required in v1 and excluded in v2',
    )
    raises_parse(mutated(null_policy_name), r'machine 3b064a0f58d5dd36\.\.\.: unknown policy ""')


def test_wrong_type_for_shape() -> None:
    def string_shape(tree: Tree) -> None:
        tree["measurements"]["mini_0d"]["shape"] = "x"

    raises_parse(mutated(string_shape), r"parsing policy artifact: cannot unmarshal JSON string into shape")


def test_duplicate_members_in_nested_blocks() -> None:
    base = mutated(lambda tree: None)
    raises_parse(
        base.replace(b'"debug":false', b'"debug":false,"debug":false'), r'duplicate object member name "debug"'
    )
    raises_parse(base.replace(b'"bl_spl":', b'"bl_spl":0,"bl_spl":', 1), r'duplicate object member name "bl_spl"')
    raises_parse(base.replace(b'"cpus":', b'"cpus":1,"cpus":', 1), r'duplicate object member name "cpus"')


def test_framing() -> None:
    raises_parse(mutated(lambda tree: None) + b"\n{}", r"^parsing policy artifact: ")
    raises_parse(b"", r"^parsing policy artifact: ")
    raises_parse(b"[]", r"^parsing policy artifact: cannot unmarshal JSON array into policy artifact")
    raises_parse(b"null", r'^unsupported artifact format ""')


def test_machine_identifier_checks() -> None:
    def uppercase_id(tree: Tree) -> None:
        tree["machines"][INF7_PPID.upper()] = tree["machines"].pop(INF7_PPID)

    def short_sev_id(tree: Tree) -> None:
        tree["machines"][BOX2_TURIN_ID[:64]] = tree["machines"].pop(BOX2_TURIN_ID)

    def long_tdx_id(tree: Tree) -> None:
        tree["machines"][INF7_PPID + "00"] = tree["machines"].pop(INF7_PPID)

    raises_parse(mutated(uppercase_id), r"identifier is not lowercase hex")
    raises_parse(mutated(short_sev_id), r"sev-snp identifier must be 128 hex chars, got 64")
    raises_parse(mutated(long_tdx_id), r"tdx identifier must be 32 hex chars, got 34")


def test_policy_block_mismatches() -> None:
    def both_blocks(tree: Tree) -> None:
        tree["policies"]["amd-turin-prod"]["tdx"] = tdx_block(tree)

    def unknown_platform(tree: Tree) -> None:
        tree["policies"]["amd-turin-prod"]["platform"] = "arm-cca"

    def require_id_block(tree: Tree) -> None:
        sev_block(tree)["require_id_block"] = True

    raises_parse(mutated(both_blocks), r'policy "amd-turin-prod": platform sev-snp requires exactly the sev_snp block')
    raises_parse(mutated(unknown_platform), r'policy "amd-turin-prod": unsupported platform "arm-cca"')
    raises_parse(mutated(require_id_block), r"require_author_key and require_id_block are not supported")
