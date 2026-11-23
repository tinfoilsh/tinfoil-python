"""The builds that a config requires for its container images (container_provenance_from_config)."""

from __future__ import annotations

import dataclasses
import time

import pytest

from tinfoil.verifier._runtime import ContainerConfigError, ContainerProvenance, container_provenance_from_config

DIGEST = "ab" * 32
IMAGE = "ghcr.io/tinfoilsh/inference-vllm@sha256:" + DIGEST
GITHUB = """    provenance:
      github:
        repository: tinfoilsh/inference
        repository_id: 902195777
        workflow: containers.yml
        ref: refs/tags/vllm-v*
"""
FLOW_DETAIL = (
    "{repository: tinfoilsh/inference, repository_id: 902195777, workflow: containers.yml, ref: 'refs/tags/vllm-v*'}"
)
FLOW_REQUIREMENT = "{github: " + FLOW_DETAIL + "}"
WANT = ContainerProvenance(
    container="model",
    digest=DIGEST,
    repository="tinfoilsh/inference",
    repository_id="902195777",
    workflow="containers.yml",
    ref="refs/tags/vllm-v*",
)


def config(image: str = IMAGE, provenance: str = GITHUB) -> bytes:
    """A config whose second container, ``model``, runs ``image`` and declares ``provenance``."""
    return (
        "cvm-version: 0.15.5\ncontainers:\n  - name: router\n    image: example.com/router@sha256:"
        + "cd" * 32
        + "\n  - name: model\n    image: "
        + image
        + "\n"
        + provenance
    ).encode()


def replace(old: str, new: str) -> str:
    assert old in GITHUB
    return GITHUB.replace(old, new, 1)


def test_config_declares_the_build_that_a_container_requires() -> None:
    assert container_provenance_from_config(config()) == (WANT,)
    longest = "9" * 18
    assert container_provenance_from_config(config(provenance=replace("902195777", longest))) == (
        dataclasses.replace(WANT, repository_id=longest),
    )
    both = config() + f"  - name: tools\n    image: {IMAGE}\n{replace('vllm-v*', 'tools-v*')}".encode()
    assert container_provenance_from_config(both) == (
        WANT,
        dataclasses.replace(WANT, container="tools", ref="refs/tags/tools-v*"),
    )


@pytest.mark.parametrize("absent", ["", "    provenance:\n", "    provenance: null\n", "    provenance: ~\n"])
def test_absent_or_null_provenance_declares_no_requirement(absent: str) -> None:
    assert container_provenance_from_config(config(provenance=absent)) == ()


@pytest.mark.parametrize(
    "config_text",
    ["cvm-version: 0.15.5\n", "containers:\n", "containers: []\n", "containers:\n  - ~\n"],
    ids=["no containers", "null containers", "empty containers", "null container"],
)
def test_config_without_containers_declares_no_requirement(config_text: str) -> None:
    assert container_provenance_from_config(config_text.encode()) == ()


@pytest.mark.parametrize(
    ("image", "provenance", "message"),
    [
        pytest.param(
            IMAGE,
            "    provenance:\n      gitlab:\n        project: a/b\n",
            r"^containers\[1\]\.provenance has unknown field 'gitlab'$",
            id="unknown kind of requirement",
        ),
        pytest.param(
            IMAGE,
            GITHUB + "      require_signed_commits: true\n",
            r"^containers\[1\]\.provenance has unknown field 'require_signed_commits'$",
            id="extra requirement",
        ),
        pytest.param(
            IMAGE,
            GITHUB + "        environment: release\n",
            r"^containers\[1\]\.provenance\.github has unknown field 'environment'$",
            id="extra detail",
        ),
        pytest.param(
            IMAGE, "    provenance: {}\n", r"^containers\[1\]\.provenance\.github is required$", id="empty requirement"
        ),
        pytest.param(
            IMAGE,
            "    provenance: tinfoilsh/inference\n",
            r"^containers\[1\]\.provenance must be a mapping$",
            id="not a mapping",
        ),
        pytest.param(
            IMAGE,
            "    provenance:\n      github:\n",
            r"^containers\[1\]\.provenance\.github must be a mapping$",
            id="null detail",
        ),
        pytest.param(
            IMAGE,
            GITHUB + "        ref: refs/heads/main\n",
            r"^containers\[1\]\.provenance\.github has duplicate field 'ref'$",
            id="duplicate detail",
        ),
        pytest.param(
            IMAGE,
            GITHUB + "      github: {}\n",
            r"^containers\[1\]\.provenance has duplicate field 'github'$",
            id="duplicate kind of requirement",
        ),
        pytest.param(
            IMAGE,
            GITHUB + "    provenance: null\n",
            r"containers\[1\]: mapping key 'provenance' already defined",
            id="duplicate requirement",
        ),
        pytest.param(
            IMAGE,
            GITHUB + "    image: " + IMAGE.replace("ab", "ef") + "\n",
            r"containers\[1\]: mapping key 'image' already defined",
            id="duplicate image",
        ),
        pytest.param(
            IMAGE, replace("tinfoilsh/inference", "inference"), "must be owner/name", id="repository without owner"
        ),
        pytest.param(
            IMAGE,
            replace("tinfoilsh/inference", '"tinfoilsh/inference\\n"'),
            "must be owner/name",
            id="repository with a trailing newline",
        ),
        pytest.param(
            IMAGE, replace("        repository_id: 902195777\n", ""), "repository_id", id="missing repository ID"
        ),
        pytest.param(IMAGE, replace("902195777", "0902195777"), "repository_id", id="repository ID leading zero"),
        pytest.param(IMAGE, replace("902195777", "0x35c66b01"), "repository_id", id="repository ID in hex"),
        pytest.param(IMAGE, replace("902195777", "0o6561465401"), "repository_id", id="repository ID in octal"),
        pytest.param(IMAGE, replace("902195777", "06561465401"), "repository_id", id="repository ID in old octal"),
        pytest.param(IMAGE, replace("902195777", "+902195777"), "repository_id", id="repository ID with a sign"),
        pytest.param(IMAGE, replace("902195777", "902_195_777"), "repository_id", id="repository ID grouped"),
        pytest.param(IMAGE, replace("902195777", "9.02195777e8"), "repository_id", id="repository ID as a float"),
        pytest.param(IMAGE, replace("902195777", "902195777.0"), "repository_id", id="repository ID with a fraction"),
        pytest.param(IMAGE, replace("902195777", '"902195777"'), "repository_id", id="repository ID as a string"),
        pytest.param(IMAGE, replace("902195777", "-902195777"), "repository_id", id="repository ID negative"),
        pytest.param(IMAGE, replace("902195777", "0"), "repository_id", id="repository ID zero"),
        pytest.param(IMAGE, replace("902195777", "9" * 19), "repository_id", id="repository ID too long"),
        pytest.param(IMAGE, replace("902195777", "[902195777]"), "repository_id", id="repository ID as a list"),
        pytest.param(IMAGE, replace("902195777", "true"), "repository_id", id="repository ID as a boolean"),
        pytest.param(IMAGE, replace("902195777", "15032629:37"), "repository_id", id="repository ID in base sixty"),
        pytest.param(
            IMAGE,
            f"    provenance: !!null {FLOW_REQUIREMENT}\n",
            r"^containers\[1\]\.provenance must be a mapping$",
            id="null-tagged requirement",
        ),
        pytest.param(
            IMAGE,
            f"    provenance:\n      github: !!null {FLOW_DETAIL}\n",
            r"^containers\[1\]\.provenance\.github must be a mapping$",
            id="null-tagged detail",
        ),
        pytest.param(IMAGE, replace("containers.yml", "sub/containers.yml"), "workflow file name", id="workflow path"),
        pytest.param(
            IMAGE,
            replace("containers.yml", '"containers.yml\\n"'),
            "workflow file name",
            id="workflow with a trailing newline",
        ),
        pytest.param(
            IMAGE, replace("refs/tags/vllm-v*", "refs/pull/*/merge"), "tag or branch ref pattern", id="pull request ref"
        ),
        pytest.param(
            IMAGE,
            replace("refs/tags/vllm-v*", "refs/tags/v@refs/heads/main"),
            "tag or branch ref pattern",
            id="ref with identity separator",
        ),
        pytest.param(
            IMAGE,
            replace("refs/tags/vllm-v*", '"refs/heads/main\\n"'),
            "tag or branch ref pattern",
            id="ref with a trailing newline",
        ),
        pytest.param(
            "ghcr.io/tinfoilsh/inference-vllm:latest",
            GITHUB,
            r"^containers\[1\]\.image must pin a SHA-256 digest to declare provenance$",
            id="image without digest",
        ),
        pytest.param(IMAGE + "@sha256:" + "ef" * 32, GITHUB, "must pin a SHA-256 digest", id="image with two digests"),
        pytest.param('"@sha256:' + DIGEST + '"', GITHUB, "must pin a SHA-256 digest", id="image without a name"),
        pytest.param('"' + IMAGE + '\\n"', GITHUB, "must pin a SHA-256 digest", id="image with a trailing newline"),
        pytest.param(
            IMAGE,
            replace("refs/tags/vllm-v*", "refs/tags/" + "*" * 300),
            "tag or branch ref pattern",
            id="oversized ref",
        ),
        pytest.param(
            IMAGE,
            replace("tinfoilsh/inference", "tinfoilsh/" + "a" * 200),
            "must be owner/name",
            id="oversized repository",
        ),
        pytest.param(
            IMAGE, replace("containers.yml", "a" * 300 + ".yml"), "workflow file name", id="oversized workflow"
        ),
        pytest.param(
            IMAGE,
            GITHUB + "---\ncontainers: []\n",
            "^config must contain exactly one YAML document$",
            id="second document",
        ),
    ],
)
def test_requirement_that_cannot_be_read_in_full_is_rejected(image: str, provenance: str, message: str) -> None:
    with pytest.raises(ContainerConfigError, match=message):
        container_provenance_from_config(config(image, provenance))


@pytest.mark.parametrize(
    "malformed",
    [
        b"containers: [\n",
        b"containers: \xff\n",
        b"",
        b"- name: model\n",
        b"containers: model\n",
        b"containers:\n  - model\n",
        b"containers:\n  - name: [model]\n",
        b"containers:\n  - image: {name: model}\n",
        b"? [a]\n: 1\n<<: {b: 2}\ncontainers: []\n",
        b"<<: {b: 2}\n? [a]\n: 1\n",
        b"? {a: 1}\n: 1\n<<: {b: 2}\n",
        b"containers: " + b"[" * 20_000 + b"]" * 20_000 + b"\n",
        b"containers:\n  - <<: model\n",
        b"containers:\n  - <<: [{name: model}, model]\n",
        b"containers:\n  - <<: {name: model}\n    <<: {image: model}\n",
        b"containers:\n  - <<: {name: model, name: router}\n",
        b"containers:\n  - &model\n    <<: *model\n",
        b"containers:\n  - <<: &model\n      <<: {<<: *model}\n",
    ],
    ids=lambda value: repr(value[:24]),
)
def test_malformed_config_is_an_error(malformed: bytes) -> None:
    with pytest.raises(ContainerConfigError, match=r"^parsing config provenance: "):
        container_provenance_from_config(malformed)


def test_merge_keys_are_resolved() -> None:
    primary = dataclasses.replace(WANT, container="primary")
    replica = dataclasses.replace(WANT, container="replica")
    anchored = f"cvm-version: 0.15.5\ncontainers:\n  - &primary\n    name: primary\n    image: {IMAGE}\n{GITHUB}"
    merged = anchored + "  - <<: *primary\n    name: replica\n"
    assert container_provenance_from_config(merged.encode()) == (primary, replica)
    # A container's own member takes precedence over a merged one, wherever the merge key stands.
    reordered = anchored + "  - name: replica\n    <<: *primary\n"
    assert container_provenance_from_config(reordered.encode()) == (primary, replica)
    assert container_provenance_from_config((merged + "    provenance: null\n").encode()) == (primary,)
    with pytest.raises(ContainerConfigError, match=r"^containers\[1\]\.image must pin a SHA-256 digest"):
        container_provenance_from_config((merged + "    image: example.com/replica:latest\n").encode())
    # An earlier merged mapping takes precedence over a later one, and a merged mapping's own members over
    # those that it merges in turn.
    layered = f"""\
base: &base {{name: base, image: example.com/base:latest}}
build: &build
  <<: *base
  image: {IMAGE}
  provenance: {FLOW_REQUIREMENT}
late: &late {{name: late, provenance: null}}
containers:
  - <<: [*build, *late]
"""
    assert container_provenance_from_config(layered.encode()) == (dataclasses.replace(WANT, container="base"),)
    # The containers themselves may be merged into the config.
    shared = f"""\
shared: &shared
  containers:
    - name: model
      image: {IMAGE}
      provenance: {FLOW_REQUIREMENT}
<<: *shared
"""
    assert container_provenance_from_config(shared.encode()) == (WANT,)


def test_mapping_merged_many_times_is_read_once() -> None:
    """Each layer merges the one below it twice, so reading a mapping once per merge would take about a minute for
    this config and twice as long for each further layer."""
    allowance_seconds = 5.0
    layers = 24
    layered = f"layer0: &layer0 {{image: {IMAGE}, provenance: {FLOW_REQUIREMENT}}}\n" + "".join(
        f"layer{layer}: &layer{layer} {{<<: [*layer{layer - 1}, *layer{layer - 1}]}}\n" for layer in range(1, layers)
    )
    config_text = layered + f"containers:\n  - <<: *layer{layers - 1}\n    name: model\n"
    started = time.monotonic()
    assert container_provenance_from_config(config_text.encode()) == (WANT,)
    assert time.monotonic() - started < allowance_seconds


def test_requirement_is_read_through_aliases_and_flow_style() -> None:
    shared = (
        "cvm-version: 0.15.5\ncontainers:\n  - name: model\n    image: "
        + IMAGE
        + "\n    provenance: &build\n"
        + GITHUB.split("\n", 1)[1]
        + "  - name: copy\n    image: "
        + IMAGE
        + "\n    provenance: *build\n"
    ).encode()
    assert container_provenance_from_config(shared) == (WANT, dataclasses.replace(WANT, container="copy"))
    flow = f"containers: [{{name: model, image: '{IMAGE}', provenance: {FLOW_REQUIREMENT}}}]\n".encode()
    assert container_provenance_from_config(flow) == (WANT,)
