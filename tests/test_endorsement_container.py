"""Container provenance: the builds that a config requires, the recorded build attestation of a published image and
the ref patterns."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from tinfoil.verifier import _json
from tinfoil.verifier._endorsement.container import (
    ContainerConfigError,
    ContainerProvenance,
    authenticate_container,
    container_provenance_from_config,
    ref_matches,
)
from tinfoil.verifier._endorsement.provenance import ProvenanceClient, ProvenanceError

DIGEST, OTHER_DIGEST = "ab" * 32, "cd" * 32
IMAGE_NAME = '"ghcr.io/tinfoilsh/inference-vllm'
IMAGE = f'{IMAGE_NAME}@sha256:{DIGEST}"'
GITHUB = (
    '{"repository":"tinfoilsh/inference","repository_id":"902195777",'
    '"workflow":"containers.yml","ref":"refs/tags/vllm-v*"}'
)
PROVENANCE = '{"github":' + GITHUB + "}"
UNCONSTRAINED = '{"name":"router","image":"example.com/router:latest"}'


def container(image: str, provenance: str) -> str:
    return '{"name":"model","image":' + image + ',"provenance":' + provenance + "}"


def config(containers: str) -> str:
    return '{"cvm-version":"0.15.5","containers":' + containers + "}"


def requiring(image: str, provenance: str) -> str:
    return config("[" + container(image, provenance) + "]")


def edited(old: str, new: str) -> str:
    """A config whose requirement is ``GITHUB`` with ``old`` replaced."""
    assert old in GITHUB
    return requiring(IMAGE, '{"github":' + GITHUB.replace(old, new, 1) + "}")


def required(digest: str) -> ContainerProvenance:
    return ContainerProvenance(
        digest=digest,
        repository="tinfoilsh/inference",
        repository_id="902195777",
        workflow="containers.yml",
        ref="refs/tags/vllm-v*",
    )


@pytest.mark.parametrize(
    ("text", "want"),
    [
        pytest.param('{"cvm-version":"0.15.5"}', (), id="no containers"),
        pytest.param("null", (), id="config null"),
        pytest.param(config("[]"), (), id="empty containers"),
        pytest.param(config("[" + UNCONSTRAINED + ',{"image":7}]'), (), id="no provenance"),
        pytest.param(
            config(
                "["
                + UNCONSTRAINED
                + ","
                + container(IMAGE, PROVENANCE)
                + ","
                + container(f'"@sha256:{OTHER_DIGEST}"', PROVENANCE)
                + "]"
            ),
            (required(DIGEST), required(OTHER_DIGEST)),
            id="required",
        ),
        pytest.param("containers: []\n", None, id="not JSON"),
        pytest.param("[]", None, id="config not an object"),
        pytest.param(config("[]") + "{}", None, id="trailing data"),
        pytest.param(config('[{"image":' + IMAGE + ',"image":' + IMAGE + "}]"), None, id="repeated container member"),
        pytest.param(config("null"), None, id="containers null"),
        pytest.param(config("{}"), None, id="containers not an array"),
        pytest.param(config("[null]"), None, id="container null"),
        pytest.param(config('["model"]'), None, id="container not an object"),
        pytest.param(requiring(IMAGE, "null"), None, id="provenance null"),
        pytest.param(requiring(IMAGE, '"github"'), None, id="provenance not an object"),
        pytest.param(requiring(IMAGE, "{}"), None, id="provenance empty"),
        pytest.param(requiring(IMAGE, '{"gitlab":' + GITHUB + "}"), None, id="unknown kind"),
        pytest.param(requiring(IMAGE, '{"github":' + GITHUB + ',"gitlab":{}}'), None, id="second kind"),
        pytest.param(requiring(IMAGE, '{"GitHub":' + GITHUB + "}"), None, id="kind in another case"),
        pytest.param(requiring(IMAGE, '{"github":null}'), None, id="github null"),
        pytest.param(requiring(IMAGE, '{"github":"tinfoilsh/inference"}'), None, id="github not an object"),
        pytest.param(edited('"repository":"tinfoilsh/inference",', ""), None, id="github without repository"),
        pytest.param(edited('"repository_id":"902195777",', ""), None, id="github without repository_id"),
        pytest.param(edited('"workflow":"containers.yml",', ""), None, id="github without workflow"),
        pytest.param(edited(',"ref":"refs/tags/vllm-v*"', ""), None, id="github without ref"),
        pytest.param(edited("}", ',"environment":"release"}'), None, id="github unknown member"),
        pytest.param(edited("}", ',"ref":"refs/heads/main"}'), None, id="github repeated member"),
        pytest.param(edited('"902195777"', "902195777"), None, id="github number member"),
        pytest.param(edited('"refs/tags/vllm-v*"', "null"), None, id="github null member"),
        pytest.param(config('[{"provenance":' + PROVENANCE + "}]"), None, id="image absent"),
        pytest.param(requiring("null", PROVENANCE), None, id="image null"),
        pytest.param(requiring("7", PROVENANCE), None, id="image not a string"),
        pytest.param(requiring(IMAGE_NAME + ':latest"', PROVENANCE), None, id="image by tag"),
        pytest.param(requiring(f'"{DIGEST}"', PROVENANCE), None, id="image digest alone"),
        pytest.param(
            requiring(f'{IMAGE_NAME}@sha256:{DIGEST.upper()}"', PROVENANCE), None, id="image digest uppercase"
        ),
        pytest.param(requiring(f'{IMAGE_NAME}@sha256:{DIGEST[1:]}"', PROVENANCE), None, id="image digest short"),
        pytest.param(requiring(f'{IMAGE_NAME}@sha256:{DIGEST}a"', PROVENANCE), None, id="image digest long"),
        pytest.param(requiring(f'{IMAGE_NAME}@sha256:{DIGEST}/"', PROVENANCE), None, id="image digest not last"),
    ],
)
def test_container_provenance_from_config(text: str, want: tuple[ContainerProvenance, ...] | None) -> None:
    """The requirements that a config declares, or None for a config that is rejected."""
    if want is None:
        with pytest.raises(ContainerConfigError):
            container_provenance_from_config(text.encode())
    else:
        assert container_provenance_from_config(text.encode()) == want


# The recorded bundle is the published build attestation of the image with this digest, which verifies against the
# embedded root and meets RECORDED_PROVENANCE. Its certificate names the workflow identity
# https://github.com/tinfoilsh/measure-image-action/.github/workflows/build.yml@refs/tags/build-v0.14.2.
RECORDED_BUNDLE = Path(__file__).parent / "testdata" / "container-provenance-bundle.json"
RECORDED_DIGEST = "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1"
RECORDED_IMAGE = "ghcr.io/tinfoilsh/measure-image-action@sha256:" + RECORDED_DIGEST
RECORDED_PROVENANCE = (
    '{"github":{"repository":"tinfoilsh/measure-image-action","repository_id":"924941172",'
    '"workflow":"build.yml","ref":"refs/tags/build-v*"}}'
)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        pytest.param({}, None, id="the recorded build"),
        pytest.param({"digest": "00" + RECORDED_DIGEST[2:]}, "verifying container provenance", id="another image"),
        pytest.param({"repository": "tinfoilsh/measure-image"}, "source repository '", id="another repository"),
        pytest.param({"repository_id": "92494117"}, "source repository ID", id="another repository ID"),
        pytest.param({"workflow": "release.yml"}, "workflow identity", id="another workflow"),
        pytest.param({"ref": "refs/tags/v*"}, "source ref", id="another ref"),
    ],
)
def test_authenticate_container(change: dict[str, str], message: str | None) -> None:
    """The recorded bundle against the requirement that it meets with ``change`` applied: accepted, or rejected with
    ``message``."""
    config = '{"containers":[{"image":"' + RECORDED_IMAGE + '","provenance":' + RECORDED_PROVENANCE + "}]}"
    (recorded,) = container_provenance_from_config(config.encode())
    bundle = _json.strict_parse(RECORDED_BUNDLE.read_bytes())
    required = dataclasses.replace(recorded, **change)
    if message is None:
        authenticate_container(ProvenanceClient.default(), bundle, required)
    else:
        with pytest.raises(ProvenanceError, match=message):
            authenticate_container(ProvenanceClient.default(), bundle, required)


@pytest.mark.parametrize(
    ("pattern", "ref", "want"),
    [
        pytest.param("refs/heads/main", "refs/heads/main", True, id="literal"),
        pytest.param("refs/heads/main", "refs/heads/maintenance", False, id="literal prefix"),
        pytest.param("refs/tags/v1.2", "refs/tags/v1x2", False, id="literal is not a pattern"),
        pytest.param("refs/tags/*", "refs/tags", False, id="fewer segments"),
        pytest.param("refs/tags/*", "refs/tags/v1/extra", False, id="more segments"),
        pytest.param("refs/tags/*", "refs/tags/v1.2.3", True, id="alone"),
        pytest.param("refs/tags/*", "refs/tags/", True, id="alone, empty match"),
        pytest.param("refs/tags/build-v*", "refs/tags/build-v0.14.2", True, id="at the end"),
        pytest.param("refs/tags/build-v*", "refs/tags/build-v", True, id="at the end, empty match"),
        pytest.param("refs/tags/build-v*", "refs/tags/rebuild-v1", False, id="at the end, another start"),
        pytest.param("refs/tags/build-v*", "refs/tags/build-v1/2", False, id="at the end, across a separator"),
        pytest.param("refs/tags/*-rc", "refs/tags/v1-rc", True, id="at the start"),
        pytest.param("refs/tags/*-rc", "refs/tags/v1-rc1", False, id="at the start, another end"),
        pytest.param("refs/tags/v*-rc", "refs/tags/v1.2-rc", True, id="in the middle"),
        pytest.param("refs/tags/v*-rc", "refs/tags/v-rc", True, id="in the middle, empty match"),
        pytest.param("refs/tags/ab*ba", "refs/tags/aba", False, id="in the middle, ends overlap"),
        pytest.param("refs/tags/v*.*.*", "refs/tags/v1.2.3", True, id="several"),
        pytest.param("refs/tags/v*.*.*", "refs/tags/v1.2", False, id="several, piece missing"),
        pytest.param("refs/tags/*ab*ab*", "refs/tags/abab", True, id="several, earliest occurrence"),
        pytest.param("refs/tags/*a*b*", "refs/tags/ba", False, id="several, out of order"),
        pytest.param("refs/tags/v**", "refs/tags/v1", True, id="several, adjacent"),
        pytest.param("refs/*/v*", "refs/tags/v1", True, id="in several segments"),
        pytest.param("refs/*/v*", "refs/remotes/origin/v1", False, id="in several segments, across a separator"),
        pytest.param("refs/tags/" + "*a" * 2000 + "*b*", "refs/tags/" + "a" * 4000, False, id="many, near miss"),
        pytest.param("refs/tags/" + "*a" * 2000 + "*b*", "refs/tags/" + "a" * 4000 + "b", True, id="many, match"),
    ],
)
def test_ref_matches(pattern: str, ref: str, want: bool) -> None:
    assert ref_matches(pattern, ref) is want
