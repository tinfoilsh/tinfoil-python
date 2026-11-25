"""Container provenance: the builds that a config requires."""

from __future__ import annotations

import pytest

from tinfoil.verifier._endorsement.container import (
    ContainerConfigError,
    ContainerProvenance,
    container_provenance_from_config,
)

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
