"""The trust argument: each variant converts to the verifier's config trust and the pin of each verification, and
the client keeps a copy that shares nothing that the caller can change."""

from __future__ import annotations

import dataclasses

import pytest

from tests import pki
from tinfoil._errors import ConfigurationError
from tinfoil._trust import (
    AuthorizedBy,
    EitherPin,
    EmbeddedConfig,
    ProjectPin,
    RepoPin,
    SignedBy,
    verifier_inputs,
)
from tinfoil.verifier import PUBLIC_REGISTRY_ID, ConfigAuthorizer, ConfigEndorsement, ConfigSigningKeys, Pin, Registries
from tinfoil.verifier import EmbeddedConfig as VerifierEmbeddedConfig


def allow(endorsement: ConfigEndorsement) -> None:
    return None


def parts(trust: object) -> tuple[object, Pin]:
    inputs = verifier_inputs(trust)
    return inputs.config, inputs.pin


def test_each_variant_converts_to_a_config_trust_and_a_pin() -> None:
    key = pki.p256().public_key()
    assert parts(RepoPin("org/repo")) == (None, Pin(repo="org/repo"))
    assert parts(ProjectPin("org/project")) == (None, Pin(project="org/project"))
    assert parts(ProjectPin("org/project", [PUBLIC_REGISTRY_ID, "acme"])) == (
        Registries((PUBLIC_REGISTRY_ID, "acme")),
        Pin(project="org/project"),
    )
    assert parts(SignedBy([key])) == (ConfigSigningKeys((key,)), Pin())
    assert parts(SignedBy([key], "org/project")) == (
        ConfigSigningKeys((key,)),
        Pin(project="org/project"),
    )
    assert parts(AuthorizedBy(allow)) == (ConfigAuthorizer(allow), Pin())
    assert parts(EmbeddedConfig(b"config", "/org/project/v1")) == (
        VerifierEmbeddedConfig(b"config", "/org/project/v1"),
        Pin(),
    )
    assert parts(EitherPin("org/repo", "org/project")) == (
        None,
        Pin(repo="org/repo", project="org/project"),
    )


@pytest.mark.parametrize(
    ("trust", "message"),
    [
        (RepoPin(""), "RepoPin requires repo"),
        (ProjectPin(""), "ProjectPin requires project"),
        (ProjectPin("org/project", []), "registry_ids must not be empty; leave it None"),
        (ProjectPin("org/project", ()), "registry_ids must not be empty; leave it None"),
        (ProjectPin("org/project", "acme"), "registry_ids must be a sequence of registry IDs"),
        (EitherPin("org/repo", ""), "EitherPin requires both repo and project"),
        (SignedBy(iter(())), "SignedBy keys must be a sequence of public keys"),  # type: ignore[arg-type]
        (SignedBy(set()), "SignedBy keys must be a sequence of public keys"),  # type: ignore[arg-type]
        (EitherPin("", "org/project"), "EitherPin requires both repo and project"),
        (None, "trust must be a RepoPin, ProjectPin, SignedBy, AuthorizedBy, EmbeddedConfig or EitherPin value"),
        (Pin(repo="org/repo"), "not Pin"),
        ("org/repo", "not str"),
    ],
)
def test_a_variant_missing_a_required_field_is_a_configuration_error(trust: object, message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        verifier_inputs(trust)


def test_the_copy_shares_nothing_that_the_caller_can_change() -> None:
    key = pki.p256().public_key()
    registry_ids = [PUBLIC_REGISTRY_ID]
    keys = [key]
    data = bytearray(b"config")
    project = verifier_inputs(ProjectPin("org/project", registry_ids))
    signed = verifier_inputs(SignedBy(keys))
    embedded = verifier_inputs(EmbeddedConfig(data))  # type: ignore[arg-type]
    registry_ids.append("acme")
    keys.clear()
    data[:] = b"other!"
    assert project.trust == ProjectPin("org/project", (PUBLIC_REGISTRY_ID,))
    assert project.config == Registries((PUBLIC_REGISTRY_ID,))
    assert signed.trust == SignedBy((key,))
    assert embedded.trust == EmbeddedConfig(b"config")
    with pytest.raises(dataclasses.FrozenInstanceError):
        project.trust.project = "org/other"  # type: ignore[misc]
