"""Release references and the well-formedness of an authenticated artifact."""

from __future__ import annotations

import dataclasses

import pytest

from tinfoil._v3.verifier._endorsement.reference import (
    PLATFORM_ENDORSEMENTS_REPO,
    AuthenticatedArtifact,
    Reference,
    ReferenceError,
    parse_reference,
    validate_authenticated_artifact,
)

DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def sample_artifact() -> AuthenticatedArtifact:
    return AuthenticatedArtifact(
        repo=PLATFORM_ENDORSEMENTS_REPO,
        tag="v0.0.4",
        commit="0123456789abcdef0123456789abcdef01234567",
        subject_name="platform-endorsements.json",
        digest=DIGEST,
    )


@pytest.mark.parametrize(
    ("ref", "want"),
    [
        ("org/repo", Reference("org/repo")),
        ("org/repo@v1.2.3", Reference("org/repo", tag="v1.2.3")),
        ("org/repo@sha256:" + DIGEST, Reference("org/repo", digest=DIGEST)),
        ("org/repo@v1@sha256:" + DIGEST, Reference("org/repo", tag="v1", digest=DIGEST)),
        ("org-1/re.po_x@release/1", Reference("org-1/re.po_x", tag="release/1")),
    ],
)
def test_parse_reference_accepts(ref: str, want: Reference) -> None:
    assert parse_reference(ref) == want


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "org/repo@",
        "org/repo@sha256:bad",
        "org/repo@v1@v2",
        "org/repo/extra",
        "org/(repo|other)",
        "org/repo@v1\n",
        "org/repo\n",
        "org/repo@v 1",
        "org/repo@v1:x",
        "org/repo@sha256:" + DIGEST.upper(),
        "org/repo@v1@sha256:" + DIGEST + "@",
    ],
)
def test_parse_reference_rejects(ref: str) -> None:
    with pytest.raises(ReferenceError, match="invalid release reference"):
        parse_reference(ref)


def test_validate_authenticated_artifact() -> None:
    validate_authenticated_artifact(sample_artifact())
    for field, value, message in [
        ("repo", "noslash", "repository is invalid"),
        ("repo", "a/b/c", "repository is invalid"),
        ("tag", "", "tag is empty"),
        ("commit", "abc", "commit is malformed"),
        ("commit", sample_artifact().commit.upper(), "commit is malformed"),
        ("subject_name", "", "subject name is empty"),
        ("digest", "abc", "digest is malformed"),
        ("digest", "sha256:" + DIGEST, "digest is malformed"),
        ("digest", "ABCDEF" + DIGEST[6:], "digest is malformed"),
    ]:
        bad = dataclasses.replace(sample_artifact(), **{field: value})
        with pytest.raises(ReferenceError, match=message):
            validate_authenticated_artifact(bad)
