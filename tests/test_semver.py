import pytest

from tinfoil.verifier import _semver

# (version, is_valid, canonical, build)
CASES = [
    ("v1", True, "v1.0.0", ""),
    ("v1.2", True, "v1.2.0", ""),
    ("v1.2.3", True, "v1.2.3", ""),
    ("v0.0.0", True, "v0.0.0", ""),
    ("v1.2.3-pre", True, "v1.2.3-pre", ""),
    ("v1.2.3-pre+build", True, "v1.2.3-pre", "+build"),
    ("v1.2.3+build", True, "v1.2.3", "+build"),
    ("v1.2.3+01", True, "v1.2.3", "+01"),
    ("v1.2.3-0a", True, "v1.2.3-0a", ""),
    ("v1.2.3-0", True, "v1.2.3-0", ""),
    ("v1.2.3-alpha.1.beta-2", True, "v1.2.3-alpha.1.beta-2", ""),
    ("v1.2.3-x.7.z.92+b.1-2", True, "v1.2.3-x.7.z.92", "+b.1-2"),
    ("v99999999999999999999.0.0", True, "v99999999999999999999.0.0", ""),
    ("1.2.3", False, "", ""),
    ("V1.2.3", False, "", ""),
    ("v", False, "", ""),
    ("", False, "", ""),
    ("v1+build", False, "", ""),
    ("v1.2+build", False, "", ""),
    ("v1-pre", False, "", ""),
    ("v1.2-pre", False, "", ""),
    ("v01.2.3", False, "", ""),
    ("v1.02.3", False, "", ""),
    ("v1.2.03", False, "", ""),
    ("v1.2.3-01", False, "", ""),
    ("v1.2.3-a..b", False, "", ""),
    ("v1.2.3-", False, "", ""),
    ("v1.2.3+", False, "", ""),
    ("v1.2.3+a.", False, "", ""),
    ("v1.2.3-a+b+c", False, "", ""),
    ("v1.2.3_x", False, "", ""),
    ("v1.2.3.4", False, "", ""),
    ("v1.2.3-é", False, "", ""),
    ("v1.", False, "", ""),
    ("v1.2.", False, "", ""),
    (" v1.2.3", False, "", ""),
    ("v1.2.3 ", False, "", ""),
    ("v١.2.3", False, "", ""),  # a non-ASCII digit
]


@pytest.mark.parametrize(("version", "valid", "canonical", "build"), CASES)
def test_semver(version: str, valid: bool, canonical: str, build: str) -> None:
    assert _semver.is_valid(version) is valid
    assert _semver.canonical(version) == canonical
    assert _semver.build(version) == build
    # A full version is a valid one that is already its canonical form plus its build metadata.
    assert _semver.is_full(version) is (valid and canonical + build == version)


@pytest.mark.parametrize(
    ("version", "full"),
    [
        ("v1.2.3", True),
        ("v1.2.3-rc.1", True),
        ("v1.2.3+build.5", True),
        ("v1.2.3-rc.1+build.5", True),
        ("v1", False),
        ("v1.2", False),
        ("v1.2-rc.1", False),
        ("1.2.3", False),
        ("", False),
    ],
)
def test_is_full(version: str, full: bool) -> None:
    assert _semver.is_full(version) is full
