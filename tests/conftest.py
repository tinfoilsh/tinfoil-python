import pytest

from tinfoil.user_cache_secret import USER_CACHE_SECRET_ENV


@pytest.fixture(autouse=True)
def _pinned_user_cache_secret(monkeypatch):
    """
    Pin TINFOIL_USER_CACHE_SECRET for every test.

    Constructing a client resolves the user cache secret; without the variable
    the resolution would fall through to generating and persisting a secret in
    the real ~/.tinfoil, making tests non-hermetic and the transport stack
    shape environment-dependent. Tests that exercise resolution itself
    override or remove the variable (and point HOME at a tmp dir) explicitly.
    """
    monkeypatch.setenv(USER_CACHE_SECRET_ENV, "test-secret")
