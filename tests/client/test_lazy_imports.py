"""The package init loads the client modules on first use: importing ``tinfoil`` or ``tinfoil.verifier`` leaves the
``openai`` and ``httpx`` stacks and the client modules unloaded, while every exported name still resolves, with
its real class, from a plain attribute read, ``dir()``, ``from tinfoil import *`` and a pickle round-trip.

Each check runs in a fresh interpreter, so that nothing that the test process has already imported stands in for
what the package imports itself.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from typing import Any

HEAVY = (
    "openai",
    "httpx",
    "httpcore",
    "tinfoil._openai",
    "tinfoil._clients",
    "tinfoil._gateway",
    "tinfoil._transport",
)
"""Modules that an import of the package or of its verifier subpackage must not load."""


def _run(script: str) -> Any:
    """Runs ``script`` in a fresh interpreter and returns the JSON that it prints last."""
    completed = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_importing_the_package_and_the_verifier_leaves_the_clients_unloaded() -> None:
    loaded = _run(
        f"""
        import json, sys
        import tinfoil
        import tinfoil.verifier
        print(json.dumps({{"loaded": sorted(set({HEAVY!r}) & set(sys.modules)), "version": tinfoil.__version__}}))
        """
    )
    assert loaded["loaded"] == []
    assert loaded["version"] not in ("", None)


def test_first_access_loads_the_client_module_and_later_accesses_are_the_same_object() -> None:
    result = _run(
        """
        import json, sys
        import tinfoil
        before = sorted(set(("openai", "tinfoil._openai")) & set(sys.modules))
        first = tinfoil.Client
        after = sorted(set(("openai", "tinfoil._openai")) & set(sys.modules))
        second = tinfoil.Client
        print(json.dumps({
            "before": before,
            "after": after,
            "same": first is second,
            "bound": "Client" in vars(tinfoil),
            "module": first.__module__,
        }))
        """
    )
    assert result["before"] == []
    assert result["after"] == ["openai", "tinfoil._openai"]
    assert result["same"] is True
    assert result["bound"] is True
    assert result["module"] == "tinfoil._openai"


def test_every_exported_name_resolves_and_is_listed_by_dir() -> None:
    result = _run(
        """
        import json
        import tinfoil
        listed = set(dir(tinfoil))
        resolved = [name for name in tinfoil.__all__ if getattr(tinfoil, name) is not None]
        print(json.dumps({
            "resolved": resolved,
            "all": list(tinfoil.__all__),
            "dir_covers_all": listed >= set(tinfoil.__all__),
            "dir_has_globals": {"__name__", "__version__", "__all__"} <= listed,
            "dir_sorted": dir(tinfoil) == sorted(dir(tinfoil)),
        }))
        """
    )
    assert result["resolved"] == result["all"]
    assert result["dir_covers_all"] is True
    assert result["dir_has_globals"] is True
    assert result["dir_sorted"] is True


def test_star_import_binds_every_public_name() -> None:
    result = _run(
        """
        import json
        import tinfoil
        namespace = {}
        exec("from tinfoil import *", namespace)
        print(json.dumps({"missing": [name for name in tinfoil.__all__ if name not in namespace]}))
        """
    )
    assert result["missing"] == []


def test_an_unknown_name_is_an_attribute_error_that_names_the_module() -> None:
    result = _run(
        """
        import json
        import tinfoil
        try:
            tinfoil.NoSuchName
        except AttributeError as err:
            print(json.dumps({"message": str(err), "has": hasattr(tinfoil, "NoSuchName")}))
        else:
            print(json.dumps({"message": None}))
        """
    )
    assert result["message"] == "module 'tinfoil' has no attribute 'NoSuchName'"
    assert result["has"] is False


def test_a_client_error_pickles_through_its_real_module() -> None:
    result = _run(
        """
        import json, pickle
        import tinfoil
        err = tinfoil.ConfigurationError("x")
        again = pickle.loads(pickle.dumps(err))
        print(json.dumps({
            "module": type(err).__module__,
            "same_type": type(again) is tinfoil.ConfigurationError,
            "message": str(again),
        }))
        """
    )
    assert result["module"] == "tinfoil._errors"
    assert result["same_type"] is True
    assert result["message"] == "x"


def test_the_lazy_table_covers_exactly_the_exported_names() -> None:
    """Every exported name but ``__version__`` has a defining module in the table, and nothing else does, so that a
    name that the table lists but ``__all__`` omits cannot become reachable without being exported."""
    import tinfoil

    assert set(tinfoil._MODULE_OF) == set(tinfoil.__all__) - {"__version__"}
