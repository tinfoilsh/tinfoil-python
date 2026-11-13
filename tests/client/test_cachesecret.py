"""Resolution of the user cache secret: the explicit option, then a random secret that is generated once per
process, with no environment variable or file consulted; and the body injection on its own."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tinfoil import _cachesecret
from tinfoil._cachesecret import inject, path_eligible, resolve, scan_object

LEGACY_ENV = "TINFOIL_USER_CACHE_SECRET"
"""The environment variable that earlier releases read; the SDK no longer looks at it."""


@pytest.fixture
def fresh_process_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clears the per-process secret that the shared fixture pins, so that resolution generates one."""
    monkeypatch.setattr(_cachesecret, "_process_secret", None)


@pytest.fixture
def legacy_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The variable and the secret file that earlier releases read, both set, in a temporary home directory. The
    file is readable by others too, which earlier releases refused with a ConfigurationError."""
    monkeypatch.setenv(LEGACY_ENV, "from-env")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    path = tmp_path / ".tinfoil" / "user_cache_secret"
    path.parent.mkdir()
    path.write_text("from-file")
    path.chmod(0o644)
    return path


def is_generated(secret: str) -> bool:
    return len(secret) == 64 and all(c in "0123456789abcdef" for c in secret)


@pytest.mark.usefixtures("fresh_process_secret")
class TestResolution:
    def test_explicit_wins(self, legacy_sources: Path) -> None:
        assert resolve("explicit") == "explicit"

    def test_empty_or_none_selects_the_process_secret(self) -> None:
        generated = resolve(None)
        assert is_generated(generated), "256 random bits, hex-encoded"
        assert resolve("") == generated
        assert resolve(None) == generated, "the secret is generated once per process"
        assert resolve("explicit") == "explicit", "the option still wins once a secret is generated"

    def test_reads_no_environment_variable_or_file(self, legacy_sources: Path) -> None:
        generated = resolve(None)
        assert is_generated(generated)
        assert generated not in ("from-env", "from-file")
        assert legacy_sources.read_text() == "from-file", "the file is left alone"
        assert sorted(legacy_sources.parent.iterdir()) == [legacy_sources], "nothing is written beside it"

    def test_creates_no_file_in_an_empty_home(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        assert is_generated(resolve(None))
        assert list(tmp_path.iterdir()) == []

    def test_concurrent_first_use_agrees(self) -> None:
        barrier = threading.Barrier(8)
        results: list[str] = []

        def run() -> None:
            barrier.wait()
            results.append(resolve(None))

        threads = [threading.Thread(target=run) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(results) == 8
        assert len(set(results)) == 1, "every thread adopts the one generated secret"

    def test_each_process_generates_its_own(self, legacy_sources: Path) -> None:
        """Two processes with the variable and the file of earlier releases both set get different secrets, so
        neither source is read."""
        script = "from tinfoil._cachesecret import resolve; print(resolve(None))"
        env = os.environ.copy()
        source = str(Path(__file__).parents[2] / "src")
        env["PYTHONPATH"] = os.pathsep.join(value for value in (source, env.get("PYTHONPATH")) if value)
        results = [
            subprocess.run(
                [sys.executable, "-c", script], capture_output=True, text=True, env=env, check=True, timeout=60
            ).stdout.strip()
            for _ in range(2)
        ]
        assert all(is_generated(result) for result in results), results
        assert results[0] != results[1]


class TestInjection:
    def test_scan_object_reports_members_in_order(self) -> None:
        members = scan_object(' {"a": 1, "b\\u0041": [1, {"c": 2}], "d": "x"} \n')
        assert members is not None
        assert [m.key for m in members] == ["a", "bA", "d"]
        assert scan_object("{}") == []
        for bad in ("[]", "{", '{"a"}', '{"a":1,}', '{"a":1} x', '{"a":NaN}', "{1:2}", ""):
            assert scan_object(bad) is None, bad

    def test_inject_appends_or_replaces(self) -> None:
        assert inject(b"{}", "s") == b'{"user_cache_secret":"s"}'
        assert inject(b'{"model":"m"}', "s") == b'{"model":"m","user_cache_secret":"s"}'
        assert inject(b'{"user_cache_secret":""}', "s") == b'{"user_cache_secret":"s"}'
        assert inject(b'{"user_cache_secret":"x"}', "s") is None
        assert inject(b'{"user_cache_secret":1}', "s") is None
        assert inject(b"{}", "") is None
        assert inject(b"", "s") is None
        assert inject(b'{"a":"\\ud800"}', "s") == b'{"a":"\\ud800","user_cache_secret":"s"}'
        assert inject(b'{"a":1}', 'q"é') == b'{"a":1,"user_cache_secret":"q\\"\\u00e9"}'

    def test_inject_preserves_the_rest_of_the_body(self) -> None:
        body = b' {\n  "model" : "m",\t"n": 1.000000000000000000001, "big": 123456789012345678901234567890 }\n'
        injected = inject(body, "s")
        assert injected == (
            b' {\n  "model" : "m",\t"n": 1.000000000000000000001, "big": 123456789012345678901234567890 '
            b',"user_cache_secret":"s"}\n'
        )
        assert inject(b'{"user_cache_secret":"a","user_cache_secret":""}', "s") is None, "a repeated field is left"

    def test_path_eligible(self) -> None:
        assert path_eligible("POST", "/v1/chat/completions")
        assert path_eligible("post", "/responses")
        assert not path_eligible("GET", "/v1/chat/completions")
        assert not path_eligible("POST", "/v1/embeddings")


def test_scan_object_caps_nesting() -> None:
    """A value nested to the cap scans; one level deeper is treated as malformed on every interpreter."""
    from tinfoil._cachesecret import MAX_NESTING, scan_object

    within = '{"a":' + "[" * MAX_NESTING + "]" * MAX_NESTING + "}"
    beyond = '{"a":' + "[" * (MAX_NESTING + 1) + "]" * (MAX_NESTING + 1) + "}"
    scanned = scan_object(within)
    assert scanned is not None
    assert [m.key for m in scanned] == ["a"]
    assert scan_object(beyond) is None
    mixed = '{"a":' + '{"k":[' * (MAX_NESTING // 2) + "]}" * (MAX_NESTING // 2) + "}"
    assert scan_object(mixed) is not None, "objects and arrays count alike"
    assert scan_object('{"a":' + '{"k":[' * (MAX_NESTING // 2 + 1) + "]}" * (MAX_NESTING // 2 + 1) + "}") is None


def _reject_constant(value: str) -> float:
    raise ValueError(value)


_STDLIB = json.JSONDecoder(parse_constant=_reject_constant)
"""The standard decoder, refusing ``NaN`` and ``Infinity`` as the scanner does."""


def _stdlib_end(text: str) -> int | None:
    """Where the standard decoder says the value at offset 0 ends, or None when it rejects the text."""
    try:
        return _STDLIB.raw_decode(text, 0)[1]
    except ValueError:
        return None


_VALUE_TEXTS = [
    # Strings: every escape form, surrogates, and what the standard decoder refuses.
    '""',
    '"plain"',
    '"\\" \\\\ \\/ \\b \\f \\n \\r \\t"',
    '"\\u0041\\u00e9\\uD83D\\uDE00"',
    '"\\ud800"',
    '"\\udc00\\ud800"',
    '"\\uD83D x"',
    '"\\uDE00"',
    '"\\u00E9"',
    '"\\u00e"',
    '"\\u00g9"',
    '"\\x41"',
    '"\\a"',
    '"\\"',
    '"unterminated',
    '"\\u',
    '"tab\there"',
    '"nul\x00"',
    '"unit\x1f"',
    '"del\x7f"',
    '"line\nbreak"',
    '"é😀 "',
    "'single'",
    # Numbers: the JSON grammar and its near misses.
    "0",
    "-0",
    "1",
    "-1",
    "123",
    "1.5",
    "-1.5",
    "1e5",
    "1E5",
    "1e+5",
    "1e-5",
    "1.5e5",
    "-0.0e-0",
    "1.",
    "1.e5",
    "01",
    "-01",
    ".5",
    "-.5",
    "1e",
    "1e+",
    "1ee5",
    "+1",
    "-",
    "--1",
    "1٣",
    "٣",
    "0x10",
    "1_000",
    # Literals, and the constants that are not JSON.
    "true",
    "false",
    "null",
    "True",
    "nul",
    "nulll",
    "truefalse",
    "NaN",
    "Infinity",
    "-Infinity",
    "-NaN",
    "undefined",
    # Containers: whitespace placement, commas, nesting, and what is left unbalanced.
    "[]",
    "[ ]",
    "[\n\t\r ]",
    "[1]",
    "[ 1 ]",
    "[1,2]",
    "[1 , 2]",
    "[1,,2]",
    "[,1]",
    "[1,]",
    "[1 ,]",
    "[",
    "[1",
    "[1,",
    "]",
    "[1}",
    "[[]]",
    "[[],[[]]]",
    "[1,[2,[3,[4]]]]",
    '[1,"a",true,null,{},[]]',
    "{}",
    "{ }",
    '{"a":1}',
    '{ "a" : 1 }',
    '{"a":1,"b":2}',
    '{"a":1 , "b":2}',
    '{"a":1,}',
    '{"a":1,,"b":2}',
    '{,"a":1}',
    '{"a"}',
    '{"a":}',
    '{"a" 1}',
    '{"a":1 "b":2}',
    '{"a":1]',
    "{1:2}",
    "{a:1}",
    "{'a':1}",
    '{"a":{"b":{"c":[{"d":null}]}}}',
    '{"a":[1,{"b":[]}],"c":{}}',
    '{"\\u0041":1}',
    '{"a\\":1}',
    '{"a\x01":1}',
    "{",
    '{"a"',
    '{"a":',
    '{"a":1',
    "}",
    "{}}",
    # Trailing data is not the scanner's concern: the end offset is reported and the caller sees the rest.
    "1 2",
    "[1] x",
    "[1]]",
    "truex",
    "nullnull",
    "1,",
    # Leading whitespace is the caller's to skip.
    " 1",
    "\n[]",
    "",
    " ",
    "\x0b1",
    "\xa01",
    # Nesting the standard decoder handles on every interpreter.
    "[" * 200 + "]" * 200,
    "[" * 200 + "]" * 199,
    '{"k":' * 200 + "1" + "}" * 200,
    '{"k":[' * 100 + "]}" * 100,
    '{"k":[' * 100 + "]}" * 99 + "]",
]


@pytest.mark.parametrize("text", _VALUE_TEXTS, ids=lambda text: repr(text) if len(text) <= 40 else f"{len(text)}-chars")
def test_scan_value_matches_the_standard_decoder(text: str) -> None:
    """For every value the standard decoder can handle, the iterative scanner gives the same verdict and, when it
    accepts, the same end offset."""
    from tinfoil._cachesecret import _scan_value

    assert _scan_value(text, 0) == _stdlib_end(text)


def test_scan_value_at_an_offset() -> None:
    """The scanner starts where it is pointed and reports an absolute end offset."""
    from tinfoil._cachesecret import _scan_value

    text = '{"a": [1, 2] , "b": "x"}'
    assert _scan_value(text, 6) == 12
    assert _scan_value(text, 20) == 23
    assert _scan_value(text, 5) is None, "a value does not begin with whitespace"
