"""Resolution of the user cache secret: the explicit option, the environment, the persisted file with its
permission and file-type rules, the cross-process election and the in-memory fallback; and the body injection
on its own."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tinfoil._v3 import _cachesecret
from tinfoil._v3._cachesecret import DIR_NAME, ENV, FILE_NAME, inject, path_eligible, resolve, scan_object
from tinfoil._v3._errors import ConfigurationError


@pytest.fixture
def secret_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A home directory with no environment value, so resolution falls through to the persisted secret."""
    monkeypatch.delenv(ENV, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(_cachesecret, "_ephemeral_secret", None)
    return tmp_path


def secret_file(home: Path) -> Path:
    return home / DIR_NAME / FILE_NAME


def write_secret(home: Path, contents: str | bytes, *, mode: int = 0o600, dir_mode: int = 0o700) -> Path:
    """A pre-existing secret file under ``home`` with the given modes, as another SDK would have left it."""
    path = secret_file(home)
    path.parent.mkdir(mode=dir_mode)
    if isinstance(contents, bytes):
        path.write_bytes(contents)
    else:
        path.write_text(contents)
    path.chmod(mode)
    path.parent.chmod(dir_mode)
    return path


class TestPrecedence:
    def test_explicit_beats_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV, "from-env")
        assert resolve("explicit") == "explicit"

    def test_explicit_empty_or_none_is_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV, "from-env")
        assert resolve("") == "from-env"
        assert resolve(None) == "from-env"

    def test_environment_beats_generation_and_touches_no_file(
        self, secret_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV, "from-env")
        assert resolve(None) == "from-env"
        assert not (secret_home / DIR_NAME).exists()

    def test_environment_set_but_empty_falls_through(self, secret_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV, "")
        assert len(resolve(None)) == 64
        assert secret_file(secret_home).exists()


class TestPersistence:
    def test_generates_and_persists(self, secret_home: Path) -> None:
        first = resolve(None)
        assert len(first) == 64
        assert all(c in "0123456789abcdef" for c in first)
        path = secret_file(secret_home)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert path.read_text() == first
        assert resolve(None) == first, "a second resolution reuses the persisted secret"
        assert sorted(path.parent.iterdir()) == [path], "no candidate file is left behind"

    def test_adopts_an_existing_file_trimming_whitespace(self, secret_home: Path) -> None:
        write_secret(secret_home, " shared-secret\n　")
        assert resolve(None) == "shared-secret"

    def test_preserves_separator_controls_in_the_value(self, secret_home: Path) -> None:
        write_secret(secret_home, "\x1cvalue\x1f")
        assert resolve(None) == "\x1cvalue\x1f"

    def test_accepts_a_permissive_preexisting_directory(self, secret_home: Path) -> None:
        path = write_secret(secret_home, "shared-secret", mode=0o600, dir_mode=0o777)
        assert resolve(None) == "shared-secret"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o777, "the directory's mode is not the file's"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
    @pytest.mark.parametrize("mode", [0o644, 0o660, 0o604, 0o640, 0o620, 0o602, 0o666])
    def test_refuses_a_file_that_group_or_others_can_read_or_write(self, secret_home: Path, mode: int) -> None:
        path = write_secret(secret_home, "shared-secret", mode=mode)
        with pytest.raises(ConfigurationError) as err:
            resolve(None)
        assert str(path) in str(err.value), "the error names the file"
        assert "0600" in str(err.value), "the error names the expected mode"
        assert "shared-secret" not in str(err.value)
        assert path.read_text() == "shared-secret", "the file is never rewritten"
        assert stat.S_IMODE(path.stat().st_mode) == mode, "nor is its mode changed"
        assert sorted(path.parent.iterdir()) == [path]

    @pytest.mark.parametrize("mode", [0o600, 0o400])
    def test_adopts_an_owner_only_file(self, secret_home: Path, mode: int) -> None:
        path = write_secret(secret_home, "shared-secret", mode=mode)
        assert resolve(None) == "shared-secret"
        assert stat.S_IMODE(path.stat().st_mode) == mode

    @pytest.mark.parametrize("contents", [b"", b"  \n", b"\xff\xfea"])
    def test_unusable_existing_file_is_untouched(self, secret_home: Path, contents: bytes) -> None:
        path = write_secret(secret_home, contents)
        first = resolve(None)
        assert len(first) == 64
        assert resolve(None) == first, "the in-memory fallback is stable"
        assert path.read_bytes() == contents

    def test_rejects_a_secret_file_symlink_without_reading_the_target(self, secret_home: Path) -> None:
        target = secret_home / "target"
        target.write_text("target-secret")
        path = secret_file(secret_home)
        path.parent.mkdir(mode=0o700)
        path.symlink_to(target)
        resolved = resolve(None)
        assert resolved
        assert resolved != "target-secret"
        assert target.read_text() == "target-secret"
        assert path.is_symlink()

    def test_rejects_a_cache_directory_symlink(self, secret_home: Path) -> None:
        target = secret_home / "target"
        target.mkdir()
        (secret_home / DIR_NAME).symlink_to(target)
        assert resolve(None)
        assert list(target.iterdir()) == [], "nothing is written through the link"

    def test_rejects_a_non_regular_secret_file(self, secret_home: Path) -> None:
        path = secret_file(secret_home)
        path.parent.mkdir(mode=0o700)
        path.mkdir()
        assert resolve(None)
        assert path.is_dir()

    @pytest.mark.skipif(os.name == "nt", reason="hard-link election is POSIX")
    def test_concurrent_first_use_converges(self, secret_home: Path) -> None:
        script = textwrap.dedent(
            """
            import sys
            from tinfoil._v3._cachesecret import resolve

            sys.stdin.read(1)
            print(resolve(None))
            """
        )
        env = os.environ.copy()
        env["HOME"] = str(secret_home)
        env.pop(ENV, None)
        source = str(Path(__file__).parents[3] / "src")
        env["PYTHONPATH"] = os.pathsep.join(value for value in (source, env.get("PYTHONPATH")) if value)
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            for _ in range(8)
        ]
        # Every process is released before any is waited for, so they contend for the election at once. The
        # input is flushed but the pipe is left open: communicate() closes it, and refuses one already closed.
        for process in processes:
            assert process.stdin is not None
            process.stdin.write("x")
            process.stdin.flush()
        results: list[str] = []
        for process in processes:
            out, err = process.communicate(timeout=60)
            assert process.returncode == 0, err
            results.append(out.strip())
        path = secret_file(secret_home)
        assert len(set(results)) == 1, "every process adopts the elected value"
        assert results[0] == path.read_text()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert list(path.parent.iterdir()) == [path]

    def test_hard_link_failure_uses_the_process_fallback(
        self, secret_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_links(source: object, destination: object) -> None:
            raise OSError("hard links unavailable")

        monkeypatch.setattr(os, "link", no_links)
        first = resolve(None)
        assert len(first) == 64
        assert resolve(None) == first
        assert list((secret_home / DIR_NAME).iterdir()) == []

    @pytest.mark.parametrize("home", [None, ""], ids=["unset", "empty"])
    def test_falls_back_without_a_home(self, monkeypatch: pytest.MonkeyPatch, home: str | None) -> None:
        monkeypatch.delenv(ENV, raising=False)
        monkeypatch.setattr(_cachesecret, "_ephemeral_secret", None)
        if home is None:
            monkeypatch.delenv("HOME", raising=False)
        else:
            monkeypatch.setenv("HOME", home)
        first = resolve(None)
        assert first
        assert resolve(None) == first

    def test_falls_back_when_home_is_not_a_directory(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.delenv(ENV, raising=False)
        home_file = tmp_path / "not-a-dir"
        home_file.write_text("x")
        monkeypatch.setenv("HOME", str(home_file))
        assert resolve(None)

    def test_falls_back_on_a_pathological_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENV, raising=False)
        monkeypatch.setattr(_cachesecret, "secret_path", lambda: Path("nul\x00l") / FILE_NAME)
        assert resolve(None)


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

    def test_path_eligible(self) -> None:
        assert path_eligible("POST", "/v1/chat/completions")
        assert path_eligible("post", "/responses")
        assert not path_eligible("GET", "/v1/chat/completions")
        assert not path_eligible("POST", "/v1/embeddings")


def test_scan_object_caps_nesting() -> None:
    """A value nested to the cap scans; one level deeper is treated as malformed on every interpreter."""
    from tinfoil._v3._cachesecret import MAX_NESTING, scan_object

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
    from tinfoil._v3._cachesecret import _scan_value

    assert _scan_value(text, 0) == _stdlib_end(text)


def test_scan_value_at_an_offset() -> None:
    """The scanner starts where it is pointed and reports an absolute end offset."""
    from tinfoil._v3._cachesecret import _scan_value

    text = '{"a": [1, 2] , "b": "x"}'
    assert _scan_value(text, 6) == 12
    assert _scan_value(text, 20) == 23
    assert _scan_value(text, 5) is None, "a value does not begin with whitespace"
