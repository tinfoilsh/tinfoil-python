"""The runtime manifest (parse_manifest, decode_manifest) and the runtime pin read from the config
(runtime_from_config).

Manifest inputs are built from a plain tree and rendered as compact JSON in a
fixed member order; a None member is written as an explicit JSON null.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

import pytest

from tinfoil.verifier._document.collateral.runtime import RUNTIME_REPO, RuntimeReference
from tinfoil.verifier._runtime import (
    FORMAT_VERSION,
    MEASUREMENT_SIZE,
    Manifest,
    ManifestError,
    Measurements,
    RuntimeConfigError,
    SNPLaunch,
    TDXLaunch,
    decode_manifest,
    parse_manifest,
    runtime_from_config,
)

Tree = dict[str, Any]

MEASUREMENT = "cd" * MEASUREMENT_SIZE
ZERO_REGISTER = "0" * (MEASUREMENT_SIZE * 2)


def valid_spec() -> Tree:
    """The valid manifest as a JSON-building tree, in member order version, igvm{format_version, snp_launch,
    tdx_launch}."""
    return {
        "version": "v0.15.0",
        "igvm": {
            "format_version": FORMAT_VERSION,
            "snp_launch": {"measurement": MEASUREMENT},
            "tdx_launch": {
                "mrtd": MEASUREMENT,
                "rtmr0": ZERO_REGISTER,
                "rtmr1": ZERO_REGISTER,
                "rtmr2": ZERO_REGISTER,
                "rtmr3": ZERO_REGISTER,
            },
        },
    }


def valid_manifest() -> Manifest:
    return Manifest(
        version="v0.15.0",
        measurements=Measurements(
            format_version=FORMAT_VERSION,
            snp_launch=SNPLaunch(measurement=MEASUREMENT),
            tdx_launch=TDXLaunch(
                mrtd=MEASUREMENT, rtmr0=ZERO_REGISTER, rtmr1=ZERO_REGISTER, rtmr2=ZERO_REGISTER, rtmr3=ZERO_REGISTER
            ),
        ),
    )


def render(tree: Tree) -> bytes:
    return json.dumps(tree, separators=(",", ":")).encode()


def manifest_bytes(tree: Tree) -> tuple[bytes, RuntimeReference]:
    """The manifest's JSON bytes and the pin whose digest is theirs."""
    data = render(tree)
    return data, RuntimeReference(repo=RUNTIME_REPO, tag="v0.15.0", digest=hashlib.sha256(data).hexdigest())


# --- parse_manifest ----------------------------------------------------------


def test_manifest_accepts_valid_under_its_pin() -> None:
    data, ref = manifest_bytes(valid_spec())
    assert parse_manifest(data, ref) == valid_manifest()
    with pytest.raises(ManifestError, match="digest pin"):
        parse_manifest(data + b"\n", ref)


def old_manifest(m: Tree) -> None:
    m["igvm"] = None


def unknown_version(m: Tree) -> None:
    m["igvm"]["format_version"] += 1


def wrong_release(m: Tree) -> None:
    m["version"] = "v0.15.1"


def missing_snp(m: Tree) -> None:
    m["igvm"]["snp_launch"] = None


def missing_tdx(m: Tree) -> None:
    m["igvm"]["tdx_launch"] = None


def nonzero_rtmr(m: Tree) -> None:
    m["igvm"]["tdx_launch"]["rtmr2"] = "ab" * MEASUREMENT_SIZE


def nonzero_rtmr0(m: Tree) -> None:
    # Format version 1 fixes MRTD alone, so RTMR0 must be zero like the others.
    m["igvm"]["tdx_launch"]["rtmr0"] = "ab" * MEASUREMENT_SIZE


def missing_rtmr(m: Tree) -> None:
    m["igvm"]["tdx_launch"]["rtmr3"] = ""


def bad_mrtd(m: Tree) -> None:
    m["igvm"]["tdx_launch"]["mrtd"] = "bad"


def uppercase_snp(m: Tree) -> None:
    m["igvm"]["snp_launch"]["measurement"] = MEASUREMENT.upper()


@pytest.mark.parametrize(
    "mutate",
    [
        old_manifest,
        unknown_version,
        wrong_release,
        missing_snp,
        missing_tdx,
        nonzero_rtmr,
        nonzero_rtmr0,
        missing_rtmr,
        bad_mrtd,
        uppercase_snp,
    ],
    ids=lambda f: f.__name__,
)
def test_manifest_requires_complete_supported_measurements(mutate: Callable[[Tree], None]) -> None:
    m = valid_spec()
    mutate(m)
    data, ref = manifest_bytes(m)
    with pytest.raises(ManifestError):
        parse_manifest(data, ref)


@pytest.mark.parametrize(
    ("prefix", "want_err"),
    [
        (b'{"root":"host image digest",', False),
        (b'{"version":"v0.15.0",', True),
        (b'{"root":"one","root":"two",', True),
    ],
    ids=["download metadata", "duplicate member", "duplicate ignored member"],
)
def test_manifest_prefixed_members(prefix: bytes, want_err: bool) -> None:
    data, ref = manifest_bytes(valid_spec())
    changed = prefix + data[1:]
    pinned = RuntimeReference(repo=ref.repo, tag=ref.tag, digest=hashlib.sha256(changed).hexdigest())
    if want_err:
        with pytest.raises(ManifestError, match="parsing runtime manifest"):
            parse_manifest(changed, pinned)
    else:
        assert parse_manifest(changed, pinned) == valid_manifest()
        with pytest.raises(ManifestError, match="digest pin"):
            parse_manifest(changed, ref)


def test_runtime_manifests_have_independent_pins() -> None:
    cpu_data, cpu_ref = manifest_bytes(valid_spec())
    gpu = valid_spec()
    gpu["version"] += "+gpu"
    gpu["igvm"]["snp_launch"]["measurement"] = "ef" * MEASUREMENT_SIZE
    gpu["igvm"]["tdx_launch"]["mrtd"] = "12" * MEASUREMENT_SIZE
    gpu_data, pinned = manifest_bytes(gpu)
    gpu_ref = RuntimeReference(repo=pinned.repo, tag=gpu["version"], digest=pinned.digest)
    parsed = parse_manifest(gpu_data, gpu_ref)
    assert parsed == Manifest(
        version="v0.15.0+gpu",
        measurements=Measurements(
            format_version=1,
            snp_launch=SNPLaunch(measurement="ef" * MEASUREMENT_SIZE),
            tdx_launch=TDXLaunch(
                mrtd="12" * MEASUREMENT_SIZE,
                rtmr0=ZERO_REGISTER,
                rtmr1=ZERO_REGISTER,
                rtmr2=ZERO_REGISTER,
                rtmr3=ZERO_REGISTER,
            ),
        ),
    )
    assert cpu_ref.digest != gpu_ref.digest
    with pytest.raises(ManifestError, match="digest pin"):
        parse_manifest(cpu_data, gpu_ref)
    with pytest.raises(ManifestError, match="digest pin"):
        parse_manifest(gpu_data, cpu_ref)
    with pytest.raises(ManifestError, match="version"):
        parse_manifest(gpu_data, RuntimeReference(repo=gpu_ref.repo, tag=cpu_ref.tag, digest=gpu_ref.digest))


# --- decode_manifest ---------------------------------------------------------


def base_text() -> bytes:
    return render(valid_spec())


def raises_decode(data: bytes, match: str) -> None:
    with pytest.raises(ManifestError, match=match):
        decode_manifest(data)


def test_decode_manifest_ignores_unknown_members() -> None:
    base = base_text()
    assert decode_manifest(b'{"root":"x",' + base[1:]) == valid_manifest()
    assert decode_manifest(base.replace(b'"format_version":1', b'"format_version":1,"extra":1')) == valid_manifest()
    assert decode_manifest(base.replace(b'"mrtd":', b'"extra":1,"mrtd":')) == valid_manifest()


def test_decode_manifest_rejects_duplicate_members() -> None:
    base = base_text()
    raises_decode(
        b'{"root":"one","root":"two",' + base[1:], r'^parsing runtime manifest: .*duplicate object member name "root"'
    )
    raises_decode(
        b'{"version":"v0.15.0",' + base[1:], r'^parsing runtime manifest: .*duplicate object member name "version"'
    )
    raises_decode(
        base.replace(b'"mrtd":', b'"mrtd":"x","mrtd":'),
        r'^parsing runtime manifest: .*duplicate object member name "mrtd"',
    )


@pytest.mark.parametrize(
    ("literal", "match"),
    [
        (b"1.0", r"^parsing runtime manifest: .* is not an integer"),
        (b"1e0", r"^parsing runtime manifest: .* is not an integer"),
        (b'"1"', r"^parsing runtime manifest: .*JSON string into number"),
        (b"null", r"^runtime manifest format is unsupported"),
    ],
)
def test_decode_manifest_format_version_literals(literal: bytes, match: str) -> None:
    raises_decode(base_text().replace(b'"format_version":1', b'"format_version":' + literal), match)


def test_decode_manifest_igvm_and_version() -> None:
    raises_decode(b'{"version":"v0.15.0","igvm":null}', r"^runtime manifest format is unsupported")
    raises_decode(b'{"version":"v0.15.0"}', r"^runtime manifest format is unsupported")
    base = base_text()
    raises_decode(base.replace(b'"version":"v0.15.0"', b'"version":null'), r"^runtime manifest version must be a full")
    raises_decode(
        base.replace(b'"version":"v0.15.0"', b'"version":1'), r"^parsing runtime manifest: .*JSON number into string"
    )
    for version in (b'"0.15.0"', b'"v0.15"'):
        raises_decode(base.replace(b'"version":"v0.15.0"', b'"version":' + version), r"must be a full semantic version")


def test_decode_manifest_framing() -> None:
    base = base_text()
    # Trailing whitespace is fine for the decoder; the digest pin in parse_manifest catches it.
    assert decode_manifest(base + b"\n") == valid_manifest()
    raises_decode(base + b"{}", r"^parsing runtime manifest: ")
    raises_decode(b"", r"^runtime manifest size is outside allowed bounds")
    raises_decode(b"[" + b" " * (1 << 20), r"^runtime manifest size is outside allowed bounds")
    raises_decode(b"[]", r"^parsing runtime manifest: cannot unmarshal JSON array into runtime manifest")


# --- runtime_from_config -----------------------------------------------------

DIGEST = "ab" * 32
GOOD = f'{{"cvm-version":"0.15.0@sha256:{DIGEST}"}}'
WANT = RuntimeReference(repo=RUNTIME_REPO, tag="v0.15.0", digest=DIGEST)
NOT_A_JSON_CONFIG = "^parsing config runtime pin: not a JSON config that states cvm-version; YAML configs are not read$"
NOT_A_FULL_VERSION = "^runtime tag must be a full semantic version"
NOT_LOWERCASE_HEX = "^runtime digest is not lowercase hex"


@pytest.mark.parametrize(
    ("version", "tag"),
    [
        ("0.15.0", "v0.15.0"),
        ("v0.15.0", "v0.15.0"),
        ("0.15.0-rc.1", "v0.15.0-rc.1"),
        ("0.15.0+gpu", "v0.15.0+gpu"),
        ("v0.15.0+gpu", "v0.15.0+gpu"),
        ("0.15.0-rc.1+gpu", "v0.15.0-rc.1+gpu"),
        ("0.15.0+mini", "v0.15.0+mini"),
        ("0.15.0+containers.initrd-1", "v0.15.0+containers.initrd-1"),
        ("0.15.0+GPU", "v0.15.0+GPU"),
        # 0.15.5-rc.1 is the first version whose guest takes a JSON config; the pin is read on either side of it.
        ("0.15.4", "v0.15.4"),
        ("0.15.5-rc.1", "v0.15.5-rc.1"),
    ],
)
def test_config_runtime_pin_accepts(version: str, tag: str) -> None:
    config = f'{{"containers":[],"cvm-version":"{version}@sha256:{DIGEST}"}}'.encode()
    assert runtime_from_config(config) == RuntimeReference(repo=RUNTIME_REPO, tag=tag, digest=DIGEST)


@pytest.mark.parametrize(
    ("config", "match"),
    [
        pytest.param('{"cvm-version":"0.15.0"}', "^cvm-version must pin", id="unpinned"),
        pytest.param(GOOD[:-1] + "," + GOOD[1:], NOT_A_JSON_CONFIG, id="duplicate"),
        pytest.param(GOOD.replace(DIGEST, DIGEST.upper()), NOT_LOWERCASE_HEX, id="bad digest"),
        pytest.param(GOOD.replace("0.15.0", "0.15.0+mini/other"), NOT_A_FULL_VERSION, id="path metadata"),
        pytest.param(GOOD.replace("0.15.0", "0.15+gpu"), NOT_A_FULL_VERSION, id="partial version"),
        pytest.param(GOOD.replace("0.15.0", "0.15.0+"), NOT_A_FULL_VERSION, id="empty metadata"),
        pytest.param(GOOD.replace("0.15.0", "0.15.0+gpu+gpu"), NOT_A_FULL_VERSION, id="double metadata"),
        pytest.param(GOOD.replace(DIGEST, DIGEST[:-2]), "^runtime digest must be 32 bytes", id="short digest"),
        pytest.param(GOOD.replace(DIGEST, DIGEST + "@sha256:" + DIGEST), NOT_LOWERCASE_HEX, id="extra digest"),
        pytest.param('{"containers":[]}', NOT_A_JSON_CONFIG, id="missing version"),
    ],
)
def test_config_runtime_pin_rejects(config: str, match: str) -> None:
    raises_config(config.encode(), match)


def raises_config(config: bytes, match: str) -> None:
    with pytest.raises(RuntimeConfigError, match=match):
        runtime_from_config(config)


def test_config_decode_rejects() -> None:
    # The config is one JSON object.
    raises_config(("[" + GOOD + "]").encode(), NOT_A_JSON_CONFIG)
    raises_config(b'"just a string"', NOT_A_JSON_CONFIG)
    raises_config(b"", NOT_A_JSON_CONFIG)
    raises_config((GOOD + GOOD).encode(), NOT_A_JSON_CONFIG)
    # A repeated member is refused at any depth, even when it is not the one being read.
    raises_config(('{"cpus":2,"cpus":2,' + GOOD[1:]).encode(), NOT_A_JSON_CONFIG)
    raises_config(('{"shim":{"port":1,"port":1},' + GOOD[1:]).encode(), NOT_A_JSON_CONFIG)
    # cvm-version is a string; no other value is read as its text.
    for value in ("null", "0.15", "1", "true", '["a"]', '{"a":"b"}'):
        raises_config(f'{{"cvm-version":{value}}}'.encode(), NOT_A_JSON_CONFIG)
    # The text "15" becomes tag "v15", which is not a full semantic version.
    raises_config(f'{{"cvm-version":"15@sha256:{DIGEST}"}}'.encode(), NOT_A_FULL_VERSION)
    # Only the top-level member is read.
    raises_config(f'{{"a":{GOOD}}}'.encode(), NOT_A_JSON_CONFIG)
    raises_config(b'{"cvm-version":', NOT_A_JSON_CONFIG)
    raises_config(b'{"cvm-version":"\xff"}', NOT_A_JSON_CONFIG)
    # Nesting deeper than the parser allows is an error, not a crash.
    depth = 20_000
    raises_config(b'{"a":' + b"[" * depth + b"]" * depth + b"," + GOOD.encode()[1:], NOT_A_JSON_CONFIG)
    raises_config(b'{"a":' + b'{"b":' * depth + b"1" + b"}" * depth + b"," + GOOD.encode()[1:], NOT_A_JSON_CONFIG)
    # The parser's reason is kept as the cause.
    with pytest.raises(RuntimeConfigError) as info:
        runtime_from_config((GOOD[:-1] + "," + GOOD[1:]).encode())
    assert "duplicate object member name" in str(info.value.__cause__)


@pytest.mark.parametrize(
    "config",
    [
        pytest.param(f"cvm-version: 0.15.4@sha256:{DIGEST}\ncpus: 2\n", id="block style, 0.15.4"),
        pytest.param(f"cvm-version: 0.15.5-rc.1@sha256:{DIGEST}\ncpus: 2\n", id="block style, 0.15.5-rc.1"),
        pytest.param(f'cvm-version: "0.15.0@sha256:{DIGEST}"\n', id="double-quoted"),
        pytest.param(f"cvm-version: '0.15.0@sha256:{DIGEST}'\n", id="single-quoted"),
        pytest.param(f"{{cvm-version: 0.15.0@sha256:{DIGEST}}}\n", id="flow style"),
        pytest.param("---\n" + GOOD, id="JSON after a document start"),
        pytest.param(GOOD + "\n...\n", id="JSON before a document end"),
        pytest.param("# c\n" + GOOD, id="JSON after a comment"),
        pytest.param("\ufeff" + GOOD, id="JSON after a byte-order mark"),
    ],
)
def test_config_decode_rejects_yaml_syntax(config: str) -> None:
    """No YAML syntax is read, whether it spells the pin or surrounds a JSON config."""
    raises_config(config.encode(), NOT_A_JSON_CONFIG)


@pytest.mark.parametrize(
    "config",
    [
        pytest.param(GOOD.replace(":", " : ", 1) + "\n", id="whitespace and a trailing newline"),
        pytest.param('{"shim":{},' + GOOD[1:-1] + ',"cpus":2}', id="members in any order"),
        pytest.param('{"cpus":null,' + GOOD[1:], id="null in another member"),
        pytest.param('{"cpus":2.5,' + GOOD[1:], id="fraction in another member"),
    ],
)
def test_config_decode_accepts(config: str) -> None:
    """Any spelling of the JSON is read: the byte form of a config is the guest's to enforce."""
    assert runtime_from_config(config.encode()) == WANT
