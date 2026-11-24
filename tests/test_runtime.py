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
    ],
)
def test_config_runtime_pin_accepts(version: str, tag: str) -> None:
    config = f'{{"containers":[],"cvm-version":"{version}@sha256:{DIGEST}"}}'.encode()
    assert runtime_from_config(config) == RuntimeReference(repo=RUNTIME_REPO, tag=tag, digest=DIGEST)


@pytest.mark.parametrize(
    ("name", "config"),
    [
        ("unpinned", '{"cvm-version":"0.15.0"}'),
        ("duplicate", GOOD[:-1] + "," + GOOD[1:]),
        ("two documents", GOOD + GOOD),
        ("not JSON", f"cvm-version: 0.15.0@sha256:{DIGEST}\n"),
        ("bad digest", GOOD.replace(DIGEST, DIGEST.upper())),
        ("path metadata", GOOD.replace("0.15.0", "0.15.0+mini/other")),
        ("partial version", GOOD.replace("0.15.0", "0.15+gpu")),
        ("empty metadata", GOOD.replace("0.15.0", "0.15.0+")),
        ("double metadata", GOOD.replace("0.15.0", "0.15.0+gpu+gpu")),
        ("short digest", GOOD.replace(DIGEST, DIGEST[:-2])),
        ("extra digest", GOOD.replace(DIGEST, DIGEST + "@sha256:" + DIGEST)),
        ("missing version", '{"containers":[]}'),
    ],
    ids=lambda value: value if " " in value or value in ("unpinned", "duplicate") else None,
)
def test_config_runtime_pin_rejects(name: str, config: str) -> None:
    with pytest.raises(RuntimeConfigError):
        runtime_from_config(config.encode())


def raises_config(config: bytes, match: str) -> None:
    with pytest.raises(RuntimeConfigError, match=match):
        runtime_from_config(config)


def test_config_decode_rejects() -> None:
    raises_config((GOOD[:-1] + "," + GOOD[1:]).encode(), r"^parsing config runtime pin: duplicate object member name")
    # A top-level key repeats even when it is not one being read.
    raises_config(('{"containers":[],"containers":[],' + GOOD[1:]).encode(), r'member name "containers"')
    # Duplicates nested under a member that is not read are rejected too.
    raises_config(('{"other":{"a":1,"a":2},' + GOOD[1:]).encode(), r'member name "a"')
    raises_config((GOOD + GOOD).encode(), r"^parsing config runtime pin: invalid JSON: ")
    raises_config(("[" + GOOD + "]").encode(), r"^parsing config runtime pin: cannot unmarshal JSON array into config")
    raises_config(b'"just a string"', r"^parsing config runtime pin: cannot unmarshal JSON string into config")
    raises_config(b"", r"^parsing config runtime pin: invalid JSON: ")
    # A null value reads as text that carries no pin.
    raises_config(b'{"cvm-version":null}', r"^cvm-version must pin a runtime manifest SHA-256 digest")
    for value in (b"0.15", b"1", b"true", b'["a"]', b'{"a":"b"}'):
        raises_config(b'{"cvm-version":' + value + b"}", r"^parsing config runtime pin: cannot unmarshal JSON")
    # The text "15" becomes tag "v15", which is not a full semantic version.
    raises_config(f'{{"cvm-version":"15@sha256:{DIGEST}"}}'.encode(), r"^runtime tag must be a full semantic version")
    # Only the top-level key is read.
    raises_config(f'{{"a":{GOOD}}}'.encode(), r"^cvm-version must pin")
    raises_config(b'{"cvm-version":[', r"^parsing config runtime pin: ")
    # Nesting deeper than the parser allows is an error, not a crash.
    depth = 20_000
    raises_config(b'{"a":' + b"[" * depth + b"]" * depth + b"," + GOOD.encode()[1:], r"exceeded max depth")
    raises_config(b'{"a":' + b'{"b":' * depth + b"1" + b"}" * depth + b"," + GOOD.encode()[1:], r"exceeded max depth")
    raises_config(b'{"cvm-version":"\xff"}', r"^parsing config runtime pin: ")


@pytest.mark.parametrize(
    ("name", "config"),
    [
        ("key with trailing space", GOOD.replace(":", " :", 1)),
        ("CRLF line endings", GOOD.replace("{", "{\r\n").replace("}", "\r\n}\r\n")),
    ],
    ids=lambda value: value if " " in value or value.endswith("quoted") else None,
)
def test_config_decode_accepts(name: str, config: str) -> None:
    assert runtime_from_config(config.encode()) == WANT
