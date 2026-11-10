"""Collateral entry shape checks and the per-format decoders."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from tinfoil._v3.verifier._canonical import base64_length
from tinfoil._v3.verifier._document.collateral import collateral, config, entry, runtime
from tinfoil._v3.verifier._document.collateral.collateral import (
    AMD_CRL_V1_FORMAT,
    AMD_VCEK_V1_FORMAT,
    ARTIFACT_FRESHNESS_V1_FORMAT,
    FRESHNESS_ID_CODE,
    FRESHNESS_ID_PLATFORM,
    FRESHNESS_ID_RUNTIME,
    INTEL_PCS_V1_FORMAT,
    SIGSTORE_CODE_V1_FORMAT,
    SIGSTORE_FRESHNESS_V1_FORMAT,
    SIGSTORE_PLATFORM_V1_FORMAT,
    CPUEndorsements,
    NotFoundError,
    Set,
)
from tinfoil._v3.verifier._document.collateral.config import (
    CONFIG_ENDORSEMENT_V1_FORMAT,
    CONFIG_ENDORSEMENT_V2_FORMAT,
    CONFIG_ID,
    CONFIG_V1_FORMAT,
)
from tinfoil._v3.verifier._document.collateral.runtime import (
    PLATFORM_ID,
    RUNTIME_ID,
    RUNTIME_REPO,
    RUNTIME_V1_FORMAT,
    RuntimeReference,
)
from tinfoil._v3.verifier._document.collateral.sev import (
    AMDCRL,
    AMDVCEK,
    MAX_CERT_CHAIN_PEM_SIZE,
    MAX_CRL_DER_SIZE,
    MAX_VCEK_DER_SIZE,
)
from tinfoil._v3.verifier._document.collateral.sigstore import Freshness
from tinfoil._v3.verifier._document.collateral.tdx import IntelPCS, PCSResponse
from tinfoil._v3.verifier._json import JsonObject, strict_parse


def b64(value: bytes | str) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def entries_of(*items: dict[str, Any]) -> tuple[entry.Entry, ...]:
    """Entries as the document decoder produces them, from JSON-ready dicts."""
    return entry.decode_entries(strict_parse(json.dumps(list(items)).encode()))


def decode(*items: dict[str, Any]) -> Set:
    return collateral.decode(entries_of(*items))


def raises_decode(*items: dict[str, Any], match: str | None = None) -> None:
    with pytest.raises(ValueError, match=match) as info:
        collateral.decode(entries_of(*items))
    assert not isinstance(info.value, NotFoundError), "malformed is not missing"


def cpu(entry_id: str, format_: str, data: dict[str, Any], subjects: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": entry_id,
        "role": entry.ROLE_ENDORSEMENT,
        "format": format_,
        "subjects": [entry.SUBJECT_CPU] if subjects is None else subjects,
        "data": data,
    }


def ref(entry_id: str, format_: str, data: dict[str, Any], role: str = entry.ROLE_REFERENCE_VALUES) -> dict[str, Any]:
    return {"id": entry_id, "role": role, "format": format_, "data": data}


def sev_entries() -> list[dict[str, Any]]:
    return [
        cpu("cpu-endorsement", AMD_VCEK_V1_FORMAT, {"vcek_der_base64": b64("vcek der"), "cert_chain_pem": "chain"}),
        cpu("cpu-crl", AMD_CRL_V1_FORMAT, {"crl_der_base64": b64("crl der")}),
    ]


def test_decode_sev_collateral() -> None:
    assert decode(*sev_entries()).cpu == CPUEndorsements(
        amd_vcek=AMDVCEK(vcek_der=b"vcek der", cert_chain_pem="chain"), amd_crl=AMDCRL(crl_der=b"crl der")
    )


def test_decode_sev_collateral_bounds_sizes_before_parsing() -> None:
    """Each AMD member is bounded at decode: a value at the bound is carried as is, one byte over is rejected."""
    vcek_at = b"\x30" * MAX_VCEK_DER_SIZE
    pem_at = "-" * MAX_CERT_CHAIN_PEM_SIZE
    crl_at = b"\x30" * MAX_CRL_DER_SIZE
    got = decode(
        cpu("cpu-endorsement", AMD_VCEK_V1_FORMAT, {"vcek_der_base64": b64(vcek_at), "cert_chain_pem": pem_at}),
        cpu("cpu-crl", AMD_CRL_V1_FORMAT, {"crl_der_base64": b64(crl_at)}),
    )
    assert got.cpu == CPUEndorsements(
        amd_vcek=AMDVCEK(vcek_der=vcek_at, cert_chain_pem=pem_at), amd_crl=AMDCRL(crl_der=crl_at)
    )
    raises_decode(
        cpu("cpu-endorsement", AMD_VCEK_V1_FORMAT, {"vcek_der_base64": b64(vcek_at + b"\x30"), "cert_chain_pem": "c"}),
        match=f"amd-vcek collateral entry 'cpu-endorsement': vcek_der_base64 exceeds {MAX_VCEK_DER_SIZE} bytes",
    )
    raises_decode(
        cpu("cpu-endorsement", AMD_VCEK_V1_FORMAT, {"vcek_der_base64": b64(b"v"), "cert_chain_pem": pem_at + "-"}),
        match=f"amd-vcek collateral entry 'cpu-endorsement': cert_chain_pem exceeds {MAX_CERT_CHAIN_PEM_SIZE}",
    )
    raises_decode(
        cpu("cpu-crl", AMD_CRL_V1_FORMAT, {"crl_der_base64": b64(crl_at + b"\x30")}),
        match=f"amd-crl collateral entry 'cpu-crl': crl_der_base64 exceeds {MAX_CRL_DER_SIZE} bytes",
    )


def test_decode_sev_collateral_bounds_the_encoded_length_before_decoding() -> None:
    """An encoded value longer than the bound's base64 expansion is rejected as oversized without being decoded:
    one that is not base64 at all still reports the size. At the expansion the value is decoded, so the same
    non-base64 content reports the decoding error, and a value that decodes past the bound reports the size."""

    def vcek_entry(value: str) -> dict[str, Any]:
        return cpu("cpu-endorsement", AMD_VCEK_V1_FORMAT, {"vcek_der_base64": value, "cert_chain_pem": "c"})

    def crl_entry(value: str) -> dict[str, Any]:
        return cpu("cpu-crl", AMD_CRL_V1_FORMAT, {"crl_der_base64": value})

    for entry_with, member, limit in (
        (vcek_entry, "vcek_der_base64", MAX_VCEK_DER_SIZE),
        (crl_entry, "crl_der_base64", MAX_CRL_DER_SIZE),
    ):
        bound = base64_length(limit)
        assert bound == len(b64(bytes(limit)))
        over = "!" + "A" * bound
        at = "!" + "A" * (bound - 1)
        past = "A" * bound  # decodes within the expansion to limit + 1 or 2 bytes
        assert len(base64.b64decode(past)) > limit
        raises_decode(entry_with(over), match=f"{member} exceeds {limit} bytes")
        raises_decode(entry_with(at), match=f"decoding {member}")
        raises_decode(entry_with(past), match=f"{member} exceeds {limit} bytes")


def test_decode_tdx_collateral() -> None:
    url = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
    body = b'{"enclaveIdentity":{}}'
    pcs = {
        "responses": [
            {"url": url, "headers": {"Sgx-Enclave-Identity-Issuer-Chain": ["chain"]}, "body_base64": b64(body)}
        ]
    }
    got = decode(cpu("pcs", INTEL_PCS_V1_FORMAT, pcs)).cpu
    assert got.intel_pcs == IntelPCS(
        responses=(PCSResponse(url=url, headers={"Sgx-Enclave-Identity-Issuer-Chain": ("chain",)}, body=body),)
    )
    assert got.amd_vcek is None
    assert got.amd_crl is None
    # No responses at all is a valid, empty capture.
    assert decode(cpu("pcs", INTEL_PCS_V1_FORMAT, {})).cpu.intel_pcs == IntelPCS(responses=())


def test_decode_empty() -> None:
    got = decode()
    assert got.cpu == CPUEndorsements()
    assert got.sigstore_code is None
    assert got.sigstore_platform is None
    assert got.freshness == {}
    assert got.config is None
    assert got.runtime is None


def test_decode_requires_cpu_subject() -> None:
    entries = sev_entries()
    entries[0]["subjects"] = ["gpu0"]
    got = decode(*entries)
    assert got.cpu.amd_vcek is None, "an entry for another subject does not endorse the CPU"
    assert got.cpu.amd_crl is not None


@pytest.mark.parametrize(
    ("items", "message"),
    [
        (
            [{"role": entry.ROLE_ENDORSEMENT, "format": AMD_CRL_V1_FORMAT, "data": {}}],
            "collateral entry 0 is incomplete",
        ),
        (
            [
                {
                    "id": "crl",
                    "role": entry.ROLE_ENDORSEMENT,
                    "format": "https://tinfoil.sh/collateral/unknown/v9",
                    "data": {},
                },
                {"id": "x", "role": entry.ROLE_ENDORSEMENT, "data": {}},
            ],
            "collateral entry 1 is incomplete",
        ),
        (
            [
                {"id": "crl", "role": entry.ROLE_ENDORSEMENT, "format": "u", "data": {}},
                {"id": "crl", "role": entry.ROLE_ENDORSEMENT, "format": "u", "data": {}},
            ],
            "duplicate collateral entry id 'crl'",
        ),
        (
            [{"id": "crl", "role": "unknown", "format": "u", "data": {}}],
            "collateral entry 'crl' has unknown role 'unknown'",
        ),
        # Unknown formats are not decoded, but their data must still be an object.
        (
            [{"id": "crl", "role": entry.ROLE_ENDORSEMENT, "format": "u"}],
            "collateral entry 'crl' data is not a valid JSON object",
        ),
        (
            [{"id": "crl", "role": entry.ROLE_ENDORSEMENT, "format": "u", "data": None}],
            "collateral entry 'crl' data is not a valid JSON object",
        ),
        (
            [{"id": "crl", "role": entry.ROLE_ENDORSEMENT, "format": "u", "data": []}],
            "collateral entry 'crl' data is not a valid JSON object",
        ),
        (
            [{"id": "crl", "role": entry.ROLE_ENDORSEMENT, "format": "u", "data": "x"}],
            "collateral entry 'crl' data is not a valid JSON object",
        ),
    ],
)
def test_decode_rejects_malformed_entry_list(items: list[dict[str, Any]], message: str) -> None:
    raises_decode(*items, match=message)


def test_decode_rejects_malformed_entry_members() -> None:
    with pytest.raises(ValueError, match="unknown object member name"):
        entries_of({"id": "x", "role": entry.ROLE_ENDORSEMENT, "format": "u", "data": {}, "extra": 1})
    with pytest.raises(ValueError, match="cannot unmarshal"):
        entries_of({"id": 1, "role": entry.ROLE_ENDORSEMENT, "format": "u", "data": {}})
    with pytest.raises(ValueError, match="cannot unmarshal"):
        entries_of({"id": "x", "role": entry.ROLE_ENDORSEMENT, "format": "u", "subjects": "cpu", "data": {}})
    with pytest.raises(ValueError, match="cannot unmarshal"):
        entry.decode_entries(strict_parse(b"{}"))
    assert entry.decode_entries(None) == ()


# Every entry of a known role and format is decoded, whether or not
# verification reads it.
@pytest.mark.parametrize(
    ("items", "message"),
    [
        ([cpu("pcs", INTEL_PCS_V1_FORMAT, {"unknown": 1})], "parsing intel-pcs collateral entry 'pcs'"),
        (
            [cpu("vcek", AMD_VCEK_V1_FORMAT, {"unknown": 1}, subjects=["gpu0"])],
            "parsing amd-vcek collateral entry 'vcek'",
        ),
        (
            [
                cpu(
                    "cpu-endorsement",
                    AMD_VCEK_V1_FORMAT,
                    {"vcek_der_base64": b64("vcek der") + "\n", "cert_chain_pem": "chain"},
                ),
                sev_entries()[1],
            ],
            "amd-vcek collateral entry 'cpu-endorsement': vcek_der_base64 is not canonical base64",
        ),
        (
            [sev_entries()[0], cpu("cpu-crl", AMD_CRL_V1_FORMAT, {"crl_der_base64": b64("crl der") + "\r\n"})],
            "amd-crl collateral entry 'cpu-crl': crl_der_base64 is not canonical base64",
        ),
        (
            [cpu("cpu-crl", AMD_CRL_V1_FORMAT, {"crl_der_base64": "not base64!"})],
            "amd-crl collateral entry 'cpu-crl': decoding crl_der_base64",
        ),
        (
            [
                cpu(
                    "pcs",
                    INTEL_PCS_V1_FORMAT,
                    {
                        "responses": [
                            {
                                "url": "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000",
                                "body_base64": b64('{"tcbInfo":{}}'),
                            },
                            {
                                "url": "https://example.com/never-requested",
                                "body_base64": b64('{"unused":true}')[:4] + "\n" + b64('{"unused":true}')[4:],
                            },
                        ]
                    },
                )
            ],
            "intel-pcs collateral entry 'pcs' response 1: body_base64 is not canonical base64",
        ),
        (
            [cpu("pcs", INTEL_PCS_V1_FORMAT, {"responses": [{"url": "u", "headers": {"h": "x"}, "body_base64": ""}]})],
            "parsing intel-pcs",
        ),
        (
            [ref("code", SIGSTORE_CODE_V1_FORMAT, {"repo": "org/code", "unknown": 1})],
            f"parsing {SIGSTORE_CODE_V1_FORMAT} collateral entry 'code'",
        ),
        (
            [ref(FRESHNESS_ID_CODE, SIGSTORE_FRESHNESS_V1_FORMAT, {"unknown": 1})],
            f"parsing {SIGSTORE_FRESHNESS_V1_FORMAT} collateral entry 'code-freshness'",
        ),
    ],
)
def test_decode_rejects_malformed_known_formats(items: list[dict[str, Any]], message: str) -> None:
    raises_decode(*items, match=message)


def test_decode_ignores_unknown_formats() -> None:
    # Unknown formats, and known formats under a role that they do not serve,
    # are never decoded: only the structural checks apply to them.
    for item in (
        {
            "id": "future",
            "role": entry.ROLE_ENDORSEMENT,
            "format": "https://tinfoil.sh/collateral/unknown/v9",
            "data": {"x": 1},
        },
        {"id": "misrole", "role": entry.ROLE_REFERENCE_VALUES, "format": AMD_VCEK_V1_FORMAT, "data": {"unknown": 1}},
    ):
        assert decode(item).cpu == CPUEndorsements(), item["id"]


def test_decode_selects_first_entry_per_purpose() -> None:
    """A document may carry several entries for one purpose; the first wins. Later ones are still decoded."""

    def pcs(entry_id: str, url: str) -> dict[str, Any]:
        return cpu(entry_id, INTEL_PCS_V1_FORMAT, {"responses": [{"url": url, "body_base64": b64("body")}]})

    def sigstore(entry_id: str, format_: str, repo: str) -> dict[str, Any]:
        return ref(entry_id, format_, {"repo": repo, "tag": "", "digest": "ab", "sigstore_bundle": {}})

    got = decode(
        cpu("vcek-1", AMD_VCEK_V1_FORMAT, {"vcek_der_base64": b64("first vcek"), "cert_chain_pem": "chain"}),
        cpu("vcek-2", AMD_VCEK_V1_FORMAT, {"vcek_der_base64": b64("second vcek"), "cert_chain_pem": "chain"}),
        cpu("crl-1", AMD_CRL_V1_FORMAT, {"crl_der_base64": b64("first crl")}),
        cpu("crl-2", AMD_CRL_V1_FORMAT, {"crl_der_base64": b64("second crl")}),
        pcs("pcs-1", "https://first.example"),
        pcs("pcs-2", "https://second.example"),
        sigstore("code-1", SIGSTORE_CODE_V1_FORMAT, "org/first"),
        sigstore("code-2", SIGSTORE_CODE_V1_FORMAT, "org/second"),
        sigstore("platform-1", SIGSTORE_PLATFORM_V1_FORMAT, "org/first-platform"),
        sigstore("platform-2", SIGSTORE_PLATFORM_V1_FORMAT, "org/second-platform"),
    )
    assert got.cpu.amd_vcek is not None
    assert got.cpu.amd_vcek.vcek_der == b"first vcek"
    assert got.cpu.amd_crl is not None
    assert got.cpu.amd_crl.crl_der == b"first crl"
    assert got.cpu.intel_pcs is not None
    assert got.cpu.intel_pcs.responses[0].url == "https://first.example"
    assert got.sigstore_code is not None
    assert got.sigstore_code.repo == "org/first"
    assert got.sigstore_platform is not None
    assert got.sigstore_platform.repo == "org/first-platform"


def test_decode_keys_freshness_by_id() -> None:
    def witness(entry_id: str, bundle: dict[str, Any]) -> dict[str, Any]:
        return ref(entry_id, SIGSTORE_FRESHNESS_V1_FORMAT, {"sigstore_bundle": bundle})

    got = decode(witness(FRESHNESS_ID_CODE, {"a": 1}), witness(FRESHNESS_ID_PLATFORM, {"b": 2}))
    assert set(got.freshness) == {FRESHNESS_ID_CODE, FRESHNESS_ID_PLATFORM}
    code = got.freshness[FRESHNESS_ID_CODE]
    assert code.format == SIGSTORE_FRESHNESS_V1_FORMAT
    assert isinstance(code.bundle, JsonObject)
    assert list(code.bundle) == ["a"]
    assert isinstance(got.freshness[FRESHNESS_ID_PLATFORM], Freshness)


@pytest.mark.parametrize(
    ("format_", "data", "message"),
    [
        (SIGSTORE_CODE_V1_FORMAT, {"repo": "o/r", "tag": "v1", "digest": "ab"}, "is missing sigstore_bundle"),
        (
            SIGSTORE_CODE_V1_FORMAT,
            {"repo": "o/r", "tag": "v1", "digest": "ab", "sigstore_bundle": None},
            "is missing sigstore_bundle",
        ),
        (SIGSTORE_PLATFORM_V1_FORMAT, {"repo": "o/r", "tag": "v1", "sigstore_bundle": {}}, "is missing digest"),
        (
            SIGSTORE_CODE_V1_FORMAT,
            {"repo": "o/r", "tag": "v1", "digest": "", "sigstore_bundle": {}},
            "is missing digest",
        ),
        (SIGSTORE_FRESHNESS_V1_FORMAT, {}, "is missing sigstore_bundle"),
        (SIGSTORE_FRESHNESS_V1_FORMAT, {"sigstore_bundle": None}, "is missing sigstore_bundle"),
    ],
)
def test_decode_requires_sigstore_bundle_and_digest(format_: str, data: dict[str, Any], message: str) -> None:
    """A reference must carry what verification needs: a bundle and a digest.

    Whether a present bundle verifies is provenance's job, and the tag is an optional hint.
    """
    raises_decode(ref("ref", format_, data), match=message)


def test_decode_accepts_empty_tag_and_repo_and_unverified_bundles() -> None:
    decode(
        ref(
            "ref",
            SIGSTORE_CODE_V1_FORMAT,
            {"repo": "", "tag": "", "digest": "ab", "sigstore_bundle": {"mediaType": "x"}},
        )
    )
    decode(ref("ref", SIGSTORE_FRESHNESS_V1_FORMAT, {"sigstore_bundle": {}}))


# --- runtime ------------------------------------------------------------------


def test_runtime_reference() -> None:
    valid = RuntimeReference(repo=RUNTIME_REPO, tag="v0.15.0-rc.1", digest="ab" * 32)
    valid.validate()
    for bad in (
        RuntimeReference(repo="other/runtime", tag=valid.tag, digest=valid.digest),
        RuntimeReference(repo=valid.repo, tag="0.15.0", digest=valid.digest),
        RuntimeReference(repo=valid.repo, tag="v0.15", digest=valid.digest),
        RuntimeReference(repo=valid.repo, tag="v0.15.0+mini/other", digest=valid.digest),
        RuntimeReference(repo=valid.repo, tag=valid.tag, digest=valid.digest.upper()),
        RuntimeReference(repo=valid.repo, tag=valid.tag, digest="ab"),
    ):
        with pytest.raises(ValueError):  # noqa: PT011 - each case names its own rule
            bad.validate()
    RuntimeReference(repo=valid.repo, tag="v0.15.0+build.1", digest=valid.digest).validate()


def test_runtime() -> None:
    reference = RuntimeReference(repo=RUNTIME_REPO, tag="v0.15.0", digest="ab" * 32)
    manifest = b'{"version":"v0.15.0"}'
    data = {
        "repo": reference.repo,
        "tag": reference.tag,
        "digest": reference.digest,
        "manifest_base64": b64(manifest),
        "sigstore_bundle": {},
    }
    item = ref(RUNTIME_ID, RUNTIME_V1_FORMAT, data)
    got = decode(item).runtime
    assert got is not None
    assert got.reference == reference
    assert got.manifest == manifest
    assert isinstance(got.bundle, JsonObject)
    raises_decode(item, {**item, "id": "other-runtime"}, match="conflicting collateral")
    raises_decode({**item, "role": entry.ROLE_ENDORSEMENT}, match="conflicting collateral")
    raises_decode(
        ref(RUNTIME_ID, RUNTIME_V1_FORMAT, {**data, "sigstore_bundle": None}), match="sigstore_bundle must be an object"
    )
    raises_decode(
        ref(RUNTIME_ID, RUNTIME_V1_FORMAT, {**data, "manifest_base64": b64(manifest) + "\n"}),
        match="not canonical base64",
    )
    raises_decode(ref(RUNTIME_ID, RUNTIME_V1_FORMAT, {**data, "tag": "0.15.0"}), match="full semantic version")
    assert isinstance(runtime.decode_runtime(entries_of(item)[0]), runtime.Runtime)


def test_config_platform() -> None:
    item = ref(
        PLATFORM_ID,
        SIGSTORE_PLATFORM_V1_FORMAT,
        {"repo": "tinfoilsh/cvmimage", "tag": "platform-v1.0.0", "digest": "ab", "sigstore_bundle": {}},
    )
    got = decode(item)
    platform = got.config_platform()
    assert platform.repo == "tinfoilsh/cvmimage"
    assert got.sigstore_platform == platform

    with pytest.raises(NotFoundError):
        decode().config_platform()
    for name, mutated in {
        "wrong id": [{**item, "id": "other"}],
        "wrong role": [{**item, "role": entry.ROLE_ENDORSEMENT}],
        "wrong format": [{**item, "format": "https://tinfoil.sh/collateral/unknown/v1"}],
        "multiple references": [item, {**item, "id": "other"}],
    }.items():
        with pytest.raises(collateral.ConflictError, match="conflicting platform collateral"):
            decode(*mutated).config_platform()
        assert name


def test_artifact_freshness_requires_reserved_profile() -> None:
    for entry_id in (FRESHNESS_ID_PLATFORM, FRESHNESS_ID_RUNTIME):
        item = ref(entry_id, ARTIFACT_FRESHNESS_V1_FORMAT, {"sigstore_bundle": {}})
        assert decode(item).freshness[entry_id].format == ARTIFACT_FRESHNESS_V1_FORMAT
        for mutated in ({**item, "id": "other"}, {**item, "role": entry.ROLE_ENDORSEMENT}, {**item, "data": {}}):
            raises_decode(mutated)
    raises_decode(
        ref(FRESHNESS_ID_RUNTIME, SIGSTORE_FRESHNESS_V1_FORMAT, {"sigstore_bundle": {}}),
        match="conflicting artifact freshness collateral",
    )


# --- config -------------------------------------------------------------------


def test_plain_config_collateral() -> None:
    item = ref(CONFIG_ID, CONFIG_V1_FORMAT, {"config_base64": "Y29uZmln"})
    got = decode(item).config
    assert got is not None
    assert got.config == b"config"
    assert got.reference == ""
    assert got.bundle is None
    assert got.issuer is None
    raises_decode(item, item)
    raises_decode({**item, "format": CONFIG_ENDORSEMENT_V1_FORMAT}, match="endorsement_ref")
    raises_decode(
        ref(CONFIG_ID, CONFIG_V1_FORMAT, {"config_base64": "Y29uZmln", "sigstore_bundle": {}}),
        match="cannot contain an endorsement",
    )
    raises_decode(
        ref(CONFIG_ID, CONFIG_V1_FORMAT, {"config_base64": "Y29uZmln", "sigstore_bundle": None}),
        match="cannot contain an endorsement",
    )
    raises_decode(
        ref(CONFIG_ID, CONFIG_V1_FORMAT, {"config_base64": "Y29uZmln", "endorsement_ref": "x"}),
        match="cannot contain an endorsement",
    )


def test_config_collateral_allows_optional_bytes() -> None:
    data = {"endorsement_ref": "sha256:" + "ab" * 32, "sigstore_bundle": {"mediaType": "test"}}
    got = decode(ref(CONFIG_ID, CONFIG_ENDORSEMENT_V2_FORMAT, data)).config
    assert got is not None
    assert got.reference == data["endorsement_ref"]
    assert got.bundle == b'{"mediaType":"test"}'
    assert got.config is None
    got = decode(ref(CONFIG_ID, CONFIG_ENDORSEMENT_V2_FORMAT, {**data, "config_base64": b64("public config")})).config
    assert got is not None
    assert got.config == b"public config"


def test_config_endorsement() -> None:
    config_bytes = b"cvm-version: 1.0.0\n"
    reference = "sha256:" + "ab" * 32
    data: dict[str, Any] = {
        "endorsement_ref": reference,
        "config_base64": b64(config_bytes),
        "sigstore_bundle": {"mediaType": "test"},
    }
    item = ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, data)
    got = decode(item).config
    assert got is not None
    assert got.reference == reference
    assert got.config == config_bytes
    assert got.bundle == b'{"mediaType":"test"}', "the bundle is kept as the entry's JSON bytes"

    cases: dict[str, list[dict[str, Any]]] = {
        "wrong role": [{**item, "role": entry.ROLE_ENDORSEMENT}],
        "wrong format": [{**item, "format": SIGSTORE_CODE_V1_FORMAT}],
        "wrong id": [{**item, "id": "other"}],
        "duplicate": [item, item],
        "ambiguous format": [item, {**item, "id": "other"}],
        "noncanonical base64": [
            ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, {**data, "config_base64": "\n" + data["config_base64"]})
        ],
        "empty config": [ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, {**data, "config_base64": ""})],
        "missing config": [
            ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, {k: v for k, v in data.items() if k != "config_base64"})
        ],
        "bad reference": [ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, {**data, "endorsement_ref": "sha256:bad"})],
        "unknown member": [ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, {"unknown": True, **data})],
        "missing bundle": [ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, {**data, "sigstore_bundle": None})],
        "array bundle": [ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, {**data, "sigstore_bundle": []})],
    }
    for name, items in cases.items():
        raises_decode(*items)
        assert name
    # A duplicate member is rejected by the document parser before entries exist.
    with pytest.raises(ValueError, match="duplicate"):
        strict_parse(b'{"endorsement_ref":"ignored","endorsement_ref":"x"}')


def test_issuer_certificate_encoding_is_canonical() -> None:
    data: dict[str, Any] = {
        "endorsement_ref": "sha256:" + "ab" * 32,
        "sigstore_bundle": {"mediaType": "test"},
        "issuer_certificate_der": "Yg==",
    }
    got = decode(ref(CONFIG_ID, CONFIG_ENDORSEMENT_V2_FORMAT, data)).config
    assert got is not None
    assert got.issuer == b"b"
    got = decode(ref(CONFIG_ID, CONFIG_ENDORSEMENT_V2_FORMAT, {**data, "config_base64": "Y29uZmln"})).config
    assert got is not None
    assert got.config == b"config"
    assert got.issuer == b"b"
    for noncanonical in ("YR==", "YQ==\n"):
        raises_decode(
            ref(CONFIG_ID, CONFIG_ENDORSEMENT_V2_FORMAT, {**data, "issuer_certificate_der": noncanonical}),
            match="issuer_certificate_der",
        )
    raises_decode(ref(CONFIG_ID, CONFIG_ENDORSEMENT_V1_FORMAT, data), match="issuer certificates require v2")
    assert isinstance(
        config.decode_config_endorsement(entries_of(ref(CONFIG_ID, CONFIG_ENDORSEMENT_V2_FORMAT, data))[0]),
        config.ConfigEndorsement,
    )
