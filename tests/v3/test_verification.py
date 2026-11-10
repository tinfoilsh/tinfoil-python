"""The verification record: key lookups, immutability and the JSON form."""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from tinfoil._v3.verifier._document.document import KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_SPKI_V1_FORMAT, CryptoMaterialItem
from tinfoil._v3.verifier._measurement import SEVSNP, TDX, ExpectedSEVSNP, ExpectedTDX
from tinfoil._v3.verifier._verification import (
    SOURCE_EMBEDDED,
    SOURCE_ENDORSEMENT,
    ArtifactVerification,
    ConfigVerification,
    SoftwareIdentity,
    Verification,
    VerificationMetadata,
    crypto_material_data,
)

REGISTER = bytes([0xAB]) * 48
AT = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
FUTURE_FORMAT = "https://example.com/key/future/v1"


def record(**overrides: object) -> Verification:
    fields: dict[str, object] = {
        "code_digest": "ab" * 32,
        "code_tag": "v1.0.0",
        "config_repo": "org/project",
        "code_measurement": ExpectedTDX(rtmr1=REGISTER),
        "enclave_measurement": TDX(mrtd=REGISTER, rtmr0=REGISTER, rtmr1=REGISTER, rtmr2=REGISTER, rtmr3=REGISTER),
        "crypto_material": (
            CryptoMaterialItem(id="tls", format=KEY_SPKI_FP_SHA256_V1_FORMAT, data="aabb"),
            CryptoMaterialItem(id="workload", format=FUTURE_FORMAT, data="010203"),
        ),
        "metadata": VerificationMetadata(verifier=SoftwareIdentity(name="tinfoil-python", version="1"), verified_at=AT),
    }
    fields.update(overrides)
    return Verification(**fields)  # type: ignore[arg-type]


def test_crypto_material_data() -> None:
    v = record()
    assert v.crypto_material_data("workload", FUTURE_FORMAT) == "010203"
    assert v.crypto_material_data("workload", KEY_SPKI_V1_FORMAT) is None, (
        "an item in another format is not the one asked for"
    )
    assert v.crypto_material_data("missing", FUTURE_FORMAT) is None
    assert crypto_material_data((), "workload", FUTURE_FORMAT) is None, "an empty record endorses nothing"
    assert v.tls_public_key_fp == "aabb"
    assert v.hpke_public_key is None


def test_code_release_record_has_no_config() -> None:
    v = record()
    assert v.config is None
    assert v.runtime is None
    assert v.platform is None
    assert v.freshness_expires_at is None


def test_record_is_frozen() -> None:
    v = record()
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.code_digest = "changed"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.metadata.verified_at = AT  # type: ignore[misc]


def test_to_dict_lays_out_registers_as_hex_and_times_in_utc() -> None:
    config = ConfigVerification(
        source=SOURCE_ENDORSEMENT,
        name="/org/project/v1",
        digest="cd" * 32,
        reference="sha256:" + "ef" * 32,
        signing_key_hint="hint",
        approval_time=AT - timedelta(hours=1),
        registry_id="https://registry.tinfoil.sh/scopes/public",
    )
    runtime = ArtifactVerification(source=SOURCE_EMBEDDED, repo="tinfoilsh/cvmimage", tag="v0.15.0", digest="12" * 32)
    platform = ArtifactVerification(
        source=SOURCE_ENDORSEMENT,
        repo="tinfoilsh/cvmimage",
        tag="platform-v1.0.0",
        digest="34" * 32,
        name="platform-endorsements.json",
        commit="0" * 40,
        approval_time=AT.astimezone(timezone(timedelta(hours=2))),
    )
    v = record(
        code_measurement=ExpectedSEVSNP(launch=REGISTER),
        enclave_measurement=SEVSNP(launch=REGISTER),
        config=config,
        runtime=runtime,
        platform=platform,
        freshness_expires_at=AT + timedelta(days=7),
    )
    got = v.to_dict()
    assert got == {
        "code_digest": "ab" * 32,
        "code_tag": "v1.0.0",
        "config_repo": "org/project",
        "code_measurement": {"platform": "sev-snp", "launch": REGISTER.hex()},
        "enclave_measurement": {"platform": "sev-snp", "launch": REGISTER.hex()},
        "crypto_material": [
            {"id": "tls", "format": KEY_SPKI_FP_SHA256_V1_FORMAT, "data": "aabb"},
            {"id": "workload", "format": FUTURE_FORMAT, "data": "010203"},
        ],
        "config": {
            "source": "endorsement",
            "name": "/org/project/v1",
            "digest": "cd" * 32,
            "reference": "sha256:" + "ef" * 32,
            "signing_key_hint": "hint",
            "approval_time": "2026-08-06T11:00:00Z",
            "registry_id": "https://registry.tinfoil.sh/scopes/public",
        },
        "runtime": {
            "source": "embedded",
            "repo": "tinfoilsh/cvmimage",
            "tag": "v0.15.0",
            "digest": "12" * 32,
        },
        "platform": {
            "source": "endorsement",
            "repo": "tinfoilsh/cvmimage",
            "tag": "platform-v1.0.0",
            "digest": "34" * 32,
            "name": "platform-endorsements.json",
            "commit": "0" * 40,
            "approval_time": "2026-08-06T12:00:00Z",
        },
        "freshness_expires_at": "2026-08-13T12:00:00Z",
        "metadata": {"verifier": {"name": "tinfoil-python", "version": "1"}, "verified_at": "2026-08-06T12:00:00Z"},
    }
    assert json.loads(v.to_json()) == got
    assert "\n" not in v.to_json(), "compact by default"
    assert ": " not in v.to_json(), "compact by default"
    assert json.loads(v.to_json(indent=2)) == got
    assert v.to_json(indent=2) == json.dumps(got, indent=2)


def test_to_dict_leaves_out_what_was_not_established() -> None:
    got = record().to_dict()
    assert got["code_measurement"] == {"platform": "tdx", "rtmr1": REGISTER.hex()}
    assert got["enclave_measurement"] == {
        "platform": "tdx",
        **{name: REGISTER.hex() for name in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")},
    }
    assert set(got) == {
        "code_digest",
        "code_tag",
        "config_repo",
        "code_measurement",
        "enclave_measurement",
        "crypto_material",
        "metadata",
    }
    # A caller-authorized config and an embedded runtime establish only a source and whatever the caller supplied:
    # the placeholders for the facts that an endorsement would have established are not emitted.
    got = record(
        config=ConfigVerification(source=SOURCE_EMBEDDED, digest="cd" * 32),
        runtime=ArtifactVerification(source=SOURCE_EMBEDDED),
    ).to_dict()
    assert got["config"] == {"source": "embedded", "digest": "cd" * 32}
    assert got["runtime"] == {"source": "embedded"}
    assert json.loads(record(runtime=ArtifactVerification(source=SOURCE_EMBEDDED)).to_json())["runtime"] == {
        "source": "embedded"
    }
