"""The trusted root decoder: the embedded root, the fixture roots, the value rules and the library's shape gate."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import ValidationError
from sigstore_models.trustroot.v1 import TrustedRoot as WireTrustedRoot

from tests import pki
from tests.vectors import vector
from tinfoil.verifier import _json
from tinfoil.verifier._sigstore import _wire
from tinfoil.verifier._sigstore.trusted_root import (
    TRUSTED_ROOT_MEDIA_TYPE,
    TrustedRootError,
    ValidFor,
    embedded_trusted_root,
    parse_trusted_root,
)
from tinfoil.verifier._trust import SIGSTORE_TRUSTED_ROOT_JSON


def root_json() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SIGSTORE_TRUSTED_ROOT_JSON)
    return data


def parse(data: dict[str, Any]) -> Any:
    return parse_trusted_root(json.dumps(data).encode())


def test_embedded_root_parses_into_the_records() -> None:
    root = embedded_trusted_root()
    assert [log.base_url for log in root.tlogs] == [
        "https://rekor.sigstore.dev",
        "https://log2025-1.rekor.sigstore.dev",
    ]
    assert isinstance(root.tlogs[0].public_key, ec.EllipticCurvePublicKey)
    assert isinstance(root.tlogs[1].public_key, ed25519.Ed25519PublicKey)
    assert root.tlogs[0].valid_for == ValidFor(datetime(2021, 1, 12, 11, 53, 27, tzinfo=UTC))
    assert len(root.tlogs[0].log_id) == 32
    assert root.tlog(root.tlogs[1].log_id) is root.tlogs[1]
    assert root.tlog(bytes(32)) is None
    assert [log.base_url for log in root.ctlogs] == ["https://ctfe.sigstore.dev/test", "https://ctfe.sigstore.dev/2022"]
    assert root.ctlogs[0].valid_for.end == datetime(2022, 10, 31, 23, 59, 59, 999000, tzinfo=UTC)
    assert root.ctlog(root.ctlogs[1].log_id) is root.ctlogs[1]
    assert len(root.certificate_authorities) == 2
    assert len(root.timestamp_authorities) == 1
    for authority in (*root.certificate_authorities, *root.timestamp_authorities):
        assert authority.subject
        assert authority.uri.startswith("https://")
        assert authority.root is authority.chain[-1]
    at = datetime(2025, 10, 1, tzinfo=UTC)
    assert len(root.certificate_authorities_at(at)) == 1
    assert root.timestamp_authorities_at(at) == root.timestamp_authorities
    assert root.timestamp_authorities_at(datetime(2025, 1, 1, tzinfo=UTC)) == ()
    assert root.tlog_by_checkpoint_key_id(root.tlogs[0].log_id) is root.tlogs[0]


def test_valid_for_is_inclusive_and_open_ended() -> None:
    start = datetime(2025, 1, 1, tzinfo=UTC)
    window = ValidFor(start, start + timedelta(days=1))
    assert window.contains(start)
    assert window.contains(start + timedelta(days=1))
    assert not window.contains(start - timedelta(microseconds=1))
    assert not window.contains(start + timedelta(days=1, microseconds=1))
    assert ValidFor(start).contains(start + timedelta(days=10_000))
    with pytest.raises(TrustedRootError, match="timezone-aware"):
        window.contains(datetime(2025, 1, 1))


@pytest.mark.parametrize("group", ["rfc3161", "approval-bundle", "provenance"])
def test_fixture_roots_parse(group: str) -> None:
    fixture_id = {"rfc3161": "granted-p256", "approval-bundle": "happy", "provenance": "provenance-happy"}[group]
    fixture = vector(group, fixture_id)
    root = parse_trusted_root(base64.b64decode(fixture["input"]["sigstore_trusted_root_json_b64"]))
    assert root.tlogs or root.timestamp_authorities or root.certificate_authorities


def test_a_root_without_transparency_logs_parses() -> None:
    data = root_json()
    data["tlogs"] = []
    assert parse(data).tlogs == ()


# --- the shape gate (sigstore_models) ----------------------------------------


def test_library_rejects_unknown_members_at_every_depth() -> None:
    """The decoder relies on sigstore_models to reject unknown members; pin that it does, at depth."""
    data = root_json()
    data["tlogs"][0]["publicKey"]["extra"] = 1
    with pytest.raises(ValidationError):
        WireTrustedRoot.model_validate_json(json.dumps(data))
    with pytest.raises(TrustedRootError, match="does not match the schema"):
        parse(data)
    data = root_json()
    data["extra"] = 1
    with pytest.raises(TrustedRootError, match="does not match the schema"):
        parse(data)


def test_member_name_check_walks_any_depth() -> None:
    """The member-name walk keeps its own stack, so a document nested far beyond the interpreter's recursion limit
    is checked and reported rather than overflowing."""
    depth = 2_000
    deep: _json.JsonValue = _json.JsonObject({"ok": _json.JsonNumber("1")})
    for _ in range(depth):
        deep = _json.JsonObject({"level": (deep,)})
    _wire.check_member_names(deep)
    bad: _json.JsonValue = _json.JsonObject({"log_id": _json.JsonNumber("1")})
    for _ in range(depth):
        bad = _json.JsonObject({"level": (bad,)})
    with pytest.raises(_wire.WireError, match="'log_id' is not the JSON field name"):
        _wire.check_member_names(bad)


def test_library_requires_log_ids_and_validity() -> None:
    data = root_json()
    del data["tlogs"][0]["logId"]
    with pytest.raises(TrustedRootError, match="does not match the schema"):
        parse(data)
    data = root_json()
    del data["certificateAuthorities"][0]["validFor"]
    with pytest.raises(TrustedRootError, match="does not match the schema"):
        parse(data)


def test_library_is_looser_than_the_value_rules() -> None:
    """What sigstore_models accepts and the decoder still rejects: the reason the value rules are local."""
    data = root_json()
    data["tlogs"][0]["publicKey"]["validFor"]["start"] = "2021-01-12T11:53:27"  # no zone
    WireTrustedRoot.model_validate_json(json.dumps(data))
    with pytest.raises(TrustedRootError, match="RFC 3339 time with a zone"):
        parse(data)
    data = root_json()
    raw = data["tlogs"][0]["publicKey"]["rawBytes"]
    data["tlogs"][0]["publicKey"]["rawBytes"] = (
        raw[:8] + "\n" + raw[8:]
    )  # a non-alphabet character, skipped by a lenient decoder
    WireTrustedRoot.model_validate_json(json.dumps(data))
    with pytest.raises(TrustedRootError, match="base64"):
        parse(data)
    data["tlogs"][0]["publicKey"]["rawBytes"] = raw.rstrip("=")  # unpadded: the library rejects this one itself
    with pytest.raises(ValidationError):
        WireTrustedRoot.model_validate_json(json.dumps(data))
    data = root_json()
    data["tlogs"][0]["base_url"] = data["tlogs"][0].pop("baseUrl")  # the proto field name
    WireTrustedRoot.model_validate_json(json.dumps(data))
    with pytest.raises(TrustedRootError, match="not the JSON field name"):
        parse(data)
    data = root_json()
    data["mediaType"] = "application/vnd.dev.sigstore.trustedroot.v0.2+json"
    WireTrustedRoot.model_validate_json(json.dumps(data))
    with pytest.raises(TrustedRootError, match="unsupported trusted root media type"):
        parse(data)


# --- value rules -------------------------------------------------------------


def test_rfc3339_forms() -> None:
    assert _wire.rfc3339("2025-01-01T00:00:00Z", "t") == datetime(2025, 1, 1, tzinfo=UTC)
    assert _wire.rfc3339("2025-01-01T01:00:00+01:00", "t") == datetime(2025, 1, 1, tzinfo=UTC)
    assert _wire.rfc3339("2025-01-01T00:00:00.123456789Z", "t").microsecond == 123456
    for bad in (
        "2025-01-01",
        "2025-01-01T00:00:00",
        "2025-01-01t00:00:00z",
        "2025-13-01T00:00:00Z",
        "2025-01-01T00:00:00+24:00",
        "２025-01-01T00:00:00Z",  # a full-width digit: only ASCII digits spell a time
        "2025-01-01T00:00:00.１Z",
        "2025-01-01T00:00:00+0１:00",
        # A local time whose UTC equivalent leaves the representable years.
        "0001-01-01T00:00:00+00:01",
        "9999-12-31T23:59:59-00:01",
    ):
        with pytest.raises(_wire.WireError):
            _wire.rfc3339(bad, "t")
    with pytest.raises(_wire.WireError, match="not a valid calendar time"):
        _wire.rfc3339("0001-01-01T00:00:00+00:01", "t")


def test_uint64_forms() -> None:
    obj = _json.JsonObject({"n": "9223372036854775807", "z": "0"})
    assert _wire.uint64(obj, "n") == (1 << 63) - 1
    assert _wire.uint64(obj, "z") == 0
    assert _wire.uint64(obj, "absent") is None
    for bad in ("", "-1", "01", "1.0", " 1", "1e3", "１"):
        with pytest.raises(_wire.WireError, match="not a non-negative decimal string"):
            _wire.uint64(_json.JsonObject({"n": bad}), "n")
    with pytest.raises(_wire.WireError, match="overflows int64"):
        _wire.uint64(_json.JsonObject({"n": "9223372036854775808"}), "n")
    # Longer than the int64 digit count: rejected by length, never converted (a 5000-digit string would
    # otherwise exceed the interpreter's conversion limit).
    with pytest.raises(_wire.WireError, match="overflows int64"):
        _wire.uint64(_json.JsonObject({"n": "1" * 5000}), "n")
    with pytest.raises(_wire.WireError, match="overflows int64"):
        _wire.uint64(_json.JsonObject({"n": "1" + "0" * 19}), "n")


def test_window_must_not_end_before_it_starts() -> None:
    data = root_json()
    data["tlogs"][0]["publicKey"]["validFor"]["end"] = "2020-01-01T00:00:00Z"
    with pytest.raises(TrustedRootError, match="ends before it starts"):
        parse(data)


def test_log_rules() -> None:
    data = root_json()
    data["tlogs"][0]["hashAlgorithm"] = "SHA2_384"
    with pytest.raises(TrustedRootError, match="hash algorithm"):
        parse(data)
    data = root_json()
    data["tlogs"][0]["logId"]["keyId"] = base64.b64encode(b"short").decode()
    with pytest.raises(TrustedRootError, match="not 32 bytes"):
        parse(data)
    data = root_json()
    data["tlogs"][0]["publicKey"]["keyDetails"] = "PKIX_ECDSA_P384_SHA_384"  # a P-256 key
    with pytest.raises(TrustedRootError, match="does not match its declared type"):
        parse(data)
    data = root_json()
    data["tlogs"][0]["publicKey"]["keyDetails"] = "PKIX_RSA_PKCS1V15_2048_SHA256"
    with pytest.raises(TrustedRootError, match="unsupported tlogs key type"):
        parse(data)
    data = root_json()
    data["tlogs"][0]["publicKey"]["rawBytes"] = base64.b64encode(
        pki.spki(ec.generate_private_key(ec.SECP521R1()))
    ).decode()
    data["tlogs"][0]["publicKey"]["keyDetails"] = "PKIX_ECDSA_P521_SHA_512"
    with pytest.raises(TrustedRootError, match="unsupported tlogs key type"):
        parse(data)
    data = root_json()
    data["tlogs"][0]["checkpointKeyId"] = {"keyId": base64.b64encode(b"\x01\x02\x03\x04").decode()}
    assert parse(data).tlogs[0].checkpoint_key_id == b"\x01\x02\x03\x04"


def test_authority_rules() -> None:
    data = root_json()
    data["certificateAuthorities"][0]["certChain"]["certificates"] = []
    with pytest.raises(TrustedRootError, match="empty certificate chain"):
        parse(data)
    data = root_json()
    chain = data["certificateAuthorities"][1]["certChain"]["certificates"]
    chain.pop()  # the self-signed root: the chain now ends in the intermediate
    with pytest.raises(TrustedRootError, match="self-signed root"):
        parse(data)
    data = root_json()
    chain = data["certificateAuthorities"][0]["certChain"]["certificates"]
    chain[0]["rawBytes"] = base64.b64encode(base64.b64decode(chain[0]["rawBytes"]) + b"\x00").decode()
    with pytest.raises(TrustedRootError, match="trailing bytes"):
        parse(data)
    # Any self-signed root is accepted; one whose signature its own key does not verify is not.
    other = pki.certificate("sigstore", pki.p256(), ca=True)
    data = root_json()
    data["certificateAuthorities"][0]["certChain"]["certificates"] = [
        {"rawBytes": base64.b64encode(other.der).decode()}
    ]
    assert parse(data).certificate_authorities[0].chain[0].serial_number == 1000
    tampered = bytearray(other.der)
    tampered[-1] ^= 0x01
    data["certificateAuthorities"][0]["certChain"]["certificates"] = [
        {"rawBytes": base64.b64encode(bytes(tampered)).decode()}
    ]
    with pytest.raises(TrustedRootError, match="does not verify"):
        parse(data)


def test_media_type_constant() -> None:
    assert root_json()["mediaType"] == TRUSTED_ROOT_MEDIA_TYPE
