"""RFC 3161 timestamps: the 14 rfc3161 vectors through ``verify_timestamp`` and the claims made of
``rfc3161-client``."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from rfc3161_client import VerificationError, VerifierBuilder, decode_timestamp_response

from tests import pki
from tests.sigstore_world import World, b64
from tests.vectors import vector, vector_params
from tinfoil.verifier import _json
from tinfoil.verifier._sigstore import timestamp as ts
from tinfoil.verifier._sigstore.trusted_root import TrustedRoot, parse_trusted_root
from tinfoil.verifier._x509.certificate import (
    OID_EKU_TIME_STAMPING,
    X509Error,
    issuer_name,
    subject_name,
    verify_chain,
)


def fixture_root(fixture: dict[str, Any]) -> TrustedRoot:
    return parse_trusted_root(base64.b64decode(fixture["input"]["sigstore_trusted_root_json_b64"]))


def fixture_inputs(fixture: dict[str, Any]) -> tuple[bytes, bytes]:
    return base64.b64decode(fixture["input"]["timestamp_response_b64"]), base64.b64decode(
        fixture["input"]["timestamp_input_b64"]
    )


@pytest.mark.parametrize("fixture", vector_params("rfc3161"))
def test_rfc3161_vectors(fixture: dict[str, Any]) -> None:
    """Every vector: the fixture's verdict, and on accept the genTime at second precision."""
    response, data = fixture_inputs(fixture)
    expected = fixture["expected"]
    if expected["accepted"]:
        gen_time = ts.verify_timestamp(fixture_root(fixture), response, data)
        assert gen_time.strftime("%Y-%m-%dT%H:%M:%SZ") == expected["timestamp"]
    else:
        with pytest.raises(ts.TimestampError):
            ts.verify_timestamp(fixture_root(fixture), response, data)


def test_parse_timestamp_response_reads_the_token() -> None:
    response, data = fixture_inputs(vector("rfc3161", "granted-p256"))
    parsed = ts.parse_timestamp_response(response)
    assert parsed.status == ts.STATUS_GRANTED
    assert parsed.policy == ts.SIGSTORE_TIMESTAMP_POLICY
    assert parsed.gen_time == datetime(2025, 3, 1, 12, tzinfo=UTC)
    assert parsed.hash_algorithm == ts.OID_SHA256
    assert parsed.hashed_message == hashlib.sha256(data).digest()
    assert parsed.tst_info_version == ts.TST_INFO_VERSION
    assert parsed.raw
    ts.check_imprint(parsed, data)
    with pytest.raises(ts.TimestampError, match="does not match the input"):
        ts.check_imprint(parsed, data + b"x")
    with pytest.raises(ts.TimestampError, match="does not match the input"):
        ts.check_imprint(dataclasses.replace(parsed, hash_algorithm="2.16.840.1.101.3.4.2.2"), data)


def test_size_bounds() -> None:
    response, _data = fixture_inputs(vector("rfc3161", "granted-p256"))
    root = fixture_root(vector("rfc3161", "granted-p256"))
    with pytest.raises(ts.TimestampError, match="response size"):
        ts.parse_timestamp_response(b"")
    with pytest.raises(ts.TimestampError, match="response size"):
        ts.parse_timestamp_response(b"\x30" + b"\x00" * ts.MAX_TIMESTAMP_SIZE)
    with pytest.raises(ts.TimestampError, match="input size"):
        ts.verify_timestamp(root, response, b"")
    with pytest.raises(ts.TimestampError, match="input size"):
        ts.verify_timestamp(root, response, b"x" * (ts.MAX_STATEMENT_SIZE + 1))


def test_status_is_checked_before_the_token_is_read() -> None:
    response, _ = fixture_inputs(vector("rfc3161", "status-rejected"))
    with pytest.raises(ts.TimestampError, match="not granted \\(status 2\\)"):
        ts.parse_timestamp_response(response)
    response, _ = fixture_inputs(vector("rfc3161", "granted-with-mods"))
    with pytest.raises(ts.TimestampError, match="not granted \\(status 1\\)"):
        ts.parse_timestamp_response(response)


def test_der_strictness_applies_to_the_whole_response() -> None:
    response, _ = fixture_inputs(vector("rfc3161", "granted-p256"))
    with pytest.raises(ts.TimestampError, match="trailing bytes"):
        ts.parse_timestamp_response(response + b"\x00")
    # A BER indefinite length anywhere in the token is rejected.
    with pytest.raises(ts.TimestampError, match="indefinite"):
        ts.parse_timestamp_response(b"\x30\x80" + response[4:] + b"\x00\x00")


def test_policy_and_window_are_local_rules() -> None:
    """The library verifies the wrong-policy and out-of-window responses; the wrapper rejects them."""
    for fixture_id, message in (
        ("wrong-policy", "unexpected timestamp policy"),
        ("after-window", "no trusted timestamp authority"),
    ):
        fixture = vector("rfc3161", fixture_id)
        response, data = fixture_inputs(fixture)
        root = fixture_root(fixture)
        with pytest.raises(ts.TimestampError, match=message):
            ts.verify_timestamp(root, response, data)
        assert library_verifies(root, response, data)


def library_verifies(root: TrustedRoot, response: bytes, data: bytes) -> bool:
    """Whether rfc3161-client alone, given the first authority's chain, accepts the response."""
    authority = root.timestamp_authorities[0]
    builder = VerifierBuilder().add_root_certificate(authority.root)
    for certificate in authority.chain[:-1]:
        builder = builder.add_intermediate_certificate(certificate)
    try:
        return bool(builder.build().verify(decode_timestamp_response(response), hashlib.sha256(data).digest()))
    except VerificationError:
        return False


def test_library_claims() -> None:
    """What the wrapper relies on rfc3161-client for, and the behaviours that make the wrapper's own checks
    necessary."""
    response, data = fixture_inputs(vector("rfc3161", "granted-p256"))
    wire = decode_timestamp_response(response)
    assert wire.status == 0
    assert wire.tst_info.policy == x509.ObjectIdentifier(ts.SIGSTORE_TIMESTAMP_POLICY)
    assert wire.tst_info.gen_time == datetime(2025, 3, 1, 12, tzinfo=UTC)
    assert wire.tst_info.message_imprint.message == hashlib.sha256(data).digest()
    assert len(wire.signed_data.signer_infos) == 1
    assert len(wire.signed_data.certificates) == 1
    (signer_info,) = wire.signed_data.signer_infos
    embedded = x509.load_der_x509_certificate(next(iter(wire.signed_data.certificates)))
    assert embedded.issuer == signer_info.issuer
    assert embedded.serial_number == signer_info.serial_number
    # The decoder rejects trailing data on its own.
    with pytest.raises(ValueError, match="ExtraData"):
        decode_timestamp_response(response + b"\x00")
    # On a rejected response the token accessors raise, which is why the status is read from the DER first.
    rejected, _ = fixture_inputs(vector("rfc3161", "status-rejected"))
    rejected_wire = decode_timestamp_response(rejected)
    assert rejected_wire.status == 2
    with pytest.raises(ValueError, match="SignedData"):
        _ = rejected_wire.tst_info
    # The library's verifier rejects a tampered signature, a mismatched imprint and a non-critical EKU on its own.
    for fixture_id in ("tampered-gentime", "imprint-mismatch", "eku-not-critical", "no-eku", "signer-expired"):
        fixture = vector("rfc3161", fixture_id)
        response, data = fixture_inputs(fixture)
        assert not library_verifies(fixture_root(fixture), response, data), fixture_id


def test_library_claims_every_handed_certificate_is_a_trust_anchor() -> None:
    """``rfc3161-client`` accepts a token whose signer chains only to an intermediate in the set it is given and
    never to the root: it treats every certificate it is handed as a trust anchor. The wrapper's own chain
    verification from the signer to the authority's root is therefore the load-bearing check. Should a release
    start enforcing the chain to a root, this test fails, and the wrapper's duplicate of that check can go."""
    world = World()
    life = timedelta(days=30)
    rogue_ca = pki.certificate(
        "rogue timestamp ca",
        pki.p256(),
        ca=True,
        key_usage=pki.CA_USAGE,
        not_before=world.now - life,
        not_after=world.now + life,
        serial=7,
    )
    rogue_signer = pki.certificate(
        "rogue timestamp signer",
        pki.p256(),
        rogue_ca,
        key_usage=pki.SIGNING_USAGE,
        eku=[ExtendedKeyUsageOID.TIME_STAMPING],
        eku_critical=True,
        not_before=world.now - life,
        not_after=world.now + life,
        serial=8,
    )
    data = b"timestamped"
    at = world.now - timedelta(hours=1)
    # The world's own signer is accepted by both the library and the wrapper.
    assert ts.verify_timestamp(world.trusted_root(), world.timestamp(data, at), data) == at
    assert library_verifies(world.trusted_root(), world.timestamp(data, at), data)
    # The rogue signer's token, under an authority whose chain names the rogue intermediate below the real root.
    world.tsa_leaf = rogue_signer
    response = world.timestamp(data, at)
    record = json.loads(world.trusted_root_json())
    record["timestampAuthorities"][0]["certChain"]["certificates"] = [
        {"rawBytes": b64(der)} for der in (rogue_signer.der, rogue_ca.der, world.tsa_root.der)
    ]
    root = parse_trusted_root(json.dumps(record).encode())
    (authority,) = root.timestamp_authorities
    assert issuer_name(authority.chain[1]) != subject_name(authority.root), "the intermediate chains to no root"
    assert library_verifies(root, response, data), "the library treats the handed intermediate as a trust anchor"
    with pytest.raises(X509Error, match="no verified path"):
        verify_chain(
            authority.chain[0], [authority.chain[1]], [authority.root], at, extended_key_usage=OID_EKU_TIME_STAMPING
        )
    with pytest.raises(ts.TimestampError, match="no trusted timestamp authority"):
        ts.verify_timestamp(root, response, data)


def test_authorities_are_tried_in_order_and_windows_apply() -> None:
    fixture = vector("rfc3161", "granted-p384-key-sha256-digest")
    response, data = fixture_inputs(fixture)
    root = fixture_root(fixture)
    # The signer is the second authority; the first fails and the second decides.
    assert ts.verify_timestamp(root, response, data) == datetime(2025, 3, 1, 12, tzinfo=UTC)
    only_first = dataclasses.replace(root, timestamp_authorities=root.timestamp_authorities[:1])
    with pytest.raises(ts.TimestampError, match="no trusted timestamp authority"):
        ts.verify_timestamp(only_first, response, data)
    none = dataclasses.replace(root, timestamp_authorities=())
    with pytest.raises(ts.TimestampError, match=r"no trusted timestamp authority authenticated the response$"):
        ts.verify_timestamp(none, response, data)
    # The window is inclusive at its edges.
    at = datetime(2025, 3, 1, 12, tzinfo=UTC)
    edged = dataclasses.replace(
        root,
        timestamp_authorities=tuple(
            dataclasses.replace(a, valid_for=dataclasses.replace(a.valid_for, start=at, end=at))
            for a in root.timestamp_authorities
        ),
    )
    assert ts.verify_timestamp(edged, response, data) == at


def test_timestamp_input_prefixes_the_domain_to_the_canonical_core() -> None:
    core = _json.strict_parse(b'{"b": 1, "a": [true, null]}')
    assert ts.timestamp_input(b"domain/v1\x00", core) == b'domain/v1\x00{"a":[true,null],"b":1}'


def test_production_timestamp_signer_is_the_embedded_authority_leaf() -> None:
    """The embedded trusted root's timestamp authority chain starts with a non-CA signing certificate."""
    from tinfoil.verifier._sigstore.trusted_root import embedded_trusted_root
    from tinfoil.verifier._x509.certificate import OID_EKU_TIME_STAMPING, basic_constraints, extended_key_usage

    (authority,) = embedded_trusted_root().timestamp_authorities
    leaf = authority.chain[0]
    constraints = basic_constraints(leaf)
    assert constraints is None or not constraints[0]
    assert extended_key_usage(leaf) == (OID_EKU_TIME_STAMPING,)
