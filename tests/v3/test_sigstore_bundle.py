"""The bundle decoder and the in-toto statement reader."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from pydantic import ValidationError
from sigstore_models.bundle.v1 import Bundle as WireBundle

from tests.v3 import pki
from tests.v3.vectors import vector
from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._sigstore import bundle as bm


def approval_bundle() -> dict[str, Any]:
    fixture = vector("approval-bundle", "happy")
    data: dict[str, Any] = json.loads(base64.b64decode(fixture["input"]["bundle_json_b64"]))
    return data


def provenance_bundle() -> dict[str, Any]:
    fixture = vector("provenance", "provenance-happy")
    document = json.loads(base64.b64decode(fixture["input"]["document_b64"]))
    for entry in document["collateral"]:
        if entry["format"] == "https://tinfoil.sh/collateral/sigstore-code/v1":
            data: dict[str, Any] = entry["data"]["sigstore_bundle"]
            return data
    raise AssertionError("fixture has no code bundle")


def parse(data: dict[str, Any]) -> bm.Bundle:
    return bm.parse_bundle(_json.strict_parse(json.dumps(data).encode()))


def test_key_signed_bundle_decodes() -> None:
    parsed = parse(approval_bundle())
    assert parsed.media_type == bm.BUNDLE_MEDIA_TYPE
    assert isinstance(parsed.material, bm.KeyMaterial)
    assert parsed.material.hint == "yPEY45L4AyvwxAIXkl0IHvxuyLYH7kJFWlv80PkLkUE="
    (entry,) = parsed.tlog_entries
    assert (entry.kind, entry.version, entry.log_index, entry.integrated_time) == ("hashedrekord", "0.0.2", 2, 0)
    assert entry.inclusion_promise is None
    assert entry.inclusion_proof is not None
    assert entry.inclusion_proof.tree_size == 5
    assert len(entry.inclusion_proof.hashes) == 3
    assert entry.inclusion_proof.checkpoint.startswith("rekor.tinfoil-conformance.test\n5\n")
    assert parsed.rfc3161_timestamps == ()
    assert parsed.envelope.payload_type == bm.IN_TOTO_PAYLOAD_TYPE
    assert parsed.envelope.signatures[0].keyid == ""


def test_certificate_signed_bundle_decodes() -> None:
    parsed = parse(provenance_bundle())
    assert isinstance(parsed.material, bm.CertificateMaterial)
    (entry,) = parsed.tlog_entries
    assert (entry.kind, entry.version) == ("dsse", "0.0.1")
    assert entry.integrated_time == 1735689601
    assert entry.inclusion_promise is not None
    assert entry.inclusion_proof is not None
    assert entry.inclusion_proof.hashes == ()


def test_parse_bundle_bytes_bounds_the_size() -> None:
    data = json.dumps(approval_bundle()).encode()
    assert isinstance(bm.parse_bundle_bytes(data).material, bm.KeyMaterial)
    with pytest.raises(bm.BundleError, match="outside allowed bounds"):
        bm.parse_bundle_bytes(b"")
    with pytest.raises(bm.BundleError, match="outside allowed bounds"):
        bm.parse_bundle_bytes(b" " * (bm.MAX_BUNDLE_SIZE + 1))
    with pytest.raises(bm.BundleError, match=f"exceeds {bm.MAX_BUNDLE_SIZE}"):
        bm.bundle_bytes(_json.JsonObject({"pad": "x" * bm.MAX_BUNDLE_SIZE}))
    with pytest.raises(bm.BundleError, match="is null"):
        bm.parse_bundle(None)


def mutated(change: Any) -> dict[str, Any]:
    data = approval_bundle()
    change(data)
    return data


def test_rejections_of_the_layout() -> None:
    cases: list[tuple[Any, str]] = [
        (
            lambda d: d.update(mediaType="application/vnd.dev.sigstore.bundle+json;version=0.2"),
            "unsupported bundle media type",
        ),
        (lambda d: d.update(messageSignature={"signature": "AQ=="}), "does not match the schema"),
        (lambda d: d.pop("dsseEnvelope"), "does not match the schema"),
        (
            lambda d: d["verificationMaterial"].update(x509CertificateChain={"certificates": [{"rawBytes": "AQ=="}]}),
            "does not match the schema",
        ),
        (
            lambda d: d["dsseEnvelope"]["signatures"].append(d["dsseEnvelope"]["signatures"][0]),
            "exactly one signature, got 2",
        ),
        (lambda d: d["dsseEnvelope"].update(signatures=[]), "exactly one signature, got 0"),
        (lambda d: d["dsseEnvelope"]["signatures"][0].update(sig=""), "DSSE signature is empty"),
        (lambda d: d["dsseEnvelope"]["signatures"][0].update(keyid="other"), "DSSE key ID disagrees"),
        (lambda d: d["dsseEnvelope"].update(payload=""), "no payload"),
        (lambda d: d["dsseEnvelope"].update(payloadType=""), "no payload type"),
        (lambda d: d["verificationMaterial"]["publicKey"].update(hint=""), "expected a signing certificate or"),
        (lambda d: d["verificationMaterial"]["tlogEntries"][0].update(extra=1), "does not match the schema"),
        (lambda d: d["verificationMaterial"]["tlogEntries"][0].update(log_index="2"), "not the JSON field name"),
        (lambda d: d["verificationMaterial"]["tlogEntries"][0].update(logIndex=2), "does not match the schema"),
        (lambda d: d["verificationMaterial"]["tlogEntries"][0].update(logIndex="-1"), "does not match the schema"),
        (lambda d: d["verificationMaterial"]["tlogEntries"][0]["logId"].update(keyId="AQ=="), "not 32 bytes"),
        (lambda d: d["verificationMaterial"]["tlogEntries"][0]["kindVersion"].update(kind=""), "no kind and version"),
        (lambda d: d["verificationMaterial"]["tlogEntries"][0].update(canonicalizedBody=""), "has no body"),
        (
            lambda d: d["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"].update(envelope=""),
            "no checkpoint",
        ),
        (
            lambda d: d["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"].append(123),
            "does not match the schema",
        ),
        (
            lambda d: d["verificationMaterial"].update(
                timestampVerificationData={"rfc3161Timestamps": [{"signedTimestamp": ""}]}
            ),
            "timestamp is empty",
        ),
        (
            lambda d: d["dsseEnvelope"]["signatures"][0].update(sig=d["dsseEnvelope"]["signatures"][0]["sig"][:-1]),
            "does not match the schema",
        ),
        (
            lambda d: d["dsseEnvelope"]["signatures"][0].update(
                sig=d["dsseEnvelope"]["signatures"][0]["sig"][:-1] + "="
            ),
            "base64",
        ),
        (
            lambda d: d["dsseEnvelope"].update(
                payload=d["dsseEnvelope"]["payload"][:4] + " " + d["dsseEnvelope"]["payload"][4:]
            ),
            "base64",
        ),
    ]
    for change, message in cases:
        with pytest.raises(bm.BundleError, match=message):
            parse(mutated(change))


def test_keyid_equal_to_the_hint_passes_the_decoder() -> None:
    data = approval_bundle()
    data["dsseEnvelope"]["signatures"][0]["keyid"] = data["verificationMaterial"]["publicKey"]["hint"]
    assert parse(data).envelope.signatures[0].keyid == data["verificationMaterial"]["publicKey"]["hint"]


def test_certificate_material_rules() -> None:
    data = provenance_bundle()
    raw = data["verificationMaterial"]["certificate"]["rawBytes"]
    data["verificationMaterial"]["certificate"]["rawBytes"] = base64.b64encode(
        b"\x00" * (bm.MAX_CERTIFICATE_SIZE + 1)
    ).decode()
    with pytest.raises(bm.BundleError, match="invalid signing certificate size"):
        parse(data)
    data["verificationMaterial"]["certificate"]["rawBytes"] = raw
    data["dsseEnvelope"]["signatures"][0]["keyid"] = "k"
    with pytest.raises(bm.BundleError, match="DSSE key ID disagrees"):
        parse(data)
    # A certificate and a key hint together violate the one-of.
    data = provenance_bundle()
    data["verificationMaterial"]["publicKey"] = {"hint": "k"}
    with pytest.raises(bm.BundleError, match="does not match the schema"):
        parse(data)


def test_library_claims_about_the_wire_shape() -> None:
    """The decoder relies on sigstore_models for the shape gate; what it is looser about is handled locally."""
    data = approval_bundle()
    data["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["extra"] = 1
    with pytest.raises(ValidationError):
        WireBundle.model_validate_json(json.dumps(data))
    # 64-bit integers must be strings: a number is rejected by the library (protobuf JSON would accept it).
    data = approval_bundle()
    data["verificationMaterial"]["tlogEntries"][0]["logIndex"] = 2
    with pytest.raises(ValidationError):
        WireBundle.model_validate_json(json.dumps(data))
    # The library accepts the proto field names and non-canonical base64; the decoder does not.
    data = approval_bundle()
    data["verificationMaterial"]["tlogEntries"][0]["log_index"] = data["verificationMaterial"]["tlogEntries"][0].pop(
        "logIndex"
    )
    WireBundle.model_validate_json(json.dumps(data))
    data = approval_bundle()
    payload = data["dsseEnvelope"]["payload"]
    data["dsseEnvelope"]["payload"] = payload[:4] + " " + payload[4:]  # skipped by a lenient decoder
    WireBundle.model_validate_json(json.dumps(data))
    with pytest.raises(bm.BundleError, match="base64"):
        parse(data)
    data["dsseEnvelope"]["payload"] = payload[:-1]  # unpadded: the library rejects this one itself
    with pytest.raises(ValidationError):
        WireBundle.model_validate_json(json.dumps(data))


# --- statements --------------------------------------------------------------

_STATEMENT = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "artifact", "digest": {"sha256": "AB" * 32, "sha512": "cd" * 64}}],
    "predicateType": "https://example.test/predicate/v1",
    "predicate": {"approved": True, "n": 1.50, "nested": {"z": [1, 2]}},
}


def statement_bytes(data: dict[str, Any], **dumps: Any) -> bytes:
    return json.dumps(data, **dumps).encode()


def test_parse_statement_reads_the_parts() -> None:
    parsed = bm.parse_statement(statement_bytes(_STATEMENT))
    assert parsed.type == bm.IN_TOTO_STATEMENT_V1
    assert parsed.predicate_type == "https://example.test/predicate/v1"
    (subject,) = parsed.subjects
    assert subject.name == "artifact"
    assert subject.digest["sha256"] == "ab" * 32  # normalized to lowercase
    with pytest.raises(TypeError):
        subject.digest["x"] = "y"  # type: ignore[index]
    assert parsed.predicate == json.dumps(_STATEMENT["predicate"]).encode()


def test_parse_statement_keeps_the_predicate_bytes_exactly() -> None:
    text = '{"predicate" : {"n": 1.50 ,"s":"\\u00e9\\n"} , "_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"00"}}],"predicateType":"t"}'
    parsed = bm.parse_statement(text.encode())
    assert parsed.predicate == b'{"n": 1.50 ,"s":"\\u00e9\\n"}'
    spaced = statement_bytes(_STATEMENT, indent=2)
    assert (
        bm.parse_statement(spaced).predicate
        == json.dumps(_STATEMENT["predicate"], indent=2).replace("\n", "\n  ").encode()
    )


def test_parse_statement_rejections() -> None:
    cases: list[tuple[dict[str, Any], str]] = [
        ({**_STATEMENT, "extra": 1}, "unknown object member"),
        ({**_STATEMENT, "_type": "https://in-toto.io/Statement/v0.1"}, "unsupported in-toto statement type"),
        ({**_STATEMENT, "subject": []}, "has no subject"),
        ({**_STATEMENT, "subject": [None]}, "subject 0 is null"),
        ({**_STATEMENT, "subject": [{"name": "a", "digest": {"sha256": "abc"}}]}, "is not hex"),
        ({**_STATEMENT, "subject": [{"name": "a", "digest": {"sha256": "zz"}}]}, "is not hex"),
        ({**_STATEMENT, "subject": [{"name": "a", "digest": {"sha256": None}}]}, "is not a string"),
        ({**_STATEMENT, "subject": [{"name": "a", "digest": {"sha256": "00"}, "extra": 1}]}, "unknown object member"),
        ({**_STATEMENT, "subject": "artifact"}, "cannot unmarshal"),
        ({**_STATEMENT, "predicate": []}, "predicate must be an object"),
        ({**_STATEMENT, "predicate": None}, "predicate must be an object"),
        ({k: v for k, v in _STATEMENT.items() if k != "predicate"}, "predicate must be an object"),
        ({**_STATEMENT, "subject": [{"name": "a", "digest": {}}] * (bm.MAX_SUBJECTS + 1)}, "too many subjects"),
        (
            {
                **_STATEMENT,
                "subject": [{"name": "a", "digest": {f"alg{i}": "00" for i in range(bm.MAX_SUBJECT_DIGESTS + 1)}}],
            },
            "too many digests",
        ),
    ]
    for data, message in cases:
        with pytest.raises(bm.BundleError, match=message):
            bm.parse_statement(statement_bytes(data))
    with pytest.raises(bm.BundleError, match="outside allowed bounds"):
        bm.parse_statement(b"")
    with pytest.raises(bm.BundleError, match="outside allowed bounds"):
        bm.parse_statement(b"{" + b" " * bm.MAX_STATEMENT_SIZE + b"}")
    with pytest.raises(bm.BundleError, match="statement is null"):
        bm.parse_statement(b"null")
    with pytest.raises(bm.BundleError, match="parsing in-toto statement"):
        bm.parse_statement(b'{"_type": 1, "_type": 2}')


def test_pre_auth_encoding_and_reference() -> None:
    assert bm.pre_auth_encoding("t", b"abc") == b"DSSEv1 1 t 3 abc"
    assert bm.pre_auth_encoding("é", b"") == b"DSSEv1 2 \xc3\xa9 0 "
    pae = b"DSSEv1 28 application/vnd.in-toto+json 3 abc"
    assert bm.endorsement_reference(b"abc") == "sha256:" + hashlib.sha256(pae).hexdigest()


def test_key_hint_of_requires_p256() -> None:
    key = pki.p256()
    assert bm.key_hint_of(key.public_key()) == base64.b64encode(hashlib.sha256(pki.spki(key)).digest()).decode()
    with pytest.raises(bm.BundleError, match="ECDSA P-256"):
        bm.key_hint_of(pki.p384().public_key())
