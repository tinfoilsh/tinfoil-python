"""The Sigstore bundle wire format (v0.3) and the shape checks that every bundle passes before verification.

A bundle is decoded from the parsed JSON that the document carries. The
decoder is strict: ``sigstore_models`` validates the shape (unknown members
reject at every depth, the one-of rules hold), the strict JSON parser
supplies the values (one base64 form per byte string, 64-bit integers as
decimal strings), the media type must be v0.3, the content must be a DSSE
envelope with exactly one signature, and the legacy
``x509CertificateChain`` layout is refused.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeAlias

from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError
from sigstore_models.bundle.v1 import Bundle as WireBundle

from tinfoil._v3.verifier import _canonical, _json
from tinfoil._v3.verifier._sigstore import _wire
from tinfoil._v3.verifier._x509.certificate import PublicKey, X509Error, certificate_public_key, parse_certificate
from tinfoil._v3.verifier._x509.certificate import public_key_spki as _public_key_spki

BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
DIGEST_ALGORITHM = "sha256"

MAX_BUNDLE_SIZE = 4 << 20
MAX_STATEMENT_SIZE = 128 << 10
MAX_TIMESTAMP_SIZE = 64 << 10
MAX_CERTIFICATE_SIZE = 16 << 10
MAX_SUBJECTS = 1024
MAX_SUBJECT_DIGESTS = 32
LOG_ID_SIZE = 32

_JSON_WHITESPACE = " \t\n\r"


class BundleError(ValueError):
    """A bundle that fails to decode or violates the accepted layout."""


@dataclass(frozen=True, slots=True)
class InclusionProof:
    """A Merkle inclusion proof and the signed checkpoint that commits to the tree."""

    log_index: int
    root_hash: bytes
    tree_size: int
    hashes: tuple[bytes, ...]
    checkpoint: str
    """The signed note, as the log serialized it."""


@dataclass(frozen=True, slots=True)
class TlogEntry:
    """One transparency-log receipt."""

    log_index: int
    log_id: bytes
    kind: str
    version: str
    integrated_time: int
    """Seconds since the epoch; 0 for a Rekor v2 entry, which carries no integrated time."""
    inclusion_promise: bytes | None
    """The signed entry timestamp (Rekor v1), or None."""
    inclusion_proof: InclusionProof | None
    canonicalized_body: bytes


@dataclass(frozen=True, slots=True)
class DsseSignature:
    sig: bytes
    keyid: str


@dataclass(frozen=True, slots=True)
class DsseEnvelope:
    payload: bytes
    payload_type: str
    signatures: tuple[DsseSignature, ...]


@dataclass(frozen=True, slots=True)
class CertificateMaterial:
    """The verification material of a certificate-signed bundle."""

    certificate: bytes
    """The signing certificate's DER."""


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    """The verification material of a key-signed bundle."""

    hint: str
    """Names the pinned key; never empty."""


VerificationMaterial: TypeAlias = CertificateMaterial | KeyMaterial


@dataclass(frozen=True, slots=True)
class Bundle:
    """A decoded v0.3 bundle: one DSSE envelope plus its verification material."""

    media_type: str
    material: VerificationMaterial
    tlog_entries: tuple[TlogEntry, ...]
    rfc3161_timestamps: tuple[bytes, ...]
    """DER TimeStampResp tokens over the DSSE signature."""
    envelope: DsseEnvelope


@dataclass(frozen=True, slots=True)
class Subject:
    """One in-toto statement subject."""

    name: str
    digest: Mapping[str, str]
    """Algorithm to lowercase hex; a read-only view (``MappingProxyType``) built by ``parse_statement``."""


@dataclass(frozen=True, slots=True)
class Statement:
    """The parts of an in-toto statement that verification reads; the predicate stays as signed bytes."""

    type: str
    subjects: tuple[Subject, ...]
    predicate_type: str
    predicate: bytes
    """The predicate member exactly as it appears in the payload, so that a strict decoder can read it."""


def bundle_bytes(value: _json.JsonValue) -> bytes:
    """Serialize a parsed bundle back to bytes, rejecting one above MAX_BUNDLE_SIZE."""
    try:
        data = _json.serialize(value)
    except _json.JsonError as err:
        raise BundleError(f"bundle: {err}") from err
    if len(data) > MAX_BUNDLE_SIZE:
        raise BundleError(f"bundle exceeds {MAX_BUNDLE_SIZE} bytes")
    return data


def parse_bundle(value: _json.JsonValue) -> Bundle:
    """Decode a bundle from parsed JSON and check its layout.

    Rejects: a media type other than v0.3; a ``messageSignature`` content;
    the ``x509CertificateChain`` layout; an envelope without exactly one
    signature or with an empty one; a bundle with neither a certificate
    nor a non-empty key hint (the material is the certificate when one is
    present, else the hint); a certificate above MAX_CERTIFICATE_SIZE; a
    DSSE ``keyid`` that disagrees with the key hint; unknown members at any
    depth; base64 that is not canonical.
    """
    data = bundle_bytes(value)
    if value is None:
        raise BundleError("bundle is null")
    try:
        _wire.check_member_names(value)
        WireBundle.model_validate_json(data)
        return _bundle(_json.object_(value, "bundle"))
    except ValidationError as err:
        raise BundleError(f"bundle does not match the schema: {_wire.first_error(err)}") from err
    except (_json.JsonError, _canonical.EncodingError, _wire.WireError, X509Error) as err:
        raise BundleError(f"bundle: {err}") from err


def parse_bundle_bytes(data: bytes) -> Bundle:
    """``parse_bundle`` over bytes, with the size bound checked first."""
    if not data or len(data) > MAX_BUNDLE_SIZE:
        raise BundleError("bundle size is outside allowed bounds")
    try:
        value = _json.strict_parse(data)
    except _json.JsonError as err:
        raise BundleError(f"bundle: {err}") from err
    return parse_bundle(value)


def _bundle(bundle: _json.JsonObject) -> Bundle:
    media_type = _json.string(bundle, "mediaType")
    if media_type != BUNDLE_MEDIA_TYPE:
        raise BundleError(f"unsupported bundle media type {media_type!r}")
    if bundle.get("messageSignature") is not None:
        raise BundleError("bundle carries a message signature instead of a DSSE envelope")
    envelope_record = _json.opt_struct(bundle, "dsseEnvelope", ("payload", "payloadType", "signatures"))
    if envelope_record is None:
        raise BundleError("bundle has no DSSE envelope")
    envelope = _envelope(envelope_record)

    material_record = _json.struct(
        bundle,
        "verificationMaterial",
        ("publicKey", "x509CertificateChain", "certificate", "tlogEntries", "timestampVerificationData"),
    )
    if material_record.get("x509CertificateChain") is not None:
        raise BundleError(
            "legacy bundle format not supported: the x509CertificateChain layout requires the v0.3 "
            "single-certificate form"
        )
    certificate_record = _json.opt_struct(material_record, "certificate", ("rawBytes",))
    key_record = _json.opt_struct(material_record, "publicKey", ("hint",))
    material: VerificationMaterial
    hint = _json.string(key_record, "hint") if key_record is not None else ""
    if certificate_record is not None:
        certificate = _canonical.decode_base64("certificate rawBytes", _json.string(certificate_record, "rawBytes"))
        if not certificate or len(certificate) > MAX_CERTIFICATE_SIZE:
            raise BundleError("invalid signing certificate size")
        material = CertificateMaterial(certificate)
    elif hint:
        material = KeyMaterial(hint)
    else:
        raise BundleError("expected a signing certificate or an independently trusted public-key hint")

    keyid = envelope.signatures[0].keyid
    if keyid:
        expected = hint if isinstance(material, KeyMaterial) else _certificate_hint(material.certificate)
        if keyid != expected:
            raise BundleError("DSSE key ID disagrees with key hint")

    entries = tuple(
        _tlog_entry(_record(item, "tlogEntries", index))
        for index, item in enumerate(_json.array(material_record, "tlogEntries") or ())
    )
    timestamp_record = _json.struct(material_record, "timestampVerificationData", ("rfc3161Timestamps",))
    timestamps: list[bytes] = []
    for index, item in enumerate(_json.array(timestamp_record, "rfc3161Timestamps") or ()):
        record = _record(item, "rfc3161Timestamps", index)
        signed = _canonical.decode_base64("signedTimestamp", _json.string(record, "signedTimestamp"))
        if not signed:
            raise BundleError("bundle RFC 3161 timestamp is empty")
        timestamps.append(signed)
    return Bundle(
        media_type=media_type,
        material=material,
        tlog_entries=entries,
        rfc3161_timestamps=tuple(timestamps),
        envelope=envelope,
    )


def _record(item: _json.JsonValue, what: str, index: int) -> _json.JsonObject:
    if item is None:
        raise BundleError(f"bundle {what}[{index}] is null")
    return _json.object_(item, f"{what}[{index}]")


def _envelope(record: _json.JsonObject) -> DsseEnvelope:
    signatures = _json.array(record, "signatures") or ()
    if len(signatures) != 1:
        raise BundleError(f"DSSE envelope must have exactly one signature, got {len(signatures)}")
    signature_record = _record(signatures[0], "signatures", 0)
    sig = _canonical.decode_base64("sig", _json.string(signature_record, "sig"))
    if not sig:
        raise BundleError("DSSE signature is empty")
    payload_type = _json.string(record, "payloadType")
    if not payload_type:
        raise BundleError("DSSE envelope has no payload type")
    payload = _canonical.decode_base64("payload", _json.string(record, "payload"))
    if not payload:
        raise BundleError("DSSE envelope has no payload")
    return DsseEnvelope(
        payload=payload,
        payload_type=payload_type,
        signatures=(DsseSignature(sig=sig, keyid=_json.string(signature_record, "keyid")),),
    )


def _tlog_entry(record: _json.JsonObject) -> TlogEntry:
    log_id = _canonical.decode_base64("logId keyId", _json.string(_json.struct(record, "logId", ("keyId",)), "keyId"))
    if len(log_id) != LOG_ID_SIZE:
        raise BundleError(f"transparency log entry log id is not {LOG_ID_SIZE} bytes")
    kind_version = _json.struct(record, "kindVersion", ("kind", "version"))
    kind, version = _json.string(kind_version, "kind"), _json.string(kind_version, "version")
    if not kind or not version:
        raise BundleError("transparency log entry has no kind and version")
    body = _canonical.decode_base64("canonicalizedBody", _json.string(record, "canonicalizedBody"))
    if not body:
        raise BundleError("transparency log entry has no body")
    promise: bytes | None = None
    promise_record = _json.opt_struct(record, "inclusionPromise", ("signedEntryTimestamp",))
    if promise_record is not None:
        promise = _canonical.decode_base64("signedEntryTimestamp", _json.string(promise_record, "signedEntryTimestamp"))
        if not promise:
            raise BundleError("transparency log inclusion promise is empty")
    proof: InclusionProof | None = None
    proof_record = _json.opt_struct(
        record, "inclusionProof", ("logIndex", "rootHash", "treeSize", "hashes", "checkpoint")
    )
    if proof_record is not None:
        root_hash = _canonical.decode_base64("rootHash", _json.string(proof_record, "rootHash"))
        if not root_hash:
            raise BundleError("transparency log inclusion proof has no root hash")
        checkpoint = _json.string(_json.struct(proof_record, "checkpoint", ("envelope",)), "envelope")
        if not checkpoint:
            raise BundleError("transparency log inclusion proof has no checkpoint")
        hashes: list[bytes] = []
        for item in _json.array(proof_record, "hashes") or ():
            if not isinstance(item, str):
                raise BundleError("transparency log inclusion proof hash is not a string")
            hashes.append(_canonical.decode_base64("hashes", item))
        proof = InclusionProof(
            log_index=_wire.uint64(proof_record, "logIndex") or 0,
            root_hash=root_hash,
            tree_size=_wire.uint64(proof_record, "treeSize") or 0,
            hashes=tuple(hashes),
            checkpoint=checkpoint,
        )
    return TlogEntry(
        log_index=_wire.uint64(record, "logIndex") or 0,
        log_id=log_id,
        kind=kind,
        version=version,
        integrated_time=_wire.uint64(record, "integratedTime") or 0,
        inclusion_promise=promise,
        inclusion_proof=proof,
        canonicalized_body=body,
    )


def key_hint_of(key: PublicKey) -> str:
    """Standard base64 of SHA-256 over the DER SubjectPublicKeyInfo of an ECDSA P-256 key."""
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise BundleError("approval requires an ECDSA P-256 key")
    return base64.b64encode(hashlib.sha256(_public_key_spki(key)).digest()).decode("ascii")


def _certificate_hint(certificate: bytes) -> str:
    return key_hint_of(certificate_public_key(parse_certificate(certificate)))


def parse_statement(payload: bytes) -> Statement:
    """Decode the DSSE payload as an in-toto v1 statement.

    Requires a size within MAX_STATEMENT_SIZE, the v1 statement type, a
    non-empty subject list whose entries each carry a name and a digest
    map, a predicate type and an object predicate; unknown members at the
    statement level reject, and a null subject rejects. Each subject's
    digest map is wrapped in a ``MappingProxyType`` over a private dict, so
    the record is immutable.
    """
    if not payload or len(payload) > MAX_STATEMENT_SIZE:
        raise BundleError("statement size is outside allowed bounds")
    try:
        value = _json.strict_parse(payload)
        if value is None:
            raise BundleError("statement is null")
        statement = _json.object_(value, "statement", ("_type", "subject", "predicateType", "predicate"))
        statement_type = _json.string(statement, "_type")
        if statement_type != IN_TOTO_STATEMENT_V1:
            raise BundleError(f"unsupported in-toto statement type {statement_type!r}")
        subjects = _subjects(_json.array(statement, "subject") or ())
        predicate = statement.get("predicate")
        if not isinstance(predicate, _json.JsonObject):
            raise BundleError("statement predicate must be an object")
        return Statement(
            type=statement_type,
            subjects=subjects,
            predicate_type=_json.string(statement, "predicateType"),
            predicate=_member_span(payload.decode("utf-8"), "predicate"),
        )
    except _json.JsonError as err:
        raise BundleError(f"parsing in-toto statement: {err}") from err


def _subjects(items: tuple[_json.JsonValue, ...]) -> tuple[Subject, ...]:
    if not items:
        raise BundleError("in-toto statement has no subject")
    if len(items) > MAX_SUBJECTS:
        raise BundleError(f"too many subjects: {len(items)} > {MAX_SUBJECTS}")
    out: list[Subject] = []
    for index, item in enumerate(items):
        if item is None:
            raise BundleError(f"in-toto statement subject {index} is null")
        record = _json.object_(item, f"subject[{index}]", ("name", "digest"))
        digests = _json.mapping(record, "digest", functools.partial(_digest, index=index))
        if len(digests) > MAX_SUBJECT_DIGESTS:
            raise BundleError(f"too many digests in subject {index}: {len(digests)} > {MAX_SUBJECT_DIGESTS}")
        out.append(Subject(name=_json.string(record, "name"), digest=MappingProxyType(dict(digests))))
    return tuple(out)


def _digest(value: _json.JsonValue, algorithm: str, *, index: int) -> str:
    if not isinstance(value, str):
        raise BundleError(f"in-toto statement subject {index} digest {algorithm!r} is not a string")
    if len(value) % 2 or not all(ch in "0123456789abcdefABCDEF" for ch in value):
        raise BundleError(f"in-toto statement subject {index} digest {algorithm!r} is not hex")
    return value.lower()


def _member_span(text: str, key: str) -> bytes:
    """The bytes of the top-level member ``key`` in an object that the strict parser has already accepted."""
    decoder = json.JSONDecoder()
    index = _skip_whitespace(text, 0) + 1  # past the opening brace
    while True:
        index = _skip_whitespace(text, index)
        if text[index] == "}":
            raise BundleError(f"statement has no {key} member")
        name, index = decoder.raw_decode(text, index)
        index = _skip_whitespace(text, index) + 1  # past the colon
        start = _skip_whitespace(text, index)
        _, end = decoder.raw_decode(text, start)
        if name == key:
            return text[start:end].encode("utf-8")
        index = _skip_whitespace(text, end)
        if text[index] == ",":
            index += 1


def _skip_whitespace(text: str, index: int) -> int:
    while index < len(text) and text[index] in _JSON_WHITESPACE:
        index += 1
    return index


def pre_auth_encoding(payload_type: str, payload: bytes) -> bytes:
    """The DSSE PAE: ``DSSEv1 <len> <type> <len> <payload>``."""
    encoded_type = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(encoded_type), encoded_type, len(payload), payload)


def endorsement_reference(payload: bytes) -> str:
    """``sha256:`` plus the hex SHA-256 of the in-toto PAE of ``payload``: the identity of a signed statement."""
    return "sha256:" + hashlib.sha256(pre_auth_encoding(IN_TOTO_PAYLOAD_TYPE, payload)).hexdigest()
