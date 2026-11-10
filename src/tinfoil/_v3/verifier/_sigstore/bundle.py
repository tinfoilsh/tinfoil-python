"""The Sigstore bundle wire format (v0.3) and the shape checks that every bundle passes before verification.

A bundle is decoded from the parsed JSON that the document carries. The
decoder is strict: unknown members reject, the media type must be v0.3,
the content must be a DSSE envelope with exactly one signature, and the
legacy ``x509CertificateChain`` layout is refused.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypeAlias

from tinfoil._v3.verifier import _json

BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
DIGEST_ALGORITHM = "sha256"

MAX_BUNDLE_SIZE = 4 << 20
MAX_STATEMENT_SIZE = 128 << 10
MAX_TIMESTAMP_SIZE = 64 << 10
MAX_CERTIFICATE_SIZE = 16 << 10


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
    raise NotImplementedError


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
    raise NotImplementedError


def parse_bundle_bytes(data: bytes) -> Bundle:
    """``parse_bundle`` over bytes, with the size bound checked first."""
    raise NotImplementedError


def parse_statement(payload: bytes) -> Statement:
    """Decode the DSSE payload as an in-toto v1 statement.

    Requires a size within MAX_STATEMENT_SIZE, the v1 statement type, a
    non-empty subject list whose entries each carry a name and a digest
    map, a predicate type and an object predicate; unknown members at the
    statement level reject, and a null subject rejects.
    """
    raise NotImplementedError


def pre_auth_encoding(payload_type: str, payload: bytes) -> bytes:
    """The DSSE PAE: ``DSSEv1 <len> <type> <len> <payload>``."""
    raise NotImplementedError


def endorsement_reference(payload: bytes) -> str:
    """``sha256:`` plus the hex SHA-256 of the in-toto PAE of ``payload``: the identity of a signed statement."""
    raise NotImplementedError
