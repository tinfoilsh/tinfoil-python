"""Verification of key-signed bundles: approvals signed with a pinned ECDSA P-256 key and logged in Rekor v2.

Trust comes from the caller's key set, never from the bundle. Freshness
comes from a separate inner timestamp, so key-signed bundles carry no
observer timestamps; the Rekor receipt proves inclusion only.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tinfoil._v3.verifier import _canonical, _json
from tinfoil._v3.verifier._sigstore import _wire
from tinfoil._v3.verifier._sigstore.bundle import (
    IN_TOTO_PAYLOAD_TYPE,
    MAX_TIMESTAMP_SIZE,
    Bundle,
    BundleError,
    CertificateMaterial,
    KeyMaterial,
    TlogEntry,
    key_hint_of,
    parse_statement,
    pre_auth_encoding,
)
from tinfoil._v3.verifier._sigstore.trusted_root import KeyedAuthority, TrustedRoot
from tinfoil._v3.verifier._x509 import der
from tinfoil._v3.verifier._x509.certificate import PublicKey, public_key_spki

MAX_LOG_RECEIPTS = 8
HASHEDREKORD_KIND = "hashedrekord"
HASHEDREKORD_VERSION = "0.0.2"
CHECKPOINT_ORIGIN_SEPARATOR = "\n\n"
MAX_INCLUSION_PROOF_HASHES = 64
MAX_NOTE_SIGNATURES = 100
HASH_ALGORITHM_SHA2_256 = "SHA2_256"
HASH_ALGORITHM_SHA2_384 = "SHA2_384"
DIGEST_SIZE = 32

_HASH_ALGORITHM_OF_KEY = {
    _wire.KEY_DETAILS_P256: (HASH_ALGORITHM_SHA2_256, 32),
    _wire.KEY_DETAILS_P384: (HASH_ALGORITHM_SHA2_384, 48),
}
"""The hash that each signing key type implies, as the log labels it, with its digest size."""

_SIGNATURE_PREFIX = "— "
_NOTE_NAME = re.compile(r"\A[^\s+]+\Z")
_DECIMAL = re.compile(r"\A[0-9]+\Z")
_V1_ORIGIN_SUFFIX = re.compile(r" - [0-9]+\Z")
"""Matched from the end of the origin: a Rekor v1 tree head names ``<origin> - <tree id>``."""
_MAX_UINT64 = (1 << 64) - 1
_ED25519_NOTE_ALGORITHM = b"\x01"


class KeyedBundleError(ValueError):
    """A key-signed bundle that does not verify."""


@dataclass(frozen=True, slots=True)
class PinnedKey:
    """A caller-trusted signing key with the hint that bundles name it by."""

    hint: str
    """Standard base64 of SHA-256 over the DER SubjectPublicKeyInfo."""
    key: ec.EllipticCurvePublicKey
    spki: bytes


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A verified signed note from a transparency log."""

    origin: str
    tree_size: int
    root_hash: bytes
    key_id: bytes
    """The 4-byte key hint of the signature line that verified."""


@dataclass(frozen=True, slots=True)
class HashedRekordBody:
    """The parts of a hashedrekord 0.0.2 entry body that bind it to a bundle."""

    digest: bytes
    signature: bytes
    verifier: bytes
    """The signer's SPKI or certificate DER, whichever the entry carries."""
    verifier_kind: Literal["publicKey", "x509Certificate"]
    """Which member of the body's verifier carries ``verifier``."""
    key_details: str = _wire.KEY_DETAILS_P256
    """The signer's key algorithm as the log names it; ``digest`` uses the hash that it implies."""


def key_hint(key: PublicKey) -> str:
    """The hint of a signing key: requires ECDSA P-256 with a point on the curve."""
    try:
        return key_hint_of(key)
    except BundleError as err:
        raise KeyedBundleError(str(err)) from err


def pinned_keys(keys: Sequence[PublicKey]) -> tuple[PinnedKey, ...]:
    """Pin a key set: at least one key, each ECDSA P-256, no two with the same hint."""
    if not keys:
        raise KeyedBundleError("at least one independently trusted signing key is required")
    out: list[PinnedKey] = []
    seen: set[str] = set()
    for key in keys:
        hint = key_hint(key)
        if hint in seen:
            raise KeyedBundleError(f"duplicate signing key {hint}")
        seen.add(hint)
        if not isinstance(key, ec.EllipticCurvePublicKey):  # key_hint already requires it; this narrows the type
            raise KeyedBundleError("approval requires an ECDSA P-256 key")
        out.append(PinnedKey(hint=hint, key=key, spki=public_key_spki(key)))
    return tuple(out)


def check_layout(bundle: Bundle, *, timestamps: Literal["none", "one"]) -> None:
    """Check the approval bundle layout.

    Requires the in-toto payload type, exactly one DSSE signature, the
    material that the caller expects (``KeyMaterial`` for a key-signed
    bundle, ``CertificateMaterial`` for a certified one), between one and MAX_LOG_RECEIPTS log entries that
    are each hashedrekord 0.0.2 with an inclusion proof, no integrated
    time and no inclusion promise, and the number of RFC 3161 timestamps
    that ``timestamps`` says: none for a key-signed bundle, exactly one
    bounded by MAX_TIMESTAMP_SIZE for a certified one.
    """
    if bundle.envelope.payload_type != IN_TOTO_PAYLOAD_TYPE:
        raise KeyedBundleError(f"unsupported DSSE payload type {bundle.envelope.payload_type!r}")
    if len(bundle.envelope.signatures) != 1:
        raise KeyedBundleError("approval requires exactly one signature")
    if timestamps == "none" and not isinstance(bundle.material, KeyMaterial):
        raise KeyedBundleError("approval bundle must carry a key hint, not a certificate")
    if timestamps == "one" and not isinstance(bundle.material, CertificateMaterial):
        raise KeyedBundleError("certified approval bundle must carry a signing certificate")
    entries = bundle.tlog_entries
    if not 1 <= len(entries) <= MAX_LOG_RECEIPTS:
        raise KeyedBundleError(f"approval requires between 1 and {MAX_LOG_RECEIPTS} transparency log entries")
    seen: set[tuple[bytes, int]] = set()
    for index, entry in enumerate(entries):
        if entry.kind != HASHEDREKORD_KIND or entry.version != HASHEDREKORD_VERSION:
            raise KeyedBundleError(
                f"transparency log entry {index} is {entry.kind} {entry.version}, "
                f"not {HASHEDREKORD_KIND} {HASHEDREKORD_VERSION}"
            )
        if entry.integrated_time:
            raise KeyedBundleError(f"transparency log entry {index} carries an integration time")
        if entry.inclusion_promise is not None:
            raise KeyedBundleError(f"transparency log entry {index} carries an inclusion promise")
        if entry.inclusion_proof is None:
            raise KeyedBundleError(f"transparency log entry {index} has no inclusion proof")
        identity = (entry.log_id, entry.log_index)
        if identity in seen:
            raise KeyedBundleError(f"transparency log entry {index} duplicates an earlier entry")
        seen.add(identity)
    if timestamps == "none":
        if bundle.rfc3161_timestamps:
            raise KeyedBundleError("signed bundle cannot contain observer timestamps")
    else:
        signature_timestamp(bundle)


def signature_timestamp(bundle: Bundle) -> bytes:
    """The one RFC 3161 timestamp of a certified bundle."""
    timestamps = bundle.rfc3161_timestamps
    if len(timestamps) != 1 or not 0 < len(timestamps[0]) <= MAX_TIMESTAMP_SIZE:
        raise KeyedBundleError("certified registry endorsement requires one bounded signature timestamp")
    return timestamps[0]


def verify_keyed_bundle(root: TrustedRoot, bundle: Bundle, keys: Sequence[PinnedKey], digest: bytes) -> str:
    """Verify a key-signed DSSE bundle and return the hint of the key that signed it.

    In order: the layout; the bundle's ``KeyMaterial`` hint names one of ``keys``; the
    DSSE signature verifies with that key over the PAE; the statement names
    ``digest`` as a subject; every log entry verifies with
    ``verify_log_entries``.
    """
    if not root.tlogs:
        raise KeyedBundleError("Rekor trust is required")
    if not keys:
        raise KeyedBundleError("at least one independently trusted signing key is required")
    if len(digest) != DIGEST_SIZE:
        raise KeyedBundleError("expected artifact digest is not SHA-256")
    check_layout(bundle, timestamps="none")
    material = bundle.material
    if not isinstance(material, KeyMaterial):  # check_layout already requires it; this narrows the type
        raise KeyedBundleError("approval bundle must carry a key hint, not a certificate")
    # The hint identifies the key; a DSSE key id, even one equal to the hint, never verifies.
    signature = bundle.envelope.signatures[0]
    if signature.keyid:
        raise KeyedBundleError("DSSE key id must be empty for a key-signed bundle")
    pinned = next((key for key in keys if key.hint == material.hint), None)
    if pinned is None:
        raise KeyedBundleError("untrusted approval signing key")
    signed = pre_auth_encoding(bundle.envelope.payload_type, bundle.envelope.payload)
    try:
        verify_signature(pinned.key, signature.sig, signed)
    except KeyedBundleError as err:
        raise KeyedBundleError(f"DSSE signature does not verify under the pinned key: {err}") from err
    if not statement_names_digest(bundle.envelope.payload, digest):
        raise KeyedBundleError("the statement's subjects do not name the artifact digest")
    verify_log_entries(
        root,
        bundle,
        HashedRekordBody(
            digest=hashlib.sha256(signed).digest(),
            signature=signature.sig,
            verifier=pinned.spki,
            verifier_kind="publicKey",
        ),
    )
    return pinned.hint


def statement_names_digest(payload: bytes, digest: bytes) -> bool:
    """Whether some subject of the in-toto statement carries ``digest`` as its sha256 digest."""
    try:
        statement = parse_statement(payload)
    except BundleError as err:
        raise KeyedBundleError(str(err)) from err
    wanted = digest.hex()
    return any(subject.digest.get("sha256") == wanted for subject in statement.subjects)


def verify_log_entries(root: TrustedRoot, bundle: Bundle, expected: HashedRekordBody) -> None:
    """Verify every transparency-log entry of a bundle.

    Each entry must name a trusted log, decode as a hashedrekord 0.0.2
    body equal to ``expected`` (digest, signature and verifier), carry a
    checkpoint that verifies under the log's key and names the log's
    origin, and prove inclusion of the body's leaf hash at its index in
    the checkpoint's tree. A log without an id, or an entry for an unknown
    log, is an error rather than a skip.
    """
    for index, entry in enumerate(bundle.tlog_entries):
        try:
            _verify_entry(root, entry, expected)
        except KeyedBundleError as err:
            raise KeyedBundleError(f"transparency log entry {index}: {err}") from err


def _verify_entry(root: TrustedRoot, entry: TlogEntry, expected: HashedRekordBody) -> None:
    if entry.kind != HASHEDREKORD_KIND or entry.version != HASHEDREKORD_VERSION:
        raise KeyedBundleError(f"is {entry.kind} {entry.version}, not {HASHEDREKORD_KIND} {HASHEDREKORD_VERSION}")
    if entry.canonicalized_body != hashedrekord_body(expected):
        raise KeyedBundleError("body is not the hashedrekord record of this envelope and signer")
    proof = entry.inclusion_proof
    if proof is None:
        raise KeyedBundleError("no inclusion proof")
    if proof.log_index != entry.log_index:
        raise KeyedBundleError("inclusion proof index differs from the entry index")
    log = root.tlog(entry.log_id)
    if log is None:
        raise KeyedBundleError("names a transparency log the trusted root does not list")
    checkpoint = verify_checkpoint(proof.checkpoint, log)
    if checkpoint.tree_size != proof.tree_size or checkpoint.root_hash != proof.root_hash:
        raise KeyedBundleError("inclusion proof does not state the checkpoint's tree size and root hash")
    verify_merkle_inclusion(
        leaf_hash(entry.canonicalized_body), entry.log_index, checkpoint.tree_size, proof.hashes, checkpoint.root_hash
    )


def hashedrekord_body(expected: HashedRekordBody) -> bytes:
    """The canonical hashedrekord 0.0.2 entry body for ``expected``, as the log serializes it.

    The body's data algorithm is not chosen by the submitter: the log
    derives it from the verifier's key details (SHA2_256 for P-256,
    SHA2_384 for P-384) and requires the digest to be that hash's size, so
    the reconstruction does the same.
    """
    if expected.key_details not in _HASH_ALGORITHM_OF_KEY:
        raise KeyedBundleError(f"hashedrekord entries do not support key type {expected.key_details!r}")
    algorithm, size = _HASH_ALGORITHM_OF_KEY[expected.key_details]
    if len(expected.digest) != size:
        raise KeyedBundleError(f"digest length {len(expected.digest)} is not {size} bytes for {algorithm}")
    verifier = _json.JsonObject(
        {
            expected.verifier_kind: _json.JsonObject({"rawBytes": _base64(expected.verifier)}),
            "keyDetails": expected.key_details,
        }
    )
    record = _json.JsonObject(
        {
            "apiVersion": HASHEDREKORD_VERSION,
            "kind": HASHEDREKORD_KIND,
            "spec": _json.JsonObject(
                {
                    "hashedRekordV002": _json.JsonObject(
                        {
                            "data": _json.JsonObject({"algorithm": algorithm, "digest": _base64(expected.digest)}),
                            "signature": _json.JsonObject(
                                {"content": _base64(expected.signature), "verifier": verifier}
                            ),
                        }
                    )
                }
            ),
        }
    )
    return _json.canonicalize(record)


def leaf_hash(body: bytes) -> bytes:
    """The RFC 6962 leaf hash of an entry body."""
    return hashlib.sha256(b"\x00" + body).digest()


def verify_checkpoint(envelope: str, log: KeyedAuthority) -> Checkpoint:
    """Verify a signed note.

    The body is ``origin\\ntree_size\\nbase64(root_hash)\\n`` with optional
    extension lines; the signature section holds ``— <name> <base64(key_id
    || signature)>`` lines. Exactly one line must verify under ``log``'s
    key, named by the log's origin (the host of its base URL) and keyed by
    the log key's note hint, which the trusted root's checkpoint key id
    must agree with when it states one; other lines are ignored. The
    stated origin must be the log's origin, or that origin followed by a
    tree id for a Rekor v1 tree head.
    """
    for ch in envelope:
        code = ord(ch)
        if (code < 0x20 and code != 0x0A) or code == 0x7F:
            raise KeyedBundleError("checkpoint contains a control character")
    split = envelope.rfind(CHECKPOINT_ORIGIN_SEPARATOR)
    if split < 0:
        raise KeyedBundleError("checkpoint has no signature section")
    text, section = envelope[: split + 1], envelope[split + 2 :]
    if not section or not section.endswith("\n"):
        raise KeyedBundleError("checkpoint signature section is malformed")
    lines = section[:-1].split("\n")
    if len(lines) > MAX_NOTE_SIGNATURES:
        raise KeyedBundleError("checkpoint has too many signatures")

    origin = log_origin(log)
    hint = note_key_hint(log, origin)
    verified = False
    for line in lines:
        if not line.startswith(_SIGNATURE_PREFIX):
            raise KeyedBundleError("checkpoint signature line is malformed")
        name, _, encoded = line[len(_SIGNATURE_PREFIX) :].partition(" ")
        if _NOTE_NAME.match(name) is None or not encoded:
            raise KeyedBundleError("checkpoint signature line is malformed")
        try:
            signature = _canonical.decode_base64("checkpoint signature", encoded)
        except _canonical.EncodingError as err:
            raise KeyedBundleError("checkpoint signature line is malformed") from err
        if len(signature) < 5:
            raise KeyedBundleError("checkpoint signature line is malformed")
        if name != origin or signature[:4] != hint or verified:
            continue
        try:
            verify_signature(log.public_key, signature[4:], text.encode("utf-8"))
        except KeyedBundleError as err:
            raise KeyedBundleError(f"checkpoint signature does not verify under the log key: {err}") from err
        verified = True
    if not verified:
        raise KeyedBundleError("checkpoint is not signed by the log")

    parts = text.split("\n")
    if len(parts) < 4:
        raise KeyedBundleError("checkpoint has too few lines")
    stated, size_text, hash_text = parts[0], parts[1], parts[2]
    if not stated:
        raise KeyedBundleError("checkpoint has an empty origin")
    if stated != origin and not (stated.startswith(origin) and _V1_ORIGIN_SUFFIX.match(stated, len(origin))):
        raise KeyedBundleError(f"checkpoint origin {stated!r} is not the log's {origin!r}")
    if _DECIMAL.match(size_text) is None or int(size_text) > _MAX_UINT64:
        raise KeyedBundleError("checkpoint tree size is not a 64-bit integer")
    try:
        root_hash = _canonical.decode_base64("checkpoint root hash", hash_text)
    except _canonical.EncodingError as err:
        raise KeyedBundleError(f"checkpoint root hash: {err}") from err
    if len(root_hash) != DIGEST_SIZE:
        raise KeyedBundleError("checkpoint root hash is not 32 bytes")
    return Checkpoint(origin=stated, tree_size=int(size_text), root_hash=root_hash, key_id=hint)


def log_origin(log: KeyedAuthority) -> str:
    """The host of the log's base URL: the name that its checkpoints are signed under."""
    url = log.base_url
    scheme, separator, rest = url.partition("://")
    if not separator or not scheme:
        raise KeyedBundleError(f"transparency log base URL {url!r} is not a URL")
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = _host_of(authority.rpartition("@")[2])
    if not host or _NOTE_NAME.match(host) is None:
        raise KeyedBundleError(f"transparency log base URL {url!r} has no usable host")
    return host


def _host_of(host_port: str) -> str:
    """The host of a ``host[:port]`` authority: a bracketed IPv6 literal keeps its brackets."""
    if host_port.startswith("["):
        end = host_port.find("]")
        return host_port[: end + 1] if end > 0 else ""
    return host_port.partition(":")[0]


def note_key_hint(log: KeyedAuthority, origin: str) -> bytes:
    """The 4-byte key hint a log's signature line carries.

    For an ECDSA key it is the leading bytes of SHA-256 over the DER
    SubjectPublicKeyInfo; for an Ed25519 key, the leading bytes of SHA-256
    over the origin, a newline, the byte 0x01 and the raw key. A checkpoint
    key id that the trusted root states must begin with the same bytes.
    """
    key = log.public_key
    if isinstance(key, ec.EllipticCurvePublicKey):
        hint = hashlib.sha256(public_key_spki(key)).digest()[:4]
    elif isinstance(key, ed25519.Ed25519PublicKey):
        raw = key.public_bytes_raw()
        hint = hashlib.sha256(origin.encode("utf-8") + b"\n" + _ED25519_NOTE_ALGORITHM + raw).digest()[:4]
    else:
        raise KeyedBundleError("unsupported transparency log key type")
    if log.checkpoint_key_id is not None and log.checkpoint_key_id[:4] != hint:
        raise KeyedBundleError("the trusted root's checkpoint key id does not match the log key")
    return hint


def verify_merkle_inclusion(leaf_hash: bytes, index: int, tree_size: int, hashes: Sequence[bytes], root: bytes) -> None:
    """Check an RFC 6962 inclusion proof: recomputes the root from the leaf hash and compares it to ``root``.

    Rejects an index at or beyond the tree size, a proof with the wrong
    number of hashes and more than MAX_INCLUSION_PROOF_HASHES hashes.
    """
    if index < 0 or index >= tree_size:
        raise KeyedBundleError(f"inclusion proof index {index} is outside a tree of {tree_size} leaves")
    if len(leaf_hash) != DIGEST_SIZE:
        raise KeyedBundleError("inclusion proof leaf hash is not 32 bytes")
    if len(hashes) > MAX_INCLUSION_PROOF_HASHES:
        raise KeyedBundleError(f"inclusion proof has more than {MAX_INCLUSION_PROOF_HASHES} hashes")
    inner = (index ^ (tree_size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    if len(hashes) != inner + border:
        raise KeyedBundleError(f"inclusion proof has {len(hashes)} hashes, expected {inner + border}")
    if any(len(h) != DIGEST_SIZE for h in hashes):
        raise KeyedBundleError("inclusion proof hash is not 32 bytes")
    node = leaf_hash
    for level in range(inner):
        sibling = hashes[level]
        node = _hash_children(sibling, node) if index >> level & 1 else _hash_children(node, sibling)
    for sibling in hashes[inner:]:
        node = _hash_children(sibling, node)
    if node != root:
        raise KeyedBundleError("inclusion proof does not reach the root hash")


def _hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def promised_log_time(root: TrustedRoot, entries: Sequence[TlogEntry]) -> datetime | None:
    """The earliest integrated time among entries whose inclusion promise verifies under a trusted log.

    Rekor v1 receipts only; None when no entry carries a verifiable
    promise. An entry with a promise from a log the root does not list, or
    whose promise does not verify, is an error rather than a skip.
    """
    earliest: datetime | None = None
    for index, entry in enumerate(entries):
        if entry.inclusion_promise is None:
            continue
        try:
            at = verify_inclusion_promise(root, entry)
        except KeyedBundleError as err:
            raise KeyedBundleError(f"transparency log entry {index}: {err}") from err
        if earliest is None or at < earliest:
            earliest = at
    return earliest


def verify_inclusion_promise(root: TrustedRoot, entry: TlogEntry) -> datetime:
    """Verify a Rekor v1 signed entry timestamp and return the integrated time that it attests.

    The signature covers the canonical JSON of the entry's body, integrated
    time, log id and index; the log must be listed in the root and its key
    valid at the integrated time.
    """
    if entry.inclusion_promise is None or not entry.integrated_time:
        raise KeyedBundleError("entry carries no inclusion promise with an integrated time")
    log = root.tlog(entry.log_id)
    if log is None:
        raise KeyedBundleError("names a transparency log the trusted root does not list")
    try:
        at = datetime.fromtimestamp(entry.integrated_time, UTC)
    except (OverflowError, OSError, ValueError) as err:
        raise KeyedBundleError("integrated time is not a representable time") from err
    if not log.valid_for.contains(at):
        raise KeyedBundleError("integrated time is outside the log key's validity")
    if not isinstance(log.public_key, ec.EllipticCurvePublicKey):
        raise KeyedBundleError("inclusion promises require an ECDSA log key")
    record = _json.JsonObject(
        {
            "body": _base64(entry.canonicalized_body),
            "integratedTime": _json.JsonNumber(str(entry.integrated_time)),
            "logID": entry.log_id.hex(),
            "logIndex": _json.JsonNumber(str(entry.log_index)),
        }
    )
    try:
        verify_signature(log.public_key, entry.inclusion_promise, _json.canonicalize(record))
    except KeyedBundleError as err:
        raise KeyedBundleError(f"inclusion promise does not verify under the log key: {err}") from err
    return at


def verify_signature(key: PublicKey, signature: bytes, data: bytes) -> None:
    """Verify a signature with the hash that the key type implies (SHA-256 for P-256, SHA-384 for P-384, none for
    Ed25519).

    An ECDSA signature must be minimal DER.
    """
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            algorithm: hashes.HashAlgorithm
            if isinstance(key.curve, ec.SECP256R1):
                size, algorithm = 32, hashes.SHA256()
            elif isinstance(key.curve, ec.SECP384R1):
                size, algorithm = 48, hashes.SHA384()
            else:
                raise KeyedBundleError(f"unsupported EC curve {key.curve.name}")
            if der.raw_signature_to_der(der.ecdsa_signature_to_raw(signature, size), size) != signature:
                raise KeyedBundleError("ECDSA signature is not minimal DER")
            key.verify(signature, data, ec.ECDSA(algorithm))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        else:
            raise KeyedBundleError(f"unsupported key type {type(key).__name__}")
    except InvalidSignature as err:
        raise KeyedBundleError("signature does not verify") from err
    except der.DerError as err:
        raise KeyedBundleError(f"malformed ECDSA signature: {err}") from err


def _base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
