"""Verification of key-signed bundles: approvals signed with a pinned ECDSA P-256 key and logged in Rekor v2.

Trust comes from the caller's key set, never from the bundle. Freshness
comes from a separate inner timestamp, so key-signed bundles carry no
observer timestamps; the Rekor receipt proves inclusion only.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil._v3.verifier._sigstore.bundle import Bundle, TlogEntry
from tinfoil._v3.verifier._sigstore.trusted_root import KeyedAuthority, TrustedRoot
from tinfoil._v3.verifier._x509.certificate import PublicKey

MAX_LOG_RECEIPTS = 8
HASHEDREKORD_KIND = "hashedrekord"
HASHEDREKORD_VERSION = "0.0.2"
CHECKPOINT_ORIGIN_SEPARATOR = "\n\n"
MAX_INCLUSION_PROOF_HASHES = 64


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


def key_hint(key: PublicKey) -> str:
    """The hint of a signing key: requires ECDSA P-256 with a point on the curve."""
    raise NotImplementedError


def pinned_keys(keys: Sequence[PublicKey]) -> tuple[PinnedKey, ...]:
    """Pin a key set: at least one key, each ECDSA P-256, no two with the same hint."""
    raise NotImplementedError


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
    raise NotImplementedError


def signature_timestamp(bundle: Bundle) -> bytes:
    """The one RFC 3161 timestamp of a certified bundle."""
    raise NotImplementedError


def verify_keyed_bundle(root: TrustedRoot, bundle: Bundle, keys: Sequence[PinnedKey], digest: bytes) -> str:
    """Verify a key-signed DSSE bundle and return the hint of the key that signed it.

    In order: the layout; the bundle's ``KeyMaterial`` hint names one of ``keys``; the
    DSSE signature verifies with that key over the PAE; the statement names
    ``digest`` as a subject; every log entry verifies with
    ``verify_log_entries``.
    """
    raise NotImplementedError


def verify_log_entries(root: TrustedRoot, bundle: Bundle, expected: HashedRekordBody) -> None:
    """Verify every transparency-log entry of a bundle.

    Each entry must name a trusted log, decode as a hashedrekord 0.0.2
    body equal to ``expected`` (digest, signature and verifier), carry a
    checkpoint that verifies under the log's key and names the log's
    origin, and prove inclusion of the body's leaf hash at its index in
    the checkpoint's tree. A log without an id, or an entry for an unknown
    log, is an error rather than a skip.
    """
    raise NotImplementedError


def verify_checkpoint(envelope: str, log: KeyedAuthority) -> Checkpoint:
    """Verify a signed note.

    The body is ``origin\\ntree_size\\nbase64(root_hash)\\n`` with optional
    extension lines; the signature section holds ``— <name> <base64(key_id
    || signature)>`` lines. Exactly one line must verify under ``log``'s
    key, named by the log's checkpoint key id (or its log id prefix when
    the log has none); other lines are ignored.
    """
    raise NotImplementedError


def verify_merkle_inclusion(leaf_hash: bytes, index: int, tree_size: int, hashes: Sequence[bytes], root: bytes) -> None:
    """Check an RFC 6962 inclusion proof: recomputes the root from the leaf hash and compares it to ``root``.

    Rejects an index at or beyond the tree size, a proof with the wrong
    number of hashes and more than MAX_INCLUSION_PROOF_HASHES hashes.
    """
    raise NotImplementedError


def promised_log_time(root: TrustedRoot, entries: Sequence[TlogEntry]) -> datetime | None:
    """The earliest integrated time among entries whose inclusion promise verifies under a trusted log.

    Rekor v1 receipts only; None when no entry carries a verifiable
    promise.
    """
    raise NotImplementedError


def verify_signature(key: PublicKey, signature: bytes, data: bytes) -> None:
    """Verify a signature with the hash that the key type implies (SHA-256 for P-256, SHA-384 for P-384, none for
    Ed25519)."""
    raise NotImplementedError
