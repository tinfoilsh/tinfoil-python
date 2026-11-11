"""Key-signed bundles: the 23 approval-bundle vectors through ``verify_keyed_bundle``, plus the pieces underneath
(key hints, checkpoints, Merkle inclusion, inclusion promises)."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tests import pki
from tests.vectors import document_bundles, vector, vector_params
from tinfoil.verifier._sigstore import _wire, keyed
from tinfoil.verifier._sigstore import bundle as bm
from tinfoil.verifier._sigstore.trusted_root import KeyedAuthority, TrustedRoot, ValidFor, parse_trusted_root
from tinfoil.verifier._x509 import der
from tinfoil.verifier._x509.certificate import load_public_key_pem, public_key_spki


def fixture_root(fixture: dict[str, Any]) -> TrustedRoot:
    return parse_trusted_root(base64.b64decode(fixture["input"]["sigstore_trusted_root_json_b64"]))


def fixture_bundle(fixture: dict[str, Any]) -> bm.Bundle:
    return bm.parse_bundle_bytes(base64.b64decode(fixture["input"]["bundle_json_b64"]))


def fixture_keys(fixture: dict[str, Any]) -> tuple[keyed.PinnedKey, ...]:
    return keyed.pinned_keys([load_public_key_pem(pem) for pem in fixture["input"]["signing_keys_pem"]])


@pytest.mark.parametrize("fixture", vector_params("approval-bundle"))
def test_approval_bundle_vectors(fixture: dict[str, Any]) -> None:
    """Every vector: the fixture's verdict, and on accept the hint of the key that verified."""
    expected = fixture["expected"]
    digest = bytes.fromhex(fixture["input"]["artifact_digest_hex"])
    if expected["accepted"]:
        hint = keyed.verify_keyed_bundle(fixture_root(fixture), fixture_bundle(fixture), fixture_keys(fixture), digest)
        assert hint == expected["signing_key_hint"]
    else:
        with pytest.raises((keyed.KeyedBundleError, bm.BundleError)):
            keyed.verify_keyed_bundle(fixture_root(fixture), fixture_bundle(fixture), fixture_keys(fixture), digest)


# --- keys --------------------------------------------------------------------


def test_key_hint_is_base64_sha256_of_the_spki() -> None:
    fixture = vector("approval-bundle", "happy")
    (first, second) = (load_public_key_pem(pem) for pem in fixture["input"]["signing_keys_pem"])
    assert keyed.key_hint(first) == fixture["expected"]["signing_key_hint"]
    assert keyed.key_hint(second) == vector("approval-bundle", "happy-second-key")["expected"]["signing_key_hint"]
    assert keyed.key_hint(first) == base64.b64encode(hashlib.sha256(public_key_spki(first)).digest()).decode()


def test_pinned_keys_rules() -> None:
    key = pki.p256().public_key()
    (pinned,) = keyed.pinned_keys([key])
    assert pinned.hint == keyed.key_hint(key)
    assert pinned.spki == public_key_spki(key)
    assert pinned.key is key
    with pytest.raises(keyed.KeyedBundleError, match="at least one"):
        keyed.pinned_keys([])
    with pytest.raises(keyed.KeyedBundleError, match="duplicate signing key"):
        keyed.pinned_keys([key, key])
    with pytest.raises(keyed.KeyedBundleError, match="ECDSA P-256"):
        keyed.pinned_keys([pki.p384().public_key()])
    with pytest.raises(keyed.KeyedBundleError, match="ECDSA P-256"):
        keyed.pinned_keys([pki.ed25519_key().public_key()])


# --- verify_keyed_bundle preconditions ----------------------------------------


def test_verify_keyed_bundle_requires_logs_keys_and_a_sha256_digest() -> None:
    fixture = vector("approval-bundle", "happy")
    root, bundle, keys = fixture_root(fixture), fixture_bundle(fixture), fixture_keys(fixture)
    digest = bytes.fromhex(fixture["input"]["artifact_digest_hex"])
    with pytest.raises(keyed.KeyedBundleError, match="Rekor trust is required"):
        keyed.verify_keyed_bundle(dataclasses.replace(root, tlogs=()), bundle, keys, digest)
    with pytest.raises(keyed.KeyedBundleError, match="at least one"):
        keyed.verify_keyed_bundle(root, bundle, [], digest)
    with pytest.raises(keyed.KeyedBundleError, match="not SHA-256"):
        keyed.verify_keyed_bundle(root, bundle, keys, digest[:-1])
    envelope = dataclasses.replace(bundle.envelope, payload_type="application/json")
    with pytest.raises(keyed.KeyedBundleError, match="unsupported DSSE payload type"):
        keyed.verify_keyed_bundle(root, dataclasses.replace(bundle, envelope=envelope), keys, digest)


# --- checkpoints -------------------------------------------------------------


def happy_checkpoint() -> tuple[str, KeyedAuthority]:
    fixture = vector("approval-bundle", "happy")
    root, bundle = fixture_root(fixture), fixture_bundle(fixture)
    (entry,) = bundle.tlog_entries
    assert entry.inclusion_proof is not None
    log = root.tlog(entry.log_id)
    assert log is not None
    return entry.inclusion_proof.checkpoint, log


def test_verify_checkpoint_reads_the_tree_state() -> None:
    envelope, log = happy_checkpoint()
    checkpoint = keyed.verify_checkpoint(envelope, log)
    assert checkpoint.origin == "rekor.tinfoil-conformance.test"
    assert checkpoint.tree_size == 5
    assert len(checkpoint.root_hash) == 32
    assert checkpoint.key_id == hashlib.sha256(public_key_spki(log.public_key)).digest()[:4]


def test_ed25519_note_key_hint_covers_the_origin() -> None:
    fixture = vector("approval-bundle", "happy-ed25519-log")
    root, bundle = fixture_root(fixture), fixture_bundle(fixture)
    (entry,) = bundle.tlog_entries
    log = root.tlog(entry.log_id)
    assert log is not None
    assert entry.inclusion_proof is not None
    origin = keyed.log_origin(log)
    assert isinstance(log.public_key, ed25519.Ed25519PublicKey)
    raw = log.public_key.public_bytes_raw()
    expected = hashlib.sha256(origin.encode() + b"\n\x01" + raw).digest()[:4]
    assert keyed.note_key_hint(log, origin) == expected
    assert keyed.verify_checkpoint(entry.inclusion_proof.checkpoint, log).key_id == expected
    # A log id that differs from the key hint is tolerated (the id names entries, the hint names signature lines).
    assert log.log_id[:4] != expected


def test_checkpoint_key_id_must_agree_with_the_key() -> None:
    envelope, log = happy_checkpoint()
    stated = dataclasses.replace(log, checkpoint_key_id=hashlib.sha256(public_key_spki(log.public_key)).digest())
    assert keyed.verify_checkpoint(envelope, stated).tree_size == 5
    disagreeing = dataclasses.replace(log, checkpoint_key_id=b"\x00\x00\x00\x00")
    with pytest.raises(keyed.KeyedBundleError, match="checkpoint key id does not match"):
        keyed.verify_checkpoint(envelope, disagreeing)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda e: e.replace("\n\n", "\n"), "no signature section"),
        (lambda e: e.rstrip("\n"), "signature section is malformed"),
        (lambda e: e.replace("— ", "- "), "signature line is malformed"),
        (lambda e: e.replace("— rekor", "— rek or"), "signature line is malformed"),
        (lambda e: e + "— other AAAA\n", "signature line is malformed"),  # four bytes: too short
        (lambda e: e.replace("\n5\n", "\n5x\n"), "does not verify under the log key"),  # the signed text changed
        (lambda e: "x" + e, "does not verify under the log key"),
        (
            lambda e: e.replace("rekor.tinfoil-conformance.test\n", "evil.test\n", 1),
            "does not verify under the log key",
        ),
        (lambda e: e.replace("\n", "\r\n", 1), "control character"),
        (lambda e: e.rsplit("— ", 1)[0] + "— x y\n", "signature line is malformed"),
        (lambda e: e.rsplit("— ", 1)[0] + "— other AAAAAAAA\n", "is not signed by the log"),
    ],
)
def test_verify_checkpoint_rejects_malformed_envelopes(change: Any, message: str) -> None:
    envelope, log = happy_checkpoint()
    with pytest.raises(keyed.KeyedBundleError, match=message):
        keyed.verify_checkpoint(change(envelope), log)


def test_verify_checkpoint_ignores_other_signers_and_limits_their_number() -> None:
    envelope, log = happy_checkpoint()
    other = "— witness.test " + base64.b64encode(b"\x01\x02\x03\x04" + b"\x00" * 64).decode() + "\n"
    assert keyed.verify_checkpoint(envelope + other, log).tree_size == 5
    with pytest.raises(keyed.KeyedBundleError, match="too many signatures"):
        keyed.verify_checkpoint(envelope + other * keyed.MAX_NOTE_SIGNATURES, log)


def test_verify_checkpoint_accepts_a_v1_tree_head_origin_only_for_the_log_host() -> None:
    """A checkpoint body ``<host> - <tree id>`` is a Rekor v1 tree head; it is verified by the same rules."""
    fixture = vector("provenance", "provenance-happy")
    root = fixture_root(fixture)
    bundle, _ = document_bundles(fixture["input"]["document_b64"])["sigstore-code"]
    (entry,) = bundle.tlog_entries
    assert entry.inclusion_proof is not None
    log = root.tlog(entry.log_id)
    assert log is not None
    checkpoint = keyed.verify_checkpoint(entry.inclusion_proof.checkpoint, log)
    assert checkpoint.origin == "rekor.synthetic - 1"
    assert checkpoint.tree_size == 1
    other_host = dataclasses.replace(log, base_url="https://other.synthetic")
    with pytest.raises(keyed.KeyedBundleError, match="is not signed by the log"):
        keyed.verify_checkpoint(entry.inclusion_proof.checkpoint, other_host)


def test_log_origin_is_the_host_of_the_base_url() -> None:
    def log(url: str) -> KeyedAuthority:
        fixture = vector("approval-bundle", "happy")
        return dataclasses.replace(fixture_root(fixture).tlogs[0], base_url=url)

    assert keyed.log_origin(log("https://rekor.example:8443/api/v2?x#y")) == "rekor.example"
    assert keyed.log_origin(log("https://user:pw@Rekor.Example/")) == "Rekor.Example"
    assert keyed.log_origin(log("http://[::1]:3000")) == "[::1]"
    for bad in ("rekor.example", "https://", "https:///path", "https://[::1", "https://a b"):
        with pytest.raises(keyed.KeyedBundleError, match="base URL"):
            keyed.log_origin(log(bad))


# --- Merkle inclusion --------------------------------------------------------


def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def test_merkle_inclusion_over_a_five_leaf_tree() -> None:
    leaves = [hash_leaf(bytes([i])) for i in range(5)]
    n01, n23 = hash_children(leaves[0], leaves[1]), hash_children(leaves[2], leaves[3])
    n0123 = hash_children(n01, n23)
    root = hash_children(n0123, leaves[4])
    proofs = {
        0: [leaves[1], n23, leaves[4]],
        1: [leaves[0], n23, leaves[4]],
        2: [leaves[3], n01, leaves[4]],
        3: [leaves[2], n01, leaves[4]],
        4: [n0123],
    }
    for index, proof in proofs.items():
        keyed.verify_merkle_inclusion(leaves[index], index, 5, proof, root)
    with pytest.raises(keyed.KeyedBundleError, match="does not reach the root"):
        keyed.verify_merkle_inclusion(leaves[0], 1, 5, proofs[0], root)
    with pytest.raises(keyed.KeyedBundleError, match="outside a tree"):
        keyed.verify_merkle_inclusion(leaves[0], 5, 5, proofs[0], root)
    with pytest.raises(keyed.KeyedBundleError, match="has 2 hashes, expected 3"):
        keyed.verify_merkle_inclusion(leaves[0], 0, 5, proofs[0][:2], root)
    with pytest.raises(keyed.KeyedBundleError, match="not 32 bytes"):
        keyed.verify_merkle_inclusion(leaves[0][:-1], 0, 5, proofs[0], root)
    with pytest.raises(keyed.KeyedBundleError, match="not 32 bytes"):
        keyed.verify_merkle_inclusion(leaves[0], 0, 5, [*proofs[0][:2], b"short"], root)
    with pytest.raises(keyed.KeyedBundleError, match="more than"):
        keyed.verify_merkle_inclusion(leaves[0], 0, 1 << 70, [leaves[0]] * (keyed.MAX_INCLUSION_PROOF_HASHES + 1), root)
    # A single-leaf tree: the leaf hash is the root.
    keyed.verify_merkle_inclusion(leaves[0], 0, 1, [], leaves[0])


# --- hashedrekord bodies ------------------------------------------------------


def test_hashedrekord_body_is_the_canonical_record() -> None:
    fixture = vector("approval-bundle", "happy")
    bundle = fixture_bundle(fixture)
    (pinned, _) = fixture_keys(fixture)
    signed = bm.pre_auth_encoding(bundle.envelope.payload_type, bundle.envelope.payload)
    body = keyed.hashedrekord_body(
        keyed.HashedRekordBody(
            digest=hashlib.sha256(signed).digest(),
            signature=bundle.envelope.signatures[0].sig,
            verifier=pinned.spki,
            verifier_kind="publicKey",
        )
    )
    assert body == bundle.tlog_entries[0].canonicalized_body
    record = json.loads(body)["spec"]["hashedRekordV002"]
    assert record["signature"]["verifier"]["keyDetails"] == "PKIX_ECDSA_P256_SHA_256"
    assert record["data"]["algorithm"] == "SHA2_256"


def test_hashedrekord_body_labels_the_digest_by_the_signer_key_type() -> None:
    """The log derives the data algorithm from the verifier's key details: a P-384 signer logs a SHA-384 digest."""
    signer = pki.p384()
    pae = bm.pre_auth_encoding(bm.IN_TOTO_PAYLOAD_TYPE, b'{"_type":"x"}')
    signature = signer.sign(pae, ec.ECDSA(hashes.SHA384()))
    expected = keyed.HashedRekordBody(
        digest=hashlib.sha384(pae).digest(),
        signature=signature,
        verifier=public_key_spki(signer.public_key()),
        verifier_kind="publicKey",
        key_details=_wire.KEY_DETAILS_P384,
    )
    record = json.loads(keyed.hashedrekord_body(expected))["spec"]["hashedRekordV002"]
    assert record["data"]["algorithm"] == "SHA2_384"
    assert base64.b64decode(record["data"]["digest"]) == hashlib.sha384(pae).digest()
    assert record["signature"]["verifier"]["keyDetails"] == "PKIX_ECDSA_P384_SHA_384"
    assert base64.b64decode(record["signature"]["verifier"]["publicKey"]["rawBytes"]) == expected.verifier
    # The digest must be the size of the hash that the key type implies, and only P-256 and P-384 are logged.
    with pytest.raises(keyed.KeyedBundleError, match="digest length 32 is not 48 bytes for SHA2_384"):
        keyed.hashedrekord_body(dataclasses.replace(expected, digest=hashlib.sha256(pae).digest()))
    with pytest.raises(keyed.KeyedBundleError, match="digest length 48 is not 32 bytes for SHA2_256"):
        keyed.hashedrekord_body(dataclasses.replace(expected, key_details=_wire.KEY_DETAILS_P256))
    with pytest.raises(keyed.KeyedBundleError, match="do not support key type"):
        keyed.hashedrekord_body(dataclasses.replace(expected, key_details=_wire.KEY_DETAILS_ED25519))


# --- inclusion promises ------------------------------------------------------


def provenance_entry() -> tuple[TrustedRoot, bm.TlogEntry]:
    fixture = vector("provenance", "provenance-happy")
    bundle, _ = document_bundles(fixture["input"]["document_b64"])["sigstore-code"]
    return fixture_root(fixture), bundle.tlog_entries[0]


def test_promised_log_time_verifies_the_signed_entry_timestamp() -> None:
    root, entry = provenance_entry()
    assert keyed.promised_log_time(root, [entry]) == datetime(2025, 1, 1, 0, 0, 1, tzinfo=UTC)
    assert keyed.promised_log_time(root, [dataclasses.replace(entry, inclusion_promise=None)]) is None
    assert entry.inclusion_promise is not None
    tampered = dataclasses.replace(
        entry, inclusion_promise=entry.inclusion_promise[:-1] + bytes([entry.inclusion_promise[-1] ^ 1])
    )
    with pytest.raises(keyed.KeyedBundleError, match=r"inclusion promise does not verify|malformed"):
        keyed.promised_log_time(root, [tampered])
    with pytest.raises(keyed.KeyedBundleError, match="does not list"):
        keyed.promised_log_time(root, [dataclasses.replace(entry, log_id=bytes(32))])
    with pytest.raises(keyed.KeyedBundleError, match="outside the log key's validity"):
        keyed.promised_log_time(root, [dataclasses.replace(entry, integrated_time=1)])
    with pytest.raises(keyed.KeyedBundleError, match="does not verify"):
        keyed.promised_log_time(root, [dataclasses.replace(entry, log_index=entry.log_index + 1)])
    with pytest.raises(keyed.KeyedBundleError, match="representable"):
        keyed.promised_log_time(root, [dataclasses.replace(entry, integrated_time=1 << 62)])


def test_verify_signature_requires_minimal_der_and_the_curve_hash() -> None:
    key = pki.p256()
    signature = key.sign(b"data", ec.ECDSA(hashes.SHA256()))
    keyed.verify_signature(key.public_key(), signature, b"data")
    # Re-encode r with a redundant leading zero: the same mathematical signature, a different encoding.
    parts = der.children(der.decode(signature))
    padded_r = b"\x02" + der.encode_length(len(parts[0].content) + 1) + b"\x00" + parts[0].content
    body = padded_r + parts[1].raw
    non_minimal = b"\x30" + der.encode_length(len(body)) + body
    with pytest.raises(keyed.KeyedBundleError, match=r"malformed ECDSA signature|not minimal"):
        keyed.verify_signature(key.public_key(), non_minimal, b"data")
    with pytest.raises(keyed.KeyedBundleError, match="does not verify"):
        keyed.verify_signature(key.public_key(), signature, b"other")
    p384 = pki.p384()
    keyed.verify_signature(p384.public_key(), p384.sign(b"data", ec.ECDSA(hashes.SHA384())), b"data")
    with pytest.raises(keyed.KeyedBundleError, match="does not verify"):
        keyed.verify_signature(p384.public_key(), p384.sign(b"data", ec.ECDSA(hashes.SHA256())), b"data")
    ed = pki.ed25519_key()
    keyed.verify_signature(ed.public_key(), ed.sign(b"data"), b"data")
    with pytest.raises(keyed.KeyedBundleError, match="unsupported key type"):
        keyed.verify_signature(pki.rsa_key().public_key(), b"", b"data")


def test_valid_for_windows_apply_to_promises_only() -> None:
    """Key-signed bundles carry no time, so the log window is not consulted there; it is for promises."""
    fixture = vector("approval-bundle", "happy")
    root, bundle, keys = fixture_root(fixture), fixture_bundle(fixture), fixture_keys(fixture)
    far_future = ValidFor(datetime(2999, 1, 1, tzinfo=UTC))
    shifted = dataclasses.replace(
        root, tlogs=tuple(dataclasses.replace(log, valid_for=far_future) for log in root.tlogs)
    )
    assert keyed.verify_keyed_bundle(shifted, bundle, keys, bytes.fromhex(fixture["input"]["artifact_digest_hex"]))
