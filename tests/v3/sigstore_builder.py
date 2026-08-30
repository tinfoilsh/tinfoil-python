"""Synthetic Sigstore stack for provenance unit tests: a self-consistent
signing chain from fixed keys so a DSSE-signed in-toto statement verifies with
SCT + transparency-log + observer-timestamp requirements. Trimmed port of
tinfoil-conformance fixturegen/v3/sigstore_synth.py (the material-shape spec
for these tests)."""

import base64
import datetime
import hashlib
import json
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

OID_ISSUER_V1 = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")  # raw string value
OID_RUNNER_ENVIRONMENT = ObjectIdentifier("1.3.6.1.4.1.57264.1.11")  # DER string
OID_SOURCE_REPO_DIGEST = ObjectIdentifier("1.3.6.1.4.1.57264.1.13")  # DER string
OID_SOURCE_REPO_REF = ObjectIdentifier("1.3.6.1.4.1.57264.1.14")  # DER string
OID_SCT_LIST = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")  # RFC 6962 3.3

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

FRESHNESS_PREDICATE = "https://tinfoil.sh/predicate/freshness-witness/v1"
FRESHNESS_WITNESS_IDENTITY = (
    "https://github.com/tinfoilsh/freshness-witness"
    "/.github/workflows/freshness.yml@refs/heads/main"
)

# Fixed instant all validity windows and timestamps hang off of.
BASE_TIME = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
INTEGRATED_TIME = int(BASE_TIME.timestamp()) + 1
SCT_TIMESTAMP_MS = int(BASE_TIME.timestamp() * 1000)

_SECRETS = {
    "fulcio_root": 0x1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A,
    "fulcio_int": 0x2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B,
    "leaf": 0x3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C,
    "ctlog": 0x4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D,
    "rekor": 0x5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E,
}


def _key(name):
    return ec.derive_private_key(_SECRETS[name], ec.SECP256R1())


def b64(data):
    return base64.b64encode(data).decode()


def sha256(data):
    return hashlib.sha256(data).digest()


def spki_der(pub):
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


# --- TLS wire encoders (RFC 8446 3) for the SCT signature --------------------
def _u8(n):
    return struct.pack("!B", n)


def _u16(n):
    return struct.pack("!H", n)


def _u64(n):
    return struct.pack("!Q", n)


def _opaque(data, length_bytes):
    return len(data).to_bytes(length_bytes, "big") + data


def _der_octet_string(data):
    if len(data) < 0x80:
        return bytes([0x04, len(data)]) + data
    length = len(data)
    nbytes = (length.bit_length() + 7) // 8
    return bytes([0x04, 0x80 | nbytes]) + length.to_bytes(nbytes, "big") + data


def _der_utf8_string(text):
    raw = text.encode()
    assert len(raw) < 0x80
    return bytes([0x0C, len(raw)]) + raw


# --- Certificate authority ----------------------------------------------------
def _build_ca_with_secrets(root_secret, int_secret):
    return _build_ca(
        ec.derive_private_key(root_secret, ec.SECP256R1()),
        ec.derive_private_key(int_secret, ec.SECP256R1()),
    )


def _build_ca(root_key=None, int_key=None):
    root_key = root_key or _key("fulcio_root")
    int_key = int_key or _key("fulcio_int")

    not_before = BASE_TIME - datetime.timedelta(days=1)
    not_after = BASE_TIME + datetime.timedelta(days=3650)

    def ca_usage():
        return x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        )

    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-sigstore-root")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-sigstore-intermediate")])
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(root_name)
        .public_key(int_key.public_key())
        .serial_number(2)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return root_cert, int_cert, int_key


# --- SCT (RFC 6962) -------------------------------------------------------------
def _sct_signature_input(tbs_no_sct, issuer_pub):
    issuer_key_hash = sha256(spki_der(issuer_pub))
    precert = issuer_key_hash + _opaque(tbs_no_sct, 3)
    return _u8(0) + _u8(0) + _u64(SCT_TIMESTAMP_MS) + _u16(1) + precert + _u16(0)


def _serialized_sct(log_key_id, signature_der):
    digitally_signed = _u8(4) + _u8(3) + _opaque(signature_der, 2)  # sha256, ecdsa
    return _u8(0) + log_key_id + _u64(SCT_TIMESTAMP_MS) + _u16(0) + digitally_signed


def _sct_list_extension_value(serialized_scts):
    entries = b"".join(_opaque(s, 2) for s in serialized_scts)
    return _der_octet_string(_opaque(entries, 2))


# --- Leaf certificate with embedded SCT ------------------------------------------
def _leaf_extensions(identity_uri, int_key, issuer, runner_environment,
                     source_ref=None, source_digest=None):
    exts = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), True),
        (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]), False),
        (x509.SubjectKeyIdentifier.from_public_key(_key("leaf").public_key()), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()), False),
        (x509.UnrecognizedExtension(OID_ISSUER_V1, issuer.encode()), False),
        (x509.UnrecognizedExtension(OID_RUNNER_ENVIRONMENT, _der_utf8_string(runner_environment)), False),
        (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity_uri)]), True),
    ]
    if source_ref is not None:
        exts.append((x509.UnrecognizedExtension(OID_SOURCE_REPO_REF, _der_utf8_string(source_ref)), False))
    if source_digest is not None:
        exts.append((x509.UnrecognizedExtension(OID_SOURCE_REPO_DIGEST, _der_utf8_string(source_digest)), False))
    return exts


def _build_leaf(identity_uri, root_cert, int_cert, int_key, dup_sct=False,
                issuer=GITHUB_ACTIONS_ISSUER, runner_environment="github-hosted",
                source_ref=None, source_digest=None):
    leaf_key = _key("leaf")
    int_name = int_cert.subject
    not_before = BASE_TIME - datetime.timedelta(minutes=5)
    not_after = BASE_TIME + datetime.timedelta(minutes=10)

    def base_builder():
        b = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(int_name)
            .public_key(leaf_key.public_key())
            .serial_number(0x1000)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )
        for ext, critical in _leaf_extensions(identity_uri, int_key, issuer, runner_environment,
                                              source_ref=source_ref, source_digest=source_digest):
            b = b.add_extension(ext, critical)
        return b

    # Pre-SCT leaf: its TBS is what the CT log signs over.
    pre_cert = base_builder().sign(int_key, hashes.SHA256())
    tbs_no_sct = pre_cert.tbs_certificate_bytes

    ctlog_key = _key("ctlog")
    log_key_id = sha256(spki_der(ctlog_key.public_key()))
    sig_input = _sct_signature_input(tbs_no_sct, int_cert.public_key())
    sct_sig_der = ctlog_key.sign(sig_input, ec.ECDSA(hashes.SHA256()))
    sct = _serialized_sct(log_key_id, sct_sig_der)
    scts = [sct, sct] if dup_sct else [sct]
    sct_ext_value = _sct_list_extension_value(scts)

    leaf = (
        base_builder()
        .add_extension(x509.UnrecognizedExtension(OID_SCT_LIST, sct_ext_value), False)
        .sign(int_key, hashes.SHA256())
    )
    return leaf, leaf_key


# --- DSSE + Rekor v1 dsse/0.0.1 entry ---------------------------------------------
def _pae(payload_type, payload):
    return b"DSSEv1 %d %b %d %b" % (len(payload_type), payload_type.encode(), len(payload), payload)


def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _rekor_body(dsse_sig, leaf_pem, statement_bytes, envelope_json):
    # Field order must match rekor's dsse/v0.0.1 Canonicalize output.
    return json.dumps({
        "apiVersion": "0.0.1",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": sha256(envelope_json).hex()},
            "payloadHash": {"algorithm": "sha256", "value": sha256(statement_bytes).hex()},
            "signatures": [{"signature": b64(dsse_sig), "verifier": b64(leaf_pem)}],
        },
        "kind": "dsse",
    }, separators=(",", ":")).encode()


def _signed_entry_timestamp(body_bytes, log_key_id, integrated_time):
    payload = _canonical_json({
        "body": b64(body_bytes),
        "integratedTime": integrated_time,
        "logID": log_key_id.hex(),
        "logIndex": 0,
    })
    return _key("rekor").sign(payload, ec.ECDSA(hashes.SHA256()))


REKOR_ORIGIN = "rekor.synthetic - 1"
REKOR_SIG_NAME = "rekor.synthetic"


def _rfc6962_leaf_hash(body_bytes):
    return sha256(b"\x00" + body_bytes)


def _checkpoint_envelope(root_hash):
    rekor_key = _key("rekor")
    note = "%s\n%d\n%s\n" % (REKOR_ORIGIN, 1, b64(root_hash))
    sig_der = rekor_key.sign(note.encode(), ec.ECDSA(hashes.SHA256()))
    key_hint = sha256(spki_der(rekor_key.public_key()))[:4]
    sig_line = "— %s %s" % (REKOR_SIG_NAME, b64(key_hint + sig_der))
    return note + "\n" + sig_line + "\n"


# --- Trusted root ---------------------------------------------------------------
def _rfc3339(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_key_entry(pub, start):
    return {
        "rawBytes": b64(spki_der(pub)),
        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
        "validFor": {"start": _rfc3339(start)},
    }


def _trusted_root(root_cert, int_cert):
    valid_start = BASE_TIME - datetime.timedelta(days=1)
    ctlog_pub = _key("ctlog").public_key()
    rekor_pub = _key("rekor").public_key()
    return {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "certificateAuthorities": [{
            "subject": {"organization": "synthetic", "commonName": "synthetic-sigstore"},
            "uri": "https://fulcio.synthetic",
            "certChain": {"certificates": [
                {"rawBytes": b64(int_cert.public_bytes(serialization.Encoding.DER))},
                {"rawBytes": b64(root_cert.public_bytes(serialization.Encoding.DER))},
            ]},
            "validFor": {"start": _rfc3339(valid_start)},
        }],
        "ctlogs": [{
            "baseUrl": "https://ctlog.synthetic",
            "hashAlgorithm": "SHA2_256",
            "publicKey": _public_key_entry(ctlog_pub, valid_start),
            "logId": {"keyId": b64(sha256(spki_der(ctlog_pub)))},
        }],
        "tlogs": [{
            "baseUrl": "https://rekor.synthetic",
            "hashAlgorithm": "SHA2_256",
            "publicKey": _public_key_entry(rekor_pub, valid_start),
            "logId": {"keyId": b64(sha256(spki_der(rekor_pub)))},
        }],
        "timestampAuthorities": [],
    }


# --- Bundle assembly --------------------------------------------------------------
def build_bundle(identity_uri, statement_bytes, integrated_time=None, dup_sct=False,
                 bad_dsse=False, issuer=GITHUB_ACTIONS_ISSUER,
                 runner_environment="github-hosted", source_ref=None, source_digest=None):
    """Return (bundle_dict, trusted_root_dict) for a DSSE-signed in-toto
    statement whose signing certificate carries identity_uri as its SAN."""
    it = INTEGRATED_TIME if integrated_time is None else integrated_time
    root_cert, int_cert, int_key = _build_ca()
    leaf, leaf_key = _build_leaf(identity_uri, root_cert, int_cert, int_key, dup_sct=dup_sct,
                                 issuer=issuer, runner_environment=runner_environment,
                                 source_ref=source_ref, source_digest=source_digest)
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)

    signing_key = _key("ctlog") if bad_dsse else leaf_key
    dsse_sig = signing_key.sign(_pae(DSSE_PAYLOAD_TYPE, statement_bytes), ec.ECDSA(hashes.SHA256()))
    envelope = {
        "payload": b64(statement_bytes),
        "payloadType": DSSE_PAYLOAD_TYPE,
        "signatures": [{"sig": b64(dsse_sig)}],
    }
    envelope_json = _canonical_json(envelope)

    body = _rekor_body(dsse_sig, leaf_pem, statement_bytes, envelope_json)
    rekor_key_id = sha256(spki_der(_key("rekor").public_key()))
    set_sig = _signed_entry_timestamp(body, rekor_key_id, it)
    root_hash = _rfc6962_leaf_hash(body)

    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": b64(leaf.public_bytes(serialization.Encoding.DER))},
            "tlogEntries": [{
                "logIndex": "0",
                "logId": {"keyId": b64(rekor_key_id)},
                "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                "integratedTime": str(it),
                "inclusionPromise": {"signedEntryTimestamp": b64(set_sig)},
                "inclusionProof": {
                    "logIndex": "0",
                    "rootHash": b64(root_hash),
                    "treeSize": "1",
                    "hashes": [],
                    "checkpoint": {"envelope": _checkpoint_envelope(root_hash)},
                },
                "canonicalizedBody": b64(body),
            }],
        },
        "dsseEnvelope": envelope,
    }
    return bundle, _trusted_root(root_cert, int_cert)


def freshness_statement(subject_name, artifact_digest, repo, tag, commit):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": subject_name, "digest": {"sha256": artifact_digest}}],
        "predicateType": FRESHNESS_PREDICATE,
        "predicate": {
            "format": FRESHNESS_PREDICATE,
            "endorses": {
                "repo": repo,
                "tag": tag,
                "commit": commit,
                "subject": {"name": subject_name, "digest": "sha256:" + artifact_digest},
            },
        },
    }


def build_freshness_bundle(subject_name, artifact_digest, repo, tag, commit,
                           integrated_time=None, identity=FRESHNESS_WITNESS_IDENTITY, stmt=None):
    statement = _canonical_json(
        stmt if stmt is not None else freshness_statement(subject_name, artifact_digest, repo, tag, commit))
    bundle, troot = build_bundle(identity, statement, integrated_time=integrated_time)
    return bundle, troot


def rogue_ca_cert_chain():
    """A certificate chain from an unrelated CA: swapping it into a trusted
    root breaks leaf chain-building."""
    root_cert, int_cert, _ = _build_ca_with_secrets(0x71, 0x72)
    return [
        {"rawBytes": b64(int_cert.public_bytes(serialization.Encoding.DER))},
        {"rawBytes": b64(root_cert.public_bytes(serialization.Encoding.DER))},
    ]
