"""Certificate-signed bundles: the provenance vectors and the production bundles of the real-frozen document through
``verify_fulcio_bundle``, the registry-issuer path through ``verify_certified_bundle``, and the pieces underneath
(Fulcio extensions, SCTs, identities)."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests.v3 import pki
from tests.v3.vectors import vector, vector_params
from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._sigstore import bundle as bm
from tinfoil._v3.verifier._sigstore import certificate as sc
from tinfoil._v3.verifier._sigstore import keyed
from tinfoil._v3.verifier._sigstore.trusted_root import (
    KeyedAuthority,
    TrustedRoot,
    ValidFor,
    embedded_trusted_root,
    parse_trusted_root,
)
from tinfoil._v3.verifier._x509 import der
from tinfoil._v3.verifier._x509.certificate import OID_SCT_LIST, extension, parse_certificate, public_key_spki

CODE_FORMAT = "https://tinfoil.sh/collateral/sigstore-code/v1"

# Provenance vectors whose rejection belongs to the statement layer (predicate contents, tag and commit rules) and
# therefore pass the bundle layer under test here.
STATEMENT_LAYER = {
    "p-code-bad-commit",
    "p-code-ref-not-tag",
    "p-code-tag-mismatch",
    "p13-missing-shape",
    "p13-no-rtmr1",
    "p13-no-snp",
    "p13-no-tdx",
    "p13-predicate-type",
    "p13-shape-missing-member",
    "p13-shape-negative",
    "p13-shape-not-object",
    "p13-tdx-not-struct",
}


def repo_identity(repo: str) -> sc.SigningIdentity:
    """The identity accepted for artifacts signed from ``repo``: any workflow file at a tag ref."""
    return sc.SigningIdentity(
        san=sc.workflow_identity_pattern(repo, r"[^/@]+", r"refs/tags/[^@]+"),
        issuer=sc.GITHUB_OIDC_ISSUER,
        runner_environment=sc.RUNNER_ENVIRONMENT_GITHUB_HOSTED,
    )


def document_bundles(document_b64: str) -> dict[str, tuple[bm.Bundle, dict[str, Any]]]:
    """Every Sigstore bundle in a document by collateral id, with the entry's data."""
    document = json.loads(base64.b64decode(document_b64))
    out: dict[str, tuple[bm.Bundle, dict[str, Any]]] = {}
    for entry in document["collateral"]:
        data = entry.get("data") or {}
        if "sigstore_bundle" in data:
            out[entry["id"]] = (bm.parse_bundle(_json.strict_parse(json.dumps(data["sigstore_bundle"]).encode())), data)
    return out


def code_bundle(fixture: dict[str, Any]) -> tuple[bm.Bundle, bytes] | None:
    document = json.loads(base64.b64decode(fixture["input"]["document_b64"]))
    for entry in document["collateral"]:
        if entry.get("format") == CODE_FORMAT and "sigstore_bundle" in (entry.get("data") or {}):
            try:
                parsed = bm.parse_bundle(_json.strict_parse(json.dumps(entry["data"]["sigstore_bundle"]).encode()))
            except bm.BundleError:
                return None
            return parsed, bytes.fromhex(entry["data"]["digest"])
    return None


@pytest.mark.parametrize("fixture", vector_params("provenance"))
def test_provenance_vectors(fixture: dict[str, Any]) -> None:
    """Every vector's code bundle: accepted vectors verify; rejected ones fail here unless the statement layer owns
    the rejection."""
    root = parse_trusted_root(base64.b64decode(fixture["input"]["sigstore_trusted_root_json_b64"]))
    found = code_bundle(fixture)
    expected = fixture["expected"]
    if found is None:
        # The bundle does not decode (or the document has none): a rejected vector, rejected before this layer.
        assert not expected["accepted"]
        return
    bundle, digest = found
    identity = repo_identity(fixture["input"]["repo"])
    if expected["accepted"] or fixture["id"] in STATEMENT_LAYER:
        verified = sc.verify_fulcio_bundle(root, bundle, identity, digest)
        assert verified.signed_at == datetime(2025, 1, 1, 0, 0, 1, tzinfo=UTC)
        assert verified.logged_at == verified.signed_at
        assert verified.extensions.issuer == sc.GITHUB_OIDC_ISSUER
    else:
        with pytest.raises(sc.CertificateBundleError):
            sc.verify_fulcio_bundle(root, bundle, identity, digest)


def test_production_bundles_verify_under_the_embedded_root() -> None:
    """The real-frozen document's bundles are production material: Rekor v1 promises and proofs, embedded SCTs."""
    fixture = vector("real-frozen", "real-sev-inference-tinfoil")
    root = embedded_trusted_root()
    bundles = document_bundles(fixture["input"]["document_b64"])
    code, data = bundles["code"]
    verified = sc.verify_fulcio_bundle(root, code, repo_identity(data["repo"]), bytes.fromhex(data["digest"]))
    assert verified.signed_at == datetime.fromtimestamp(code.tlog_entries[0].integrated_time, UTC)
    assert verified.logged_at == verified.signed_at
    assert verified.extensions.source_repository_ref == f"refs/tags/{data['tag']}"
    assert verified.extensions.source_repository_uri == f"https://github.com/{data['repo']}"
    assert re.fullmatch(r"[0-9a-f]{40}", verified.extensions.source_repository_digest)
    assert verified.extensions.runner_environment == sc.RUNNER_ENVIRONMENT_GITHUB_HOSTED
    assert verified.payload == code.envelope.payload
    platform, data = bundles["platform"]
    sc.verify_fulcio_bundle(root, platform, repo_identity(data["repo"]), bytes.fromhex(data["digest"]))
    witness = sc.SigningIdentity(
        sc.workflow_identity_pattern("tinfoilsh/freshness-witness", r"freshness\.yml", r"refs/heads/main"),
        sc.GITHUB_OIDC_ISSUER,
        sc.RUNNER_ENVIRONMENT_GITHUB_HOSTED,
    )
    for name in ("code-freshness", "platform-freshness"):
        freshness, _ = bundles[name]
        statement = bm.parse_statement(freshness.envelope.payload)
        sc.verify_fulcio_bundle(root, freshness, witness, bytes.fromhex(statement.subjects[0].digest["sha256"]))


def production_code() -> tuple[TrustedRoot, bm.Bundle, sc.SigningIdentity, bytes]:
    fixture = vector("real-frozen", "real-sev-inference-tinfoil")
    code, data = document_bundles(fixture["input"]["document_b64"])["code"]
    return embedded_trusted_root(), code, repo_identity(data["repo"]), bytes.fromhex(data["digest"])


def test_production_leaf_extensions_and_scts() -> None:
    root, bundle, _, _ = production_code()
    assert isinstance(bundle.material, bm.CertificateMaterial)
    leaf = parse_certificate(bundle.material.certificate)
    scts = sc.signed_certificate_timestamps(leaf)
    assert scts
    assert all(root.ctlog(s.log_id) is not None for s in scts)
    assert all(s.signature_algorithm == (sc.SCT_HASH_SHA256, sc.SCT_SIGNATURE_ECDSA) for s in scts)
    sc.check_duplicate_sct_logs(scts)
    with pytest.raises(sc.CertificateBundleError, match="duplicate SCT log id"):
        sc.check_duplicate_sct_logs((*scts, scts[0]))
    tbs = sc.precertificate_tbs(leaf)
    assert len(tbs) < len(leaf.tbs_certificate_bytes)
    assert OID_SCT_LIST not in [
        der.object_identifier(der.expect_sequence(e, "ext")[0])
        for e in der.children(der.children(der.children(der.decode(tbs))[-1])[0])
    ]
    extensions = sc.fulcio_extensions(leaf)
    assert extensions.source_repository_identifier.isdigit()
    assert extensions.source_repository_owner_identifier.isdigit()
    assert extensions.build_signer_uri.startswith("https://github.com/")


def test_sct_rejections() -> None:
    root, bundle, identity, digest = production_code()
    assert isinstance(bundle.material, bm.CertificateMaterial)
    leaf_der = bundle.material.certificate
    leaf = parse_certificate(leaf_der)
    issuers = tuple(ca.chain[0] for ca in root.certificate_authorities)
    assert sc.verify_scts(root, leaf, issuers) >= 1
    # Flip a byte inside the SCT list: the leaf still parses, the SCT signature no longer verifies.
    ext = extension(leaf, OID_SCT_LIST)
    assert ext is not None
    position = leaf_der.find(ext.value) + len(ext.value) - 1
    tampered = leaf_der[:position] + bytes([leaf_der[position] ^ 0x01]) + leaf_der[position + 1 :]
    with pytest.raises(sc.CertificateBundleError, match="does not verify under its CT log key"):
        sc.verify_scts(root, parse_certificate(tampered), issuers)
    # An issuer other than the one that issued the leaf gives a different precertificate hash.
    with pytest.raises(sc.CertificateBundleError, match="does not verify under its CT log key"):
        sc.verify_scts(root, leaf, (root.certificate_authorities[0].root,))
    # A root without the CT log rejects rather than skipping the SCT.
    no_ct = dataclasses.replace(root, ctlogs=())
    with pytest.raises(sc.CertificateBundleError, match="names a CT log the trusted root does not list"):
        sc.verify_fulcio_bundle(no_ct, bundle, identity, digest)
    # A CT log window that excludes the SCT time rejects too.
    late = tuple(dataclasses.replace(log, valid_for=ValidFor(datetime(2999, 1, 1, tzinfo=UTC))) for log in root.ctlogs)
    with pytest.raises(sc.CertificateBundleError, match="outside its CT log's validity"):
        sc.verify_fulcio_bundle(dataclasses.replace(root, ctlogs=late), bundle, identity, digest)


def test_identity_rejections() -> None:
    root, bundle, identity, digest = production_code()
    other_repo = repo_identity("tinfoilsh/other")
    with pytest.raises(sc.CertificateBundleError, match="does not match the expected workflow identity"):
        sc.verify_fulcio_bundle(root, bundle, other_repo, digest)
    with pytest.raises(sc.CertificateBundleError, match="issuer"):
        sc.verify_fulcio_bundle(root, bundle, dataclasses.replace(identity, issuer="https://other.example"), digest)
    with pytest.raises(sc.CertificateBundleError, match="runner environment"):
        sc.verify_fulcio_bundle(root, bundle, dataclasses.replace(identity, runner_environment="self-hosted"), digest)
    with pytest.raises(sc.CertificateBundleError, match="do not name the artifact digest"):
        sc.verify_fulcio_bundle(root, bundle, identity, bytes(32))
    with pytest.raises(sc.CertificateBundleError, match="not SHA-256"):
        sc.verify_fulcio_bundle(root, bundle, identity, digest[:-1])


def test_time_and_material_rejections() -> None:
    root, bundle, identity, digest = production_code()
    (entry,) = bundle.tlog_entries
    # Without a promise there is no observer timestamp and nothing anchors the signing time.
    no_promise = dataclasses.replace(bundle, tlog_entries=(dataclasses.replace(entry, inclusion_promise=None),))
    with pytest.raises(sc.CertificateBundleError, match="no verified observer timestamp"):
        sc.verify_fulcio_bundle(root, no_promise, identity, digest)
    # An entry from a log the root does not list is an error, not a skip.
    unknown = dataclasses.replace(bundle, tlog_entries=(dataclasses.replace(entry, log_id=bytes(32)),))
    with pytest.raises(sc.CertificateBundleError, match="does not list"):
        sc.verify_fulcio_bundle(root, unknown, identity, digest)
    duplicate = dataclasses.replace(bundle, tlog_entries=(entry, entry))
    with pytest.raises(sc.CertificateBundleError, match="duplicate tlog entries"):
        sc.verify_fulcio_bundle(root, duplicate, identity, digest)
    other_kind = dataclasses.replace(bundle, tlog_entries=(dataclasses.replace(entry, kind="intoto", version="0.0.2"),))
    with pytest.raises(sc.CertificateBundleError, match="unsupported transparency log entry kind"):
        sc.verify_fulcio_bundle(root, other_kind, identity, digest)
    no_entries = dataclasses.replace(bundle, tlog_entries=())
    with pytest.raises(sc.CertificateBundleError, match="no transparency log entry"):
        sc.verify_fulcio_bundle(root, no_entries, identity, digest)
    too_many = dataclasses.replace(
        bundle, tlog_entries=tuple(dataclasses.replace(entry, log_index=i) for i in range(33))
    )
    with pytest.raises(sc.CertificateBundleError, match="too many tlog entries"):
        sc.verify_fulcio_bundle(root, too_many, identity, digest)
    early = dataclasses.replace(bundle, tlog_entries=(dataclasses.replace(entry, integrated_time=1),))
    with pytest.raises(sc.CertificateBundleError, match="integrated time outside certificate validity"):
        sc.verify_fulcio_bundle(root, early, identity, digest)
    keyed_material = dataclasses.replace(bundle, material=bm.KeyMaterial("hint"))
    with pytest.raises(sc.CertificateBundleError, match="has no signing certificate"):
        sc.verify_fulcio_bundle(root, keyed_material, identity, digest)
    signature = bundle.envelope.signatures[0]
    with_keyid = dataclasses.replace(
        bundle, envelope=dataclasses.replace(bundle.envelope, signatures=(dataclasses.replace(signature, keyid="k"),))
    )
    with pytest.raises(sc.CertificateBundleError, match="key id must be empty"):
        sc.verify_fulcio_bundle(root, with_keyid, identity, digest)
    # A Fulcio authority whose window excludes the signing time fails the chain.
    shifted = dataclasses.replace(
        root,
        certificate_authorities=tuple(
            dataclasses.replace(ca, valid_for=ValidFor(datetime(2999, 1, 1, tzinfo=UTC)))
            for ca in root.certificate_authorities
        ),
    )
    with pytest.raises(sc.CertificateBundleError, match="leaf certificate verification failed"):
        sc.verify_fulcio_bundle(shifted, bundle, identity, digest)


def test_workflow_identity_pattern_is_anchored_and_escaped() -> None:
    pattern = sc.workflow_identity_pattern("org/re.po", r"a\.yml|b\.yml", r"refs/tags/v[0-9]+")
    assert pattern.search("https://github.com/org/re.po/.github/workflows/b.yml@refs/tags/v1")
    assert pattern.search("https://github.com/org/reXpo/.github/workflows/b.yml@refs/tags/v1") is None
    assert pattern.search("https://github.com/org/re.po/.github/workflows/b.yml@refs/tags/v1\n") is None
    assert pattern.search("xhttps://github.com/org/re.po/.github/workflows/b.yml@refs/tags/v1") is None
    assert pattern.search("https://github.com/org/re.po/.github/workflows/b.yml@refs/tags/v1x") is None


def test_fulcio_extensions_rules() -> None:
    def leaf_with(extra: list[tuple[x509.ExtensionType, bool]]) -> x509.Certificate:
        return parse_certificate(pki.certificate("leaf", pki.p256(), extra=extra).der)

    utf8 = b"\x0c\x05hello"
    v2 = x509.UnrecognizedExtension(x509.ObjectIdentifier(sc.OID_FULCIO_ISSUER), utf8)
    v1 = x509.UnrecognizedExtension(x509.ObjectIdentifier(sc.OID_FULCIO_ISSUER_V1), b"hello")
    assert sc.fulcio_extensions(leaf_with([(v2, False)])).issuer == "hello"
    assert sc.fulcio_extensions(leaf_with([(v1, False)])).issuer == "hello"
    assert sc.fulcio_extensions(leaf_with([(v1, False), (v2, False)])).issuer == "hello"
    other_v1 = x509.UnrecognizedExtension(x509.ObjectIdentifier(sc.OID_FULCIO_ISSUER_V1), b"other")
    with pytest.raises(sc.CertificateBundleError, match="issuer extensions disagree"):
        sc.fulcio_extensions(leaf_with([(other_v1, False), (v2, False)]))
    printable = x509.UnrecognizedExtension(x509.ObjectIdentifier(sc.OID_FULCIO_RUNNER_ENVIRONMENT), b"\x13\x05hello")
    with pytest.raises(sc.CertificateBundleError, match="malformed Fulcio extension"):
        sc.fulcio_extensions(leaf_with([(printable, False)]))
    assert sc.fulcio_extensions(leaf_with([])) == sc.FulcioExtensions("", "", "", "", "", "", "", "")


def test_signed_certificate_timestamps_rejects_malformed_lists() -> None:
    def leaf_with_sct_list(serialized: bytes) -> x509.Certificate:
        value = b"\x04" + der.encode_length(len(serialized)) + serialized
        ext = x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_SCT_LIST), value)
        return parse_certificate(pki.certificate("leaf", pki.p256(), extra=[(ext, False)]).der)

    with pytest.raises(sc.CertificateBundleError, match="no SCT list"):
        sc.signed_certificate_timestamps(parse_certificate(pki.certificate("leaf", pki.p256()).der))
    with pytest.raises(sc.CertificateBundleError, match="SCT list is empty"):
        sc.signed_certificate_timestamps(leaf_with_sct_list(b"\x00\x00"))
    with pytest.raises(sc.CertificateBundleError, match="trailing bytes"):
        sc.signed_certificate_timestamps(leaf_with_sct_list(b"\x00\x00\x00"))

    def sct_bytes(version: int) -> bytes:
        body = bytes([version]) + bytes(32) + (1700000000000).to_bytes(8, "big")
        body += b"\x00\x00" + bytes([4, 3]) + b"\x00\x02\x30\x00"
        return len(body).to_bytes(2, "big") + body

    good = sct_bytes(0)
    (parsed,) = sc.signed_certificate_timestamps(leaf_with_sct_list(len(good).to_bytes(2, "big") + good))
    assert parsed.timestamp == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert parsed.signature_algorithm == (4, 3)
    assert parsed.signature == b"\x30\x00"
    with pytest.raises(sc.CertificateBundleError, match="unsupported SCT version"):
        sc.signed_certificate_timestamps(leaf_with_sct_list(len(good).to_bytes(2, "big") + sct_bytes(1)))
    with pytest.raises(sc.CertificateBundleError, match="truncated"):
        sc.signed_certificate_timestamps(leaf_with_sct_list(len(good).to_bytes(2, "big") + good[:-1]))


# --- the registry-issuer path --------------------------------------------------


def rekor_log(key: ec.EllipticCurvePrivateKey, host: str) -> KeyedAuthority:
    spki = public_key_spki(key.public_key())
    return KeyedAuthority(
        base_url=f"https://{host}",
        log_id=hashlib.sha256(spki).digest(),
        public_key=key.public_key(),
        key_details="PKIX_ECDSA_P256_SHA_256",
        hash_algorithm="SHA2_256",
        valid_for=ValidFor(datetime(2024, 1, 1, tzinfo=UTC)),
    )


def checkpoint_for(log_key: ec.EllipticCurvePrivateKey, host: str, size: int, root_hash: bytes) -> str:
    text = f"{host}\n{size}\n{base64.b64encode(root_hash).decode()}\n"
    signature = log_key.sign(text.encode(), ec.ECDSA(hashes.SHA256()))
    hint = hashlib.sha256(public_key_spki(log_key.public_key())).digest()[:4]
    return text + "\n— " + host + " " + base64.b64encode(hint + signature).decode() + "\n"


def certified_fixture(
    *, san: str = "https://registry.tinfoil.sh/scopes/public", oidc_issuer: bool = False
) -> tuple[TrustedRoot, bm.Bundle, x509.Certificate, bytes]:
    issuer = pki.certificate("registry-root", pki.p256(), ca=True, key_usage=pki.CA_USAGE)
    extra: list[tuple[x509.ExtensionType, bool]] = []
    if oidc_issuer:
        extra.append((x509.UnrecognizedExtension(x509.ObjectIdentifier(sc.OID_FULCIO_ISSUER), b"\x0c\x01x"), False))
    leaf = pki.certificate(
        "registry-leaf",
        pki.p256(),
        issuer,
        subject_name=x509.Name([]),
        key_usage=pki.SIGNING_USAGE,
        eku=[ExtendedKeyUsageOID.CODE_SIGNING],
        sans=[x509.UniformResourceIdentifier(san)],
        san_critical=True,
        extra=extra,
    )
    statement = json.dumps(
        {
            "_type": bm.IN_TOTO_STATEMENT_V1,
            "subject": [{"name": "config", "digest": {"sha256": "ab" * 32}}],
            "predicateType": "https://tinfoil.sh/predicate/config-endorsement/v2",
            "predicate": {},
        }
    ).encode()
    pae = bm.pre_auth_encoding(bm.IN_TOTO_PAYLOAD_TYPE, statement)
    assert isinstance(leaf.key, ec.EllipticCurvePrivateKey)
    signature = leaf.key.sign(pae, ec.ECDSA(hashes.SHA256()))
    body = keyed.hashedrekord_body(
        keyed.HashedRekordBody(hashlib.sha256(pae).digest(), signature, leaf.der, "x509Certificate")
    )
    log_key = pki.p256()
    host = "rekor.test"
    leaf_hash = keyed.leaf_hash(body)
    entry = bm.TlogEntry(
        log_index=0,
        log_id=rekor_log(log_key, host).log_id,
        kind="hashedrekord",
        version="0.0.2",
        integrated_time=0,
        inclusion_promise=None,
        inclusion_proof=bm.InclusionProof(0, leaf_hash, 1, (), checkpoint_for(log_key, host, 1, leaf_hash)),
        canonicalized_body=body,
    )
    bundle = bm.Bundle(
        media_type=bm.BUNDLE_MEDIA_TYPE,
        material=bm.CertificateMaterial(leaf.der),
        tlog_entries=(entry,),
        rfc3161_timestamps=(b"\x30\x03\x02\x01\x00",),
        envelope=bm.DsseEnvelope(statement, bm.IN_TOTO_PAYLOAD_TYPE, (bm.DsseSignature(signature, ""),)),
    )
    root = TrustedRoot(
        tlogs=(rekor_log(log_key, host),), ctlogs=(), certificate_authorities=(), timestamp_authorities=()
    )
    return root, bundle, parse_certificate(issuer.der), bytes.fromhex("ab" * 32)


def test_verify_certified_bundle_accepts_a_registry_signed_approval() -> None:
    root, bundle, issuer, digest = certified_fixture()
    verified = sc.verify_certified_bundle(
        root, bundle, issuer, "https://registry.tinfoil.sh/scopes/public", digest, pki.AT
    )
    assert verified.signed_at == pki.AT
    assert verified.logged_at is None
    assert verified.extensions.issuer == ""


def test_verify_certified_bundle_rejections() -> None:
    root, bundle, issuer, digest = certified_fixture()
    san = "https://registry.tinfoil.sh/scopes/public"
    with pytest.raises(sc.CertificateBundleError, match="exactly one URI SAN naming the registry"):
        sc.verify_certified_bundle(root, bundle, issuer, san + "x", digest, pki.AT)
    with pytest.raises(sc.CertificateBundleError, match="do not name the artifact digest"):
        sc.verify_certified_bundle(root, bundle, issuer, san, bytes(32), pki.AT)
    other_issuer = parse_certificate(pki.certificate("registry-root", pki.p256(), ca=True, key_usage=pki.CA_USAGE).der)
    with pytest.raises(sc.CertificateBundleError, match="signing certificate"):
        sc.verify_certified_bundle(root, bundle, other_issuer, san, digest, pki.AT)
    with pytest.raises(sc.CertificateBundleError, match="signing certificate"):
        sc.verify_certified_bundle(root, bundle, issuer, san, digest, pki.NOT_AFTER.replace(year=2040))
    no_timestamp = dataclasses.replace(bundle, rfc3161_timestamps=())
    with pytest.raises(sc.CertificateBundleError, match="one bounded signature timestamp"):
        sc.verify_certified_bundle(root, no_timestamp, issuer, san, digest, pki.AT)
    (entry,) = bundle.tlog_entries
    unknown_log = dataclasses.replace(bundle, tlog_entries=(dataclasses.replace(entry, log_id=bytes(32)),))
    with pytest.raises(sc.CertificateBundleError, match="does not list"):
        sc.verify_certified_bundle(root, unknown_log, issuer, san, digest, pki.AT)
    other_body = dataclasses.replace(
        bundle, tlog_entries=(dataclasses.replace(entry, canonicalized_body=entry.canonicalized_body + b" "),)
    )
    with pytest.raises(sc.CertificateBundleError, match="body is not the hashedrekord record"):
        sc.verify_certified_bundle(root, other_body, issuer, san, digest, pki.AT)
    root, bundle, issuer, digest = certified_fixture(oidc_issuer=True)
    with pytest.raises(sc.CertificateBundleError, match="carries no OIDC issuer"):
        sc.verify_certified_bundle(root, bundle, issuer, san, digest, pki.AT)
    root, bundle, issuer, digest = certified_fixture(san="https://registry.tinfoil.sh/scopes/other")
    with pytest.raises(sc.CertificateBundleError, match="exactly one URI SAN naming the registry"):
        sc.verify_certified_bundle(root, bundle, issuer, san, digest, pki.AT)
