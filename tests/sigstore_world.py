"""A synthetic Sigstore world for the endorsement tests.

Everything is generated at test time: a Rekor v2 transparency log, a CT
log, a Fulcio-style certificate authority, a timestamp authority and an
approval signing key, plus builders for the material that they sign:
RFC 3161 tokens, key-signed and certificate-signed approval bundles,
registry signing certificates and Fulcio-signed provenance bundles with
Rekor receipts. The trusted root is produced as JSON and parsed by the
verifier, so the tests exercise the wire path.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests import pki
from tests.der_tree import encode_length
from tinfoil.verifier import _json
from tinfoil.verifier._sigstore import bundle as bm
from tinfoil.verifier._sigstore import certificate as sc
from tinfoil.verifier._sigstore import keyed
from tinfoil.verifier._sigstore.timestamp import SIGSTORE_TIMESTAMP_POLICY
from tinfoil.verifier._sigstore.trusted_root import TrustedRoot, parse_trusted_root
from tinfoil.verifier._x509.certificate import OID_SCT_LIST, parse_certificate, public_key_spki

REKOR_HOST = "rekor.test"
CT_HOST = "ctfe.test"
NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
"""The world's clock: every certificate and log is valid around it."""

_LIFETIME = timedelta(days=30)
_FULCIO_LEAF_LIFETIME = timedelta(minutes=10)
_SCOPE_ROOT_LIFETIME = timedelta(days=365)
_CERTIFICATE_VALIDITY = timedelta(minutes=10)
_CERTIFICATE_CLOCK_SKEW = timedelta(minutes=1)

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"

# --- DER ------------------------------------------------------------------------

_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(content)) + content


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(parts)))


def integer(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return tlv(0x02, value.to_bytes(length, "big", signed=True))


def oid(text: str) -> bytes:
    arcs = [int(part) for part in text.split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7F))
            arc >>= 7
        body += chunk
    return tlv(0x06, bytes(body))


def octet_string(data: bytes) -> bytes:
    return tlv(0x04, data)


def utf8_string(text: str) -> bytes:
    return tlv(0x0C, text.encode("utf-8"))


def explicit(number: int, inner: bytes) -> bytes:
    return tlv(0xA0 | number, inner)


def generalized_time(at: datetime) -> bytes:
    return tlv(0x18, at.astimezone(UTC).strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def rfc3339(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign_p256(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def as_json(value: dict[str, Any]) -> _json.JsonValue:
    """A JSON-ready dict as the parsed value that the verifier takes."""
    return _json.strict_parse(json.dumps(value).encode())


# --- The world ------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeCertificate:
    """A registry signing certificate with its issuer, both DER."""

    certificate: bytes
    issuer: bytes


@dataclass(frozen=True)
class FulcioIdentity:
    """What a Fulcio-style leaf asserts about the workflow that signed."""

    san: str
    issuer: str = GITHUB_ISSUER
    runner_environment: str = "github-hosted"
    source_repository_uri: str = ""
    source_repository_digest: str = "0123456789abcdef0123456789abcdef01234567"
    source_repository_ref: str = ""
    source_repository_identifier: str = ""
    source_repository_owner_identifier: str = ""


class World:
    """One synthetic Sigstore trust domain and the signers inside it."""

    def __init__(self, now: datetime = NOW) -> None:
        self.now = now
        self.key = pki.p256()
        """The approval signing key; also the registry root key of ``scope_certificate``."""
        self.log_key = pki.p256()
        self.ct_key = pki.p256()
        self.tsa_root = pki.certificate(
            "test timestamp root",
            pki.p256(),
            ca=True,
            key_usage=pki.CA_USAGE,
            not_before=now - _LIFETIME,
            not_after=now + _LIFETIME,
            serial=1,
        )
        self.tsa_leaf = pki.certificate(
            "test timestamp signer",
            pki.p256(),
            self.tsa_root,
            key_usage=pki.SIGNING_USAGE,
            eku=[ExtendedKeyUsageOID.TIME_STAMPING],
            eku_critical=True,
            not_before=now - _LIFETIME,
            not_after=now + _LIFETIME,
            serial=2,
        )
        self.fulcio_root = pki.certificate(
            "test fulcio root",
            pki.p256(),
            ca=True,
            key_usage=pki.CA_USAGE,
            not_before=now - _LIFETIME,
            not_after=now + _LIFETIME,
            serial=1,
        )
        self._root: TrustedRoot | None = None

    # -- trust --------------------------------------------------------------------

    @property
    def hint(self) -> str:
        return keyed.key_hint(self.key.public_key())

    @property
    def public_key_pem(self) -> str:
        return pki.public_pem(self.key)

    @property
    def log_id(self) -> bytes:
        return hashlib.sha256(public_key_spki(self.log_key.public_key())).digest()

    @property
    def ct_log_id(self) -> bytes:
        return hashlib.sha256(public_key_spki(self.ct_key.public_key())).digest()

    def trusted_root_json(
        self, *, tlogs: bool = True, ctlogs: bool = True, fulcio: bool = True, tsa: bool = True
    ) -> bytes:
        """The trusted-root document naming the world's log, CT log, certificate authority and timestamp
        authority; each may be left out."""
        start = rfc3339(self.now - _LIFETIME)

        def keyed_authority(host: str, key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
            spki = public_key_spki(key.public_key())
            return {
                "baseUrl": f"https://{host}",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": b64(spki),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {"start": start},
                },
                "logId": {"keyId": b64(hashlib.sha256(spki).digest())},
            }

        def authority(uri: str, common_name: str, chain: list[bytes]) -> dict[str, Any]:
            return {
                "subject": {"organization": "test", "commonName": common_name},
                "uri": uri,
                "certChain": {"certificates": [{"rawBytes": b64(der)} for der in chain]},
                "validFor": {"start": start},
            }

        return json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                "tlogs": [keyed_authority(REKOR_HOST, self.log_key)] if tlogs else [],
                "certificateAuthorities": [authority("https://fulcio.test", "fulcio", [self.fulcio_root.der])]
                if fulcio
                else [],
                "ctlogs": [keyed_authority(CT_HOST, self.ct_key)] if ctlogs else [],
                "timestampAuthorities": [authority("https://tsa.test", "tsa", [self.tsa_leaf.der, self.tsa_root.der])]
                if tsa
                else [],
            }
        ).encode()

    def trusted_root(self) -> TrustedRoot:
        if self._root is None:
            self._root = parse_trusted_root(self.trusted_root_json())
        return self._root

    # -- timestamps ---------------------------------------------------------------

    def timestamp(
        self,
        data: bytes,
        at: datetime,
        policy: str = SIGSTORE_TIMESTAMP_POLICY,
        *,
        signing_key: ec.EllipticCurvePrivateKey | None = None,
        extra_certificates: Sequence[bytes] = (),
    ) -> bytes:
        """A granted DER TimeStampResp over ``data`` at ``at``, signed by the timestamp authority. ``signing_key``
        signs in place of the authority's key, and ``extra_certificates`` are carried beside its certificate."""
        tst_info = seq(
            integer(1),
            oid(policy),
            seq(seq(oid(_OID_SHA256)), octet_string(hashlib.sha256(data).digest())),
            integer(7),
            generalized_time(at),
        )
        signed_attributes = set_of(
            seq(oid(_OID_CONTENT_TYPE), set_of(oid(_OID_TST_INFO))),
            seq(oid(_OID_MESSAGE_DIGEST), set_of(octet_string(hashlib.sha256(tst_info).digest()))),
        )
        leaf = x509.load_der_x509_certificate(self.tsa_leaf.der)
        key = signing_key or self.tsa_leaf.key
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        signer_info = seq(
            integer(1),
            seq(leaf.issuer.public_bytes(), integer(leaf.serial_number)),
            seq(oid(_OID_SHA256)),
            _implicit_attributes(signed_attributes),
            seq(oid(_OID_ECDSA_SHA256)),
            octet_string(sign_p256(key, signed_attributes)),
        )
        signed_data = seq(
            integer(3),
            set_of(seq(oid(_OID_SHA256))),
            seq(oid(_OID_TST_INFO), explicit(0, octet_string(tst_info))),
            tlv(0xA0, b"".join(sorted([self.tsa_leaf.der, *extra_certificates]))),
            set_of(signer_info),
        )
        token = seq(oid(_OID_SIGNED_DATA), explicit(0, signed_data))
        return seq(seq(integer(0)), token)

    # -- Rekor receipts -----------------------------------------------------------

    def checkpoint(self, size: int, root_hash: bytes) -> str:
        text = f"{REKOR_HOST}\n{size}\n{b64(root_hash)}\n"
        hint = hashlib.sha256(public_key_spki(self.log_key.public_key())).digest()[:4]
        return text + "\n— " + REKOR_HOST + " " + b64(hint + sign_p256(self.log_key, text.encode())) + "\n"

    def log_entry_v2(self, body: bytes) -> dict[str, Any]:
        """A Rekor v2 ``hashedrekord`` 0.0.2 receipt for ``body`` in a one-leaf tree."""
        leaf_hash = keyed.leaf_hash(body)
        return {
            "logIndex": "0",
            "logId": {"keyId": b64(self.log_id)},
            "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
            "inclusionProof": {
                "logIndex": "0",
                "rootHash": b64(leaf_hash),
                "treeSize": "1",
                "hashes": [],
                "checkpoint": {"envelope": self.checkpoint(1, leaf_hash)},
            },
            "canonicalizedBody": b64(body),
        }

    def log_entry_v1(self, payload: bytes, signature: bytes, certificate_der: bytes, at: datetime) -> dict[str, Any]:
        """A Rekor v1 ``dsse`` 0.0.1 receipt with an inclusion promise integrated at ``at`` and a one-leaf inclusion
        proof."""
        pem = "-----BEGIN CERTIFICATE-----\n" + b64(certificate_der) + "\n-----END CERTIFICATE-----\n"
        body = _json.canonicalize(
            as_json(
                {
                    "apiVersion": "0.0.1",
                    "kind": "dsse",
                    "spec": {
                        "envelopeHash": {"algorithm": "sha256", "value": hashlib.sha256(signature).hexdigest()},
                        "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(payload).hexdigest()},
                        "signatures": [{"signature": b64(signature), "verifier": b64(pem.encode())}],
                    },
                }
            )
        )
        integrated_time = int(at.timestamp())
        record = _json.JsonObject(
            {
                "body": b64(body),
                "integratedTime": _json.JsonNumber(str(integrated_time)),
                "logID": self.log_id.hex(),
                "logIndex": _json.JsonNumber("0"),
            }
        )
        leaf_hash = keyed.leaf_hash(body)
        return {
            "logIndex": "0",
            "logId": {"keyId": b64(self.log_id)},
            "kindVersion": {"kind": "dsse", "version": "0.0.1"},
            "integratedTime": str(integrated_time),
            "inclusionPromise": {"signedEntryTimestamp": b64(sign_p256(self.log_key, _json.canonicalize(record)))},
            "inclusionProof": {
                "logIndex": "0",
                "rootHash": b64(leaf_hash),
                "treeSize": "1",
                "hashes": [],
                "checkpoint": {"envelope": self.checkpoint(1, leaf_hash)},
            },
            "canonicalizedBody": b64(body),
        }

    # -- approval bundles ---------------------------------------------------------

    def keyed_bundle(self, payload: bytes, key: ec.EllipticCurvePrivateKey | None = None) -> dict[str, Any]:
        """A v0.3 DSSE bundle over ``payload`` signed under ``key`` (the world's approval key by default), named by
        its hint and logged in the Rekor v2 log."""
        key = key or self.key
        pae = bm.pre_auth_encoding(bm.IN_TOTO_PAYLOAD_TYPE, payload)
        signature = sign_p256(key, pae)
        body = keyed.hashedrekord_body(
            keyed.HashedRekordBody(
                hashlib.sha256(pae).digest(), signature, public_key_spki(key.public_key()), "publicKey"
            )
        )
        return {
            "mediaType": bm.BUNDLE_MEDIA_TYPE,
            "verificationMaterial": {
                "publicKey": {"hint": keyed.key_hint(key.public_key())},
                "tlogEntries": [self.log_entry_v2(body)],
            },
            "dsseEnvelope": {
                "payload": b64(payload),
                "payloadType": bm.IN_TOTO_PAYLOAD_TYPE,
                "signatures": [{"sig": b64(signature)}],
            },
        }

    def certified_bundle(
        self, payload: bytes, certificate: ScopeCertificate, key: ec.EllipticCurvePrivateKey, at: datetime
    ) -> dict[str, Any]:
        """A bundle signed under ``certificate`` (whose key is ``key``), timestamped at ``at`` and logged with the
        certificate as the verifier."""
        pae = bm.pre_auth_encoding(bm.IN_TOTO_PAYLOAD_TYPE, payload)
        signature = sign_p256(key, pae)
        body = keyed.hashedrekord_body(
            keyed.HashedRekordBody(hashlib.sha256(pae).digest(), signature, certificate.certificate, "x509Certificate")
        )
        return {
            "mediaType": bm.BUNDLE_MEDIA_TYPE,
            "verificationMaterial": {
                "certificate": {"rawBytes": b64(certificate.certificate)},
                "tlogEntries": [self.log_entry_v2(body)],
                "timestampVerificationData": {
                    "rfc3161Timestamps": [{"signedTimestamp": b64(self.timestamp(signature, at))}]
                },
            },
            "dsseEnvelope": {
                "payload": b64(payload),
                "payloadType": bm.IN_TOTO_PAYLOAD_TYPE,
                "signatures": [{"sig": b64(signature)}],
            },
        }

    def scope_certificate(
        self,
        key: ec.EllipticCurvePrivateKey,
        registry_id: str,
        now: datetime | None = None,
        root_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> ScopeCertificate:
        """A registry signing certificate for ``key``'s public key naming ``registry_id``, issued by a root under
        ``root_key`` (the world's approval key by default)."""
        now = now or self.now
        root_key = root_key or self.key
        issuer = pki.certificate(
            "registry test root",
            root_key,
            ca=True,
            path_length=0,
            key_usage=_REGISTRY_ROOT_USAGE,
            not_before=now - timedelta(hours=1),
            not_after=now + _SCOPE_ROOT_LIFETIME,
            serial=1,
        )
        leaf = pki.certificate(
            "",
            key,
            issuer,
            subject_name=x509.Name([]),
            key_usage=pki.SIGNING_USAGE,
            eku=[ExtendedKeyUsageOID.CODE_SIGNING],
            sans=[x509.UniformResourceIdentifier(registry_id)],
            san_critical=True,
            not_before=now - _CERTIFICATE_CLOCK_SKEW,
            not_after=now + _CERTIFICATE_VALIDITY - _CERTIFICATE_CLOCK_SKEW,
            serial=1,
        )
        return ScopeCertificate(certificate=leaf.der, issuer=issuer.der)

    # -- Fulcio provenance --------------------------------------------------------

    def fulcio_leaf(self, identity: FulcioIdentity, key: ec.EllipticCurvePrivateKey, at: datetime) -> pki.Issued:
        """A short-lived signing certificate around ``at`` carrying the workflow identity and an SCT from the CT
        log."""
        extensions: list[tuple[x509.ExtensionType, bool]] = []
        for oid_text, value in (
            (sc.OID_FULCIO_ISSUER, identity.issuer),
            (sc.OID_FULCIO_BUILD_SIGNER_URI, identity.san),
            (sc.OID_FULCIO_RUNNER_ENVIRONMENT, identity.runner_environment),
            (sc.OID_FULCIO_SOURCE_REPOSITORY_URI, identity.source_repository_uri),
            (sc.OID_FULCIO_SOURCE_REPOSITORY_DIGEST, identity.source_repository_digest),
            (sc.OID_FULCIO_SOURCE_REPOSITORY_REF, identity.source_repository_ref),
            (sc.OID_FULCIO_SOURCE_REPOSITORY_IDENTIFIER, identity.source_repository_identifier),
            (sc.OID_FULCIO_SOURCE_REPOSITORY_OWNER_IDENTIFIER, identity.source_repository_owner_identifier),
        ):
            if value:
                extensions.append(
                    (x509.UnrecognizedExtension(x509.ObjectIdentifier(oid_text), utf8_string(value)), False)
                )

        def issue(extra: list[tuple[x509.ExtensionType, bool]]) -> pki.Issued:
            return pki.certificate(
                "",
                key,
                self.fulcio_root,
                subject_name=x509.Name([]),
                key_usage=pki.SIGNING_USAGE,
                eku=[ExtendedKeyUsageOID.CODE_SIGNING],
                sans=[x509.UniformResourceIdentifier(identity.san)],
                san_critical=True,
                extra=extra,
                not_before=at - _FULCIO_LEAF_LIFETIME / 2,
                not_after=at + _FULCIO_LEAF_LIFETIME / 2,
                serial=4242,
            )

        precertificate = issue(extensions)
        tbs = x509.load_der_x509_certificate(precertificate.der).tbs_certificate_bytes
        sct = self.sct(tbs, at)
        leaf = issue([*extensions, (x509.UnrecognizedExtension(x509.ObjectIdentifier(OID_SCT_LIST), sct), False)])
        assert sc.precertificate_tbs(parse_certificate(leaf.der)) == tbs
        return leaf

    def sct(self, precertificate_tbs: bytes, at: datetime, extensions: bytes = b"") -> bytes:
        """The SCT list extension value (an OCTET STRING) holding one SCT from the CT log over the
        precertificate."""
        milliseconds = int(at.timestamp() * 1000)
        issuer_key_hash = hashlib.sha256(public_key_spki(self.fulcio_root.key.public_key())).digest()
        signed = b"".join(
            (
                bytes([0, 0]),
                milliseconds.to_bytes(8, "big"),
                (1).to_bytes(2, "big"),
                issuer_key_hash,
                len(precertificate_tbs).to_bytes(3, "big"),
                precertificate_tbs,
                len(extensions).to_bytes(2, "big"),
                extensions,
            )
        )
        signature = sign_p256(self.ct_key, signed)
        sct = b"".join(
            (
                bytes([0]),
                self.ct_log_id,
                milliseconds.to_bytes(8, "big"),
                len(extensions).to_bytes(2, "big"),
                extensions,
                bytes([4, 3]),
                len(signature).to_bytes(2, "big"),
                signature,
            )
        )
        entries = len(sct).to_bytes(2, "big") + sct
        serialized = len(entries).to_bytes(2, "big") + entries
        return octet_string(serialized)

    def fulcio_bundle(
        self,
        payload: bytes,
        identity: FulcioIdentity,
        at: datetime | None = None,
        *,
        receipt: str = "v1",
        timestamp: bool = False,
    ) -> dict[str, Any]:
        """A provenance bundle: a fresh Fulcio-style leaf signs ``payload`` at ``at``; the Rekor receipt is a v1
        ``dsse`` entry with a promise (the log time) or a v2 ``hashedrekord`` entry (no time), and a signature
        timestamp may be added."""
        at = at or self.now
        key = pki.p256()
        leaf = self.fulcio_leaf(identity, key, at)
        pae = bm.pre_auth_encoding(bm.IN_TOTO_PAYLOAD_TYPE, payload)
        signature = sign_p256(key, pae)
        if receipt == "v1":
            entry = self.log_entry_v1(payload, signature, leaf.der, at)
        else:
            body = keyed.hashedrekord_body(
                keyed.HashedRekordBody(hashlib.sha256(pae).digest(), signature, leaf.der, "x509Certificate")
            )
            entry = self.log_entry_v2(body)
        material: dict[str, Any] = {"certificate": {"rawBytes": b64(leaf.der)}, "tlogEntries": [entry]}
        if timestamp:
            material["timestampVerificationData"] = {
                "rfc3161Timestamps": [{"signedTimestamp": b64(self.timestamp(signature, at))}]
            }
        return {
            "mediaType": bm.BUNDLE_MEDIA_TYPE,
            "verificationMaterial": material,
            "dsseEnvelope": {
                "payload": b64(payload),
                "payloadType": bm.IN_TOTO_PAYLOAD_TYPE,
                "signatures": [{"sig": b64(signature)}],
            },
        }


_REGISTRY_ROOT_USAGE = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)


def _implicit_attributes(signed_attributes: bytes) -> bytes:
    """The signed attributes as ``[0] IMPLICIT``: the SET's content under the context tag (the signature itself
    covers the SET form)."""
    first = signed_attributes[1]
    header = 2 + (first & 0x7F if first & 0x80 else 0)
    return tlv(0xA0, signed_attributes[header:])


def statement(subjects: list[dict[str, Any]], predicate_type: str, predicate: dict[str, Any]) -> bytes:
    """An in-toto v1 statement payload."""
    return json.dumps(
        {"_type": bm.IN_TOTO_STATEMENT_V1, "subject": subjects, "predicateType": predicate_type, "predicate": predicate}
    ).encode()
