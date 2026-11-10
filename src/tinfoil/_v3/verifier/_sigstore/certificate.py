"""Verification of certificate-signed bundles: the Fulcio path for release provenance and the registry-issuer path
for certified config approvals.

Both paths establish a signing time from verified material (a transparency
log receipt or an RFC 3161 timestamp, never the wall clock), build the
signing certificate's chain at that time, check the certificate's identity
and check the DSSE signature over the artifact digest.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil._v3.verifier import _canonical, _json
from tinfoil._v3.verifier._sigstore import _wire
from tinfoil._v3.verifier._sigstore.bundle import (
    IN_TOTO_PAYLOAD_TYPE,
    Bundle,
    BundleError,
    CertificateMaterial,
    TlogEntry,
    parse_statement,
    pre_auth_encoding,
)
from tinfoil._v3.verifier._sigstore.keyed import (
    HASHEDREKORD_KIND,
    HASHEDREKORD_VERSION,
    HashedRekordBody,
    KeyedBundleError,
    check_layout,
    leaf_hash,
    signature_timestamp,
    verify_checkpoint,
    verify_inclusion_promise,
    verify_log_entries,
    verify_merkle_inclusion,
    verify_signature,
)
from tinfoil._v3.verifier._sigstore.timestamp import TimestampError, verify_timestamp
from tinfoil._v3.verifier._sigstore.trusted_root import CertificateAuthority, KeyedAuthority, TrustedRoot
from tinfoil._v3.verifier._x509 import der
from tinfoil._v3.verifier._x509.certificate import (
    OID_EKU_CODE_SIGNING,
    OID_SCT_LIST,
    Certificate,
    X509Error,
    certificate_public_key,
    extension,
    parse_certificate,
    public_key_spki,
    uri_sans,
    valid_at,
    verify_chain,
)
from tinfoil._v3.verifier._x509.certificate import extensions as certificate_extensions

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
RUNNER_ENVIRONMENT_GITHUB_HOSTED = "github-hosted"

# Fulcio certificate extensions (1.3.6.1.4.1.57264.1.x).
OID_FULCIO_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"
"""The original issuer extension: a raw string rather than a DER one."""
OID_FULCIO_ISSUER = "1.3.6.1.4.1.57264.1.8"
OID_FULCIO_BUILD_SIGNER_URI = "1.3.6.1.4.1.57264.1.9"
OID_FULCIO_RUNNER_ENVIRONMENT = "1.3.6.1.4.1.57264.1.11"
OID_FULCIO_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12"
OID_FULCIO_SOURCE_REPOSITORY_DIGEST = "1.3.6.1.4.1.57264.1.13"
OID_FULCIO_SOURCE_REPOSITORY_REF = "1.3.6.1.4.1.57264.1.14"
OID_FULCIO_SOURCE_REPOSITORY_IDENTIFIER = "1.3.6.1.4.1.57264.1.15"
OID_FULCIO_SOURCE_REPOSITORY_OWNER_URI = "1.3.6.1.4.1.57264.1.16"
OID_FULCIO_SOURCE_REPOSITORY_OWNER_IDENTIFIER = "1.3.6.1.4.1.57264.1.17"

SCT_VERSION_V1 = 0
SCT_LOG_ID_SIZE = 32
SCT_HASH_SHA256 = 4
SCT_SIGNATURE_ECDSA = 3
SCT_SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP = 0
SCT_ENTRY_TYPE_PRECERT = 1

MAX_TLOG_ENTRIES = 32
"""The most transparency-log entries a certificate-signed bundle may carry."""
MAX_SIGNED_TIMESTAMPS = 32
"""The most RFC 3161 timestamps a certificate-signed bundle may carry."""

REKOR_V1_DSSE_KIND = "dsse"
REKOR_V1_DSSE_VERSION = "0.0.1"

_DER = serialization.Encoding.DER


class CertificateBundleError(ValueError):
    """A certificate-signed bundle that does not verify."""


@dataclass(frozen=True, slots=True)
class SigningIdentity:
    """What the signing certificate must assert: a SAN pattern, the OIDC issuer and the runner environment."""

    san: re.Pattern[str]
    issuer: str
    runner_environment: str


@dataclass(frozen=True, slots=True)
class FulcioExtensions:
    """The Fulcio extensions that the verifier reads from a signing certificate; "" when absent."""

    issuer: str
    source_repository_uri: str
    source_repository_digest: str
    source_repository_ref: str
    source_repository_identifier: str
    source_repository_owner_identifier: str
    runner_environment: str
    build_signer_uri: str


@dataclass(frozen=True, slots=True)
class SignedCertificateTimestamp:
    """One SCT from the leaf's embedded list."""

    log_id: bytes
    milliseconds: int
    """The log's timestamp as it was signed: milliseconds since the epoch, kept exact for the signed input."""
    timestamp: datetime
    """``milliseconds`` as an aware time, for the log's validity window."""
    signature_algorithm: tuple[int, int]
    """The TLS HashAlgorithm and SignatureAlgorithm codes."""
    signature: bytes
    extensions: bytes


@dataclass(frozen=True, slots=True)
class VerifiedBundle:
    """The outcome of verifying a certificate-signed bundle."""

    payload: bytes
    leaf: Certificate
    extensions: FulcioExtensions
    signed_at: datetime
    """The instant the chain was verified at: the earliest observer timestamp, or the log integrated time."""
    logged_at: datetime | None
    """The earliest verified transparency-log time, or None when only an RFC 3161 timestamp was verified."""


def workflow_identity_pattern(repo: str, workflow_pattern: str, ref_pattern: str) -> re.Pattern[str]:
    """An anchored SAN regex for a GitHub workflow of ``repo``.

    ``repo`` is escaped; ``workflow_pattern`` matches the workflow file
    name under ``.github/workflows/`` and ``ref_pattern`` the ref after
    ``@``. Each fragment is grouped so that an alternation inside it cannot
    escape the anchors.
    """
    return re.compile(
        rf"\Ahttps://github\.com/{re.escape(repo)}/\.github/workflows/(?:{workflow_pattern})@(?:{ref_pattern})\Z"
    )


_STRING_EXTENSIONS = {
    OID_FULCIO_BUILD_SIGNER_URI: "build_signer_uri",
    OID_FULCIO_RUNNER_ENVIRONMENT: "runner_environment",
    OID_FULCIO_SOURCE_REPOSITORY_URI: "source_repository_uri",
    OID_FULCIO_SOURCE_REPOSITORY_DIGEST: "source_repository_digest",
    OID_FULCIO_SOURCE_REPOSITORY_REF: "source_repository_ref",
    OID_FULCIO_SOURCE_REPOSITORY_IDENTIFIER: "source_repository_identifier",
    OID_FULCIO_SOURCE_REPOSITORY_OWNER_IDENTIFIER: "source_repository_owner_identifier",
}


def fulcio_extensions(leaf: Certificate) -> FulcioExtensions:
    """Read the Fulcio extensions, each a DER UTF8String; a malformed value is an error, an absent one is "".

    The issuer comes from the DER-encoded extension when present; the
    original raw-string issuer extension, when also present, must carry
    the same value and is used alone only when the DER one is absent.
    """
    values: dict[str, str] = dict.fromkeys(_STRING_EXTENSIONS.values(), "")
    issuer_v1: str | None = None
    issuer_v2: str | None = None
    try:
        for ext in certificate_extensions(leaf):
            if ext.oid == OID_FULCIO_ISSUER_V1:
                issuer_v1 = ext.value.decode("utf-8")
            elif ext.oid == OID_FULCIO_ISSUER:
                issuer_v2 = der.utf8_string(der.decode(ext.value))
            elif ext.oid in _STRING_EXTENSIONS:
                values[_STRING_EXTENSIONS[ext.oid]] = der.utf8_string(der.decode(ext.value))
    except (der.DerError, UnicodeDecodeError, X509Error) as err:
        raise CertificateBundleError(f"malformed Fulcio extension: {err}") from err
    if issuer_v1 is not None and issuer_v2 is not None and issuer_v1 != issuer_v2:
        raise CertificateBundleError("the signing certificate's issuer extensions disagree")
    issuer = issuer_v2 if issuer_v2 is not None else (issuer_v1 or "")
    return FulcioExtensions(issuer=issuer, **values)


def signed_certificate_timestamps(leaf: Certificate) -> tuple[SignedCertificateTimestamp, ...]:
    """Decode the leaf's embedded SCT list (RFC 6962 SignedCertificateTimestampList), in order."""
    ext = extension(leaf, OID_SCT_LIST)
    if ext is None:
        raise CertificateBundleError("the signing certificate carries no SCT list")
    try:
        serialized = der.octet_string(der.decode(ext.value))
    except (der.DerError, X509Error) as err:
        raise CertificateBundleError(f"SCT list: {err}") from err
    reader = _TlsReader(serialized)
    body = _TlsReader(reader.vector(2))
    reader.finish("SCT list")
    out: list[SignedCertificateTimestamp] = []
    while not body.done:
        out.append(_parse_sct(_TlsReader(body.vector(2))))
    if not out:
        raise CertificateBundleError("the signing certificate's SCT list is empty")
    return tuple(out)


def _parse_sct(reader: _TlsReader) -> SignedCertificateTimestamp:
    version = reader.u8()
    if version != SCT_VERSION_V1:
        raise CertificateBundleError(f"unsupported SCT version {version}")
    log_id = reader.take(SCT_LOG_ID_SIZE)
    milliseconds = reader.uint(8)
    extensions = reader.vector(2)
    algorithm = (reader.u8(), reader.u8())
    signature = reader.vector(2)
    reader.finish("SCT")
    try:
        timestamp = datetime.fromtimestamp(milliseconds / 1000, UTC)
    except (OverflowError, OSError, ValueError) as err:
        raise CertificateBundleError("SCT timestamp is not a representable time") from err
    return SignedCertificateTimestamp(
        log_id=log_id,
        milliseconds=milliseconds,
        timestamp=timestamp,
        signature_algorithm=algorithm,
        signature=signature,
        extensions=extensions,
    )


class _TlsReader:
    """A cursor over TLS-presentation-language bytes that rejects short and surplus input."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def done(self) -> bool:
        return self._pos == len(self._data)

    def take(self, count: int) -> bytes:
        if self._pos + count > len(self._data):
            raise CertificateBundleError("SCT list is truncated")
        out = self._data[self._pos : self._pos + count]
        self._pos += count
        return out

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def u8(self) -> int:
        return self.uint(1)

    def vector(self, length_size: int) -> bytes:
        return self.take(self.uint(length_size))

    def finish(self, what: str) -> None:
        if not self.done:
            raise CertificateBundleError(f"{what} has trailing bytes")


def check_duplicate_sct_logs(scts: tuple[SignedCertificateTimestamp, ...]) -> None:
    """Reject a list in which two SCTs name the same CT log."""
    seen: set[bytes] = set()
    for sct in scts:
        if sct.log_id in seen:
            raise CertificateBundleError(
                "duplicate SCT log id: leaf certificate carries multiple SCTs from the same CT log"
            )
        seen.add(sct.log_id)


def verify_scts(root: TrustedRoot, leaf: Certificate, issuers: tuple[Certificate, ...]) -> int:
    """Verify every embedded SCT against the CT logs valid at its timestamp and return how many verified.

    The signed input is the precertificate: the leaf's TBSCertificate
    with the SCT extension removed, prefixed by the hash of the issuer's
    key; ``issuers`` are the certificates that verified chains name as the
    leaf's issuer, and an SCT verifies under any of them. An SCT from an
    unknown log, outside its log's window, or that does not verify is an
    error, not a skip.
    """
    scts = signed_certificate_timestamps(leaf)
    check_duplicate_sct_logs(scts)
    tbs = precertificate_tbs(leaf)
    for index, sct in enumerate(scts):
        log = root.ctlog(sct.log_id)
        if log is None:
            raise CertificateBundleError(f"SCT {index} names a CT log the trusted root does not list")
        if not log.valid_for.contains(sct.timestamp):
            raise CertificateBundleError(f"SCT {index} is outside its CT log's validity window")
        if sct.signature_algorithm[0] != SCT_HASH_SHA256:
            raise CertificateBundleError(f"SCT {index} does not use SHA-256")
        if not any(_sct_verifies(sct, log, tbs, issuer) for issuer in issuers):
            raise CertificateBundleError(f"SCT {index} does not verify under its CT log key")
    return len(scts)


def _sct_verifies(sct: SignedCertificateTimestamp, log: KeyedAuthority, tbs: bytes, issuer: Certificate) -> bool:
    key = log.public_key
    if not isinstance(key, ec.EllipticCurvePublicKey) or sct.signature_algorithm[1] != SCT_SIGNATURE_ECDSA:
        return False
    issuer_key_hash = hashlib.sha256(public_key_spki(certificate_public_key(issuer))).digest()
    signed = b"".join(
        (
            bytes([SCT_VERSION_V1, SCT_SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP]),
            sct.milliseconds.to_bytes(8, "big"),
            SCT_ENTRY_TYPE_PRECERT.to_bytes(2, "big"),
            issuer_key_hash,
            len(tbs).to_bytes(3, "big"),
            tbs,
            len(sct.extensions).to_bytes(2, "big"),
            sct.extensions,
        )
    )
    size = 32 if isinstance(key.curve, ec.SECP256R1) else 48
    try:
        if der.raw_signature_to_der(der.ecdsa_signature_to_raw(sct.signature, size), size) != sct.signature:
            return False
        key.verify(sct.signature, signed, ec.ECDSA(hashes.SHA256()))
    except (der.DerError, InvalidSignature):
        return False
    return True


def precertificate_tbs(leaf: Certificate) -> bytes:
    """The leaf's TBSCertificate with the SCT list extension removed: what a CT log signed."""
    try:
        parts = der.children(der.decode(leaf.public_bytes(_DER)))
        fields = list(der.children(parts[0]))
        wrapper = fields[-1]
        if not der.is_context(wrapper, 3) or not wrapper.constructed:
            raise CertificateBundleError("the signing certificate has no extensions")
        (extension_list,) = der.children(wrapper)
        kept = [
            ext.raw
            for ext in der.expect_sequence(extension_list, "extensions")
            if der.object_identifier(der.expect_sequence(ext, "extension")[0]) != OID_SCT_LIST
        ]
    except der.DerError as err:
        raise CertificateBundleError(f"the signing certificate: {err}") from err
    sequence = _der_element(der.TAG_SEQUENCE | 0x20, b"".join(kept))
    fields[-1] = der.Element(der.CLASS_CONTEXT, True, 3, sequence, _der_element(0xA3, sequence))
    return _der_element(der.TAG_SEQUENCE | 0x20, b"".join(field.raw for field in fields))


def _der_element(identifier: int, content: bytes) -> bytes:
    return bytes([identifier]) + der.encode_length(len(content)) + content


def verify_certificate_chain_at(
    leaf: Certificate,
    authorities: tuple[CertificateAuthority, ...],
    at: datetime,
    *,
    extended_key_usage: str,
) -> CertificateAuthority:
    """Build the leaf's chain to one of ``authorities`` at ``at`` and return the authority that anchored it.

    Each authority's chain supplies the intermediates; the authority
    itself must be valid at ``at``.
    """
    return _chain_at(leaf, authorities, at, extended_key_usage)[0]


def _chain_at(
    leaf: Certificate, authorities: tuple[CertificateAuthority, ...], at: datetime, extended_key_usage: str
) -> tuple[CertificateAuthority, tuple[Certificate, ...]]:
    failures: list[str] = []
    for authority in authorities:
        if not authority.valid_for.contains(at):
            continue
        try:
            path = verify_chain(leaf, authority.chain[:-1], [authority.root], at, extended_key_usage=extended_key_usage)
        except X509Error as err:
            failures.append(f"{authority.uri}: {err}")
            continue
        return authority, path
    detail = f" ({'; '.join(failures)})" if failures else ""
    raise CertificateBundleError(f"leaf certificate verification failed at {at.isoformat()}{detail}")


def check_identity(leaf: Certificate, extensions: FulcioExtensions, identity: SigningIdentity) -> None:
    """Check that exactly one URI SAN matches ``identity.san`` and the issuer and runner-environment extensions equal
    the expected values."""
    try:
        sans = uri_sans(leaf)
    except X509Error as err:
        raise CertificateBundleError(f"signing certificate: {err}") from err
    if len(sans) != 1:
        raise CertificateBundleError(f"signing certificate must carry exactly one URI SAN, found {len(sans)}")
    if identity.san.search(sans[0]) is None:
        raise CertificateBundleError(f"signing identity {sans[0]!r} does not match the expected workflow identity")
    if extensions.issuer != identity.issuer:
        raise CertificateBundleError(f"signing certificate issuer {extensions.issuer!r} is not {identity.issuer!r}")
    if extensions.runner_environment != identity.runner_environment:
        raise CertificateBundleError(
            f"signing certificate runner environment {extensions.runner_environment!r} "
            f"is not {identity.runner_environment!r}"
        )


def verify_dsse_signature(leaf: Certificate, bundle: Bundle) -> None:
    """Check the envelope's one signature over the PAE with the leaf's key; the signature must carry no key id."""
    if len(bundle.envelope.signatures) != 1:
        raise CertificateBundleError("DSSE envelope must have exactly one signature")
    signature = bundle.envelope.signatures[0]
    if signature.keyid:
        raise CertificateBundleError("DSSE key id must be empty for a certificate-signed bundle")
    try:
        verify_signature(
            certificate_public_key(leaf),
            signature.sig,
            pre_auth_encoding(bundle.envelope.payload_type, bundle.envelope.payload),
        )
    except (KeyedBundleError, X509Error) as err:
        raise CertificateBundleError(f"DSSE signature does not verify under the signing certificate: {err}") from err


def verify_fulcio_bundle(root: TrustedRoot, bundle: Bundle, identity: SigningIdentity, digest: bytes) -> VerifiedBundle:
    """Verify a Fulcio-signed DSSE bundle: the production path for release provenance.

    In order: the bundle's material is a ``CertificateMaterial`` and its
    envelope an in-toto statement; every transparency-log entry verifies
    against a trusted log (inclusion proof and checkpoint, the promise when
    present, the body's binding to the signature and certificate); every
    RFC 3161 timestamp verifies; at least one observer timestamp (a
    verified promise's integrated time or a timestamp) establishes the
    signing time; the chain verifies to a Fulcio authority at every such
    time with the code-signing EKU; the SCTs verify (at least one, no
    duplicate logs); the identity matches; the DSSE signature verifies;
    the statement names ``digest`` as a subject.
    """
    if not isinstance(bundle.material, CertificateMaterial):
        raise CertificateBundleError("bundle has no signing certificate")
    if bundle.envelope.payload_type != IN_TOTO_PAYLOAD_TYPE:
        raise CertificateBundleError(f"unsupported DSSE payload type {bundle.envelope.payload_type!r}")
    if len(digest) != 32:
        raise CertificateBundleError("expected artifact digest is not SHA-256")
    try:
        leaf = parse_certificate(bundle.material.certificate)
    except X509Error as err:
        raise CertificateBundleError(f"signing certificate: {err}") from err

    log_times = _verify_log_entries(root, bundle, leaf)
    timestamp_times = _verify_signed_timestamps(root, bundle)
    observed = sorted([*log_times, *timestamp_times])
    if not observed:
        raise CertificateBundleError("no verified observer timestamp (no inclusion promise and no RFC 3161 timestamp)")

    issuers: list[Certificate] = []
    for at in observed:
        _, path = _chain_at(leaf, root.certificate_authorities, at, OID_EKU_CODE_SIGNING)
        if len(path) < 2:
            raise CertificateBundleError("the signing certificate has no issuer in its chain")
        if all(path[1].public_bytes(_DER) != issuer.public_bytes(_DER) for issuer in issuers):
            issuers.append(path[1])
    verify_scts(root, leaf, tuple(issuers))

    extensions = fulcio_extensions(leaf)
    check_identity(leaf, extensions, identity)
    verify_dsse_signature(leaf, bundle)
    _check_statement_names(bundle, digest)
    return VerifiedBundle(
        payload=bundle.envelope.payload,
        leaf=leaf,
        extensions=extensions,
        signed_at=observed[0],
        logged_at=min(log_times) if log_times else None,
    )


def _check_statement_names(bundle: Bundle, digest: bytes) -> None:
    try:
        statement = parse_statement(bundle.envelope.payload)
    except BundleError as err:
        raise CertificateBundleError(str(err)) from err
    if not any(subject.digest.get("sha256") == digest.hex() for subject in statement.subjects):
        raise CertificateBundleError("the statement's subjects do not name the artifact digest")


def _verify_signed_timestamps(root: TrustedRoot, bundle: Bundle) -> list[datetime]:
    if len(bundle.rfc3161_timestamps) > MAX_SIGNED_TIMESTAMPS:
        raise CertificateBundleError(f"too many signed timestamps: {len(bundle.rfc3161_timestamps)}")
    signature = bundle.envelope.signatures[0].sig
    times: list[datetime] = []
    for index, timestamp in enumerate(bundle.rfc3161_timestamps):
        try:
            times.append(verify_timestamp(root, timestamp, signature))
        except TimestampError as err:
            raise CertificateBundleError(f"signed timestamp {index}: {err}") from err
    return times


def _verify_log_entries(root: TrustedRoot, bundle: Bundle, leaf: Certificate) -> list[datetime]:
    """Verify every transparency-log entry and return the integrated times that verified promises attest.

    At least one entry is required; every entry must name a trusted log.
    """
    entries = bundle.tlog_entries
    if not entries:
        raise CertificateBundleError("no transparency log entry")
    if len(entries) > MAX_TLOG_ENTRIES:
        raise CertificateBundleError(f"too many tlog entries: {len(entries)} > {MAX_TLOG_ENTRIES}")
    seen: set[tuple[bytes, int]] = set()
    times: list[datetime] = []
    for index, entry in enumerate(entries):
        identity = (entry.log_id, entry.log_index)
        if identity in seen:
            raise CertificateBundleError("duplicate tlog entries found")
        seen.add(identity)
        log = root.tlog(entry.log_id)
        if log is None:
            raise CertificateBundleError(f"transparency log entry {index} names a log the trusted root does not list")
        try:
            if (entry.kind, entry.version) == (REKOR_V1_DSSE_KIND, REKOR_V1_DSSE_VERSION):
                at = _verify_rekor_v1_entry(root, entry, log, leaf, bundle)
                if at is not None:
                    times.append(at)
            elif (entry.kind, entry.version) == (HASHEDREKORD_KIND, HASHEDREKORD_VERSION):
                _verify_rekor_v2_entry(root, entry, leaf, bundle)
            else:
                raise CertificateBundleError(f"unsupported transparency log entry kind {entry.kind} {entry.version}")
        except KeyedBundleError as err:
            raise CertificateBundleError(f"transparency log entry {index}: {err}") from err
        except CertificateBundleError as err:
            raise CertificateBundleError(f"transparency log entry {index}: {err}") from err
    return times


def _verify_rekor_v1_entry(
    root: TrustedRoot, entry: TlogEntry, log: KeyedAuthority, leaf: Certificate, bundle: Bundle
) -> datetime | None:
    """Verify a Rekor v1 ``dsse`` 0.0.1 entry: its body names this envelope and certificate, its inclusion proof
    reaches the signed checkpoint and, when it carries a promise, the promise verifies. Returns the integrated time
    that a verified promise attests, else None."""
    _check_dsse_body(entry.canonicalized_body, leaf, bundle)
    proof = entry.inclusion_proof
    if proof is None and entry.inclusion_promise is None:
        raise CertificateBundleError("entry must contain an inclusion proof and/or promise")
    if proof is not None:
        checkpoint = verify_checkpoint(proof.checkpoint, log)
        if checkpoint.tree_size != proof.tree_size or checkpoint.root_hash != proof.root_hash:
            raise CertificateBundleError("inclusion proof does not state the checkpoint's tree size and root hash")
        verify_merkle_inclusion(
            leaf_hash(entry.canonicalized_body),
            proof.log_index,
            checkpoint.tree_size,
            proof.hashes,
            checkpoint.root_hash,
        )
    if entry.integrated_time and not valid_at(leaf, _integrated_time(entry)):
        raise CertificateBundleError("integrated time outside certificate validity")
    if entry.inclusion_promise is None:
        return None
    return verify_inclusion_promise(root, entry)


def _integrated_time(entry: TlogEntry) -> datetime:
    try:
        return datetime.fromtimestamp(entry.integrated_time, UTC)
    except (OverflowError, OSError, ValueError) as err:
        raise CertificateBundleError("integrated time is not a representable time") from err


_DSSE_BODY_MEMBERS = ("apiVersion", "kind", "spec")
_DSSE_SPEC_MEMBERS = ("envelopeHash", "payloadHash", "signatures")
_HASH_MEMBERS = ("algorithm", "value")
_DSSE_SIGNATURE_MEMBERS = ("signature", "verifier")


def _check_dsse_body(body: bytes, leaf: Certificate, bundle: Bundle) -> None:
    """The entry body must record this envelope's payload hash and its one signature under the signing certificate."""
    try:
        value = _json.strict_parse(body)
        if value is None:
            raise CertificateBundleError("entry body is null")
        record = _json.object_(value, "entry body", _DSSE_BODY_MEMBERS)
        if (
            _json.string(record, "kind") != REKOR_V1_DSSE_KIND
            or _json.string(record, "apiVersion") != REKOR_V1_DSSE_VERSION
        ):
            raise CertificateBundleError("entry body is not a dsse 0.0.1 record")
        spec = _json.struct(record, "spec", _DSSE_SPEC_MEMBERS)
        payload_hash = _json.struct(spec, "payloadHash", _HASH_MEMBERS)
        if _json.string(payload_hash, "algorithm") != "sha256":
            raise CertificateBundleError("entry payload hash algorithm is not sha256")
        if _json.string(payload_hash, "value") != hashlib.sha256(bundle.envelope.payload).hexdigest():
            raise CertificateBundleError("entry payload hash does not match the envelope payload")
        signatures = _json.array(spec, "signatures") or ()
        if len(signatures) != 1 or signatures[0] is None:
            raise CertificateBundleError("entry must record exactly one signature")
        signature = _json.object_(signatures[0], "signatures[0]", _DSSE_SIGNATURE_MEMBERS)
        if (
            _canonical.decode_base64("signature", _json.string(signature, "signature"))
            != bundle.envelope.signatures[0].sig
        ):
            raise CertificateBundleError("transparency log signature does not match")
        verifier_pem = _canonical.decode_base64("verifier", _json.string(signature, "verifier")).decode("ascii")
        blocks = der.pem_blocks(verifier_pem, "CERTIFICATE")
        if len(blocks) != 1 or blocks[0] != leaf.public_bytes(_DER):
            raise CertificateBundleError("transparency log certificate does not match")
    except (_json.JsonError, _canonical.EncodingError, der.DerError, UnicodeDecodeError) as err:
        raise CertificateBundleError(f"entry body: {err}") from err


def _verify_rekor_v2_entry(root: TrustedRoot, entry: TlogEntry, leaf: Certificate, bundle: Bundle) -> None:
    """Verify a Rekor v2 ``hashedrekord`` 0.0.2 entry whose verifier is the signing certificate.

    Such an entry attests no time; an integrated time that it nevertheless
    states must fall inside the certificate's validity.
    """
    if entry.integrated_time and not valid_at(leaf, _integrated_time(entry)):
        raise CertificateBundleError("integrated time outside certificate validity")
    key = certificate_public_key(leaf)
    key_details = _wire.key_details_of(key)
    if key_details == _wire.KEY_DETAILS_P256:
        digest = hashlib.sha256
    elif key_details == _wire.KEY_DETAILS_P384:
        digest = hashlib.sha384
    else:
        raise CertificateBundleError("hashedrekord entries require an ECDSA P-256 or P-384 signing key")
    expected = HashedRekordBody(
        digest=digest(pre_auth_encoding(bundle.envelope.payload_type, bundle.envelope.payload)).digest(),
        signature=bundle.envelope.signatures[0].sig,
        verifier=leaf.public_bytes(_DER),
        verifier_kind="x509Certificate",
        key_details=key_details,
    )
    single = Bundle(
        media_type=bundle.media_type,
        material=bundle.material,
        tlog_entries=(entry,),
        rfc3161_timestamps=bundle.rfc3161_timestamps,
        envelope=bundle.envelope,
    )
    verify_log_entries(root, single, expected)


def signed_timestamp(root: TrustedRoot, bundle: Bundle) -> datetime:
    """Verify the bundle's one RFC 3161 timestamp over the DSSE signature and return its genTime.

    Requires exactly one timestamp within MAX_TIMESTAMP_SIZE, verified by
    a timestamp authority whose window contains the genTime.
    """
    try:
        return verify_timestamp(root, signature_timestamp(bundle), bundle.envelope.signatures[0].sig)
    except (KeyedBundleError, TimestampError) as err:
        raise CertificateBundleError(str(err)) from err


def verify_certified_bundle(
    root: TrustedRoot, bundle: Bundle, issuer: Certificate, san_uri: str, digest: bytes, at: datetime
) -> VerifiedBundle:
    """Verify a bundle signed with a short-lived certificate issued by a registry issuer.

    ``at`` is the independently verified signing time (from
    ``signed_timestamp``). The leaf must chain directly to ``issuer`` at
    ``at``, carry exactly ``san_uri`` as its one URI SAN and no OIDC
    issuer, the transparency-log receipts (Rekor v2, naming the
    certificate) must verify, and the DSSE signature must verify over
    ``digest``.
    """
    if len(digest) != 32:
        raise CertificateBundleError("expected artifact digest is not SHA-256")
    try:
        check_layout(bundle, timestamps="one")
    except KeyedBundleError as err:
        raise CertificateBundleError(str(err)) from err
    if not isinstance(bundle.material, CertificateMaterial):
        raise CertificateBundleError("certified approval bundle must carry a signing certificate")
    try:
        leaf = parse_certificate(bundle.material.certificate)
        verify_chain(leaf, [], [issuer], at, extended_key_usage=OID_EKU_CODE_SIGNING)
        sans = uri_sans(leaf)
    except X509Error as err:
        raise CertificateBundleError(f"signing certificate: {err}") from err
    if sans != (san_uri,):
        raise CertificateBundleError("registry identity requires exactly one URI SAN naming the registry")
    extensions = fulcio_extensions(leaf)
    if extensions.issuer or extension(leaf, OID_FULCIO_ISSUER_V1) is not None:
        raise CertificateBundleError("a registry signing certificate carries no OIDC issuer")
    verify_dsse_signature(leaf, bundle)
    try:
        _verify_rekor_v2_entry_set(root, bundle, leaf)
    except KeyedBundleError as err:
        raise CertificateBundleError(str(err)) from err
    _check_statement_names(bundle, digest)
    return VerifiedBundle(
        payload=bundle.envelope.payload, leaf=leaf, extensions=extensions, signed_at=at, logged_at=None
    )


def _verify_rekor_v2_entry_set(root: TrustedRoot, bundle: Bundle, leaf: Certificate) -> None:
    key = certificate_public_key(leaf)
    if _wire.key_details_of(key) != _wire.KEY_DETAILS_P256:
        raise CertificateBundleError("a registry signing certificate must carry an ECDSA P-256 key")
    signed = pre_auth_encoding(bundle.envelope.payload_type, bundle.envelope.payload)
    verify_log_entries(
        root,
        bundle,
        HashedRekordBody(
            digest=hashlib.sha256(signed).digest(),
            signature=bundle.envelope.signatures[0].sig,
            verifier=leaf.public_bytes(_DER),
            verifier_kind="x509Certificate",
        ),
    )
