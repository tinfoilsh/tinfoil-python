"""The Sigstore trusted root: the transparency logs, CT logs, certificate authorities and timestamp authorities
that bundle verification trusts, each with its validity window.

The records here hold exactly the members that verification reads. The
wire document passes two gates: ``sigstore_models`` validates its shape
(required members, unknown members rejected at every depth, member types)
and the strict JSON parser supplies the values, so that every byte string
has one accepted base64 form and every time one accepted RFC 3339 form.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pydantic import ValidationError
from sigstore_models.trustroot.v1 import TrustedRoot as WireTrustedRoot

from tinfoil._v3.verifier import _canonical, _json
from tinfoil._v3.verifier._sigstore import _wire
from tinfoil._v3.verifier._trust import SIGSTORE_TRUSTED_ROOT_JSON
from tinfoil._v3.verifier._x509.certificate import (
    Certificate,
    PublicKey,
    X509Error,
    load_public_key_der,
    parse_certificate,
    verify_certificate_signature,
)
from tinfoil._v3.verifier._x509.certificate import issuer_name as _issuer_name
from tinfoil._v3.verifier._x509.certificate import subject_name as _subject_name

TRUSTED_ROOT_MEDIA_TYPE = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

HASH_ALGORITHM_SHA2_256 = "SHA2_256"
KEY_DETAILS_P256 = "PKIX_ECDSA_P256_SHA_256"
KEY_DETAILS_P384 = "PKIX_ECDSA_P384_SHA_384"
KEY_DETAILS_ED25519 = "PKIX_ED25519"
SUPPORTED_KEY_DETAILS = (KEY_DETAILS_P256, KEY_DETAILS_P384, KEY_DETAILS_ED25519)
LOG_ID_SIZE = 32


class TrustedRootError(ValueError):
    """A trusted root that fails to parse or names material that the verifier cannot use."""


@dataclass(frozen=True, slots=True)
class ValidFor:
    """A closed validity window: ``start`` and ``end`` are both inclusive; ``end`` None means still valid."""

    start: datetime
    end: datetime | None = None

    def contains(self, at: datetime) -> bool:
        """Whether ``at`` is within the window, start and end inclusive."""
        if at.tzinfo is None or at.utcoffset() is None:
            raise TrustedRootError("time must be timezone-aware")
        return self.start <= at and (self.end is None or at <= self.end)


@dataclass(frozen=True, slots=True)
class KeyedAuthority:
    """A transparency log or CT log: one public key identified by a log id."""

    base_url: str
    log_id: bytes
    """The 32-byte key id that bundles name the log by."""
    public_key: PublicKey
    key_details: str
    hash_algorithm: str
    valid_for: ValidFor
    checkpoint_key_id: bytes | None = None
    """The key id that signed checkpoints name (Rekor v2); None when the log uses ``log_id``."""


@dataclass(frozen=True, slots=True)
class CertificateAuthority:
    """A Fulcio or timestamp authority: a chain from the issuing certificate up to its self-signed root."""

    uri: str
    subject: str
    chain: tuple[Certificate, ...]
    """Leaf-first; the last entry is the root."""
    valid_for: ValidFor

    @property
    def root(self) -> Certificate:
        return self.chain[-1]


@dataclass(frozen=True, slots=True)
class TrustedRoot:
    """The parsed trusted root."""

    tlogs: tuple[KeyedAuthority, ...]
    ctlogs: tuple[KeyedAuthority, ...]
    certificate_authorities: tuple[CertificateAuthority, ...]
    timestamp_authorities: tuple[CertificateAuthority, ...]

    def tlog(self, log_id: bytes) -> KeyedAuthority | None:
        """The transparency log with ``log_id``, or None."""
        return _find(self.tlogs, log_id)

    def tlog_by_checkpoint_key_id(self, key_id: bytes) -> KeyedAuthority | None:
        """The transparency log whose checkpoints are signed under ``key_id``, or None."""
        for log in self.tlogs:
            if (log.checkpoint_key_id if log.checkpoint_key_id is not None else log.log_id) == key_id:
                return log
        return None

    def ctlog(self, log_id: bytes) -> KeyedAuthority | None:
        """The CT log with ``log_id``, or None."""
        return _find(self.ctlogs, log_id)

    def certificate_authorities_at(self, at: datetime) -> tuple[CertificateAuthority, ...]:
        """The certificate authorities whose window contains ``at``."""
        return tuple(ca for ca in self.certificate_authorities if ca.valid_for.contains(at))

    def timestamp_authorities_at(self, at: datetime) -> tuple[CertificateAuthority, ...]:
        """The timestamp authorities whose window contains ``at``."""
        return tuple(ta for ta in self.timestamp_authorities if ta.valid_for.contains(at))


def _find(logs: tuple[KeyedAuthority, ...], log_id: bytes) -> KeyedAuthority | None:
    for log in logs:
        if log.log_id == log_id:
            return log
    return None


def parse_trusted_root(data: bytes) -> TrustedRoot:
    """Decode a trusted-root document.

    Requires the v0.1 media type, keys of a supported type with a 32-byte
    log id, RFC 3339 times, and every certificate chain to parse and end
    in a self-signed root. Unknown members reject at every depth.
    """
    try:
        value = _json.strict_parse(data)
        _wire.check_member_names(value)
        WireTrustedRoot.model_validate_json(_json.serialize(value))
        root = _json.object_(value, "trusted root")
        if _json.string(root, "mediaType") != TRUSTED_ROOT_MEDIA_TYPE:
            raise TrustedRootError(f"unsupported trusted root media type {_json.string(root, 'mediaType')!r}")
        return TrustedRoot(
            tlogs=tuple(_keyed_authority(item, "tlogs") for item in _records(root, "tlogs")),
            ctlogs=tuple(_keyed_authority(item, "ctlogs") for item in _records(root, "ctlogs")),
            certificate_authorities=tuple(_authority(item) for item in _records(root, "certificateAuthorities")),
            timestamp_authorities=tuple(_authority(item) for item in _records(root, "timestampAuthorities")),
        )
    except ValidationError as err:
        raise TrustedRootError(f"trusted root does not match the schema: {_wire.first_error(err)}") from err
    except (_json.JsonError, _canonical.EncodingError, X509Error, _wire.WireError) as err:
        raise TrustedRootError(f"trusted root: {err}") from err


def embedded_trusted_root() -> TrustedRoot:
    """The trusted root that the verifier ships, parsed on each call."""
    return parse_trusted_root(SIGSTORE_TRUSTED_ROOT_JSON)


def _records(root: _json.JsonObject, key: str) -> tuple[_json.JsonObject, ...]:
    items = _json.array(root, key) or ()
    out: list[_json.JsonObject] = []
    for index, item in enumerate(items):
        if item is None:
            raise TrustedRootError(f"{key}[{index}] is null")
        out.append(_json.object_(item, f"{key}[{index}]"))
    return tuple(out)


def _keyed_authority(record: _json.JsonObject, what: str) -> KeyedAuthority:
    hash_algorithm = _json.string(record, "hashAlgorithm")
    if hash_algorithm != HASH_ALGORITHM_SHA2_256:
        raise TrustedRootError(f"unsupported {what} hash algorithm {hash_algorithm!r}")
    key_record = _json.struct(record, "publicKey", ("rawBytes", "keyDetails", "validFor"))
    spki = _canonical.decode_base64("publicKey rawBytes", _json.string(key_record, "rawBytes"))
    if not spki:
        raise TrustedRootError(f"{what} public key is empty")
    key_details = _json.string(key_record, "keyDetails")
    if key_details not in SUPPORTED_KEY_DETAILS:
        raise TrustedRootError(f"unsupported {what} key type {key_details!r}")
    public_key = load_public_key_der(spki)
    if _wire.key_details_of(public_key) != key_details:
        raise TrustedRootError(f"{what} key does not match its declared type {key_details!r}")
    log_id = _canonical.decode_base64("logId keyId", _json.string(_json.struct(record, "logId", ("keyId",)), "keyId"))
    if len(log_id) != LOG_ID_SIZE:
        raise TrustedRootError(f"{what} log id is not {LOG_ID_SIZE} bytes")
    checkpoint_key_id: bytes | None = None
    checkpoint_record = _json.opt_struct(record, "checkpointKeyId", ("keyId",))
    if checkpoint_record is not None:
        checkpoint_key_id = _canonical.decode_base64("checkpointKeyId keyId", _json.string(checkpoint_record, "keyId"))
        if not checkpoint_key_id:
            raise TrustedRootError(f"{what} checkpoint key id is empty")
    return KeyedAuthority(
        base_url=_json.string(record, "baseUrl"),
        log_id=log_id,
        public_key=public_key,
        key_details=key_details,
        hash_algorithm=hash_algorithm,
        valid_for=_valid_for(key_record, what),
        checkpoint_key_id=checkpoint_key_id,
    )


def _authority(record: _json.JsonObject) -> CertificateAuthority:
    uri = _json.string(record, "uri")
    chain_record = _json.struct(record, "certChain", ("certificates",))
    certificates = _json.array(chain_record, "certificates") or ()
    if not certificates:
        raise TrustedRootError(f"certificate authority {uri!r} has an empty certificate chain")
    chain: list[Certificate] = []
    for index, item in enumerate(certificates):
        if item is None:
            raise TrustedRootError(f"certificate authority {uri!r} chain entry {index} is null")
        raw = _canonical.decode_base64(
            "certificate rawBytes", _json.string(_json.object_(item, "certificate"), "rawBytes")
        )
        if not raw:
            raise TrustedRootError(f"certificate authority {uri!r} chain entry {index} is empty")
        chain.append(parse_certificate(raw))
    root = chain[-1]
    if _issuer_name(root) != _subject_name(root):
        raise TrustedRootError(f"certificate authority {uri!r} chain does not end in a self-signed root")
    verify_certificate_signature(root, root)
    subject_record = _json.struct(record, "subject", ("organization", "commonName"))
    return CertificateAuthority(
        uri=uri,
        subject=_json.string(subject_record, "commonName"),
        chain=tuple(chain),
        valid_for=_valid_for(record, f"certificate authority {uri!r}"),
    )


def _valid_for(record: _json.JsonObject, what: str) -> ValidFor:
    window = _json.struct(record, "validFor", ("start", "end"))
    start_text = _json.string(window, "start")
    if not start_text:
        raise TrustedRootError(f"{what} validity window has no start")
    start = _wire.rfc3339(start_text, f"{what} validFor.start")
    end_text = _json.string(window, "end")
    if not end_text:
        return ValidFor(start)
    end = _wire.rfc3339(end_text, f"{what} validFor.end")
    if end < start:
        raise TrustedRootError(f"{what} validity window ends before it starts")
    return ValidFor(start, end)
