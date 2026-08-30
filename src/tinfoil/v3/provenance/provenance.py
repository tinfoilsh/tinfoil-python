"""Sigstore verification of Tinfoil reference values (Go:
verifier/provenance/provenance.go): verifies Sigstore-signed bundles against
the pinned Tinfoil workflow identities, producing verified value types - the
code measurement (with its declared VM shape) and the platform-endorsements
artifact.

Core Sigstore verification (certificate chain to the Fulcio root of the
supplied trusted-root JSON, SCT against the trusted CT log keys,
transparency-log entry: Merkle inclusion proof + signed checkpoint + SET,
observer/integrated timestamp within certificate validity, DSSE signature
under the leaf key, dsse/0.0.1 log-entry body consistency) is delegated to
sigstore-python's Verifier.verify_dsse, which mirrors sigstore-go's
SignedEntityVerifier configured with WithSignedCertificateTimestamps(1) +
WithTransparencyLog(1) + WithObserverTimestamps(1). Everything sigstore-go
does not provide there - media-type gate, legacy-layout rejection,
signature-count rule, duplicate-SCT-log rejection, SAN-regex certificate
identity, issuer/runner_environment extensions, artifact-digest policy,
strict statement parsing, source ref/commit recovery - is implemented here,
mirroring the Go code. All errors carry PROVENANCE_REJECTED."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.x509 import ObjectIdentifier

from sigstore.errors import VerificationError as _SigstoreVerificationError
from sigstore.models import Bundle as _SigstoreBundle
from sigstore.models import TrustedRoot as _SigstoreTrustedRoot
from sigstore.verify.verifier import Verifier as _SigstoreVerifier
from sigstore_models.trustroot import v1 as _trustroot_v1

from .. import strictjson
from ..bytesutil import decode_hex
from ..embedded_roots import TRUSTED_ROOT_JSON
from ..errors import PROVENANCE_REJECTED, VerificationError
from ..measurement import SNP_TDX_MULTI_PLATFORM_V1, Measurement
from ..policy import ARTIFACT_FORMAT, Artifact, Shape, parse_artifact
from ..strictjson import RAW
from .bundle_format import (
    parse_bundle,
    reject_legacy_bundle_format,
    require_exactly_one_dsse_signature,
)

OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# platform_endorsements_repo publishes the platform-endorsements artifact.
PLATFORM_ENDORSEMENTS_REPO = "tinfoilsh/platform-endorsements"
FRESHNESS_WITNESS_REPO = "tinfoilsh/freshness-witness"

IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Fulcio certificate-extension OIDs (github.com/sigstore/fulcio spec).
_OID_ISSUER_V1 = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")  # raw string value
_OID_ISSUER_V2 = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")  # DER string
_OID_RUNNER_ENVIRONMENT = ObjectIdentifier("1.3.6.1.4.1.57264.1.11")  # DER string
_OID_SOURCE_REPO_DIGEST = ObjectIdentifier("1.3.6.1.4.1.57264.1.13")  # DER string
_OID_SOURCE_REPO_REF = ObjectIdentifier("1.3.6.1.4.1.57264.1.14")  # DER string


def _prov_error(message: str) -> VerificationError:
    return VerificationError(PROVENANCE_REJECTED, message)


# repo_name_re matches a GitHub "owner/name" repository slug.
REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def github_workflow_identity_pattern(
    repo: str, workflow_pattern: str, ref_pattern: str
) -> str:
    return (
        "^https://github\\.com/"
        + re.escape(repo)
        + "/\\.github/workflows/"
        + workflow_pattern
        + "@"
        + ref_pattern
        + "$"
    )


# platform_endorsements_identity is the only signing certificate identity
# accepted for the platform-endorsements artifact: the tag-triggered build
# workflow of the publisher repo. Dots are escaped and the pattern is anchored
# at both ends so no other workflow path, ref type, or trailing SAN content
# can match.
PLATFORM_ENDORSEMENTS_IDENTITY = github_workflow_identity_pattern(
    PLATFORM_ENDORSEMENTS_REPO, r"build\.yml", r"refs/tags/v[0-9][^@]*"
)
FRESHNESS_WITNESS_IDENTITY = github_workflow_identity_pattern(
    FRESHNESS_WITNESS_REPO, r"freshness\.yml", r"refs/heads/main"
)


def signing_identity(repo: str) -> str:
    """The anchored SAN regex accepted for artifacts signed from repo: one
    workflow file directly under the repository's .github/workflows directory,
    run from a tag ref. The repository name is validated and escaped so it
    cannot alter the pattern."""
    if REPO_NAME_RE.fullmatch(repo) is None:
        raise _prov_error(f"invalid repository name {repo!r}")
    return github_workflow_identity_pattern(repo, r"[^/@]+", r"refs/tags/[^@]+")


@dataclass
class AuthenticatedArtifact:
    """Release identity recovered from a verified Sigstore statement and its
    signing certificate."""

    repo: str
    tag: str
    commit: str
    subject_name: str
    digest: str


@dataclass
class Code(AuthenticatedArtifact):
    """The verified content of a code-provenance bundle."""

    # measurement is the attested launch measurement.
    measurement: Measurement
    # shape is the VM shape the artifact declares.
    shape: Shape


@dataclass
class PlatformEndorsements(AuthenticatedArtifact):
    artifact: Artifact


@dataclass
class StatementSubject:
    name: str
    digest: dict[str, str]


@dataclass
class Statement:
    """The in-toto statement recovered from the DSSE payload, mirroring
    sigstore-go's protojson decode into in_toto.Statement. predicate is None
    when the statement carries a JSON null (nil Struct in Go)."""

    type: str
    subject: list[StatementSubject]
    predicate_type: str
    predicate: Optional[dict[str, Any]]


@dataclass
class VerifiedBundle:
    """The parts of sigstore-go's verify.VerificationResult this package
    consumes."""

    statement: Statement
    cert: x509.Certificate
    # tlog_timestamps are the Type=="Tlog" observer timestamps: the integrated
    # time of every verified transparency-log entry.
    tlog_timestamps: list[datetime]


# --- in-toto statement parsing (protojson semantics) --------------------------

# protojson accepts both the JSON name and the original proto field name.
_STATEMENT_MEMBERS = {
    "_type": "type",
    "type": "type",
    "subject": "subject",
    "predicateType": "predicate_type",
    "predicate_type": "predicate_type",
    "predicate": "predicate",
}

_SUBJECT_MEMBERS = frozenset(
    (
        "name",
        "uri",
        "digest",
        "content",
        "downloadLocation",
        "download_location",
        "mediaType",
        "media_type",
        "annotations",
    )
)


def _is_plain_object(v: Any) -> bool:
    return isinstance(v, dict)


def _parse_statement(payload: bytes) -> Statement:
    """Decode the DSSE payload as an in-toto statement, mirroring
    sigstore-go's Envelope.Statement(): the JSON must be valid UTF-8 with no
    duplicate members anywhere (protojson), unknown statement members reject,
    and member types are enforced."""
    try:
        # The raw-schema walk enforces protojson's structural rules: valid
        # UTF-8, no duplicate object members anywhere, no trailing data.
        strictjson.unmarshal(payload, RAW)
        v = json.loads(bytes(payload).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise _prov_error(f"parsing in-toto statement: {e}") from None
    if not _is_plain_object(v):
        raise _prov_error("in-toto statement is not a JSON object")

    out: dict[str, Any] = {}
    for key, value in v.items():
        prop = _STATEMENT_MEMBERS.get(key)
        if prop is None:
            raise _prov_error(f"in-toto statement has unknown member {key!r}")
        if prop in out:
            raise _prov_error(f"in-toto statement has duplicate member {key!r}")
        out[prop] = value

    type_ = out.get("type") or ""
    if not isinstance(type_, str):
        raise _prov_error("in-toto statement _type is not a string")
    predicate_type = out.get("predicate_type") or ""
    if not isinstance(predicate_type, str):
        raise _prov_error("in-toto statement predicateType is not a string")
    raw_subject = out.get("subject")
    if raw_subject is not None and not isinstance(raw_subject, list):
        raise _prov_error("in-toto statement subject is not an array")
    subject = [_parse_subject(s) for s in (raw_subject or [])]
    raw_predicate = out.get("predicate")
    if raw_predicate is not None and not _is_plain_object(raw_predicate):
        raise _prov_error("in-toto statement predicate is not an object")
    return Statement(
        type=type_,
        subject=subject,
        predicate_type=predicate_type,
        predicate=raw_predicate,
    )


def _parse_subject(s: Any) -> StatementSubject:
    if not _is_plain_object(s):
        raise _prov_error("in-toto statement subject entry is not an object")
    for key in s:
        if key not in _SUBJECT_MEMBERS:
            raise _prov_error(f"in-toto statement subject has unknown member {key!r}")
    name = s.get("name") or ""
    if not isinstance(name, str):
        raise _prov_error("in-toto statement subject name is not a string")
    raw_digest = s.get("digest")
    if raw_digest is not None and not _is_plain_object(raw_digest):
        raise _prov_error("in-toto statement subject digest is not an object")
    digest: dict[str, str] = {}
    for alg, value in (raw_digest or {}).items():
        if not isinstance(value, str):
            raise _prov_error("in-toto statement subject digest value is not a string")
        digest[alg] = value
    return StatementSubject(name=name, digest=digest)


# --- artifact digest policy ----------------------------------------------------

# Mirror sigstore-go's verifyEnvelopeWithArtifactDigests DoS limits.
_MAX_ALLOWED_SUBJECTS = 1024
_MAX_ALLOWED_SUBJECT_DIGESTS = 32


def _check_artifact_digest(statement: Statement, hex_digest: str) -> None:
    """sigstore-go's WithArtifactDigest: the digest must match SOME subject;
    every declared subject digest must be decodable hex. The caller then
    narrows to subject[0] via _enforce_subject0_digest."""
    want = hex_digest.lower()
    if len(statement.subject) > _MAX_ALLOWED_SUBJECTS:
        raise _prov_error(
            f"too many subjects: {len(statement.subject)} > {_MAX_ALLOWED_SUBJECTS}"
        )
    found = False
    for subject in statement.subject:
        if len(subject.digest) > _MAX_ALLOWED_SUBJECT_DIGESTS:
            raise _prov_error(
                f"too many digests: {len(subject.digest)} > {_MAX_ALLOWED_SUBJECT_DIGESTS}"
            )
        for alg, value in subject.digest.items():
            try:
                decode_hex(value)
            except ValueError as e:
                raise _prov_error(f"unable to decode subject digest: {e}") from None
            if alg == "sha256" and value.lower() == want:
                found = True
    if not found:
        raise _prov_error("provided artifact digest does not match any digest in statement")


def _enforce_subject0_digest(statement: Statement, expected_digest: str) -> None:
    """SPEC 5.4: only the FIRST in-toto subject is checked against the
    expected artifact digest; digests are compared case-insensitively
    (lowercase-normalized per SPEC 7.3)."""
    if len(statement.subject) == 0:
        raise _prov_error("in-toto statement has no subject")
    got = statement.subject[0].digest.get("sha256", "")
    if got.lower() != expected_digest.lower():
        raise _prov_error(
            f"subject[0] digest {got!r} does not match expected artifact digest "
            f"{expected_digest!r}"
        )


# --- certificate extensions ----------------------------------------------------

# Go's encoding/asn1 unmarshals a string from UTF8String, PrintableString, or
# IA5String; length must be definite, minimal, and exact.
_DER_STRING_TAGS = frozenset((0x0C, 0x13, 0x16))


def _parse_der_string(data: bytes) -> str:
    if len(data) < 2:
        raise ValueError("truncated DER string")
    if data[0] not in _DER_STRING_TAGS:
        raise ValueError(f"unexpected DER string tag 0x{data[0]:02x}")
    first = data[1]
    idx = 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise ValueError("indefinite DER length")
    else:
        n = first & 0x7F
        if n == 0 or n > 8 or 2 + n > len(data):
            raise ValueError("invalid DER length")
        if data[2] == 0:
            raise ValueError("non-minimal DER length")
        length = int.from_bytes(data[2 : 2 + n], "big")
        if length < 0x80:
            raise ValueError("non-minimal DER length")
        idx = 2 + n
    if idx + length != len(data):
        raise ValueError("DER string length mismatch")
    return data[idx : idx + length].decode("utf-8")


def _ext_value(cert: x509.Certificate, oid: ObjectIdentifier) -> Optional[bytes]:
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None
    value = ext.value
    if isinstance(value, x509.UnrecognizedExtension):
        return value.value
    return ext.value.public_bytes()  # pragma: no cover - Fulcio OIDs are unrecognized


def _der_string_ext(cert: x509.Certificate, oid: ObjectIdentifier) -> str:
    """The DER-encoded string value of an extension, or "" when absent
    (matching sigstore-go's certificate.Extensions zero value)."""
    raw = _ext_value(cert, oid)
    if raw is None:
        return ""
    try:
        return _parse_der_string(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise _prov_error(f"parsing certificate extension {oid.dotted_string}: {e}") from None


def _cert_issuer(cert: x509.Certificate) -> str:
    """The Fulcio OIDC issuer: OID .1.8 (DER string), falling back to the
    deprecated .1.1 raw form (sigstore-go certificate.ParseExtensions)."""
    v2 = _der_string_ext(cert, _OID_ISSUER_V2)
    if v2 != "":
        return v2
    raw = _ext_value(cert, _OID_ISSUER_V1)
    if raw is None:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _prov_error(f"parsing certificate issuer extension: {e}") from None


def _subject_alternative_names(cert: x509.Certificate) -> list[str]:
    """All SAN strings of the certificate (sigstore-go SANMatcher gathers DNS
    names, email addresses, and URIs)."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    names: list[str] = []
    names.extend(san.get_values_for_type(x509.DNSName))
    names.extend(san.get_values_for_type(x509.RFC822Name))
    names.extend(san.get_values_for_type(x509.UniformResourceIdentifier))
    return names


def _check_certificate_identity(cert: x509.Certificate, san_regex: str) -> None:
    """sigstore-go's certificate identity policy: SAN regex, exact OIDC
    issuer, and runner_environment == "github-hosted". runner_environment
    comes from the OIDC token, so a workflow retargeted to self-hosted
    (operator-controlled) infrastructure cannot claim github-hosted. Raises
    the sigstore VerificationError so the failure surfaces from verify_dsse
    exactly like sigstore-go's Verify."""
    sans = _subject_alternative_names(cert)
    if not sans:
        raise _SigstoreVerificationError("no Subject Alternative Name found")
    pattern = re.compile(san_regex)
    if not any(pattern.search(san) is not None for san in sans):
        raise _SigstoreVerificationError(
            f"certificate identity {sans!r} does not match {san_regex!r}"
        )
    issuer = _cert_issuer(cert)
    if issuer != OIDC_ISSUER:
        raise _SigstoreVerificationError(
            f"certificate OIDC issuer {issuer!r} is not {OIDC_ISSUER!r}"
        )
    runner_environment = _der_string_ext(cert, _OID_RUNNER_ENVIRONMENT)
    if runner_environment != "github-hosted":
        raise _SigstoreVerificationError(
            f'certificate runner_environment {runner_environment!r} is not "github-hosted"'
        )


class _CertificateIdentityPolicy:
    """sigstore-python VerificationPolicy running the Tinfoil identity checks
    inside Verifier.verify_dsse."""

    def __init__(self, san_regex: str):
        self._san_regex = san_regex

    def verify(self, cert: x509.Certificate) -> None:
        _check_certificate_identity(cert, self._san_regex)


def check_duplicate_sct_logs(cert: x509.Certificate) -> None:
    """SPEC 5.2: reject duplicate-log SCTs. sigstore-go dedups SCTs by log id
    rather than rejecting; sigstore-python requires exactly one SCT, which
    covers the duplicate case indirectly - this check names the reason
    explicitly, matching the go/rs/js SDKs."""
    try:
        scts = cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        ).value
    except x509.ExtensionNotFound:
        return
    except Exception:
        # A malformed SCT extension is the main verifier's concern, not this
        # guard's (Go: sctLogIDsInCertDER parse errors return nil).
        return
    seen: set[bytes] = set()
    for sct in scts:
        if sct.log_id in seen:
            raise _prov_error(
                f"certificate carries multiple SCTs from CT log {sct.log_id.hex()}"
            )
        seen.add(sct.log_id)


# --- core verification ---------------------------------------------------------


def _load_trusted_root(trust_root_json: Optional[bytes]) -> _SigstoreTrustedRoot:
    raw = trust_root_json if trust_root_json is not None else TRUSTED_ROOT_JSON.encode()
    try:
        inner = _trustroot_v1.TrustedRoot.from_json(raw)
        return _SigstoreTrustedRoot(inner)
    except Exception as e:
        raise _prov_error(f"parsing trust root: {e}") from None


def check_trust_root(trust_root_json: bytes) -> None:
    """Parse-check a caller-supplied Sigstore trusted-root document (Go:
    NewClientFromJSON). The conformance adapter runs this before any stage so
    an unparseable trust root is malformed input, not a rejection."""
    _load_trusted_root(trust_root_json)


def verify_bundle_with_identity(
    bundle_json: bytes,
    san_regex: str,
    hex_digest: str,
    trust_root_json: Optional[bytes] = None,
) -> VerifiedBundle:
    """Verify a Sigstore bundle against an explicit signing certificate SAN
    regex (Go: Client.verifyBundleWithIdentity)."""
    wire = parse_bundle(bundle_json)
    reject_legacy_bundle_format(wire)
    require_exactly_one_dsse_signature(wire)

    try:
        decode_hex(hex_digest)
    except ValueError as e:
        raise _prov_error(f"decoding hex digest: {e}") from None

    trusted_root = _load_trusted_root(trust_root_json)

    try:
        bundle = _SigstoreBundle.from_json(bytes(bundle_json))
    except Exception as e:
        raise _prov_error(f"parsing bundle: {e}") from None

    check_duplicate_sct_logs(bundle.signing_certificate)

    try:
        verifier = _SigstoreVerifier(trusted_root=trusted_root)
    except Exception as e:
        raise _prov_error(f"creating signed entity verifier: {e}") from None

    try:
        payload_type, payload = verifier.verify_dsse(
            bundle, _CertificateIdentityPolicy(san_regex)
        )
    except VerificationError:
        raise
    except Exception as e:
        # Fail closed: every failure mode of the delegated verification —
        # sigstore errors, malformed material, missing trust anchors — is a
        # provenance rejection (Go: fmt.Errorf("verifying: %w", err)).
        raise _prov_error(f"verifying: {e}") from None

    if payload_type != IN_TOTO_PAYLOAD_TYPE:
        raise _prov_error(f"unsupported DSSE payload type {payload_type!r}")

    statement = _parse_statement(payload)
    _check_artifact_digest(statement, hex_digest)
    _enforce_subject0_digest(statement, hex_digest)

    # The Type=="Tlog" observer timestamps (Go: result.VerifiedTimestamps
    # filtered to Tlog). integrated_time is only cryptographically bound when
    # the inclusion promise (SET) is present and verified — the same gate
    # sigstore-python uses to run _verify_set — so require it before trusting
    # the time as the freshness anchor. Absent it (e.g. a TSA-only bundle),
    # integrated_time is unverified and must not anchor freshness.
    entry = bundle.log_entry._inner
    tlog_timestamps: list[datetime] = []
    if entry.inclusion_promise is not None and entry.integrated_time is not None:
        tlog_timestamps.append(datetime.fromtimestamp(entry.integrated_time, tz=timezone.utc))

    return VerifiedBundle(
        statement=statement,
        cert=bundle.signing_certificate,
        tlog_timestamps=tlog_timestamps,
    )


def _verify_bundle(
    bundle_json: bytes,
    repo: str,
    hex_digest: str,
    trust_root_json: Optional[bytes],
) -> VerifiedBundle:
    san_regex = signing_identity(repo)
    return verify_bundle_with_identity(bundle_json, san_regex, hex_digest, trust_root_json)


# --- predicate parsing ----------------------------------------------------------


def _string_value(v: Any) -> str:
    """structpb.Value.GetStringValue: "" unless the value is a JSON string."""
    return v if isinstance(v, str) else ""


def _shape_int(v: Any) -> Optional[int]:
    """Go accepts only a structpb NumberValue that is a non-negative integer
    representable in an int (< 2^63)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if isinstance(v, float):
        if not math.isfinite(v) or v != math.trunc(v):
            return None
        v = int(v)
    if v < 0 or v >= 1 << 63:
        return None
    return v


def _shape_from_predicate(fields: dict[str, Any]) -> Shape:
    """Parse the required vm_shape predicate member."""
    if "vm_shape" not in fields:
        raise _prov_error("code predicate declares no vm_shape")
    v = fields["vm_shape"]
    if not _is_plain_object(v):
        raise _prov_error("vm_shape is not an object")
    members: dict[str, int] = {}
    for name in ("cpus", "memory_mb", "gpus", "disks"):
        if name not in v:
            raise _prov_error(f"vm_shape is missing {name!r}")
        n = _shape_int(v[name])
        if n is None:
            raise _prov_error(f"vm_shape member {name!r} is not a non-negative integer")
        members[name] = n
    return Shape(
        cpus=members["cpus"],
        memory_mb=members["memory_mb"],
        gpus=members["gpus"],
        disks=members["disks"],
    )


def _measurement_from_statement(statement: Statement) -> Measurement:
    predicate_fields = statement.predicate or {}

    measurement_type = statement.predicate_type
    if measurement_type == SNP_TDX_MULTI_PLATFORM_V1:
        if "tdx_measurement" not in predicate_fields:
            raise _prov_error("invalid multiplatform measurement: no tdx measurement")
        tdx_measurement = predicate_fields["tdx_measurement"]
        if not _is_plain_object(tdx_measurement):
            raise _prov_error(
                "invalid multiplatform measurement: tdx measurement is not a struct"
            )
        rtmrs = tdx_measurement

        if "snp_measurement" not in predicate_fields:
            raise _prov_error("invalid multiplatform measurement: no snp measurement")

        for rtmr in ("rtmr1", "rtmr2"):
            if rtmr not in rtmrs:
                raise _prov_error(f"invalid multiplatform measurement: no {rtmr}")

        return Measurement(
            type=measurement_type,
            registers=[
                _string_value(predicate_fields["snp_measurement"]),
                _string_value(rtmrs["rtmr1"]),
                _string_value(rtmrs["rtmr2"]),
            ],
        )
    raise _prov_error(f"unsupported predicate type: {statement.predicate_type}")


# --- authenticated artifact ------------------------------------------------------


def _authenticated_artifact(
    result: VerifiedBundle, repo: str, tag: str, hex_digest: str, label: str
) -> AuthenticatedArtifact:
    if result.cert is None:
        raise _prov_error(f"{label} bundle has no signing certificate")
    source_repository_ref = _der_string_ext(result.cert, _OID_SOURCE_REPO_REF)
    tag_ref_prefix = "refs/tags/"
    if not source_repository_ref.startswith(tag_ref_prefix):
        raise _prov_error(f"{label} source ref {source_repository_ref!r} is not a tag")
    authenticated_tag = source_repository_ref[len(tag_ref_prefix) :]
    if tag != "" and authenticated_tag != tag:
        raise _prov_error(
            f"{label} source ref {source_repository_ref!r} does not match tag {tag!r}"
        )
    commit = _der_string_ext(result.cert, _OID_SOURCE_REPO_DIGEST)
    if _COMMIT_RE.fullmatch(commit) is None:
        raise _prov_error(f"{label} source digest is not a lowercase Git commit")
    if len(result.statement.subject) == 0 or result.statement.subject[0].name == "":
        raise _prov_error(f"{label} statement has no named subject")
    return AuthenticatedArtifact(
        repo=repo,
        tag=authenticated_tag,
        commit=commit,
        subject_name=result.statement.subject[0].name,
        digest=hex_digest,
    )


# --- public entry points -----------------------------------------------------------


def authenticate_code(
    bundle_json: bytes,
    repo: str,
    tag: str,
    hex_digest: str,
    trust_root_json: Optional[bytes] = None,
) -> Code:
    """Authenticate a code-provenance bundle against the repo's signing
    identity and the expected artifact digest, and return the verified code
    measurement plus the VM shape the artifact declares (required)."""
    try:
        result = _verify_bundle(bundle_json, repo, hex_digest, trust_root_json)
    except VerificationError as e:
        raise _prov_error(f"verifying bundle: {e}") from None
    try:
        m = _measurement_from_statement(result.statement)
        shape = _shape_from_predicate(result.statement.predicate or {})
    except VerificationError as e:
        raise _prov_error(f"code predicate: {e}") from None
    authenticated = _authenticated_artifact(result, repo, tag, hex_digest, "code")
    return Code(
        repo=authenticated.repo,
        tag=authenticated.tag,
        commit=authenticated.commit,
        subject_name=authenticated.subject_name,
        digest=authenticated.digest,
        measurement=m,
        shape=shape,
    )


def authenticate_platform_endorsements(
    bundle_json: bytes,
    repo: str,
    tag: str,
    hex_digest: str,
    trust_root_json: Optional[bytes] = None,
) -> PlatformEndorsements:
    """Authenticate a platform-endorsements bundle against the publisher's
    pinned signing identity and return the parsed, validated artifact."""
    try:
        result = verify_bundle_with_identity(
            bundle_json, PLATFORM_ENDORSEMENTS_IDENTITY, hex_digest, trust_root_json
        )
    except VerificationError as e:
        raise _prov_error(f"verifying platform endorsements bundle: {e}") from None

    if result.statement.predicate_type != ARTIFACT_FORMAT:
        raise _prov_error(f"unexpected predicate type: {result.statement.predicate_type}")

    # Go re-serializes the verified predicate (protojson.Marshal) and hands it
    # to the fail-closed artifact parser; duplicate members were already
    # rejected during statement parsing.
    predicate_json = json.dumps(result.statement.predicate, separators=(",", ":")).encode()
    artifact = parse_artifact(predicate_json)
    if repo != PLATFORM_ENDORSEMENTS_REPO:
        raise _prov_error(
            f"platform endorsements repo {repo!r} does not equal "
            f"{PLATFORM_ENDORSEMENTS_REPO!r}"
        )
    authenticated = _authenticated_artifact(
        result, repo, tag, hex_digest, "platform endorsements"
    )
    return PlatformEndorsements(
        repo=authenticated.repo,
        tag=authenticated.tag,
        commit=authenticated.commit,
        subject_name=authenticated.subject_name,
        digest=authenticated.digest,
        artifact=artifact,
    )
