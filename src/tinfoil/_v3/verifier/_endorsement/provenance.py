"""Release provenance: Sigstore-signed reference values verified against pinned GitHub workflow identities.

A ``ProvenanceClient`` holds one trusted root. Its methods authenticate
the code bundle, the platform-endorsements bundle, freshness witnesses
and runtime provenance, and build the approval verifiers that use the
same root.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._document.collateral.runtime import Runtime as RuntimeCollateral
from tinfoil._v3.verifier._document.collateral.runtime import RuntimeReference
from tinfoil._v3.verifier._endorsement import freshness as freshness_module
from tinfoil._v3.verifier._endorsement import runtime as runtime_module
from tinfoil._v3.verifier._endorsement._common import ProvenanceError as ProvenanceError
from tinfoil._v3.verifier._endorsement._common import authenticated_artifact as authenticated_artifact
from tinfoil._v3.verifier._endorsement._common import freshness_witness_identity as freshness_witness_identity
from tinfoil._v3.verifier._endorsement._common import platform_endorsements_identity as platform_endorsements_identity
from tinfoil._v3.verifier._endorsement._common import signing_identity as signing_identity
from tinfoil._v3.verifier._endorsement._common import workflow_identity as workflow_identity
from tinfoil._v3.verifier._endorsement.approval import ConfigVerifier, FreshnessVerifier
from tinfoil._v3.verifier._endorsement.reference import (
    PLATFORM_ENDORSEMENTS_REPO,
    AuthenticatedArtifact,
    Reference,
)
from tinfoil._v3.verifier._endorsement.runtime import (
    RuntimeArtifact,
    RuntimeProvenanceError,
    enforce_artifact_subject,
)
from tinfoil._v3.verifier._measurement import ExpectedSEVSNP, ExpectedTDX, parse_register
from tinfoil._v3.verifier._policy import ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2, Artifact, PolicyError, Shape
from tinfoil._v3.verifier._policy import parse as parse_policy_artifact
from tinfoil._v3.verifier._sigstore.bundle import BundleError, Statement, parse_bundle, parse_statement
from tinfoil._v3.verifier._sigstore.certificate import (
    CertificateBundleError,
    SigningIdentity,
    VerifiedBundle,
    verify_fulcio_bundle,
)
from tinfoil._v3.verifier._sigstore.trusted_root import (
    TrustedRoot,
    TrustedRootError,
    embedded_trusted_root,
    parse_trusted_root,
)
from tinfoil._v3.verifier._x509.certificate import PublicKey

MULTI_PLATFORM_PREDICATE_TYPE = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
"""The code-provenance predicate fixing a release's SEV-SNP launch measurement and its TDX RTMR1 and RTMR2."""

_SHAPE_MEMBERS = ("cpus", "memory_mb", "gpus", "disks")
_MAX_SHAPE_VALUE = math.ldexp(1, 63)


@dataclass(frozen=True, slots=True)
class Code:
    """The verified content of a code-provenance bundle."""

    artifact: AuthenticatedArtifact
    sevsnp: ExpectedSEVSNP
    """The registers the release fixes on SEV-SNP: the launch measurement."""
    tdx: ExpectedTDX
    """The registers the release fixes on TDX: RTMR1 and RTMR2."""
    shape: Shape | None
    """The VM shape the artifact declares."""


@dataclass(frozen=True, slots=True)
class PlatformEndorsements:
    """The verified platform-endorsements artifact."""

    artifact: AuthenticatedArtifact
    endorsements: Artifact


class ProvenanceClient:
    """Verifies reference-values bundles against one trusted root."""

    __slots__ = ("_root",)

    def __init__(self, root: TrustedRoot) -> None:
        self._root = root

    @classmethod
    def default(cls) -> ProvenanceClient:
        """A client over the embedded trusted root."""
        return cls(embedded_trusted_root())

    @classmethod
    def from_json(cls, trusted_root: bytes) -> ProvenanceClient:
        """A client over a parsed trusted-root document."""
        try:
            return cls(parse_trusted_root(trusted_root))
        except TrustedRootError as err:
            raise ProvenanceError(f"parsing trust root: {err}") from err

    @property
    def root(self) -> TrustedRoot:
        return self._root

    def authenticate_code(self, bundle: _json.JsonValue, ref: Reference, tag: str, digest: str) -> Code:
        """Verify code provenance against the pinned reference.

        ``ref.tag`` and ``ref.digest`` take precedence over the document's
        ``tag`` and ``digest`` hints. The bundle must be signed from
        ``ref.repo`` over the digest, carry the multiplatform predicate
        with a ``vm_shape``, and its certificate must name a tag ref that
        equals the tag when one is known.
        """
        repo = ref.repo
        tag = ref.tag or tag
        digest = ref.digest or digest
        try:
            verified, statement = self.verify_bundle_with_identity(bundle, signing_identity(repo), digest)
        except ProvenanceError as err:
            raise ProvenanceError(f"verifying bundle: {err}") from err
        try:
            sevsnp, tdx = measurements_from_statement(statement)
            shape = shape_from_predicate(statement)
        except ProvenanceError as err:
            raise ProvenanceError(f"code predicate: {err}") from err
        artifact = authenticated_artifact(verified, statement, repo, tag, digest, "code")
        return Code(artifact=artifact, sevsnp=sevsnp, tdx=tdx, shape=shape)

    def authenticate_platform_endorsements(
        self, bundle: _json.JsonValue, repo: str, tag: str, digest: str, artifact_format: str
    ) -> PlatformEndorsements:
        """Verify the platform-endorsements bundle.

        ``artifact_format`` is the artifact format the verification flow selected
        (v1 or v2); ``repo`` must be the platform-endorsements repository.
        The bundle must be signed by the platform-release workflow over
        the digest; the signed predicate must parse as a policy artifact
        whose format, and the statement's predicate type, equal
        ``artifact_format``.
        """
        if artifact_format not in (ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2):
            raise ProvenanceError(f"unsupported platform artifact format {artifact_format!r}")
        if repo != PLATFORM_ENDORSEMENTS_REPO:
            raise ProvenanceError(f"platform endorsements repo {repo!r} does not equal {PLATFORM_ENDORSEMENTS_REPO!r}")
        try:
            verified, statement = self.verify_bundle_with_identity(bundle, platform_endorsements_identity(), digest)
        except ProvenanceError as err:
            raise ProvenanceError(f"verifying platform endorsements bundle: {err}") from err
        try:
            predicate = signed_predicate(verified.payload)
        except ProvenanceError as err:
            raise ProvenanceError(f"platform endorsements statement: {err}") from err
        try:
            endorsements = parse_policy_artifact(predicate)
        except PolicyError as err:
            raise ProvenanceError(str(err)) from err
        if statement.predicate_type != artifact_format or endorsements.format != artifact_format:
            raise ProvenanceError(f"platform predicate and artifact must use {artifact_format!r}")
        artifact = authenticated_artifact(verified, statement, repo, tag, digest, "platform endorsements")
        return PlatformEndorsements(artifact=artifact, endorsements=endorsements)

    def authenticate_freshness(
        self,
        bundle: _json.JsonValue,
        expected: AuthenticatedArtifact,
        now: datetime,
        max_age: timedelta | None = None,
    ) -> datetime:
        """Verify a freshness witness for ``expected`` and return its log time; see ``freshness``."""
        return freshness_module.authenticate_freshness(self, bundle, expected, now, max_age)

    def authenticate_runtime(self, material: RuntimeCollateral, expected: RuntimeReference) -> RuntimeArtifact:
        """Authenticate runtime collateral against a config's runtime pin; see ``runtime``."""
        return runtime_module.authenticate_runtime(self, material, expected)

    def config_verifier(self, keys: Sequence[PublicKey]) -> ConfigVerifier:
        """A verifier of key-signed config approvals under ``keys``."""
        return ConfigVerifier(self._root, keys)

    def registry_verifier(self, keys: Sequence[PublicKey]) -> ConfigVerifier:
        """A verifier of config approvals whose root keys are ``keys``: certified (v2) registry endorsements and,
        for the public registry, key-signed ones."""
        return ConfigVerifier(self._root, keys, root_keys=keys)

    def freshness_verifier(self, keys: Sequence[PublicKey]) -> FreshnessVerifier:
        """A verifier of artifact freshness approvals signed under ``keys``."""
        return FreshnessVerifier(self._root, keys)

    def verify_bundle(self, bundle: _json.JsonValue, repo: str, digest: str) -> VerifiedBundle:
        """Verify a bundle signed from ``repo`` (see ``signing_identity``) over ``digest``."""
        verified, _ = self.verify_bundle_with_identity(bundle, signing_identity(repo), digest)
        return verified

    def verify_bundle_with_identity(
        self, bundle: _json.JsonValue, identity: SigningIdentity, digest: str, subject_name: str = ""
    ) -> tuple[VerifiedBundle, Statement]:
        """Verify a bundle against an explicit identity and return it with its parsed statement.

        In order: the bundle parses with the v0.3 layout checks; the
        Fulcio verification runs over the lowercase decoded digest with
        ``identity``; the leaf carries no two SCTs from one CT log; the
        subject check runs (``subject_name`` empty: the first subject's
        digest must equal ``digest`` case-insensitively; otherwise exactly
        one subject with that name and digest).
        """
        try:
            parsed = parse_bundle(bundle)
        except BundleError as err:
            raise ProvenanceError(f"parsing bundle: {err}") from err
        try:
            verified = verify_fulcio_bundle(self._root, parsed, identity, _decode_hex_digest(digest))
            statement = parse_statement(verified.payload)
        except (CertificateBundleError, BundleError) as err:
            raise ProvenanceError(f"verifying: {err}") from err
        try:
            enforce_artifact_subject(statement.subjects, subject_name, digest)
        except RuntimeProvenanceError as err:
            raise ProvenanceError(str(err)) from err
        return verified, statement


def _decode_hex_digest(digest: str) -> bytes:
    """Decode a hex digest in either case; whitespace and odd lengths reject."""
    if len(digest) % 2 or not all(ch in "0123456789abcdefABCDEF" for ch in digest):
        raise ProvenanceError("decoding hex digest: invalid hex string")
    return bytes.fromhex(digest)


def measurements_from_statement(statement: Statement) -> tuple[ExpectedSEVSNP, ExpectedTDX]:
    """Read the multiplatform predicate: ``snp_measurement`` and ``tdx_measurement.rtmr1``/``rtmr2`` as registers in
    either hex case. A predicate type other than the multiplatform one, or a missing or null member, is an error."""
    if statement.predicate_type != MULTI_PLATFORM_PREDICATE_TYPE:
        raise ProvenanceError(f"unsupported predicate type: {statement.predicate_type}")
    fields = _predicate_fields(statement)
    if "tdx_measurement" not in fields:
        raise ProvenanceError("invalid multiplatform measurement: no tdx measurement")
    tdx_measurement = fields["tdx_measurement"]
    if not isinstance(tdx_measurement, _json.JsonObject):
        raise ProvenanceError("invalid multiplatform measurement: tdx measurement is not a struct")
    if "snp_measurement" not in fields:
        raise ProvenanceError("invalid multiplatform measurement: no snp measurement")
    for name in ("rtmr1", "rtmr2"):
        if name not in tdx_measurement:
            raise ProvenanceError(f"invalid multiplatform measurement: no {name}")
    launch = _register("snp measurement", fields["snp_measurement"])
    rtmr1 = _register("rtmr1", tdx_measurement["rtmr1"])
    rtmr2 = _register("rtmr2", tdx_measurement["rtmr2"])
    return ExpectedSEVSNP(launch=launch), ExpectedTDX(rtmr1=rtmr1, rtmr2=rtmr2)


def _register(name: str, value: _json.JsonValue) -> bytes:
    """A register from a predicate member; a member that is not a string reads as the empty string."""
    try:
        return parse_register(value if isinstance(value, str) else "")
    except ValueError as err:
        raise ProvenanceError(f"invalid multiplatform measurement: {name}: {err}") from err


def shape_from_predicate(statement: Statement) -> Shape:
    """Read ``vm_shape``: an object with ``cpus``, ``memory_mb``, ``gpus`` and ``disks``, each a non-negative integer
    number below 2**63; a missing member or a fractional, negative or non-number value is an error."""
    fields = _predicate_fields(statement)
    if "vm_shape" not in fields:
        raise ProvenanceError("code predicate declares no vm_shape")
    shape = fields["vm_shape"]
    if not isinstance(shape, _json.JsonObject):
        raise ProvenanceError("vm_shape is not an object")
    values: dict[str, int] = {}
    for name in _SHAPE_MEMBERS:
        if name not in shape:
            raise ProvenanceError(f"vm_shape is missing {name!r}")
        member = shape[name]
        # A number is read at double precision, as a generic JSON decoder
        # holds it: an integral literal with a fraction or exponent is accepted.
        try:
            number = member.to_float() if isinstance(member, _json.JsonNumber) else None
        except _json.JsonError:
            number = None
        if (
            number is None
            or math.isnan(number)
            or math.isinf(number)
            or number < 0
            or number != math.trunc(number)
            or number >= _MAX_SHAPE_VALUE
        ):
            raise ProvenanceError(f"vm_shape member {name!r} is not a non-negative integer")
        values[name] = int(number)
    return Shape(cpus=values["cpus"], memory_mb=values["memory_mb"], disks=values["disks"], gpus=values["gpus"])


def _predicate_fields(statement: Statement) -> _json.JsonObject:
    try:
        value = _json.strict_parse(statement.predicate)
    except _json.JsonError as err:
        raise ProvenanceError(f"parsing predicate: {err}") from err
    if not isinstance(value, _json.JsonObject):
        raise ProvenanceError("predicate is not an object")
    return value


def signed_predicate(payload: bytes) -> bytes:
    """The ``predicate`` member of a statement payload exactly as signed, which must be an object.

    The strict policy parser reads these bytes so that integer precision
    and literal forms survive.
    """
    try:
        statement = parse_statement(payload)
    except BundleError as err:
        raise ProvenanceError(f"parsing: {err}") from err
    return statement.predicate
