"""tinfoil-python conformance adapter for the cross-SDK v3 suite.

Test tooling, not part of the published package. Run from a source checkout:

    uv run python conformance/tinfoil_conformance.py <stage>     Input JSON on stdin, Output JSON on stdout
    uv run python conformance/tinfoil_conformance.py capabilities

The exit code is the verdict that the suite reads; stdout is diagnostic. The
contract is tinfoil-conformance ``docs/CONFORMANCE_ADAPTER_SPEC.md`` v1.2.0.

Every v3 stage decodes its Input first, so malformed input is reported as such
(exit 30) before anything else. A stage that this adapter does not implement
yet exits 20 (unsupported), never with a verdict. Stages are wired in as the
verifier modules that they drive land. ``live-verify`` and ``capture`` take
their own arguments, not an Input, and exit 20 without reading stdin until
they are implemented.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, BinaryIO, TextIO

from tinfoil._v3.verifier._document import document
from tinfoil._v3.verifier._document.collateral.collateral import NotFoundError
from tinfoil._v3.verifier._endorsement import approval, provenance, reference
from tinfoil._v3.verifier._endorsement import time as approval_time
from tinfoil._v3.verifier._policy import ARTIFACT_FORMAT
from tinfoil._v3.verifier._sigstore import bundle as sigstore_bundle
from tinfoil._v3.verifier._sigstore import timestamp as sigstore_timestamp
from tinfoil._v3.verifier._sigstore import trusted_root as sigstore_trusted_root
from tinfoil._v3.verifier._x509 import certificate as x509_certificate

# Exit codes are the cross-SDK contract.
EXIT_ACCEPTED = 0
EXIT_INTERNAL = 1
EXIT_REJECTED = 10
EXIT_UNSUPPORTED = 20
EXIT_MALFORMED = 30

SCHEMA_VERSION = "1"
SDK_NAME = "tinfoil-python"

STAGE_VERIFY = "verify-attestation-v3"
STAGE_CHECK_ENVELOPE = "v3-check-envelope"
STAGE_AUTHENTICATE_PROVENANCE = "v3-authenticate-provenance"
STAGE_ASSEMBLE_POLICY = "v3-assemble-policy"
STAGE_AUTHENTICATE_QUOTE = "v3-authenticate-quote"
STAGE_AUTHENTICATE_APPROVAL = "v3-authenticate-approval"
STAGE_VERIFY_TIMESTAMP = "v3-verify-timestamp"
STAGE_LIVE_VERIFY = "live-verify"
STAGE_CAPTURE = "capture"

# Every stage the contract defines, in the order the spec lists them. The
# capabilities output names only the implemented subset.
ALL_STAGES = (
    STAGE_VERIFY,
    STAGE_CHECK_ENVELOPE,
    STAGE_AUTHENTICATE_PROVENANCE,
    STAGE_ASSEMBLE_POLICY,
    STAGE_AUTHENTICATE_QUOTE,
    STAGE_AUTHENTICATE_APPROVAL,
    STAGE_VERIFY_TIMESTAMP,
)
STAGES_SUPPORTED: tuple[str, ...] = (
    STAGE_CHECK_ENVELOPE,
    STAGE_AUTHENTICATE_PROVENANCE,
    STAGE_ASSEMBLE_POLICY,
    STAGE_AUTHENTICATE_APPROVAL,
    STAGE_VERIFY_TIMESTAMP,
)

ENVELOPE_REJECTED = "ENVELOPE_REJECTED"
PROVENANCE_REJECTED = "PROVENANCE_REJECTED"
QUOTE_REJECTED = "QUOTE_REJECTED"
POLICY_REJECTED = "POLICY_REJECTED"
MALFORMED_INPUT = "MALFORMED_INPUT"

# Every member the Input schema defines; anything else is malformed.
_INPUT_MEMBERS = frozenset(
    {
        "schema_version",
        "document_b64",
        "nonce_hex",
        "repo",
        "amd_root_ca_pem",
        "ask_pem",
        "intel_sgx_root_pem",
        "sigstore_trusted_root_json_b64",
        "verification_time_unix",
        "bundle_json_b64",
        "signing_keys_pem",
        "artifact_digest_hex",
        "timestamp_response_b64",
        "timestamp_input_b64",
    }
)
_LOWER_HEX = re.compile(r"^[0-9a-f]*$")


class MalformedInput(ValueError):
    """The adapter input itself did not parse."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Input:
    """A decoded adapter Input.

    Document stages read ``document``, ``nonce`` and ``repo``; the approval
    stage reads ``bundle_json``, ``signing_keys_pem`` and ``artifact_digest``;
    the timestamp stage reads ``timestamp_response`` and ``timestamp_input``.
    Absent trust roots select the embedded production roots. Which members a
    stage requires is checked by the stage, not here: the Input schema makes
    every member optional and the fixture schema decides per stage.
    """

    document: bytes | None
    nonce: bytes | None
    repo: str
    # The ASK then the ARK, PEM-encoded, in the AMD KDS cert_chain layout.
    amd_chain_pem: bytes | None
    intel_root_pem: bytes | None
    sigstore_trusted_root: bytes | None
    # Pins the validity-window and freshness clock; None means the current time.
    verification_time: datetime | None
    bundle_json: bytes | None
    signing_keys_pem: tuple[str, ...]
    artifact_digest: str
    timestamp_response: bytes | None
    timestamp_input: bytes | None

    @classmethod
    def from_json(cls, data: Any) -> Input:
        """Decode the Input JSON object. Raises MalformedInput."""
        if not isinstance(data, Mapping):
            raise MalformedInput("input is not a JSON object")
        if data.get("schema_version") != SCHEMA_VERSION:
            raise MalformedInput(f"schema_version must be {SCHEMA_VERSION!r}")
        unknown = sorted(set(data) - _INPUT_MEMBERS)
        if unknown:
            raise MalformedInput(f"unknown input members: {', '.join(map(str, unknown))}")

        amd_root, ask = _string(data, "amd_root_ca_pem"), _string(data, "ask_pem")
        if bool(amd_root) != bool(ask):
            raise MalformedInput("amd_root_ca_pem and ask_pem must be supplied together")
        intel_root = _string(data, "intel_sgx_root_pem")
        sigstore_root = _string(data, "sigstore_trusted_root_json_b64")

        # Absent or 0 selects the current time, as the Input schema says.
        timestamp = data.get("verification_time_unix", 0)
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
            raise MalformedInput("verification_time_unix must be a non-negative integer")
        try:
            verification_time = datetime.fromtimestamp(timestamp, UTC) if timestamp else None
        except (OverflowError, OSError, ValueError) as err:
            raise MalformedInput(f"verification_time_unix is out of range: {err}") from err

        keys = data.get("signing_keys_pem", [])
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            raise MalformedInput("signing_keys_pem must be an array of strings")

        document = _string(data, "document_b64")
        nonce = _string(data, "nonce_hex")
        bundle = _string(data, "bundle_json_b64")
        tsr = _string(data, "timestamp_response_b64")
        tsi = _string(data, "timestamp_input_b64")

        return cls(
            document=_base64(document, "document_b64") if document else None,
            nonce=_hex(nonce, "nonce_hex") if nonce else None,
            repo=_string(data, "repo"),
            amd_chain_pem=f"{ask.strip()}\n{amd_root.strip()}\n".encode() if amd_root else None,
            intel_root_pem=intel_root.encode() if intel_root else None,
            sigstore_trusted_root=_base64(sigstore_root, "sigstore_trusted_root_json_b64") if sigstore_root else None,
            verification_time=verification_time,
            bundle_json=_base64(bundle, "bundle_json_b64") if bundle else None,
            signing_keys_pem=tuple(keys),
            artifact_digest=_lower_hex(_string(data, "artifact_digest_hex"), "artifact_digest_hex"),
            timestamp_response=_base64(tsr, "timestamp_response_b64") if tsr else None,
            timestamp_input=_base64(tsi, "timestamp_input_b64") if tsi else None,
        )


def _string(data: Mapping[str, Any], name: str) -> str:
    """An optional string member; absent reads as empty, ``null`` is malformed."""
    value = data.get(name, "")
    if not isinstance(value, str):
        raise MalformedInput(f"{name} must be a string")
    return value


def _base64(value: str, name: str) -> bytes:
    """Standard base64 with padding, exactly one encoding accepted."""
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as err:
        raise MalformedInput(f"{name} is not valid base64: {err}") from err
    if base64.b64encode(decoded).decode() != value:
        raise MalformedInput(f"{name} is not canonical base64")
    return decoded


def _hex(value: str, name: str) -> bytes:
    """Lowercase hex digits only, of even length; no whitespace or prefix."""
    if not _LOWER_HEX.fullmatch(value) or len(value) % 2:
        raise MalformedInput(f"{name} must be lowercase hex of even length")
    return bytes.fromhex(value)


def _lower_hex(value: str, name: str) -> str:
    if value:
        _hex(value, name)
    return value


@dataclass(frozen=True, slots=True)
class Result:
    output: dict[str, Any]
    exit_code: int


def capabilities() -> dict[str, Any]:
    """The adapter's self-description (capabilities.schema.json)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "sdk": SDK_NAME,
        "v3": {
            "supported": bool(STAGES_SUPPORTED),
            "stages_supported": list(STAGES_SUPPORTED),
            "synthetic_roots": {"amd": False, "intel": False, "sigstore": True},
            "freshness_enforced": True,
            "live_verify": False,
            "channel_binding": "tls-spki",
        },
    }


def _malformed(stage: str) -> Result:
    return Result({"stage": stage, "accepted": False, "rejection": {"code": MALFORMED_INPUT}}, EXIT_MALFORMED)


def _unsupported(stage: str) -> Result:
    return Result({"stage": stage, "accepted": False}, EXIT_UNSUPPORTED)


def _rejected(stage: str, code: str) -> Result:
    return Result({"stage": stage, "accepted": False, "rejection": {"code": code}}, EXIT_REJECTED)


def run(stage: str, raw: Any) -> Result:
    """Execute one stage on a parsed Input JSON value.

    Never raises: an unexpected error maps to the internal exit code; given
    well-formed input, a stage that this adapter does not implement maps to
    unsupported. Malformed input is reported first.
    """
    try:
        return _run_stage(stage, raw)
    except Exception:  # the exit code is the report
        return Result({"stage": stage, "accepted": False}, EXIT_INTERNAL)


def _run_stage(stage: str, raw: Any) -> Result:
    try:
        decoded = Input.from_json(raw)
    except MalformedInput:
        return _malformed(stage)
    if stage == STAGE_CHECK_ENVELOPE:
        return _check_envelope(decoded)
    if stage == STAGE_AUTHENTICATE_PROVENANCE:
        return _authenticate_provenance(decoded)
    if stage == STAGE_ASSEMBLE_POLICY:
        return _assemble_policy(decoded)
    if stage == STAGE_AUTHENTICATE_APPROVAL:
        return _authenticate_approval(decoded)
    if stage == STAGE_VERIFY_TIMESTAMP:
        return _verify_timestamp(decoded)
    # Further stage handlers are added here as the modules that they drive land.
    return _unsupported(stage)


def _trusted_root(decoded: Input) -> sigstore_trusted_root.TrustedRoot:
    """The injected Sigstore trusted root, or the embedded one. Raises TrustedRootError."""
    if decoded.sigstore_trusted_root is None:
        return sigstore_trusted_root.embedded_trusted_root()
    return sigstore_trusted_root.parse_trusted_root(decoded.sigstore_trusted_root)


def _decode_document(decoded: Input) -> document.Document:
    """The document decoded without the challenge bindings, which the block stages do not check.

    Raises MalformedInput for a document that is absent or does not
    decode: the stage never reaches the layer that it isolates.
    """
    try:
        return document.decode_unbound(decoded.document or b"")
    except document.DocumentError as err:
        raise MalformedInput(str(err)) from err


def _authenticate_provenance(decoded: Input) -> Result:
    """The code bundle against the pinned repository: identity, digest and predicate.

    An injected trusted root that does not parse or a document that does
    not decode is malformed input. A document without a code entry, an
    invalid repository reference and every verification failure are
    provenance rejections.
    """
    stage = STAGE_AUTHENTICATE_PROVENANCE
    try:
        client = provenance.ProvenanceClient(_trusted_root(decoded))
        parsed = _decode_document(decoded)
    except (sigstore_trusted_root.TrustedRootError, MalformedInput):
        return _malformed(stage)
    try:
        code_ref = parsed.sigstore_code()
        pin = reference.parse_reference(decoded.repo)
        code = client.authenticate_code(code_ref.bundle, pin, code_ref.tag, code_ref.digest)
    except (NotFoundError, ValueError):
        return _rejected(stage, PROVENANCE_REJECTED)
    outputs = {
        "code_digest": code.artifact.digest,
        # The release's own predicate: SNP launch, then TDX RTMR1 and RTMR2.
        "code_measurement": {
            "type": provenance.MULTI_PLATFORM_PREDICATE_TYPE,
            "registers": [_register(code.sevsnp.launch), _register(code.tdx.rtmr1), _register(code.tdx.rtmr2)],
        },
    }
    return Result({"stage": stage, "accepted": True, "outputs": outputs}, EXIT_ACCEPTED)


def _register(register: bytes | None) -> str:
    """A register as lowercase hex, "" when the release leaves it unconstrained."""
    return "" if register is None else register.hex()


def _assemble_policy(decoded: Input) -> Result:
    """The platform-endorsements bundle: identity, digest and a fail-closed parse of the policy artifact."""
    stage = STAGE_ASSEMBLE_POLICY
    try:
        client = provenance.ProvenanceClient(_trusted_root(decoded))
        parsed = _decode_document(decoded)
    except (sigstore_trusted_root.TrustedRootError, MalformedInput):
        return _malformed(stage)
    try:
        platform_ref = parsed.sigstore_platform()
        client.authenticate_platform_endorsements(
            platform_ref.bundle, platform_ref.repo, platform_ref.tag, platform_ref.digest, ARTIFACT_FORMAT
        )
    except (NotFoundError, ValueError):
        return _rejected(stage, PROVENANCE_REJECTED)
    return Result({"stage": stage, "accepted": True}, EXIT_ACCEPTED)


def _authenticate_approval(decoded: Input) -> Result:
    """A key-signed approval bundle under the keys that the input pins.

    An injected trusted root that does not parse, an empty key set, a PEM
    block that is not a public key and a key set that the verifier cannot
    use (a repeated or unsupported key) are malformed input. A trusted
    root without transparency logs, a bundle that does not parse and every
    verification failure are provenance rejections.
    """
    stage = STAGE_AUTHENTICATE_APPROVAL
    try:
        root = _trusted_root(decoded)
        if not decoded.signing_keys_pem:
            raise MalformedInput("at least one signing key is required")
        keys = [x509_certificate.load_public_key_pem(pem) for pem in decoded.signing_keys_pem]
    except (sigstore_trusted_root.TrustedRootError, x509_certificate.X509Error, MalformedInput):
        return _malformed(stage)
    if not root.tlogs:
        return _rejected(stage, PROVENANCE_REJECTED)
    try:
        verifier = approval.ApprovalVerifier(root, keys)
    except approval.ApprovalError:
        return _malformed(stage)
    try:
        bundle = sigstore_bundle.parse_bundle_bytes(decoded.bundle_json or b"")
        hint = verifier.verify(bundle, bytes.fromhex(decoded.artifact_digest))
    except (sigstore_bundle.BundleError, approval.ApprovalError):
        return _rejected(stage, PROVENANCE_REJECTED)
    return Result({"stage": stage, "accepted": True, "outputs": {"signing_key_hint": hint}}, EXIT_ACCEPTED)


def _check_envelope(decoded: Input) -> Result:
    """Strict parse plus the nonce, endorsed-hash and REPORT_DATA bindings.

    A document or nonce that is absent is rejected like any other that fails.
    """
    try:
        document.parse(decoded.document or b"", decoded.nonce or b"")
    except (document.DocumentError, document.InvalidInputError):
        return _rejected(STAGE_CHECK_ENVELOPE, ENVELOPE_REJECTED)
    return Result({"stage": STAGE_CHECK_ENVELOPE, "accepted": True}, EXIT_ACCEPTED)


def _verify_timestamp(decoded: Input) -> Result:
    """An RFC 3161 response over the given input, against the trusted root's authorities, inside the appraisal window.

    The response, the input and a non-zero verification time are required;
    an injected trusted root that does not parse is malformed input. Every
    verification failure, including a genTime outside the default approval
    window (the maximum age and future skew of the time policy), is a
    provenance rejection.
    """
    if decoded.timestamp_response is None or decoded.timestamp_input is None or decoded.verification_time is None:
        return _malformed(STAGE_VERIFY_TIMESTAMP)
    try:
        root = _trusted_root(decoded)
        policy = approval_time.new_time_policy(decoded.verification_time)
    except (sigstore_trusted_root.TrustedRootError, approval_time.TimePolicyError):
        return _malformed(STAGE_VERIFY_TIMESTAMP)
    try:
        gen_time = sigstore_timestamp.verify_timestamp(root, decoded.timestamp_response, decoded.timestamp_input)
        policy.verify(gen_time)
    except (sigstore_timestamp.TimestampError, approval_time.TimePolicyError):
        return _rejected(STAGE_VERIFY_TIMESTAMP, PROVENANCE_REJECTED)
    outputs = {"timestamp": gen_time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    return Result({"stage": STAGE_VERIFY_TIMESTAMP, "accepted": True, "outputs": outputs}, EXIT_ACCEPTED)


def main(argv: list[str], stdin: BinaryIO, stdout: TextIO, stderr: TextIO) -> int:
    if not argv:
        stderr.write("usage: tinfoil_conformance.py <stage>|capabilities|live-verify|capture\n")
        return EXIT_MALFORMED
    command = argv[0]

    if command == "capabilities":
        _write(stdout, capabilities())
        return EXIT_ACCEPTED

    if command in (STAGE_LIVE_VERIFY, STAGE_CAPTURE):
        _write(stdout, {"stage": command, "accepted": False})
        return EXIT_UNSUPPORTED

    try:
        raw = json.loads(stdin.read())
    except (ValueError, UnicodeDecodeError):
        result = _malformed(command)
    else:
        result = run(command, raw)
    _write(stdout, result.output)
    return result.exit_code


def _write(stream: TextIO, value: Any) -> None:
    stream.write(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], sys.stdin.buffer, sys.stdout, sys.stderr))
    except Exception as err:  # the exit code is the report
        sys.stderr.write(f"internal error: {err}\n")
        sys.exit(EXIT_INTERNAL)
