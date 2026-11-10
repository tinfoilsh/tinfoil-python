"""tinfoil-python conformance adapter for the cross-SDK v3 suite.

Test tooling, not part of the published package. Run from a source checkout:

    uv run python conformance/tinfoil_conformance.py <stage>     Input JSON on stdin, Output JSON on stdout
    uv run python conformance/tinfoil_conformance.py capabilities
    uv run python conformance/tinfoil_conformance.py live-verify {"host": ..., "repo": ...} on stdin
    uv run python conformance/tinfoil_conformance.py capture --host H --repo R [--id I] [--out F] [--nonce HEX]

The exit code is the verdict that the suite reads; stdout is diagnostic. The
contract is tinfoil-conformance ``docs/CONFORMANCE_ADAPTER_SPEC.md`` v1.2.0.

Every v3 stage decodes its Input first, so malformed input is reported as such
(exit 30) before anything else. The full-verify stage is one ``verify_v3_at``
call on the public ``Verifier``, or on one built with the injected roots when
the Input supplies any, so the shared fixtures appraise exactly the code that
production runs; the layer on its ``VerificationError`` names the rejection.
The block stages isolate a single layer by calling into the document,
endorsement and quote modules that the verifier uses. A stage that this
adapter does not implement exits 20 (unsupported), never with a verdict.

``live-verify`` and ``capture`` are the integration lane: the only commands
that open a connection. Both fetch a fresh nonce-bound document from the
enclave and verify it through the public ``Verifier`` with the embedded roots
and the current time. ``live-verify`` then dials the enclave again to check
that the TLS key on the wire is the endorsed one, and reports the facts with
``channel_binding``. ``capture`` freezes an accepted document as a fixture
pinned to its capture time, so that it replays as an accept under the
production roots.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import socket
import ssl
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, TextIO
from urllib.parse import urlsplit

import httpx

from tinfoil._sdkinfo import attestation_headers
from tinfoil._v3.verifier import (
    NONCE_SIZE,
    UsageError,
    VerificationError,
    Verifier,
    _measurement,
    _verifier,
    connection_cert_fp,
    random_nonce,
)
from tinfoil._v3.verifier import Verification as PublicVerification
from tinfoil._v3.verifier._document import document
from tinfoil._v3.verifier._document.collateral.collateral import NotFoundError
from tinfoil._v3.verifier._endorsement import approval, provenance, reference
from tinfoil._v3.verifier._endorsement import time as approval_time
from tinfoil._v3.verifier._errors import LAYER_ENVELOPE, LAYER_POLICY, LAYER_PROVENANCE, LAYER_QUOTE
from tinfoil._v3.verifier._policy import ARTIFACT_FORMAT
from tinfoil._v3.verifier._quote import quote
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
    STAGE_VERIFY,
    STAGE_CHECK_ENVELOPE,
    STAGE_AUTHENTICATE_PROVENANCE,
    STAGE_ASSEMBLE_POLICY,
    STAGE_AUTHENTICATE_QUOTE,
    STAGE_AUTHENTICATE_APPROVAL,
    STAGE_VERIFY_TIMESTAMP,
)

# The measurement types of the wire contract.
SEV_SNP_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
TDX_MEASUREMENT_TYPE = "https://tinfoil.sh/predicate/tdx-guest/v2"

# The integration lane's wire facts.
ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation"
CHANNEL_BINDING = "tls-spki"
# Bounds on the document fetch: the whole fetch from the request to the last body byte (and each socket
# operation within it), and the body that it may carry.
FETCH_TIMEOUT = 30.0
MAX_DOCUMENT_BYTES = 32 << 20
# The TLS handshake that checks the channel binding.
DIAL_TIMEOUT = 10.0
DEFAULT_CAPTURE_ID = "real-frozen"

ENVELOPE_REJECTED = "ENVELOPE_REJECTED"
PROVENANCE_REJECTED = "PROVENANCE_REJECTED"
QUOTE_REJECTED = "QUOTE_REJECTED"
POLICY_REJECTED = "POLICY_REJECTED"
MALFORMED_INPUT = "MALFORMED_INPUT"

# The rejection code of each verification layer. A layer outside this map is a bug in the verifier.
_LAYER_CODES = {
    LAYER_ENVELOPE: ENVELOPE_REJECTED,
    LAYER_PROVENANCE: PROVENANCE_REJECTED,
    LAYER_QUOTE: QUOTE_REJECTED,
    LAYER_POLICY: POLICY_REJECTED,
}

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
    diagnostic: str = ""
    """Why a stage gave no verdict or a rejection, for stderr; the output carries only the code."""


def capabilities() -> dict[str, Any]:
    """The adapter's self-description (capabilities.schema.json)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "sdk": SDK_NAME,
        "v3": {
            "supported": bool(STAGES_SUPPORTED),
            "stages_supported": list(STAGES_SUPPORTED),
            "synthetic_roots": {"amd": True, "intel": True, "sigstore": True},
            "freshness_enforced": True,
            "live_verify": True,
            "channel_binding": "tls-spki",
        },
    }


def _malformed(stage: str, diagnostic: str = "") -> Result:
    return Result(
        {"stage": stage, "accepted": False, "rejection": {"code": MALFORMED_INPUT}}, EXIT_MALFORMED, diagnostic
    )


def _unsupported(stage: str) -> Result:
    return Result({"stage": stage, "accepted": False}, EXIT_UNSUPPORTED)


def _rejected(stage: str, code: str, diagnostic: str = "") -> Result:
    return Result({"stage": stage, "accepted": False, "rejection": {"code": code}}, EXIT_REJECTED, diagnostic)


def _internal(stage: str, diagnostic: str) -> Result:
    return Result({"stage": stage, "accepted": False}, EXIT_INTERNAL, diagnostic)


def run(stage: str, raw: Any) -> Result:
    """Execute one stage on a parsed Input JSON value.

    Never raises: an unexpected error maps to the internal exit code; given
    well-formed input, a stage that this adapter does not implement maps to
    unsupported. Malformed input is reported first.
    """
    try:
        return _run_stage(stage, raw)
    except Exception as err:  # the exit code is the report
        return _internal(stage, f"{type(err).__name__}: {err}")


def _run_stage(stage: str, raw: Any) -> Result:
    if stage == STAGE_LIVE_VERIFY:
        return _live_verify(raw)
    try:
        decoded = Input.from_json(raw)
    except MalformedInput:
        return _malformed(stage)
    if stage == STAGE_VERIFY:
        return _verify(decoded)
    if stage == STAGE_CHECK_ENVELOPE:
        return _check_envelope(decoded)
    if stage == STAGE_AUTHENTICATE_PROVENANCE:
        return _authenticate_provenance(decoded)
    if stage == STAGE_ASSEMBLE_POLICY:
        return _assemble_policy(decoded)
    if stage == STAGE_AUTHENTICATE_APPROVAL:
        return _authenticate_approval(decoded)
    if stage == STAGE_AUTHENTICATE_QUOTE:
        return _authenticate_quote(decoded)
    if stage == STAGE_VERIFY_TIMESTAMP:
        return _verify_timestamp(decoded)
    return _unsupported(stage)


def _verify(decoded: Input) -> Result:
    """The whole flow through the verifier: envelope, provenance with freshness, quote, policy.

    An Input without trust roots verifies through the public ``Verifier``,
    exactly as an application does; one that injects a root builds the
    verifier through the harness seam. A verifier that cannot be built (an
    unparseable Sigstore root) is malformed input, as is any usage error of
    the call itself (an absent nonce). The layer of a VerificationError
    names the rejection code. A document that verifies but endorses no
    usable channel keys is useless to every real client, so the stage
    requires both the TLS fingerprint and the HPKE key.
    """
    stage = STAGE_VERIFY
    try:
        verifier = _verifier_for(decoded)
    except UsageError:
        return _malformed(stage)
    appraisal = decoded.verification_time or datetime.now(UTC)
    try:
        verified = verifier.verify_v3_at(decoded.document or b"", decoded.nonce or b"", decoded.repo, appraisal)
    except UsageError:
        return _malformed(stage)
    except VerificationError as err:
        return _verification_rejected(stage, err)
    outputs = _accept_outputs(verified)
    if outputs is None:
        return _rejected(stage, ENVELOPE_REJECTED, "document endorses no TLS fingerprint or no HPKE key")
    return Result({"stage": stage, "accepted": True, "outputs": outputs}, EXIT_ACCEPTED)


def _verifier_for(decoded: Input) -> Verifier:
    """The production verifier, or one with the Input's injected roots in place of the embedded ones."""
    if decoded.sigstore_trusted_root is None and decoded.amd_chain_pem is None and decoded.intel_root_pem is None:
        return Verifier()
    overrides = _verifier.Overrides(
        sigstore_root=decoded.sigstore_trusted_root,
        amd_root_pem=decoded.amd_chain_pem,
        intel_root_pem=decoded.intel_root_pem,
    )
    return _verifier._build(overrides=overrides)


def _verification_rejected(stage: str, err: VerificationError) -> Result:
    """The rejection that a VerificationError's layer selects; a layer outside the contract gives no verdict."""
    code = _LAYER_CODES.get(err.layer)
    if code is None:
        return _internal(stage, f"unknown verification layer {err.layer!r}: {err}")
    return _rejected(stage, code, str(err))


def _accept_outputs(verified: PublicVerification) -> dict[str, Any] | None:
    """The accept facts of a verification, or None when it endorses no TLS fingerprint or no HPKE key."""
    tls_fp = verified.tls_public_key_fp
    hpke_key = verified.hpke_public_key
    if tls_fp is None or hpke_key is None:
        return None
    return {
        "code_digest": verified.code_digest,
        "code_measurement": _expected_of(verified.code_measurement),
        "enclave_measurement": _measurement_of(verified.enclave_measurement),
        "tls_public_key_fp": tls_fp,
        "hpke_public_key": hpke_key,
    }


def _expected_of(expected: _measurement.Expected) -> dict[str, Any]:
    """Expected registers for the wire like ``_measurement_of``, with "" for a register left unconstrained."""
    if isinstance(expected, _measurement.ExpectedSEVSNP):
        return {"type": SEV_SNP_MEASUREMENT_TYPE, "registers": [_register(expected.launch)]}
    registers = (expected.mrtd, expected.rtmr0, expected.rtmr1, expected.rtmr2, expected.rtmr3)
    return {"type": TDX_MEASUREMENT_TYPE, "registers": [_register(register) for register in registers]}


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


def _injected_sigstore_root_parses(decoded: Input) -> bool:
    """Whether the injected Sigstore trusted root, when there is one, is a trusted-root document.

    The document stages hold a provenance client built from it, so one
    that does not parse is malformed input for every one of them.
    """
    if decoded.sigstore_trusted_root is None:
        return True
    try:
        sigstore_trusted_root.parse_trusted_root(decoded.sigstore_trusted_root)
    except sigstore_trusted_root.TrustedRootError:
        return False
    return True


def _authenticate_quote(decoded: Input) -> Result:
    """The CPU quote's signature chain up to the vendor root, from the document's own collateral.

    The document is decoded without its challenge bindings (the envelope
    stage owns those); one that does not decode is malformed input. The
    injected vendor roots replace the embedded anchors; an absent
    verification time means the current time. Every authentication failure
    is a quote rejection. A platform whose authentication is not available
    yet is reported as unsupported.
    """
    if not _injected_sigstore_root_parses(decoded):
        return _malformed(STAGE_AUTHENTICATE_QUOTE)
    try:
        parsed = document.decode_unbound(decoded.document or b"")
    except document.DocumentError:
        return _malformed(STAGE_AUTHENTICATE_QUOTE)
    appraisal = decoded.verification_time or datetime.now(UTC)
    options = quote.QuoteOptions(
        test_only_roots=quote.TestOnlyRoots(amd=decoded.amd_chain_pem, intel=decoded.intel_root_pem)
    )
    try:
        authenticated = quote.authenticate(parsed.cpu_evidence(), parsed.cpu_endorsements(), appraisal, options)
    except quote.QuoteError:
        return _rejected(STAGE_AUTHENTICATE_QUOTE, QUOTE_REJECTED)
    outputs = {"enclave_measurement": _measurement_of(authenticated.measurement)}
    return Result({"stage": STAGE_AUTHENTICATE_QUOTE, "accepted": True, "outputs": outputs}, EXIT_ACCEPTED)


def _measurement_of(measurement: _measurement.Measurement) -> dict[str, Any]:
    """An authenticated measurement for the wire, in platform register order."""
    if isinstance(measurement, _measurement.SEVSNP):
        return {"type": SEV_SNP_MEASUREMENT_TYPE, "registers": [measurement.launch.hex()]}
    registers = (measurement.mrtd, measurement.rtmr0, measurement.rtmr1, measurement.rtmr2, measurement.rtmr3)
    return {"type": TDX_MEASUREMENT_TYPE, "registers": [register.hex() for register in registers]}


def _check_envelope(decoded: Input) -> Result:
    """Strict parse plus the nonce, endorsed-hash and REPORT_DATA bindings.

    An injected Sigstore root that does not parse is malformed input. A
    document or nonce that is absent is rejected like any other that fails.
    """
    if not _injected_sigstore_root_parses(decoded):
        return _malformed(STAGE_CHECK_ENVELOPE)
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


# --- the integration lane -----------------------------------------------------------------------


class FetchError(RuntimeError):
    """The enclave did not serve a document: a failed request, a status outside 2xx, an oversized body, or a
    response that did not complete within FETCH_TIMEOUT."""


def _live_verify(raw: Any) -> Result:
    """Verify a live enclave as an application does: a fresh nonce, the enclave's document, the public
    ``Verifier`` with the embedded roots at the current time, then the TLS key on the wire against the endorsed
    one.

    The request is ``{"host": ..., "repo": ...}``, both non-empty strings
    and the host a bare host with an optional port; anything else is
    malformed input, found before any connection. A document that cannot
    be fetched, or an enclave that cannot be dialed for the channel
    binding, gives no verdict. The verifier's errors map as in the
    full-verify stage. A document that endorses no usable channel keys is
    an envelope rejection, and a live TLS key other than the endorsed one
    is a policy rejection.
    """
    stage = STAGE_LIVE_VERIFY
    request = _live_request(raw)
    if request is None:
        return _malformed(stage)
    host, repo = request
    try:
        _authority(host)
    except ValueError as err:
        return _malformed(stage, str(err))
    verifier = Verifier()
    nonce = random_nonce()
    try:
        document_bytes = _fetch_document(host, nonce)
    except (FetchError, httpx.HTTPError, OSError, ValueError) as err:
        return _internal(stage, f"fetching attestation from {host}: {err}")
    try:
        verified = verifier.verify_v3(document_bytes, nonce, repo)
    except UsageError as err:
        return _malformed(stage, str(err))
    except VerificationError as err:
        return _verification_rejected(stage, err)
    outputs = _accept_outputs(verified)
    if outputs is None:
        return _rejected(stage, ENVELOPE_REJECTED, "document endorses no TLS fingerprint or no HPKE key")
    # Channel binding: the endorsed TLS key must be the key the live enclave presents on the wire.
    try:
        live = _live_tls_fingerprint(host)
    except (OSError, ValueError) as err:
        return _internal(stage, f"dialing {host} for channel binding: {err}")
    endorsed = outputs["tls_public_key_fp"]
    if live != endorsed:
        return _rejected(stage, POLICY_REJECTED, f"channel binding: live TLS key {live} != endorsed {endorsed}")
    outputs["channel_binding"] = CHANNEL_BINDING
    return Result({"stage": stage, "accepted": True, "outputs": outputs}, EXIT_ACCEPTED)


def _live_request(raw: Any) -> tuple[str, str] | None:
    """The host and repo of a live-verify request, or None when it is not one."""
    if not isinstance(raw, Mapping):
        return None
    host, repo = raw.get("host"), raw.get("repo")
    if not isinstance(host, str) or not isinstance(repo, str) or not host or not repo:
        return None
    return host, repo


def capture(args: list[str], stdout: TextIO, stderr: TextIO) -> int:
    """Fetch a live enclave's document and, only if the full-verify stage accepts it under the embedded roots at
    the capture time, freeze it as a fixture pinned to that time.

    ``--host`` (a bare host with an optional port) and ``--repo`` are
    required; ``--id`` names the fixture, ``--out`` is the file to write
    (stdout by default) and ``--nonce`` fixes the challenge as lowercase hex
    (fresh and random by default). Invalid flags are found before any
    connection. A document that the verifier does not accept is never
    written; the exit code is the stage's.
    """
    options = _capture_options(args)
    if options is None:
        stderr.write(
            "usage: tinfoil_conformance.py capture --host <enclave> --repo <owner/name>"
            " [--id ..] [--out ..] [--nonce ..]\n"
        )
        return EXIT_MALFORMED
    try:
        nonce = _hex(options["nonce"], "nonce") if options["nonce"] else random_nonce()
    except MalformedInput as err:
        stderr.write(f"nonce: {err}\n")
        return EXIT_MALFORMED
    if len(nonce) != NONCE_SIZE:
        stderr.write(f"nonce: must be {NONCE_SIZE} bytes, got {len(nonce)}\n")
        return EXIT_MALFORMED
    host = options["host"]
    try:
        _authority(host)
    except ValueError as err:
        stderr.write(f"host: {err}\n")
        return EXIT_MALFORMED
    try:
        document_bytes = _fetch_document(host, nonce)
    except (FetchError, httpx.HTTPError, OSError, ValueError) as err:
        stderr.write(f"fetching attestation from {host}: {err}\n")
        return EXIT_INTERNAL

    # Pinned to the capture instant: the collateral is fresh now, and every replay reproduces this appraisal.
    capture_unix = int(datetime.now(UTC).timestamp())
    fixture_input = {
        "schema_version": SCHEMA_VERSION,
        "document_b64": base64.b64encode(document_bytes).decode(),
        "nonce_hex": nonce.hex(),
        "repo": options["repo"],
        "verification_time_unix": capture_unix,
    }
    result = run(STAGE_VERIFY, fixture_input)
    if result.exit_code != EXIT_ACCEPTED:
        rejection = result.output.get("rejection") or {}
        code = rejection.get("code", "unknown")
        detail = f": {result.diagnostic}" if result.diagnostic else ""
        stderr.write(f"refusing to freeze: verification did not accept (exit {result.exit_code}, {code}){detail}\n")
        return result.exit_code

    fixture = {
        "id": options["id"],
        "stage": STAGE_VERIFY,
        "input": fixture_input,
        "expected": {"accepted": True},
    }
    text = json.dumps(fixture, indent=2) + "\n"
    if options["out"] == "":
        stdout.write(text)
    else:
        Path(options["out"]).write_text(text, encoding="utf-8")
        stderr.write(f"froze live v3 document -> {options['out']} (verified at capture time {capture_unix})\n")
    return EXIT_ACCEPTED


def _capture_options(args: list[str]) -> dict[str, str] | None:
    """The capture flags as ``--name value`` or ``--name=value`` pairs; None for an unknown flag, a missing value
    or an absent host or repo."""
    options = {"host": "", "repo": "", "id": DEFAULT_CAPTURE_ID, "out": "", "nonce": ""}
    remaining = list(args)
    while remaining:
        flag = remaining.pop(0)
        if not flag.startswith("--"):
            return None
        name, separator, value = flag[2:].partition("=")
        if name not in options:
            return None
        if not separator:
            if not remaining:
                return None
            value = remaining.pop(0)
        options[name] = value
    if not options["host"] or not options["repo"]:
        return None
    return options


def _authority(host: str) -> tuple[str, int]:
    """The host name and port of ``host``, a bare host with an optional port: never a URL, a path or user
    information. Raises ValueError for anything else."""
    parts = urlsplit("//" + host)
    if (
        not host
        or parts.netloc != host
        or parts.username is not None
        or parts.password is not None
        or parts.path
        or parts.query
        or parts.fragment
        or not parts.hostname
    ):
        raise ValueError(f"invalid host {host!r}: want a host with an optional port")
    try:
        port = parts.port
    except ValueError as err:
        raise ValueError(f"invalid host {host!r}: want a host with an optional port") from err
    return parts.hostname, 443 if port is None else port


def _attestation_url(host: str, nonce: bytes) -> str:
    """Where the document of ``host`` is fetched with ``nonce``."""
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    _authority(host)
    return f"https://{host}{ATTESTATION_ENDPOINT}?nonce={nonce.hex()}"


def _fetch_document(host: str, nonce: bytes, *, transport: httpx.BaseTransport | None = None) -> bytes:
    """The raw document that ``host`` serves for ``nonce``: one GET with the SDK identity headers, no redirects,
    bounded in time and size. Parses nothing. Raises FetchError for a response that is not a document or that
    does not complete within FETCH_TIMEOUT, ValueError for a host or nonce that cannot form the URL, and httpx's
    errors for a request that fails.

    FETCH_TIMEOUT bounds the fetch twice: the client applies it to each
    socket operation, which catches a silent peer, and a deadline taken
    before the request applies it to the whole exchange, which catches a
    peer that keeps the connection alive by trickling bytes.
    """
    url = _attestation_url(host, nonce)
    deadline = time.monotonic() + FETCH_TIMEOUT

    def check_deadline() -> None:
        if time.monotonic() > deadline:
            raise FetchError(f"HTTP GET {url}: no complete document within {FETCH_TIMEOUT}s")

    with (
        httpx.Client(
            transport=transport, timeout=FETCH_TIMEOUT, follow_redirects=False, headers=attestation_headers()
        ) as client,
        client.stream("GET", url) as response,
    ):
        check_deadline()
        if not 200 <= response.status_code < 300:
            raise FetchError(f"HTTP GET {url}: {response.status_code} {response.reason_phrase}")
        body = bytearray()
        for chunk in response.iter_bytes():
            check_deadline()
            body += chunk
            if len(body) > MAX_DOCUMENT_BYTES:
                raise FetchError(f"attestation document exceeds {MAX_DOCUMENT_BYTES} bytes")
    return bytes(body)


def _live_tls_fingerprint(host: str) -> str:
    """The SPKI fingerprint of the leaf certificate that ``host`` presents on a fresh TLS connection. The chain
    is not verified: trust comes from matching the endorsed fingerprint, not from the public PKI."""
    hostname, port = _authority(host)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((hostname, port), timeout=DIAL_TIMEOUT) as raw,
        context.wrap_socket(raw, server_hostname=hostname) as connection,
    ):
        return connection_cert_fp(connection)


def main(argv: list[str], stdin: BinaryIO, stdout: TextIO, stderr: TextIO) -> int:
    if not argv:
        stderr.write("usage: tinfoil_conformance.py <stage>|capabilities|live-verify|capture\n")
        return EXIT_MALFORMED
    command = argv[0]

    if command == "capabilities":
        _write(stdout, capabilities())
        return EXIT_ACCEPTED

    if command == STAGE_CAPTURE:
        return capture(argv[1:], stdout, stderr)

    try:
        raw = json.loads(stdin.read())
    except (ValueError, UnicodeDecodeError):
        result = _malformed(command)
    else:
        result = run(command, raw)
    if result.diagnostic:
        stderr.write(result.diagnostic + "\n")
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
