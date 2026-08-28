"""Pure stage logic of the conformance adapter, mirroring tinfoil-go
verifier/conformance (Run). Foundation skeleton: v3-check-envelope is
implemented; the remaining stages exit 20 until their verifier slices land
(the integration worker replaces the stage dispatch with the full flow)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from tinfoil.v3 import envelope
from tinfoil.v3.bytesutil import decode_base64
from tinfoil.v3.errors import VerificationError

# Adapter wire-contract version.
SCHEMA_VERSION = "1"

# Exit codes are the cross-SDK adapter contract: the suite reads them to
# decide pass/skip and never depends on stdout for the verdict.
EXIT_ACCEPTED = 0  # verification accepted; outputs populated
EXIT_INTERNAL = 1  # unexpected adapter error
EXIT_REJECTED = 10  # verification rejected; rejection populated
EXIT_UNSUPPORTED = 20  # stage/capability not supported by this SDK
EXIT_MALFORMED = 30  # input did not parse

# Stages. The full stage runs the whole flow including freshness; the block
# stages isolate a single layer.
STAGE_VERIFY = "verify-attestation-v3"
STAGE_CHECK_ENVELOPE = "v3-check-envelope"
STAGE_AUTHENTICATE_PROVENANCE = "v3-authenticate-provenance"
STAGE_ASSEMBLE_POLICY = "v3-assemble-policy"
STAGE_AUTHENTICATE_QUOTE = "v3-authenticate-quote"

ALL_STAGES = (
    STAGE_VERIFY,
    STAGE_CHECK_ENVELOPE,
    STAGE_AUTHENTICATE_PROVENANCE,
    STAGE_ASSEMBLE_POLICY,
    STAGE_AUTHENTICATE_QUOTE,
)

# Stages this skeleton actually implements; capabilities derives from this.
SUPPORTED_STAGES = (STAGE_CHECK_ENVELOPE,)


@dataclass
class Input:
    """Decoded stdin JSON: a v3 document, the verifier-supplied nonce, the
    pinned repo, and the synthetic roots it was produced under. Empty root
    fields select the embedded production roots."""

    schema_version: str = ""
    document_b64: str = ""
    nonce_hex: str = ""
    repo: str = ""
    # AMD SEV-SNP anchor, supplied as the ARK plus its ASK (KDS convention).
    amd_root_ca_pem: str = ""
    ask_pem: str = ""
    # Intel TDX anchor.
    intel_sgx_root_pem: str = ""
    # Sigstore trusted-root document, base64 (JSON bytes).
    sigstore_trusted_root_json_b64: str = ""
    # Pins the validity-window and freshness-appraisal clock so a frozen
    # document replays at its capture time; 0 uses the current time.
    verification_time_unix: int = 0


class MalformedInput(Exception):
    """The adapter input itself did not parse (exit 30)."""


_STR_FIELDS = (
    "schema_version",
    "document_b64",
    "nonce_hex",
    "repo",
    "amd_root_ca_pem",
    "ask_pem",
    "intel_sgx_root_pem",
    "sigstore_trusted_root_json_b64",
)


def parse_input(obj: Any) -> Input:
    """Decode the stdin JSON value into an Input. Mirrors Go's json decode of
    the Input struct: unknown members are tolerated, type mismatches are
    malformed input."""
    if not isinstance(obj, dict):
        raise MalformedInput("input is not a JSON object")
    in_ = Input()
    for name in _STR_FIELDS:
        v = obj.get(name)
        if v is None:
            continue
        if not isinstance(v, str):
            raise MalformedInput(f"{name} is not a string")
        setattr(in_, name, v)
    v = obj.get("verification_time_unix")
    if v is not None:
        if isinstance(v, bool) or not isinstance(v, int):
            raise MalformedInput("verification_time_unix is not an integer")
        in_.verification_time_unix = v
    return in_


@dataclass
class Roots:
    """Injected synthetic anchors; a None field selects the embedded
    production root."""

    amd: Optional[bytes] = None  # ASK+ARK KDS chain
    intel: Optional[bytes] = None  # Intel SGX root PEM
    sigstore: Optional[bytes] = None  # Sigstore trusted-root JSON


def _roots(in_: Input) -> Roots:
    r = Roots()
    if in_.amd_root_ca_pem != "" and in_.ask_pem != "":
        # KDS cert_chain is ASK then ARK.
        r.amd = (in_.ask_pem.strip() + "\n" + in_.amd_root_ca_pem.strip() + "\n").encode()
    elif in_.amd_root_ca_pem != "" or in_.ask_pem != "":
        raise MalformedInput("amd_root_ca_pem and ask_pem must be supplied together")
    if in_.intel_sgx_root_pem != "":
        r.intel = in_.intel_sgx_root_pem.encode()
    if in_.sigstore_trusted_root_json_b64 != "":
        try:
            r.sigstore = decode_base64(in_.sigstore_trusted_root_json_b64)
        except ValueError as e:
            raise MalformedInput(f"sigstore_trusted_root_json_b64: {e}") from None
    return r


def _hex_to_bytes(value: str) -> bytes:
    """Go hex.DecodeString: either case, even length, no whitespace."""
    import re

    if re.fullmatch(r"[0-9a-fA-F]*", value) is None or len(value) % 2 != 0:
        raise MalformedInput("nonce_hex is not hex")
    return bytes.fromhex(value)


def _reject(stage: str, code: str) -> tuple[dict, int]:
    return {"stage": stage, "accepted": False, "rejection": {"code": code}}, EXIT_REJECTED


def malformed(stage: str) -> tuple[dict, int]:
    return (
        {"stage": stage, "accepted": False, "rejection": {"code": "MALFORMED_INPUT"}},
        EXIT_MALFORMED,
    )


def run(stage: str, in_: Input) -> tuple[dict, int]:
    """Execute one stage; returns the wire Output dict plus the adapter exit
    code. Mirrors Go conformance.Run's input validation order."""
    if in_.schema_version != SCHEMA_VERSION:
        return malformed(stage)
    try:
        doc = decode_base64(in_.document_b64)
    except ValueError:
        return malformed(stage)
    try:
        nonce = _hex_to_bytes(in_.nonce_hex)
    except MalformedInput:
        return malformed(stage)
    try:
        _roots(in_)  # validated here; consumed once the quote/provenance slices land
    except MalformedInput:
        return malformed(stage)

    if stage == STAGE_CHECK_ENVELOPE:
        try:
            envelope.check(doc, nonce)
        except VerificationError:
            return _reject(stage, "ENVELOPE_REJECTED")
        return {"stage": stage, "accepted": True}, EXIT_ACCEPTED

    if stage in ALL_STAGES:
        # Not yet ported (provenance/sev/tdx/integration phases).
        return {"stage": stage, "accepted": False}, EXIT_UNSUPPORTED

    return {"stage": stage, "accepted": False}, EXIT_UNSUPPORTED
