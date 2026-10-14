"""Pure stage logic of the conformance adapter, mirroring tinfoil-go
verifier/conformance (Run). The full-verify stage runs the public flow through
the adapter-only root/clock seam (_verify_document_v3, CONFORMANCE_ADAPTER_SPEC
§3); block stages deliberately reach internal layers. Live verification
(cli.py) uses the seamless public verify_document_v3."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from tinfoil import (
    VerificationError,
    hpke_public_key,
    tls_public_key_fp,
)
from tinfoil.v3 import envelope
from tinfoil.v3.bytesutil import decode_base64, decode_hex
# The adapter-only root/clock injection seam (CONFORMANCE_ADAPTER_SPEC §3).
from tinfoil.v3.client import _verify_document_v3
from tinfoil.v3.measurement import Measurement
from tinfoil.v3 import provenance
from tinfoil.v3.quote import quote_authenticate
from tinfoil.v3.tdx.der import parse_certificate, pem_decode

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

# Stages this adapter actually implements; capabilities derives from this.
SUPPORTED_STAGES = ALL_STAGES


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
        nonce = decode_hex(in_.nonce_hex)  # Go hex.DecodeString semantics
    except ValueError:
        return malformed(stage)
    try:
        rts = _roots(in_)
    except MalformedInput:
        return malformed(stage)
    # A supplied trusted root that does not parse is malformed input, for
    # every stage (Go: newProvAuth → provenance.NewClientFromJSON).
    if rts.sigstore is not None:
        try:
            provenance.check_trust_root(rts.sigstore)
        except VerificationError:
            return malformed(stage)

    if stage == STAGE_CHECK_ENVELOPE:
        try:
            envelope.check(doc, nonce)
        except VerificationError:
            return _reject(stage, "ENVELOPE_REJECTED")
        return {"stage": stage, "accepted": True}, EXIT_ACCEPTED

    if stage == STAGE_AUTHENTICATE_PROVENANCE:
        try:
            parsed = envelope.parse_document(doc)
        except VerificationError:
            return malformed(stage)
        try:
            code_ref = envelope.reference_values_collateral(
                parsed, envelope.COLLATERAL_SIGSTORE_CODE_V1_FORMAT
            )
            code = provenance.authenticate_code(
                code_ref.sigstore_bundle,
                in_.repo,
                code_ref.tag,
                code_ref.digest,
                trust_root_json=rts.sigstore,
            )
        except VerificationError:
            return _reject(stage, "PROVENANCE_REJECTED")
        return {
            "stage": stage,
            "accepted": True,
            "outputs": {
                "code_digest": code.digest,
                "code_measurement": _to_measurement(code.measurement),
            },
        }, EXIT_ACCEPTED

    if stage == STAGE_ASSEMBLE_POLICY:
        try:
            parsed = envelope.parse_document(doc)
        except VerificationError:
            return malformed(stage)
        try:
            plat_ref = envelope.reference_values_collateral(
                parsed, envelope.COLLATERAL_SIGSTORE_PLATFORM_V1_FORMAT
            )
            provenance.authenticate_platform_endorsements(
                plat_ref.sigstore_bundle,
                plat_ref.repo,
                plat_ref.tag,
                plat_ref.digest,
                trust_root_json=rts.sigstore,
            )
        except VerificationError:
            return _reject(stage, "PROVENANCE_REJECTED")
        return {"stage": stage, "accepted": True}, EXIT_ACCEPTED

    # An injected Intel root is parsed eagerly: a PEM that does not parse is
    # malformed input, not a rejection (Go: tdx.SetIntelRoot at setQuoteRoots).
    amd_root_pem = rts.amd.decode() if rts.amd is not None else None
    intel_root_pem = rts.intel.decode() if rts.intel is not None else None
    # verification_time_unix pins the validity-window and freshness-appraisal
    # clock so a frozen document replays at its capture time; 0 uses the
    # current time (Go: Run's Set/ResetVerificationTime).
    verification_time = (
        datetime.fromtimestamp(in_.verification_time_unix, tz=timezone.utc)
        if in_.verification_time_unix != 0
        else None
    )

    if stage == STAGE_AUTHENTICATE_QUOTE:
        try:
            parsed = envelope.parse_document(doc)
        except VerificationError:
            return malformed(stage)
        if intel_root_pem is not None and not _parses_as_certificate(intel_root_pem):
            return malformed(stage)
        try:
            auth = quote_authenticate(
                parsed,
                amd_root_pem=amd_root_pem,
                intel_root_pem=intel_root_pem,
                now=verification_time,
            )
        except VerificationError:
            return _reject(stage, "QUOTE_REJECTED")
        return {
            "stage": stage,
            "accepted": True,
            "outputs": {"enclave_measurement": _to_measurement(auth.measurement)},
        }, EXIT_ACCEPTED

    if stage == STAGE_VERIFY:
        if intel_root_pem is not None and not _parses_as_certificate(intel_root_pem):
            return malformed(stage)
        try:
            verified = _verify_document_v3(
                doc,
                nonce,
                in_.repo,
                sigstore_root_json=rts.sigstore,
                amd_root_pem=amd_root_pem,
                intel_root_pem=intel_root_pem,
                verification_time=verification_time,
            )
        except VerificationError as e:
            # The first failing step names the layer (Go: verifyFull).
            return _reject(stage, e.layer)
        # A document that verifies but endorses no usable channel keys is
        # useless to every real client, so the full stage requires both
        # (Go: verifyFull); the public accessors raise when a key is absent
        # or format-mismatched.
        try:
            tls_fp = tls_public_key_fp(verified)
            hpke = hpke_public_key(verified)
        except ValueError:
            return _reject(stage, "ENVELOPE_REJECTED")
        return {
            "stage": stage,
            "accepted": True,
            "outputs": {
                "code_digest": verified.code_digest,
                "code_measurement": _to_measurement(verified.code_measurement),
                "enclave_measurement": _to_measurement(verified.enclave_measurement),
                "tls_public_key_fp": tls_fp,
                "hpke_public_key": hpke,
            },
        }, EXIT_ACCEPTED

    return {"stage": stage, "accepted": False}, EXIT_UNSUPPORTED


def _parses_as_certificate(pem: str) -> bool:
    """The same PEM/DER parse the TDX layer performs on an injected root
    (tdx/authenticate _root_from_pem), gating malformed input up front."""
    block = pem_decode(pem)
    if block is None:
        return False
    try:
        parse_certificate(block.der)
    except ValueError:
        return False
    return True


def _to_measurement(m: Measurement) -> dict:
    return {"type": m.type, "registers": list(m.registers)}
