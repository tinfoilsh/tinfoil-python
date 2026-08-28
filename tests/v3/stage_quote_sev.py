#!/usr/bin/env python3
"""Standalone conformance adapter for the SEV quote stage.

Implements the v3-authenticate-quote stage of the conformance wire contract
(CONFORMANCE_ADAPTER_SPEC v1.1) for SEV-SNP documents only: Input JSON on
stdin, Output JSON on stdout, the exit code is the verdict. Any other stage —
and a document whose cpu_evidence is not an SEV-SNP report — exits 20
(unsupported). Mirrors tinfoil-go conformance.Run's StageAuthenticateQuote
branch: an unparseable input or document is MALFORMED_INPUT (exit 30), an
authentication failure is the VerificationError's layer (exit 10).

Usage: python stage_quote_sev.py v3-authenticate-quote < input.json
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
from datetime import datetime, timezone
from typing import Any, NoReturn, Optional

from tinfoil.v3 import envelope
from tinfoil.v3.errors import VerificationError
from tinfoil.v3.sev import sev_authenticate

EXIT_ACCEPTED = 0
EXIT_INTERNAL = 1
EXIT_REJECTED = 10
EXIT_UNSUPPORTED = 20
EXIT_MALFORMED = 30

STAGE_AUTHENTICATE_QUOTE = "v3-authenticate-quote"


def _emit(stage: str, body: dict[str, Any], code: int) -> NoReturn:
    print(json.dumps({"stage": stage, **body}, separators=(",", ":")))
    sys.exit(code)


def _malformed(stage: str) -> NoReturn:
    _emit(stage, {"accepted": False, "rejection": {"code": "MALFORMED_INPUT"}}, EXIT_MALFORMED)


def _reject(stage: str, code: str) -> NoReturn:
    _emit(stage, {"accepted": False, "rejection": {"code": code}}, EXIT_REJECTED)


def _amd_root(inp: dict[str, Any], stage: str) -> Optional[str]:
    """The injected AMD anchor in KDS cert_chain order (ASK then ARK), or
    None for the embedded production roots. Both-or-neither, else malformed
    (Go conformance Input.roots)."""
    ark = inp.get("amd_root_ca_pem") or ""
    ask = inp.get("ask_pem") or ""
    if not isinstance(ark, str) or not isinstance(ask, str):
        _malformed(stage)
    if ark != "" and ask != "":
        return ask.strip() + "\n" + ark.strip() + "\n"
    if ark != "" or ask != "":
        _malformed(stage)  # amd_root_ca_pem and ask_pem must come together
    return None


def _verification_time(inp: dict[str, Any], stage: str) -> Optional[datetime]:
    """verification_time_unix pins the validity-window clock; absent/0 is the
    current time. A non-integer is malformed (Go json int64 decode)."""
    ts = inp.get("verification_time_unix", 0)
    if isinstance(ts, bool) or not isinstance(ts, int):
        _malformed(stage)
    if ts == 0:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        print("usage: stage_quote_sev.py <stage>", file=sys.stderr)
        sys.exit(EXIT_INTERNAL)
    stage = argv[1]
    if stage != STAGE_AUTHENTICATE_QUOTE:
        _emit(stage, {"accepted": False}, EXIT_UNSUPPORTED)

    try:
        inp = json.loads(sys.stdin.read())
    except (ValueError, UnicodeDecodeError):
        _malformed(stage)
    if not isinstance(inp, dict):
        _malformed(stage)
    if inp.get("schema_version") != "1":
        _malformed(stage)
    try:
        doc_bytes = base64.b64decode(inp.get("document_b64") or "", validate=True)
    except (binascii.Error, ValueError, TypeError):
        _malformed(stage)
    nonce_hex = inp.get("nonce_hex") or ""
    if not isinstance(nonce_hex, str):
        _malformed(stage)
    try:
        bytes.fromhex(nonce_hex)  # the nonce plays no role at this stage
    except ValueError:
        _malformed(stage)
    root_pem = _amd_root(inp, stage)
    now = _verification_time(inp, stage)

    # Stage semantics (Go conformance StageAuthenticateQuote): a document
    # that does not parse is malformed input, not a rejection.
    try:
        doc = envelope.parse_document(doc_bytes)
    except VerificationError:
        _malformed(stage)

    # SEV-only adapter: any other CPU evidence format is unsupported here.
    if doc.cpu_evidence.format != envelope.SEV_SNP_REPORT_V1_FORMAT:
        _emit(stage, {"accepted": False}, EXIT_UNSUPPORTED)

    try:
        quote = sev_authenticate(doc, root_pem=root_pem, now=now)
    except VerificationError as e:
        _reject(stage, e.layer)

    _emit(
        stage,
        {
            "accepted": True,
            "outputs": {
                "enclave_measurement": {
                    "type": quote.measurement.type,
                    "registers": quote.measurement.registers,
                }
            },
        },
        EXIT_ACCEPTED,
    )


if __name__ == "__main__":
    main(sys.argv)
