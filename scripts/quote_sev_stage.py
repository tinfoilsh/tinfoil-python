#!/usr/bin/env python3
"""Standalone conformance wire-protocol adapter for the v3-authenticate-quote
stage, SEV-SNP only (spec: tinfoil-conformance/docs/CONFORMANCE_ADAPTER_SPEC.md).

Invoked as `python scripts/quote_sev_stage.py <stage>` with the Input JSON on
stdin; emits the Output JSON on stdout with the exit code as the verdict.
TDX documents and every other stage exit 20 (unsupported). This script exists
so the SEV slice can be driven before the full tinfoil-conformance adapter
lands; it mirrors tinfoil-go conformance.Run's StageAuthenticateQuote branch.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from tinfoil.v3 import envelope
from tinfoil.v3.bytesutil import decode_base64, decode_hex
from tinfoil.v3.errors import VerificationError
from tinfoil.v3.sev import sev_authenticate

EXIT_ACCEPTED = 0
EXIT_INTERNAL = 1
EXIT_REJECTED = 10
EXIT_UNSUPPORTED = 20
EXIT_MALFORMED = 30

STAGE_AUTHENTICATE_QUOTE = "v3-authenticate-quote"
SCHEMA_VERSION = "1"


def _emit(payload: dict, code: int) -> int:
    print(json.dumps(payload))
    return code


def _malformed(stage: str) -> int:
    return _emit(
        {"stage": stage, "accepted": False, "rejection": {"code": "MALFORMED_INPUT"}},
        EXIT_MALFORMED,
    )


def _reject(stage: str, code: str) -> int:
    return _emit(
        {"stage": stage, "accepted": False, "rejection": {"code": code}}, EXIT_REJECTED
    )


def run(stage: str, stdin_data: str) -> int:
    if stage != STAGE_AUTHENTICATE_QUOTE:
        return _emit({"stage": stage, "accepted": False}, EXIT_UNSUPPORTED)

    try:
        raw = json.loads(stdin_data)
    except ValueError:
        return _malformed(stage)
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        return _malformed(stage)
    try:
        doc_bytes = decode_base64(str(raw.get("document_b64", "")))
        decode_hex(str(raw.get("nonce_hex", "")))  # validated, unused at this stage
    except ValueError:
        return _malformed(stage)

    # Trust-root injection: ARK + ASK both-or-neither; the root chain uses
    # the KDS cert_chain order (ASK then ARK). Empty selects the embedded
    # per-product production root.
    ark_pem = str(raw.get("amd_root_ca_pem", "") or "")
    ask_pem = str(raw.get("ask_pem", "") or "")
    root_pem = None
    if ark_pem != "" and ask_pem != "":
        root_pem = ask_pem.strip() + "\n" + ark_pem.strip() + "\n"
    elif ark_pem != "" or ask_pem != "":
        return _malformed(stage)

    # verification_time_unix pins the validity-window clock; 0/absent = now.
    now = None
    vtime = raw.get("verification_time_unix", 0)
    if not isinstance(vtime, int) or isinstance(vtime, bool):
        if vtime is not None:
            return _malformed(stage)
        vtime = 0
    if vtime != 0:
        now = datetime.fromtimestamp(vtime, tz=timezone.utc)

    try:
        doc = envelope.parse_document(doc_bytes)
    except VerificationError:
        return _malformed(stage)

    fmt = doc.cpu_evidence.format
    if fmt == envelope.TDX_QUOTE_V1_FORMAT:
        # The TDX slice is owned elsewhere; this adapter only does SEV.
        return _emit({"stage": stage, "accepted": False}, EXIT_UNSUPPORTED)
    if fmt != envelope.SEV_SNP_REPORT_V1_FORMAT:
        return _reject(stage, "QUOTE_REJECTED")

    try:
        quote = sev_authenticate(doc, root_pem=root_pem, now=now)
    except VerificationError:
        return _reject(stage, "QUOTE_REJECTED")

    return _emit(
        {
            "stage": stage,
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


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: quote_sev_stage.py <stage>", file=sys.stderr)
        return EXIT_INTERNAL
    return run(sys.argv[1], sys.stdin.read())


if __name__ == "__main__":
    sys.exit(main())
