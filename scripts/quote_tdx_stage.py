#!/usr/bin/env python3
"""Standalone v3-authenticate-quote adapter, TDX only: reads the wire Input on
stdin, runs tdx_authenticate against the fixture's pinned Intel root and
verification time, and emits the wire Output. Exit codes: 0 accepted, 10
rejected, 20 unsupported (stage or non-TDX cpu_evidence), 30 malformed."""

import json
import sys
import traceback
from datetime import datetime, timezone

from tinfoil.v3 import envelope
from tinfoil.v3.bytesutil import decode_base64
from tinfoil.v3.errors import VerificationError
from tinfoil.v3.tdx import tdx_authenticate

STAGE = "v3-authenticate-quote"


def emit(obj: dict, code: int) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.exit(code)


def malformed(stage: str, code: int = 30) -> None:
    emit({"stage": stage, "accepted": False, "rejection": {"code": "MALFORMED_INPUT"}}, code)


def main() -> None:
    stage = sys.argv[1] if len(sys.argv) > 1 else ""
    if stage != STAGE:
        malformed(stage, code=20)

    raw = sys.stdin.buffer.read()
    try:
        input_ = json.loads(raw)
    except ValueError:
        malformed(stage)
    if not isinstance(input_, dict) or not isinstance(input_.get("document_b64"), str):
        malformed(stage)

    try:
        doc_bytes = decode_base64(input_["document_b64"])
    except ValueError:
        malformed(stage)

    root_pem = None
    pem = input_.get("intel_sgx_root_pem")
    if isinstance(pem, str) and pem != "":
        root_pem = pem
    now = None
    t = input_.get("verification_time_unix")
    if isinstance(t, int) and not isinstance(t, bool) and t > 0:
        now = datetime.fromtimestamp(t, tz=timezone.utc)

    try:
        doc = envelope.parse_document(doc_bytes)
        if doc.cpu_evidence.format != envelope.TDX_QUOTE_V1_FORMAT:
            # Non-TDX evidence (e.g. SEV documents) is another adapter's job.
            malformed(stage, code=20)
        quote = tdx_authenticate(doc, root_pem=root_pem, now=now)
        emit(
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
            0,
        )
    except VerificationError as e:
        emit({"stage": stage, "accepted": False, "rejection": {"code": e.layer}}, 10)
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc(file=sys.stderr)
        malformed(stage)


if __name__ == "__main__":
    main()
