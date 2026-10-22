"""tinfoil-python conformance adapter for the cross-SDK v3 suite.

``tinfoil_conformance.py <stage>`` reads an Input JSON on stdin, writes an
Output JSON on stdout and exits with the adapter code; ``capabilities``
prints the SDK's self-description (tinfoil-conformance
CONFORMANCE_ADAPTER_SPEC.md). Tests drive ``run`` in-process.

The full-verify stage is one Verifier.verify_at call, so the shared fixtures
appraise exactly the code production runs, and the layer of its
VerificationError names the rejection. Block stages, which isolate one layer
by calling into the modules the verifier composes, are added alongside those
modules. Synthetic roots and the appraisal clock travel as per-call
arguments, so no process state changes.

Unimplemented verification steps exit 20 (unsupported), never with a
verdict.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
import traceback
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, BinaryIO, TextIO

from tinfoil import verify
from tinfoil.verify import _dangerous_test_only
from tinfoil.verify import document as _document
from tinfoil.verify.measurement import Measurement

# Exit codes are the cross-SDK contract: the suite reads them for the verdict.
EXIT_ACCEPTED = 0
EXIT_INTERNAL = 1
EXIT_REJECTED = 10
EXIT_UNSUPPORTED = 20
EXIT_MALFORMED = 30

SCHEMA_VERSION = "1"
SDK_NAME = "tinfoil-python"

STAGE_VERIFY = "verify-attestation-v3"
STAGE_CHECK_ENVELOPE = "v3-check-envelope"

ENVELOPE_REJECTED = "ENVELOPE_REJECTED"
PROVENANCE_REJECTED = "PROVENANCE_REJECTED"
QUOTE_REJECTED = "QUOTE_REJECTED"
POLICY_REJECTED = "POLICY_REJECTED"
MALFORMED_INPUT = "MALFORMED_INPUT"

_LAYER_CODES = {
    verify.Layer.ENVELOPE: ENVELOPE_REJECTED,
    verify.Layer.PROVENANCE: PROVENANCE_REJECTED,
    verify.Layer.QUOTE: QUOTE_REJECTED,
    verify.Layer.POLICY: POLICY_REJECTED,
}

_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")


class MalformedInput(ValueError):
    """The adapter input itself did not parse."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Input:
    """A decoded adapter Input: a document, the verifier's expectations and synthetic roots.

    Absent roots select the embedded production roots.
    """

    document: bytes
    nonce: bytes
    repo: str
    # The ASK then ARK, PEM-encoded (the AMD KDS cert_chain layout).
    amd_root_pem: bytes | None
    intel_root_pem: bytes | None
    sigstore_trusted_root: bytes | None
    # Pins the validity-window and freshness clock; None uses the current time.
    verification_time: datetime | None

    @classmethod
    def from_json(cls, data: Any) -> Input:
        """Decode the Input JSON object. Raises MalformedInput."""
        if not isinstance(data, Mapping):
            raise MalformedInput("input is not a JSON object")
        if data.get("schema_version") != SCHEMA_VERSION:
            raise MalformedInput(f"schema_version must be {SCHEMA_VERSION!r}")

        amd_root, ask = _string(data, "amd_root_ca_pem"), _string(data, "ask_pem")
        if bool(amd_root) != bool(ask):
            raise MalformedInput("amd_root_ca_pem and ask_pem must be supplied together")
        sigstore_root = _string(data, "sigstore_trusted_root_json_b64")
        intel_root = _string(data, "intel_sgx_root_pem")
        timestamp = data.get("verification_time_unix", 0)
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            raise MalformedInput("verification_time_unix must be an integer")
        try:
            verification_time = datetime.fromtimestamp(timestamp, timezone.utc) if timestamp else None
        except (OverflowError, OSError, ValueError) as err:
            raise MalformedInput(f"verification_time_unix is out of range: {err}") from err

        return cls(
            document=_base64(_string(data, "document_b64"), "document_b64"),
            nonce=_hex(_string(data, "nonce_hex"), "nonce_hex"),
            repo=_string(data, "repo"),
            # The KDS cert_chain is the ASK then the ARK.
            amd_root_pem=f"{ask.strip()}\n{amd_root.strip()}\n".encode() if amd_root else None,
            intel_root_pem=intel_root.encode() if intel_root else None,
            sigstore_trusted_root=_base64(sigstore_root, "sigstore_trusted_root_json_b64") if sigstore_root else None,
            verification_time=verification_time,
        )


def _string(data: Mapping[str, Any], name: str) -> str:
    value = data.get(name, "")
    if not isinstance(value, str):
        raise MalformedInput(f"{name} must be a string")
    return value


def _base64(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as err:
        raise MalformedInput(f"{name}: {err}") from err


def _hex(value: str, name: str) -> bytes:
    if not _HEX.fullmatch(value):
        raise MalformedInput(f"{name} is not hex")
    return bytes.fromhex(value)


def capabilities() -> dict[str, Any]:
    """The adapter's self-description, which the suite uses to gate fixtures."""
    return {
        "schema_version": SCHEMA_VERSION,
        "sdk": SDK_NAME,
        "v3": {
            "supported": True,
            "stages_supported": [STAGE_VERIFY, STAGE_CHECK_ENVELOPE],
            "synthetic_roots": {"amd": True, "intel": True, "sigstore": True},
            "freshness_enforced": True,
            "live_verify": False,
            "channel_binding": "none",
        },
    }


def rejection_code(err: BaseException) -> tuple[str | None, int]:
    """Report a verification error the way the wire contract does.

    A VerificationError is rejected with its layer's code, and a UsageError
    means the input was malformed. Anything else, including a
    VerificationError without a known layer, is a verifier bug.
    """
    if isinstance(err, verify.UsageError):
        return MALFORMED_INPUT, EXIT_MALFORMED
    if isinstance(err, verify.VerificationError) and err.layer in _LAYER_CODES:
        return _LAYER_CODES[err.layer], EXIT_REJECTED
    return None, EXIT_INTERNAL


Output = dict[str, Any]


def run(stage: str, request: Any) -> tuple[Output, int]:
    """Run one stage on a decoded Input JSON value; return the Output and exit code."""
    try:
        inputs = Input.from_json(request)
        verifier = _dangerous_test_only.verifier(
            sigstore_trusted_root=inputs.sigstore_trusted_root,
            amd_root_pem=inputs.amd_root_pem,
            intel_root_pem=inputs.intel_root_pem,
        )
    except (MalformedInput, verify.UsageError):
        return _reject(stage, MALFORMED_INPUT, EXIT_MALFORMED)
    except NotImplementedError:
        return _output(stage), EXIT_UNSUPPORTED

    appraisal = inputs.verification_time or datetime.now(timezone.utc)
    handlers: dict[str, Callable[[], tuple[Output, int]]] = {
        STAGE_VERIFY: lambda: _verify(inputs, verifier, appraisal),
        STAGE_CHECK_ENVELOPE: lambda: _check_envelope(inputs),
    }
    handler = handlers.get(stage)
    if handler is None:
        return _output(stage), EXIT_UNSUPPORTED
    try:
        return handler()
    except NotImplementedError:
        return _output(stage), EXIT_UNSUPPORTED


def _verify(inputs: Input, verifier: verify.Verifier, appraisal: datetime) -> tuple[Output, int]:
    try:
        verified = verifier.verify_at(inputs.document, inputs.nonce, inputs.repo, appraisal)
    except NotImplementedError:
        raise
    except Exception as err:
        code, exit_code = rejection_code(err)
        if code is None:
            return _output(STAGE_VERIFY), exit_code
        return _reject(STAGE_VERIFY, code, exit_code)
    # A document that verifies but endorses no usable channel keys is useless
    # to every real client, so the full stage requires both.
    tls_public_key_fp, hpke_public_key = verified.tls_public_key_fp, verified.hpke_public_key
    if tls_public_key_fp is None or hpke_public_key is None:
        return _reject(STAGE_VERIFY, ENVELOPE_REJECTED)
    return _accept(
        STAGE_VERIFY,
        code_digest=verified.code_digest,
        code_measurement=_measurement(verified.code_measurement),
        enclave_measurement=_measurement(verified.enclave_measurement),
        tls_public_key_fp=tls_public_key_fp,
        hpke_public_key=hpke_public_key,
    )


def _check_envelope(inputs: Input) -> tuple[Output, int]:
    if _fails(lambda: _document.parse(inputs.document, inputs.nonce)):
        return _reject(STAGE_CHECK_ENVELOPE, ENVELOPE_REJECTED)
    return _accept(STAGE_CHECK_ENVELOPE)


def _fails(step: Callable[[], object]) -> bool:
    try:
        step()
    except NotImplementedError:
        raise
    except Exception:
        return True
    return False


def _measurement(measurement: Measurement) -> dict[str, Any]:
    return {"type": str(measurement.type), "registers": list(measurement.registers)}


def _output(stage: str) -> Output:
    return {"stage": stage, "accepted": False}


def _accept(stage: str, **facts: Any) -> tuple[Output, int]:
    output: Output = {"stage": stage, "accepted": True}
    if facts:
        output["outputs"] = facts
    return output, EXIT_ACCEPTED


def _reject(stage: str, code: str, exit_code: int = EXIT_REJECTED) -> tuple[Output, int]:
    return {"stage": stage, "accepted": False, "rejection": {"code": code}}, exit_code


def main(argv: list[str] | None = None, stdin: BinaryIO | None = None, stdout: TextIO | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if not args:
        print("usage: tinfoil_conformance.py <stage>|capabilities", file=sys.stderr)
        return EXIT_MALFORMED
    command = args[0]
    if command == "capabilities":
        _write(stdout, capabilities())
        return EXIT_ACCEPTED
    try:
        # Exactly one JSON value: trailing data is malformed input.
        request = json.loads(stdin.read())
    except ValueError:
        output, exit_code = _reject(command, MALFORMED_INPUT, EXIT_MALFORMED)
        _write(stdout, output)
        return exit_code
    try:
        output, exit_code = run(command, request)
    except Exception:
        traceback.print_exc()
        output, exit_code = _output(command), EXIT_INTERNAL
    _write(stdout, output)
    return exit_code


def _write(stdout: TextIO, value: Any) -> None:
    stdout.write(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
