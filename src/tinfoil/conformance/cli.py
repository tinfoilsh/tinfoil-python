"""stdin/stdout/exit-code wrapper of the conformance adapter, mirroring
tinfoil-go cmd/tinfoil-conformance: `tinfoil-conformance <stage>` reads an
Input JSON on stdin and writes an Output JSON on stdout, exiting with the
adapter code; `tinfoil-conformance capabilities` prints the SDK's
capabilities. capture/live-verify land with the integration phase."""

from __future__ import annotations

import json
import sys

from . import run as runner
from .capabilities import capabilities


def _write_json(v) -> None:
    json.dump(v, sys.stdout, indent=2)
    sys.stdout.write("\n")


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: tinfoil-conformance <stage>|capabilities", file=sys.stderr)
        sys.exit(runner.EXIT_MALFORMED)
    cmd = sys.argv[1]

    if cmd == "capabilities":
        _write_json(capabilities())
        sys.exit(0)

    if cmd in ("capture", "live-verify"):
        # Not yet implemented (integration phase); never a wrong verdict.
        sys.exit(runner.EXIT_UNSUPPORTED)

    try:
        # Exactly one JSON value; json.loads rejects trailing data.
        obj = json.loads(sys.stdin.buffer.read())
        in_ = runner.parse_input(obj)
    except (ValueError, runner.MalformedInput):
        _write_json(
            {"stage": cmd, "accepted": False, "rejection": {"code": "MALFORMED_INPUT"}}
        )
        sys.exit(runner.EXIT_MALFORMED)

    try:
        out, code = runner.run(cmd, in_)
    except Exception as e:  # unexpected adapter error
        print(f"internal error: {e}", file=sys.stderr)
        sys.exit(runner.EXIT_INTERNAL)
    _write_json(out)
    sys.exit(code)


if __name__ == "__main__":
    main()
