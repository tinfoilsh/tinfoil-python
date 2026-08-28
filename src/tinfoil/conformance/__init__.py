"""tinfoil-python v3 conformance adapter (CONFORMANCE_ADAPTER_SPEC v1.1).

The cross-SDK suite invokes ``tinfoil-conformance <stage>`` with an Input JSON
on stdin and reads an Output JSON on stdout; the exit code carries the
verdict. run.py holds the pure stage logic, cli.py the stdin/stdout/exit
wrapper, capabilities.py the self-description.
"""
