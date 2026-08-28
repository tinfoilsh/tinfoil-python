"""The standalone v3-authenticate-quote wire adapter (scripts/quote_tdx_stage.py):
exit codes and wire shapes per CONFORMANCE_ADAPTER_SPEC."""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from docbuilder import build_doc
from tdx_material import build_synth_chain, build_tdx_quote_v4, default_responses, tdx_document
from tinfoil.v3.measurement import TDX_GUEST_V2

SCRIPT = str(Path(__file__).resolve().parents[2] / "scripts" / "quote_tdx_stage.py")


def run_stage(stage: str, payload: bytes):
    proc = subprocess.run(
        [sys.executable, SCRIPT, stage], input=payload, capture_output=True
    )
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def wire_input(doc_bytes: bytes, root_pem: str) -> bytes:
    return json.dumps(
        {
            "schema_version": "1",
            "document_b64": base64.b64encode(doc_bytes).decode(),
            "nonce_hex": "",
            "repo": "tinfoilsh/confidential-inference-proxy",
            "intel_sgx_root_pem": root_pem,
        }
    ).encode()


@pytest.fixture(scope="module")
def material():
    chain = build_synth_chain()
    quote = build_tdx_quote_v4(chain)
    return chain, tdx_document(quote, default_responses(chain))


def test_happy_accepts(material):
    chain, doc_bytes = material
    code, out = run_stage("v3-authenticate-quote", wire_input(doc_bytes, chain.root_ca.pem))
    assert code == 0
    assert out["accepted"] is True
    m = out["outputs"]["enclave_measurement"]
    assert m["type"] == TDX_GUEST_V2
    assert len(m["registers"]) == 5


def test_wrong_root_rejects_quote(material):
    chain, doc_bytes = material
    rogue = build_synth_chain()
    code, out = run_stage("v3-authenticate-quote", wire_input(doc_bytes, rogue.root_ca.pem))
    assert code == 10
    assert out["rejection"]["code"] == "QUOTE_REJECTED"


def test_sev_document_unsupported(material):
    chain, _ = material
    sev_doc = build_doc()  # cpu_evidence.format is the SEV report format
    code, out = run_stage("v3-authenticate-quote", wire_input(sev_doc, chain.root_ca.pem))
    assert code == 20
    assert out["rejection"]["code"] == "MALFORMED_INPUT"


def test_unknown_stage_unsupported(material):
    chain, doc_bytes = material
    code, out = run_stage("v3-check-envelope", wire_input(doc_bytes, chain.root_ca.pem))
    assert code == 20


def test_malformed_input(material):
    code, out = run_stage("v3-authenticate-quote", b"not json")
    assert code == 30
    assert out["rejection"]["code"] == "MALFORMED_INPUT"

    code, out = run_stage("v3-authenticate-quote", b'{"document_b64": 7}')
    assert code == 30

    code, out = run_stage("v3-authenticate-quote", b'{"document_b64": "@@"}')
    assert code == 30


def test_unparseable_document_rejects_envelope(material):
    chain, _ = material
    code, out = run_stage(
        "v3-authenticate-quote",
        wire_input(b'{"format":"nope"}', chain.root_ca.pem),
    )
    assert code == 10
    assert out["rejection"]["code"] == "ENVELOPE_REJECTED"
