"""Unit tests for the PCS replay getter (tinfoil.v3.tdx.authenticate): URL
canonicalization keying, canonical-MIME header normalization, the captured-CRL
validity window, and the tcbEvaluationDataNumber recorder."""

from datetime import datetime, timedelta, timezone

import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tinfoil.v3.envelope import PCSResponse
from tinfoil.v3.tdx.authenticate import (
    PCSReplayGetter,
    TcbEvaluationRecorder,
    canonical_mime_header_key,
    pcs_collateral_key,
)

NOW = datetime(2025, 6, 1, tzinfo=timezone.utc)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _resp(url: str, body: bytes, headers=None) -> PCSResponse:
    return PCSResponse(url=url, headers=headers or {}, body_base64=b64(body))


# --- replay keying --------------------------------------------------------------


def test_key_strips_tcb_evaluation_data_number():
    a = pcs_collateral_key(
        "https://x.test/tdx/v4/tcb?fmspc=50806f000000&tcbEvaluationDataNumber=18"
    )
    b = pcs_collateral_key("https://x.test/tdx/v4/tcb?fmspc=50806f000000")
    assert a == b


def test_key_sorts_remaining_params():
    a = pcs_collateral_key("https://x.test/p?b=2&a=1")
    b = pcs_collateral_key("https://x.test/p?a=1&b=2")
    assert a == b


def test_key_without_query_has_no_question_mark():
    assert pcs_collateral_key("https://x.test/p?tcbEvaluationDataNumber=9") == "https://x.test/p"


def test_getter_lookup_is_case_insensitive():
    getter = PCSReplayGetter([_resp("https://X.test/QE/identity", b"{}")], NOW)
    _, body = getter.get("https://x.test/qe/identity")
    assert body == b"{}"


def test_getter_missing_capture_errors():
    getter = PCSReplayGetter([], NOW)
    with pytest.raises(ValueError, match="no captured response"):
        getter.get("https://x.test/tcb?fmspc=00")


def test_getter_matches_capture_with_eval_number_to_bare_request():
    url = "https://api.test/tdx/certification/v4/tcb?fmspc=aa&tcbEvaluationDataNumber=18"
    getter = PCSReplayGetter([_resp(url, b'{"tcbInfo":{}}')], NOW)
    _, body = getter.get("https://api.test/tdx/certification/v4/tcb?fmspc=aa")
    assert body == b'{"tcbInfo":{}}'


# --- header canonicalization -----------------------------------------------------


def test_canonical_mime_header_key():
    assert canonical_mime_header_key("tcb-info-issuer-chain") == "Tcb-Info-Issuer-Chain"
    assert canonical_mime_header_key("SGX-PCK-CRL-ISSUER-CHAIN") == "Sgx-Pck-Crl-Issuer-Chain"
    # Non-token names pass through untouched.
    assert canonical_mime_header_key("bad header") == "bad header"


def test_getter_normalizes_header_casing():
    getter = PCSReplayGetter(
        [_resp("https://x.test/tcb", b"{}", headers={"tcb-INFO-issuer-CHAIN": ["v"]})],
        NOW,
    )
    headers, _ = getter.get("https://x.test/tcb")
    assert headers == {"Tcb-Info-Issuer-Chain": ["v"]}


# --- captured CRL validity window ------------------------------------------------


def _crl_der(last_update: datetime, next_update: datetime) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .last_update(last_update.replace(tzinfo=None))
        .next_update(next_update.replace(tzinfo=None))
        .sign(key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.DER)


def test_crl_inside_window_passes():
    der = _crl_der(NOW - timedelta(days=1), NOW + timedelta(days=1))
    getter = PCSReplayGetter([_resp("https://x.test/root.der", der)], NOW)
    _, body = getter.get("https://x.test/root.der")
    assert body == der


def test_crl_expired_rejects():
    der = _crl_der(NOW - timedelta(days=9), NOW - timedelta(days=1))
    getter = PCSReplayGetter([_resp("https://x.test/root.der", der)], NOW)
    with pytest.raises(ValueError, match="outside its validity window"):
        getter.get("https://x.test/root.der")


def test_crl_future_dated_rejects():
    # The library only checks NextUpdate; the getter also enforces ThisUpdate.
    der = _crl_der(NOW + timedelta(days=1), NOW + timedelta(days=9))
    getter = PCSReplayGetter([_resp("https://x.test/root.der", der)], NOW)
    with pytest.raises(ValueError, match="outside its validity window"):
        getter.get("https://x.test/root.der")


def test_crl_url_with_unparseable_body_rejects():
    getter = PCSReplayGetter([_resp("https://x.test/pckcrl?ca=platform", b"nope")], NOW)
    with pytest.raises(ValueError, match="parsing captured CRL"):
        getter.get("https://x.test/pckcrl?ca=platform")


def test_non_crl_url_with_non_crl_body_passes_through():
    getter = PCSReplayGetter([_resp("https://x.test/qe/identity", b"nope")], NOW)
    _, body = getter.get("https://x.test/qe/identity")
    assert body == b"nope"


# --- tcbEvaluationDataNumber recorder ---------------------------------------------


def test_recorder_minimum_over_both_responses():
    responses = [
        _resp("https://x.test/tdx/v4/tcb?fmspc=aa", b'{"tcbInfo":{"tcbEvaluationDataNumber":18}}'),
        _resp(
            "https://x.test/tdx/v4/qe/identity",
            b'{"enclaveIdentity":{"tcbEvaluationDataNumber":17}}',
        ),
    ]
    rec = TcbEvaluationRecorder(PCSReplayGetter(responses, NOW))
    rec.get("https://x.test/tdx/v4/tcb?fmspc=aa")
    rec.get("https://x.test/tdx/v4/qe/identity")
    assert rec.minimum() == 17


def test_recorder_requires_both_observations():
    responses = [
        _resp("https://x.test/tdx/v4/tcb?fmspc=aa", b'{"tcbInfo":{"tcbEvaluationDataNumber":18}}')
    ]
    rec = TcbEvaluationRecorder(PCSReplayGetter(responses, NOW))
    rec.get("https://x.test/tdx/v4/tcb?fmspc=aa")
    with pytest.raises(ValueError, match="was not observed"):
        rec.minimum()


def test_recorder_ignores_unparseable_and_non_integer_numbers():
    responses = [
        _resp("https://x.test/tdx/v4/tcb?fmspc=aa", b'{"tcbInfo":{"tcbEvaluationDataNumber":1.5}}'),
        _resp(
            "https://x.test/tdx/v4/qe/identity",
            b'{"enclaveIdentity":{"tcbEvaluationDataNumber":17}}',
        ),
    ]
    rec = TcbEvaluationRecorder(PCSReplayGetter(responses, NOW))
    rec.get("https://x.test/tdx/v4/tcb?fmspc=aa")
    rec.get("https://x.test/tdx/v4/qe/identity")
    with pytest.raises(ValueError, match="was not observed"):
        rec.minimum()
