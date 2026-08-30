"""TDX quote authentication (tinfoil.v3.tdx.authenticate): the PCS replay
getter, the tcbEvaluationDataNumber recorder, and the full DCAP verification
against synthetic Intel material. Ports the Go replay_test.go cases and adds
end-to-end negatives per check family."""

import base64
from datetime import datetime, timedelta, timezone

import pytest

from tdx_material import (
    NOT_AFTER,
    NOT_BEFORE,
    PCKCRL_URL,
    QE_URL,
    ROOTCRL_URL,
    TCB_URL,
    TdBodyFields,
    build_crl,
    build_synth_chain,
    build_qe_identity_response,
    build_tcb_info_response,
    build_tdx_quote_v4,
    default_responses,
    default_tcb_levels,
    tdx_document,
)
from tinfoil.v3 import envelope
from tinfoil.v3.errors import QUOTE_REJECTED, VerificationError
from tinfoil.v3.measurement import TDX_GUEST_V2
from tinfoil.v3.tdx.authenticate import (
    PCSReplayGetter,
    TcbEvaluationRecorder,
    canonical_mime_header_key,
    pcs_collateral_key,
    tdx_authenticate,
)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def resp(url: str, body: bytes, headers=None) -> envelope.PCSResponse:
    return envelope.PCSResponse(url=url, headers=headers or {}, body_base64=b64(body))


NOW = datetime(2026, 1, 15, tzinfo=timezone.utc)


# --- pcsCollateralKey / canonical MIME keys -------------------------------------


def test_pcs_collateral_key_strips_tcb_evaluation_data_number():
    a = pcs_collateral_key(
        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000&tcbEvaluationDataNumber=19"
    )
    b = pcs_collateral_key(
        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000"
    )
    assert a == b


def test_pcs_collateral_key_sorts_query():
    assert pcs_collateral_key("https://x/y?b=2&a=1") == pcs_collateral_key("https://x/y?a=1&b=2")


def test_key_without_query_has_no_question_mark():
    assert (
        pcs_collateral_key("https://x.test/p?tcbEvaluationDataNumber=9") == "https://x.test/p"
    )


def test_canonical_mime_header_key():
    assert canonical_mime_header_key("tcb-info-issuer-chain") == "Tcb-Info-Issuer-Chain"
    assert canonical_mime_header_key("SGX-Enclave-Identity-Issuer-Chain") == "Sgx-Enclave-Identity-Issuer-Chain"
    assert canonical_mime_header_key("bad header") == "bad header"  # not a token


# --- PCSReplayGetter (Go TestPCSReplayGetter) ------------------------------------


def test_pcs_replay_getter():
    body = b'{"tcbInfo":{"tcbEvaluationDataNumber":19}}'
    getter = PCSReplayGetter(
        [
            resp(
                "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000&tcbEvaluationDataNumber=19",
                body,
                headers={"tcb-info-issuer-chain": ["chain"]},
            )
        ],
        NOW,
    )
    # The library requests the same resource without the
    # tcbEvaluationDataNumber parameter; the capture must still answer.
    headers, got = getter.get(
        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000"
    )
    assert got == body
    assert headers["Tcb-Info-Issuer-Chain"] == ["chain"]

    with pytest.raises(ValueError, match="no captured response"):
        getter.get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity")


def test_getter_lookup_is_case_insensitive():
    getter = PCSReplayGetter([resp("https://X.test/QE/identity", b"{}")], NOW)
    _, body = getter.get("https://x.test/qe/identity")
    assert body == b"{}"


# --- TcbEvaluationRecorder (Go TestTCBEvaluationRecorder) -------------------------


def test_tcb_evaluation_recorder():
    inner = PCSReplayGetter(
        [
            resp(TCB_URL, b'{"tcbInfo":{"tcbEvaluationDataNumber":20}}'),
            resp(QE_URL, b'{"enclaveIdentity":{"tcbEvaluationDataNumber":19}}'),
        ],
        NOW,
    )
    recorder = TcbEvaluationRecorder(inner)
    with pytest.raises(ValueError, match="was not observed"):
        recorder.minimum()
    recorder.get(TCB_URL)
    recorder.get(QE_URL)
    assert recorder.minimum() == 19


def test_recorder_ignores_non_integers():
    inner = PCSReplayGetter(
        [
            resp(TCB_URL, b'{"tcbInfo":{"tcbEvaluationDataNumber":1.5}}'),
            resp(QE_URL, b'{"enclaveIdentity":{"tcbEvaluationDataNumber":true}}'),
        ],
        NOW,
    )
    recorder = TcbEvaluationRecorder(inner)
    recorder.get(TCB_URL)
    recorder.get(QE_URL)
    with pytest.raises(ValueError, match="was not observed"):
        recorder.minimum()


# --- Replay getter CRL validation (Go TestPCSReplayGetterValidatesCRL) ------------


def _crl(chain, this_update, next_update):
    return build_crl(chain.root_ca, this_update=this_update, next_update=next_update)


@pytest.fixture(scope="module")
def module_chain():
    return build_synth_chain()


def test_replay_getter_validates_crl(module_chain):
    chain = module_chain
    pckcrl_url = "https://api.trustedservices.intel.com/tdx/certification/v4/pckcrl?ca=platform"
    cases = {
        "malformed": (pckcrl_url, b"not a CRL", "parsing captured CRL"),
        "future DER": (
            ROOTCRL_URL,
            _crl(chain, NOW + timedelta(hours=1), NOW + timedelta(hours=2)),
            "outside its validity window",
        ),
        "expired": (
            pckcrl_url,
            _crl(chain, NOW - timedelta(hours=2), NOW - timedelta(hours=1)),
            "outside its validity window",
        ),
        "current DER": (
            ROOTCRL_URL,
            _crl(chain, NOW - timedelta(hours=1), NOW + timedelta(hours=1)),
            None,
        ),
    }
    for name, (url, body, want_err) in cases.items():
        getter = PCSReplayGetter([resp(url, body)], NOW)
        if want_err:
            with pytest.raises(ValueError, match=want_err):
                getter.get(url)
        else:
            _, got = getter.get(url)
            assert got == body, name


def test_non_crl_body_off_crl_url_passes_through():
    getter = PCSReplayGetter([resp(TCB_URL, b"not json not crl")], NOW)
    _, got = getter.get(TCB_URL)
    assert got == b"not json not crl"


# --- Full authentication ----------------------------------------------------------


def authenticate(doc_bytes: bytes, root_pem: str, now=NOW):
    doc = envelope.parse_document(doc_bytes)
    return tdx_authenticate(doc, root_pem=root_pem, now=now)


def reject(doc_bytes: bytes, root_pem: str, match: str, now=NOW):
    with pytest.raises(VerificationError, match=match) as exc_info:
        authenticate(doc_bytes, root_pem, now=now)
    assert exc_info.value.layer == QUOTE_REJECTED


def test_authenticate_happy(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    doc_bytes = tdx_document(quote, default_responses(chain))
    q = authenticate(doc_bytes, chain.root_ca.pem)
    assert q.identity == "55" * 16
    body = TdBodyFields()
    assert q.measurement.type == TDX_GUEST_V2
    assert q.measurement.registers == [
        body.mr_td.hex(),
        body.rtmr0.hex(),
        body.rtmr1.hex(),
        body.rtmr2.hex(),
        body.rtmr3.hex(),
    ]
    assert q.tcb_evaluation_data_number == 18
    assert q.body.report_data == body.report_data
    assert q.quote is not None


def test_authenticate_minimum_of_tcb_numbers(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    responses = default_responses(
        chain,
        tcb=build_tcb_info_response(chain, tcb_evaluation_data_number=21),
        qe=build_qe_identity_response(chain, tcb_evaluation_data_number=17),
    )
    q = authenticate(tdx_document(quote, responses), chain.root_ca.pem)
    assert q.tcb_evaluation_data_number == 17


def test_reserved_header_bytes_reject(module_chain):
    chain = module_chain
    quote = bytearray(build_tdx_quote_v4(chain))
    quote[8] ^= 0xFF
    reject(
        tdx_document(bytes(quote), default_responses(chain)),
        chain.root_ca.pem,
        "non-zero reserved bytes",
    )


def test_nonzero_trailing_bytes_reject(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain) + b"\x01"
    reject(
        tdx_document(quote, default_responses(chain)),
        chain.root_ca.pem,
        "non-zero bytes after the signed data",
    )


def test_zero_trailing_padding_accepted(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain) + b"\x00" * 32
    q = authenticate(tdx_document(quote, default_responses(chain)), chain.root_ca.pem)
    assert q.identity == "55" * 16


def test_tampered_body_signature_rejects(module_chain):
    chain = module_chain
    quote = bytearray(build_tdx_quote_v4(chain))
    quote[100] ^= 0xFF  # inside the signed TD body
    reject(
        tdx_document(bytes(quote), default_responses(chain)),
        chain.root_ca.pem,
        "unable to verify message digest",
    )


def test_missing_collateral_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)

    doc = envelope.parse_document(tdx_document(quote, default_responses(chain)))
    doc.collateral = []
    with pytest.raises(VerificationError, match="no intel-pcs endorsement collateral") as ei:
        tdx_authenticate(doc, root_pem=chain.root_ca.pem, now=NOW)
    assert ei.value.layer == QUOTE_REJECTED


def test_missing_capture_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    responses = [r for r in default_responses(chain) if r["url"] != QE_URL]
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        "no captured response",
    )


def test_wrong_root_rejects(module_chain):
    chain = module_chain
    rogue = build_synth_chain()
    quote = build_tdx_quote_v4(chain)
    reject(
        tdx_document(quote, default_responses(chain)),
        rogue.root_ca.pem,
        "verifying TDX quote",
    )


def test_qe_mrsigner_mismatch_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain, qe_mrsigner=b"\xee" * 32)
    reject(
        tdx_document(quote, default_responses(chain)),
        chain.root_ca.pem,
        "MRSIGNER value in QE Report",
    )


def test_qe_report_binding_rejects(module_chain):
    # A QE report whose REPORT_DATA is not SHA-256(AK || auth data), with a
    # valid PCK signature over it, isolates the binding check.
    chain = module_chain
    quote = build_tdx_quote_v4(chain, qe_report_data=b"\x01" * 64)
    reject(
        tdx_document(quote, default_responses(chain)),
        chain.root_ca.pem,
        "error verifying QE report data",
    )


def test_tcb_status_not_up_to_date_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    responses = default_responses(
        chain, tcb=build_tcb_info_response(chain, tcb_levels=default_tcb_levels("OutOfDate"))
    )
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        'TCB Status is not "UpToDate"',
    )


def test_tdx_module_status_not_up_to_date_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    responses = default_responses(
        chain, tcb=build_tcb_info_response(chain, module_status="OutOfDate")
    )
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        "TDX Module TCB Status",
    )


def test_pcesvn_below_level_rejects(module_chain):
    chain = module_chain  # PCK carries pcesvn=11
    quote = build_tdx_quote_v4(chain)
    levels = default_tcb_levels()
    levels[0]["tcb"]["pcesvn"] = 99
    responses = default_responses(chain, tcb=build_tcb_info_response(chain, tcb_levels=levels))
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        "no matching TCB level found",
    )


def test_fmspc_mismatch_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    responses = default_responses(chain, tcb=build_tcb_info_response(chain, fmspc="ffffff000000"))
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        "FMSPC from PCK Certificate",
    )


def test_mr_signer_seam_mismatch_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain, body=TdBodyFields(mr_signer_seam=b"\xee" * 48))
    reject(
        tdx_document(quote, default_responses(chain)),
        chain.root_ca.pem,
        "MRSIGNERSEAM",
    )


def test_seam_attributes_mask_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain, body=TdBodyFields(seam_attributes=b"\xff" * 8))
    reject(
        tdx_document(quote, default_responses(chain)),
        chain.root_ca.pem,
        "TdxModule.Attributes",
    )


def test_revoked_pck_leaf_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    pck_crl = build_crl(
        chain.platform_ca, revoked_serials=[chain.pck_leaf.cert.serial_number]
    )
    responses = default_responses(chain, pck_crl=pck_crl)
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        "PCK Leaf certificate in PCK certificate chain was revoked",
    )


def test_revoked_tcb_signer_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    root_crl = build_crl(
        chain.root_ca, revoked_serials=[chain.tcb_signer.cert.serial_number]
    )
    responses = default_responses(chain, root_crl=root_crl)
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        "signing certificate was revoked",
    )


def test_expired_tcb_info_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    responses = default_responses(
        chain, tcb=build_tcb_info_response(chain, next_update="2024-01-01T00:00:00Z")
    )
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        "tcbInfo has expired",
    )


def test_now_pins_crl_window(module_chain):
    # A capture whose PCK CRL window closed long ago verifies at its capture
    # time and rejects at the current time.
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    window_end = NOT_BEFORE + timedelta(days=31)
    pck_crl = build_crl(chain.platform_ca, this_update=NOT_BEFORE, next_update=window_end)
    responses = default_responses(chain, pck_crl=pck_crl)
    doc_bytes = tdx_document(quote, responses)

    inside = NOT_BEFORE + timedelta(days=15)
    q = authenticate(doc_bytes, chain.root_ca.pem, now=inside)
    assert q.identity == "55" * 16

    reject(doc_bytes, chain.root_ca.pem, "outside its validity window", now=NOW)


def test_expired_certificates_reject(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    doc_bytes = tdx_document(quote, default_responses(chain))
    reject(
        doc_bytes,
        chain.root_ca.pem,
        "verifying TDX quote",
        now=NOT_AFTER + timedelta(days=1),
    )


def test_tampered_pcs_signature_rejects(module_chain):
    chain = module_chain
    quote = build_tdx_quote_v4(chain)
    tcb = build_tcb_info_response(chain)
    # Flip a digit inside the signed tcbInfo body (keep JSON valid).
    tampered = tcb.replace('"tcbEvaluationDataNumber":18', '"tcbEvaluationDataNumber":19')
    assert tampered != tcb
    responses = default_responses(chain, tcb=tampered)
    reject(
        tdx_document(quote, responses),
        chain.root_ca.pem,
        "could not verify response body",
    )
