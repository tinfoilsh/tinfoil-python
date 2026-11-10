"""Replay of captured Intel PCS responses: URL keys, header names, CRL windows, issue dates and evaluation numbers."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from tests.v3 import pki
from tests.v3 import tdx_builders as tb
from tinfoil._v3.verifier._document.collateral.tdx import PCSResponse
from tinfoil._v3.verifier._quote.tdx.lib.collateral import TdxCollateral
from tinfoil._v3.verifier._quote.tdx.pcs import (
    INTEL_SGX_ROOT_CA_CRL_URL,
    PCSReplay,
    PCSReplayError,
    canonical_header_name,
    check_issue_dates,
    crl_distribution_points,
    minimum_tcb_evaluation_data_number,
    pck_crl_url,
    pcs_collateral_key,
    qe_identity_url,
    tcb_info_url,
)

TCB_URL = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000"
QE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
PCK_CRL_URL = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"


def test_urls() -> None:
    assert tcb_info_url("90c06f000000") == TCB_URL
    assert qe_identity_url() == QE_URL
    assert pck_crl_url("platform") == PCK_CRL_URL
    assert pck_crl_url("processor") == PCK_CRL_URL.replace("platform", "processor")


def test_collateral_key_drops_the_evaluation_number_and_sorts_parameters() -> None:
    assert pcs_collateral_key(TCB_URL + "&tcbEvaluationDataNumber=19") == pcs_collateral_key(TCB_URL)
    assert (
        pcs_collateral_key("https://A.example/P?encoding=der&ca=platform")
        == "https://a.example/p?ca=platform&encoding=der"
    )
    assert (
        pcs_collateral_key("https://a.example/p?ca=platform&ca=processor")
        == "https://a.example/p?ca=platform&ca=processor"
    )
    assert pcs_collateral_key("https://a.example/p?flag") == "https://a.example/p?flag="
    assert pcs_collateral_key("https://a.example/p?tcbEvaluationDataNumber=1") == "https://a.example/p"


def test_collateral_key_rejects_an_unparseable_url() -> None:
    with pytest.raises(PCSReplayError, match="parsing PCS URL"):
        pcs_collateral_key("https://[::1/x")


def test_replay_serves_the_capture_for_the_parameterless_request() -> None:
    body = b'{"tcbInfo":{"tcbEvaluationDataNumber":19}}'
    replay = PCSReplay(
        [
            PCSResponse(
                url=TCB_URL + "&tcbEvaluationDataNumber=19", headers={"tcb-info-issuer-chain": ("chain",)}, body=body
            )
        ],
        datetime.now(UTC),
    )
    captured = replay.get(TCB_URL)
    assert captured.body == body
    assert captured.headers["Tcb-Info-Issuer-Chain"] == ("chain",)
    assert captured.header("tcb-info-issuer-chain") == "chain"
    with pytest.raises(PCSReplayError, match="no captured response"):
        replay.get(QE_URL)


def test_repeated_url_keeps_the_last_capture() -> None:
    replay = PCSReplay(
        [
            PCSResponse(url=TCB_URL, headers={}, body=b"first"),
            PCSResponse(url=TCB_URL + "&tcbEvaluationDataNumber=2", headers={}, body=b"second"),
        ],
        datetime.now(UTC),
    )
    assert replay.get(TCB_URL).body == b"second"


def test_header_lookup() -> None:
    captured = PCSReplay(
        [PCSResponse(url=TCB_URL, headers={"X-One": ("a",), "X-Two": ("a", "b"), "X-Empty": ("",)}, body=b"{}")],
        datetime.now(UTC),
    ).get(TCB_URL)
    assert captured.header("x-one") == "a"
    with pytest.raises(PCSReplayError, match="is empty"):
        captured.header("X-Missing")
    with pytest.raises(PCSReplayError, match="expected to be of size 1, found 2"):
        captured.header("X-Two")
    with pytest.raises(PCSReplayError, match="certificates missing"):
        captured.header("X-Empty")


def test_header_repeated_under_another_case_rejects() -> None:
    """Two captured names with one canonical form never overwrite each other: the replay refuses to pick one."""
    replay = PCSReplay(
        [
            PCSResponse(
                url=TCB_URL,
                headers={"Tcb-Info-Issuer-Chain": ("first",), "tcb-info-issuer-chain": ("second",)},
                body=b"{}",
            )
        ],
        tb.NOW,
    )
    with pytest.raises(PCSReplayError, match="repeated header 'Tcb-Info-Issuer-Chain'"):
        replay.get(TCB_URL)
    with pytest.raises(PCSReplayError, match="repeated header 'Tcb-Info-Issuer-Chain'"):
        replay.tcb_info("90c06f000000")


@pytest.mark.parametrize(
    ("name", "canonical"),
    [
        ("tcb-info-issuer-chain", "Tcb-Info-Issuer-Chain"),
        ("SGX-PCK-CRL-ISSUER-CHAIN", "Sgx-Pck-Crl-Issuer-Chain"),
        ("content-type", "Content-Type"),
        ("x--y", "X--Y"),
        ("bad header", "bad header"),
        ("", ""),
    ],
)
def test_canonical_header_name(name: str, canonical: str) -> None:
    assert canonical_header_name(name) == canonical


def _crl(this_update: datetime, next_update: datetime) -> bytes:
    issuer = pki.certificate(
        "test CA",
        pki.ed25519_key(),
        ca=True,
        key_usage=pki.CA_USAGE,
        not_before=this_update - timedelta(hours=1),
        not_after=next_update + timedelta(hours=1),
    )
    return pki.crl(issuer, this_update=this_update, next_update=next_update)


@pytest.mark.parametrize(
    ("url", "kind", "error"),
    [
        (PCK_CRL_URL, "malformed", "parsing captured CRL"),
        (INTEL_SGX_ROOT_CA_CRL_URL, "future", "outside its validity window"),
        (PCK_CRL_URL, "expired", "outside its validity window"),
        (INTEL_SGX_ROOT_CA_CRL_URL, "current", ""),
        (TCB_URL, "malformed", ""),
    ],
    ids=["malformed", "future DER", "expired", "current DER", "non-CRL body"],
)
def test_replay_validates_crl_bodies(url: str, kind: str, error: str) -> None:
    now = datetime.now(UTC)
    bodies: dict[str, Callable[[], bytes]] = {
        "malformed": lambda: b"not a CRL",
        "future": lambda: _crl(now + timedelta(hours=1), now + timedelta(hours=2)),
        "expired": lambda: _crl(now - timedelta(hours=2), now - timedelta(hours=1)),
        "current": lambda: _crl(now - timedelta(hours=1), now + timedelta(hours=1)),
    }
    body = bodies[kind]()
    replay = PCSReplay([PCSResponse(url=url, headers={}, body=body)], now)
    if error:
        with pytest.raises(PCSReplayError, match=error):
            replay.get(url)
    else:
        assert replay.get(url).body == body


def test_replay_accepts_a_crl_at_its_window_edges() -> None:
    now = datetime(2026, 1, 15, tzinfo=UTC)
    for this_update, next_update in ((now, now + timedelta(hours=1)), (now - timedelta(hours=1), now)):
        body = _crl(this_update, next_update)
        assert PCSReplay([PCSResponse(url=PCK_CRL_URL, headers={}, body=body)], now).get(PCK_CRL_URL).body == body


def test_replay_returns_private_buffers() -> None:
    body = bytearray(b'{"tcbInfo":{"tcbEvaluationDataNumber":19}}')
    replay = PCSReplay([PCSResponse(url=TCB_URL, headers={}, body=bytes(body))], datetime.now(UTC))
    first = replay.get(TCB_URL).body
    assert isinstance(first, bytes)
    body[0] = ord("!")
    assert replay.get(TCB_URL).body == first


# --- the recorded numbers and dates ------------------------------------------------------------------


def _collateral(tcb_info: dict[str, object], qe_identity: dict[str, object]) -> TdxCollateral:
    scenario = tb.Scenario(tcb_info=tcb_info, qe_identity=qe_identity)
    return PCSReplay(scenario.responses(), tb.NOW).collateral(tb.FMSPC, "platform")


def test_minimum_evaluation_number() -> None:
    assert (
        minimum_tcb_evaluation_data_number(
            _collateral(tb.tcb_info_object(evaluation_number=20), tb.qe_identity_object(evaluation_number=19))
        )
        == 19
    )
    with pytest.raises(PCSReplayError, match="was not observed"):
        minimum_tcb_evaluation_data_number(
            _collateral(tb.tcb_info_object(evaluation_number=None), tb.qe_identity_object(evaluation_number=19))
        )


@pytest.mark.parametrize(
    ("tcb_issued", "qe_issued", "error"),
    [
        (tb.NOW, tb.NOW, ""),
        (tb.NOW + timedelta(seconds=1), tb.NOW, "TCB Info is not yet valid"),
        (tb.NOW, tb.NOW + timedelta(seconds=1), "QE Identity is not yet valid"),
        (None, tb.NOW, "issueDate was not observed"),
    ],
    ids=["issued at the verification time", "TCB Info issued later", "QE Identity issued later", "no issue date"],
)
def test_check_issue_dates(tcb_issued: datetime | None, qe_issued: datetime, error: str) -> None:
    info = tb.tcb_info_object(issue_date=tcb_issued)
    if tcb_issued is None:
        del info["issueDate"]
    collateral = _collateral(info, tb.qe_identity_object(issue_date=qe_issued))
    if error:
        with pytest.raises(PCSReplayError, match=error):
            check_issue_dates(collateral, tb.NOW)
    else:
        check_issue_dates(collateral, tb.NOW)


# --- loading -----------------------------------------------------------------------------------------


def test_collateral_loads_every_part() -> None:
    scenario = tb.Scenario()
    collateral = PCSReplay(scenario.responses(), tb.NOW).collateral(tb.FMSPC, "platform")
    assert collateral.tcb_info.tcb_info.fmspc == tb.FMSPC
    assert collateral.tcb_info_body.startswith(b'{"id":"TDX"')
    assert collateral.enclave_identity_body.startswith(b'{"id":"TD_QE"')
    assert collateral.pck_crl.ca_type == "platform"
    assert collateral.qe_identity_issuer_root.serial_number == 1
    assert collateral.tcb_info_issuer_intermediate.serial_number == 3


def test_root_crl_comes_from_the_qe_identity_issuer_root() -> None:
    other_url = "https://certificates.example/other.der"
    scenario = tb.Scenario(intel=tb.intel_pki(root_crl_url=other_url))
    responses = tuple(
        tb.response(other_url, r.body) if r.url == INTEL_SGX_ROOT_CA_CRL_URL else r for r in scenario.responses()
    )
    collateral = PCSReplay(responses, tb.NOW).collateral(tb.FMSPC, "platform")
    assert collateral.root_crl.crl.issuer.rfc4514_string() == "CN=Intel SGX Root CA"
    assert crl_distribution_points(collateral.qe_identity_issuer_root) == (other_url,)
    with pytest.raises(PCSReplayError, match="could not fetch root CRL"):
        PCSReplay(scenario.responses(), tb.NOW).collateral(tb.FMSPC, "platform")


def test_root_crl_falls_through_to_the_next_distribution_point() -> None:
    replay = PCSReplay(tb.Scenario().responses(), tb.NOW)
    assert replay.root_crl(["https://certificates.example/missing.der", INTEL_SGX_ROOT_CA_CRL_URL]).crl
    with pytest.raises(PCSReplayError, match="empty url found"):
        replay.root_crl([])


def test_pck_crl_must_be_der() -> None:
    scenario = tb.Scenario()
    responses = tuple(
        tb.response(r.url, b"-----BEGIN X509 CRL-----\nMA==\n-----END X509 CRL-----\n", dict(r.headers))
        if r.url == PCK_CRL_URL
        else r
        for r in scenario.responses()
    )
    with pytest.raises(PCSReplayError, match="parsing captured CRL"):
        PCSReplay(responses, tb.NOW).pck_crl("platform")


def test_issuer_chain_header_decoding() -> None:
    intel = tb.intel_pki()
    chain = intel.pem(intel.tcb_signing) + intel.pem(intel.root)
    qe_body = tb.signed_response("enclaveIdentity", tb.qe_identity_object(), intel.tcb_signing.key)  # type: ignore[arg-type]
    replay = PCSReplay(
        [
            PCSResponse(
                url=QE_URL,
                headers={"Sgx-Enclave-Identity-Issuer-Chain": (tb.issuer_chain_header(chain),)},
                body=qe_body,
            ),
            PCSResponse(url=TCB_URL, headers={"Tcb-Info-Issuer-Chain": ("%zz",)}, body=qe_body),
        ],
        tb.NOW,
    )
    identity, body, (signing, root) = replay.qe_identity()
    assert (signing.serial_number, root.serial_number) == (3, 1)
    assert identity.enclave_identity.id == "TD_QE"
    assert body.startswith(b'{"id":"TD_QE"')
    assert body in qe_body
    with pytest.raises(PCSReplayError, match="invalid URL escape"):
        replay.tcb_info("90c06f000000")
