"""Intel PCS collateral: response parsing, the signed member bytes, issuer-chain headers, response verification,
expiration, and the appraisal of a quote body and QE report."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from tests.v3 import pki
from tests.v3 import tdx_builders as tb
from tinfoil._v3.verifier._quote.tdx.lib.abi import parse_quote
from tinfoil._v3.verifier._quote.tdx.lib.collateral import (
    CollateralError,
    EnclaveIdentity,
    Tcb,
    TcbComponent,
    TcbInfo,
    TcbLevel,
    TcbStatus,
    TdxCollateral,
    TdxModule,
    TdxModuleIdentity,
    apply_mask,
    check_collateral_expiration,
    check_qe_tcb_status,
    decode_hex,
    get_matching_tcb_level,
    is_cpu_svn_higher_or_equal,
    is_tdx_tcb_svn_higher_or_equal,
    parse_issuer_chain_header,
    parse_qe_identity_response,
    parse_rfc3339,
    parse_tcb_info_response,
    top_level_member,
    verify_qe_identity,
    verify_qe_report,
    verify_response,
    verify_tcb_info,
    verify_td_quote_body,
)
from tinfoil._v3.verifier._quote.tdx.lib.pck import PckCertTCB, PckExtensions
from tinfoil._v3.verifier._quote.tdx.pcs import PCSReplay
from tinfoil._v3.verifier._x509.crl import parse_revocation_list

SCENARIO = tb.Scenario()
ROOTS = (pki.load(SCENARIO.intel.root.der),)
PLATFORM_TCB: dict[str, Any] = tb.tcb_level(list(tb.CPU_SVN_COMPONENTS), tb.PCE_SVN, tb.TDX_COMPONENTS)["tcb"]


def level(tcb: dict[str, Any] | None = None, **members: Any) -> dict[str, Any]:
    """A TCB Info level whose ``tcb`` is complete, with ``tcb`` members and level members replaced as given."""
    return {"tcb": {**PLATFORM_TCB, **(tcb or {})}, **members}


def tcb_info_body(**changes: Any) -> bytes:
    return tb.signed_response("tcbInfo", tb.tcb_info_object(**changes), SCENARIO.intel.tcb_signing.key)  # type: ignore[arg-type]


def qe_identity_body(**changes: Any) -> bytes:
    return tb.signed_response("enclaveIdentity", tb.qe_identity_object(**changes), SCENARIO.intel.tcb_signing.key)  # type: ignore[arg-type]


def edited(body: bytes, **members: Any) -> bytes:
    """The body with top-level members of its signed object replaced (the signature is left stale)."""
    data = json.loads(body)
    key = "tcbInfo" if "tcbInfo" in data else "enclaveIdentity"
    for name, value in members.items():
        if value is None:
            data[key].pop(name, None)
        else:
            data[key][name] = value
    return json.dumps(data, separators=(",", ":")).encode()


def collateral(scenario: tb.Scenario = SCENARIO) -> TdxCollateral:
    return PCSReplay(scenario.responses(), tb.NOW).collateral(tb.FMSPC, "platform")


# --- scalar helpers --------------------------------------------------------------------


class TestDecodeHex:
    def test_either_case(self) -> None:
        assert decode_hex("00AbCd") == bytes.fromhex("00abcd")
        assert decode_hex("") == b""

    @pytest.mark.parametrize("value", ["abc", "ab cd", "zz", "0x00", " ab"])
    def test_rejects(self, value: str) -> None:
        with pytest.raises(ValueError, match="hex"):
            decode_hex(value)


class TestParseRfc3339:
    def test_zulu(self) -> None:
        assert parse_rfc3339("2025-12-17T06:24:56Z") == datetime(2025, 12, 17, 6, 24, 56, tzinfo=UTC)

    def test_offset(self) -> None:
        parsed = parse_rfc3339("2025-12-17T06:24:56+02:00")
        assert parsed == datetime(2025, 12, 17, 4, 24, 56, tzinfo=UTC)
        assert parsed.tzinfo == timezone(timedelta(hours=2))
        assert parse_rfc3339("2025-12-17T06:24:56-02:30") == datetime(2025, 12, 17, 8, 54, 56, tzinfo=UTC)

    def test_fraction_truncates_to_microseconds(self) -> None:
        assert parse_rfc3339("2025-12-17T06:24:56.1234567Z").microsecond == 123456
        assert parse_rfc3339("2025-12-17T06:24:56.5Z").microsecond == 500000

    @pytest.mark.parametrize(
        "value",
        [
            "2025-12-17T06:24:56",
            "2025-12-17 06:24:56Z",
            "2025-12-17t06:24:56Z",
            "2025-12-17T06:24:56z",
            "2025-12-17T6:24:56Z",
            "2025-12-17T06:24:56,5Z",
            "2025-12-17T06:24:56+0200",
            "2025-12-17T06:24:56+24:00",
            "2025-12-17T06:24:56+02:60",
            "2025-13-17T06:24:56Z",
            "2025-12-17T06:24:60Z",
            "20251217T062456Z",
            "",
        ],
    )
    def test_rejects(self, value: str) -> None:
        with pytest.raises(ValueError, match=r"RFC 3339|calendar|offset"):
            parse_rfc3339(value)


def test_apply_mask() -> None:
    assert apply_mask(b"\xf0\x0f", b"\xff\xff\xff") == b"\xf0\x0f"
    assert apply_mask(b"", b"\xff") == b""


# --- response parsing ---------------------------------------------------------------------


class TestParseTcbInfoResponse:
    def test_parses_every_member(self) -> None:
        parsed = parse_tcb_info_response(tcb_info_body())
        info = parsed.tcb_info
        assert info.id == "TDX"
        assert info.version == 3
        assert info.issue_date == tb.NOW - timedelta(days=1)
        assert info.next_update == tb.NOW + timedelta(days=365)
        assert (info.fmspc, info.pce_id, info.tcb_type) == (tb.FMSPC, tb.PCEID, 0)
        assert info.tcb_evaluation_data_number == 18
        assert info.tdx_module == TdxModule(mrsigner=bytes(48), attributes=bytes(8), attributes_mask=bytes([0xFF]) * 8)
        assert [m.id for m in info.tdx_module_identities] == ["TDX_03"]
        assert info.tdx_module_identities[0].tcb_levels[0].tcb.isv_svn == 0
        level = info.tcb_levels[0]
        assert [c.svn for c in level.tcb.sgx_tcb_components] == list(tb.CPU_SVN_COMPONENTS)
        assert level.tcb.pce_svn == tb.PCE_SVN
        assert [c.svn for c in level.tcb.tdx_tcb_components] == tb.TDX_COMPONENTS
        assert level.tcb_status == TcbStatus.UP_TO_DATE
        assert level.tcb_date == "2023-02-15T00:00:00Z"
        assert len(parsed.signature) == 128

    def test_absent_members_keep_zero_values(self) -> None:
        body = edited(
            tcb_info_body(),
            id=None,
            version=None,
            fmspc=None,
            tcbType=None,
            tcbEvaluationDataNumber=None,
            issueDate=None,
            nextUpdate=None,
            tdxModule=None,
            tdxModuleIdentities=None,
            tcbLevels=None,
        )
        info = parse_tcb_info_response(body).tcb_info
        assert info == TcbInfo(pce_id=tb.PCEID)
        assert parse_tcb_info_response(b'{"signature":"ab"}').tcb_info == TcbInfo()
        assert parse_tcb_info_response(b"{}").signature == ""

    def test_null_members(self) -> None:
        """Null reads as absent for plain members and is an error for hex and status members."""
        info = parse_tcb_info_response(
            edited(tcb_info_body(), fmspc=None).replace(b'"pceId"', b'"fmspc":null,"pceId"')
        ).tcb_info
        assert info.fmspc == ""
        with pytest.raises(CollateralError, match="'mrsigner' is not a hex string"):
            parse_tcb_info_response(edited(tcb_info_body(), tdxModule={"mrsigner": None}))
        with pytest.raises(CollateralError, match="'tcbStatus' is not a status string"):
            parse_tcb_info_response(edited(tcb_info_body(), tcbLevels=[level(tcbStatus=None)]))

    def test_level_without_status(self) -> None:
        info = parse_tcb_info_response(edited(tcb_info_body(), tcbLevels=[level(tcb={"pcesvn": 1})])).tcb_info
        assert info.tcb_levels[0] == TcbLevel(
            tcb=Tcb(components(list(tb.CPU_SVN_COMPONENTS)), 1, components(tb.TDX_COMPONENTS))
        )

    @pytest.mark.parametrize("member", ["sgxtcbcomponents", "pcesvn", "tdxtcbcomponents"])
    def test_platform_level_requires_the_compared_tcb_members(self, member: str) -> None:
        """A level without a member that the appraisal compares would be reached by every quote."""
        tcb = dict(PLATFORM_TCB)
        del tcb[member]
        with pytest.raises(CollateralError, match=f"TCB has no '{member}'"):
            parse_tcb_info_response(edited(tcb_info_body(), tcbLevels=[{"tcb": tcb, "tcbStatus": "UpToDate"}]))
        with pytest.raises(CollateralError, match=f"TCB has no '{member}'"):
            parse_tcb_info_response(edited(tcb_info_body(), tcbLevels=[level(tcb={member: None})]))

    def test_platform_level_requires_a_tcb(self) -> None:
        for levels in ([{"tcbStatus": "UpToDate"}], [{"tcb": None, "tcbStatus": "UpToDate"}]):
            with pytest.raises(CollateralError, match="TCB level has no 'tcb'"):
                parse_tcb_info_response(edited(tcb_info_body(), tcbLevels=levels))

    def test_module_identity_level_requires_an_isvsvn(self) -> None:
        def identities(levels: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [{"id": "TDX_03", "tcbLevels": levels}]

        with pytest.raises(CollateralError, match="TCB has no 'isvsvn'"):
            parse_tcb_info_response(edited(tcb_info_body(), tdxModuleIdentities=identities([{"tcb": {}}])))
        with pytest.raises(CollateralError, match="TCB has no 'isvsvn'"):
            parse_tcb_info_response(
                edited(tcb_info_body(), tdxModuleIdentities=identities([{"tcb": {"isvsvn": None}}]))
            )
        with pytest.raises(CollateralError, match="TCB level has no 'tcb'"):
            parse_tcb_info_response(edited(tcb_info_body(), tdxModuleIdentities=identities([{}])))

    @pytest.mark.parametrize(
        ("members", "match"),
        [
            ({"id": 3}, "'id' is not a string"),
            ({"version": "3"}, "'version' is not a number"),
            ({"version": 256}, "overflows uint8"),
            ({"version": 3.0}, "not an integer"),
            ({"version": -1}, "negative"),
            ({"tcbType": "x"}, "'tcbType' is not a number"),
            ({"issueDate": 12}, "'issueDate' is not a timestamp string"),
            ({"issueDate": "2025-12-17"}, "'issueDate'"),
            ({"tcbEvaluationDataNumber": "18"}, "'tcbEvaluationDataNumber' is not a number"),
            ({"tcbEvaluationDataNumber": 1e3}, "not an integer"),
            ({"tcbEvaluationDataNumber": -5}, "'tcbEvaluationDataNumber': JSON number -5 is negative"),
            ({"tcbEvaluationDataNumber": 2**64}, "overflows uint64"),
            ({"tdxModule": {"mrsigner": "zz"}}, "'mrsigner': invalid hex byte"),
            ({"tdxModule": {"attributes": "abc"}}, "odd length"),
            ({"tdxModule": "x"}, "tdxModule is not a JSON object"),
            ({"tdxModuleIdentities": {}}, "'tdxModuleIdentities' is not an array"),
            ({"tcbLevels": [level(tcbStatus="Fine")]}, "unexpected tcb status found: 'Fine'"),
            ({"tcbLevels": [level(tcbStatus=1)]}, "'tcbStatus' is not a status string"),
            ({"tcbLevels": [level(tcb={"pcesvn": 65536})]}, "overflows uint16"),
            ({"tcbLevels": [level(tcb={"sgxtcbcomponents": [{"svn": 256}]})]}, "overflows uint8"),
            ({"tcbLevels": [level(tcb={"sgxtcbcomponents": [{"svn": "1"}]})]}, "'svn' is not a number"),
            ({"tcbLevels": [level(tcb={"isvsvn": -1})]}, "negative"),
            ({"tcbLevels": [level(advisoryIDs=[1])]}, "not an array of strings"),
            ({"tcbLevels": [level(tcbDate=1)]}, "'tcbDate' is not a string"),
            ({"tcbLevels": [1]}, "TCB level is not a JSON object"),
        ],
    )
    def test_wrong_types_reject(self, members: dict[str, Any], match: str) -> None:
        with pytest.raises(CollateralError, match=match):
            parse_tcb_info_response(edited(tcb_info_body(), **members))

    def test_evaluation_number_is_optional_but_never_negative(self) -> None:
        assert (
            parse_tcb_info_response(
                edited(tcb_info_body(), tcbEvaluationDataNumber=0)
            ).tcb_info.tcb_evaluation_data_number
            == 0
        )
        assert (
            parse_tcb_info_response(
                edited(tcb_info_body(), tcbEvaluationDataNumber=None)
            ).tcb_info.tcb_evaluation_data_number
            is None
        )
        with pytest.raises(CollateralError, match="negative"):
            parse_tcb_info_response(edited(tcb_info_body(), tcbEvaluationDataNumber=-1))

    def test_member_names_match_exactly(self) -> None:
        body = tcb_info_body().replace(b'"tcbLevels"', b'"TcbLevels"')
        assert parse_tcb_info_response(body).tcb_info.tcb_levels == ()

    def test_unknown_members_are_ignored(self) -> None:
        body = edited(tcb_info_body(), extra={"a": [1, {"b": None}]})
        assert parse_tcb_info_response(body).tcb_info.fmspc == tb.FMSPC

    def test_duplicates_reject_at_any_depth(self) -> None:
        with pytest.raises(CollateralError, match="duplicate"):
            parse_tcb_info_response(tcb_info_body().replace(b'"fmspc"', b'"fmspc":"x","fmspc"'))
        with pytest.raises(CollateralError, match="duplicate"):
            parse_tcb_info_response(b'{"tcbInfo":{},"tcbInfo":{},"signature":""}')

    @pytest.mark.parametrize("body", [b"", b"null", b"[]", b'"x"', b"{", b'{"tcbInfo": 1}', b'{"signature": 1}'])
    def test_malformed_bodies_reject(self, body: bytes) -> None:
        with pytest.raises(CollateralError):
            parse_tcb_info_response(body)


class TestParseQeIdentityResponse:
    def test_parses_every_member(self) -> None:
        identity = parse_qe_identity_response(qe_identity_body()).enclave_identity
        assert (identity.id, identity.version) == ("TD_QE", 2)
        assert identity.tcb_evaluation_data_number == 18
        assert (identity.miscselect, identity.miscselect_mask) == (bytes(4), bytes([0xFF]) * 4)
        assert identity.attributes == tb.QE_ATTRIBUTES
        assert identity.attributes_mask == bytes.fromhex("fbffffffffffffff0000000000000000")
        assert identity.mrsigner == tb.QE_MRSIGNER
        assert identity.isv_prod_id == 2
        assert identity.tcb_levels[0].tcb.isv_svn == 8
        assert identity.tcb_levels[0].tcb_status == TcbStatus.UP_TO_DATE

    def test_absent_members_keep_zero_values(self) -> None:
        assert parse_qe_identity_response(b'{"enclaveIdentity":{}}').enclave_identity == EnclaveIdentity()

    @pytest.mark.parametrize(
        ("members", "match"),
        [
            ({"isvprodid": 65536}, "overflows uint16"),
            ({"mrsigner": "DCDC "}, "'mrsigner'"),
            ({"tcbEvaluationDataNumber": -1}, "'tcbEvaluationDataNumber': JSON number -1 is negative"),
            ({"tcbLevels": [{"tcb": {"isvsvn": 4294967296}}]}, "overflows uint32"),
            ({"tcbLevels": [{"tcb": {"isvsvn": None}}]}, "TCB has no 'isvsvn'"),
            ({"tcbLevels": [{"tcb": {}, "tcbStatus": "UpToDate"}]}, "TCB has no 'isvsvn'"),
            ({"tcbLevels": [{"tcbStatus": "UpToDate"}]}, "TCB level has no 'tcb'"),
        ],
    )
    def test_wrong_types_reject(self, members: dict[str, Any], match: str) -> None:
        with pytest.raises(CollateralError, match=match):
            parse_qe_identity_response(edited(qe_identity_body(), **members))


class TestTopLevelMember:
    def test_signed_bytes_are_the_members_exact_text(self) -> None:
        genuine = '{"id": "TDX", "version": 3}'
        for body in (
            f'{{"tcbInfo":{genuine},"signature":"ab"}}',
            f'{{ "tcbInfo" : {genuine} ,\n  "signature": "ab" }}',
            f'{{"signature": "ab",\n\t"tcbInfo":\n{genuine}\n}}',
            f'{{"other": {{"tcbInfo": 1}}, "tcbInfo":{genuine}, "signature":"ab"}}',
        ):
            assert top_level_member(body.encode(), "tcbInfo") == genuine.encode()

    def test_nested_copy_does_not_stand_in(self) -> None:
        forged = '{"id": "TDX", "version": 4}'
        body = f'{{"a":{{"tcbInfo":{{"x":1}}}},"tcbInfo":{forged},"signature":"ab"}}'
        assert top_level_member(body.encode(), "tcbInfo") == forged.encode()

    @pytest.mark.parametrize(
        ("body", "match"),
        [
            (b"", "is empty"),
            (b'{"other": 1}', "field is missing"),
            (b'{"tcbInfo": {"a": 1}, "tcbInfo": {"a": 2}}', "duplicate top-level member"),
            (b'{"tcbInfo": [1]}', "is not an object"),
            (b'{"tcbInfo": "x"}', "is not an object"),
            (b'["tcbInfo"]', "not a JSON object"),
            (b'{"tcbInfo": {}', "unterminated"),
            (b'{"tcbInfo": {} "x": 1}', "unexpected character"),
            (b'{"tcbInfo"}', "has no value"),
            (b"{1: 2}", "member name is not a string"),
            (b"\xff", "could not convert"),
        ],
    )
    def test_rejects(self, body: bytes, match: str) -> None:
        with pytest.raises(CollateralError, match=match):
            top_level_member(body, "tcbInfo")


class TestParseIssuerChainHeader:
    def test_decodes_two_certificates(self) -> None:
        intel = SCENARIO.intel
        header = tb.issuer_chain_header(intel.pem(intel.tcb_signing), intel.pem(intel.root))
        signing, root = parse_issuer_chain_header(header, "Tcb-Info-Issuer-Chain")
        assert (signing.serial_number, root.serial_number) == (3, 1)
        assert "+" not in header

    def test_plus_decodes_to_a_space(self) -> None:
        intel = SCENARIO.intel
        pem = intel.pem(intel.tcb_signing) + intel.pem(intel.root)
        assert b"+" in pem
        with pytest.raises(CollateralError, match="could not parse PEM"):
            parse_issuer_chain_header(pem.decode(), "Tcb-Info-Issuer-Chain")

    @pytest.mark.parametrize(
        ("value", "match"),
        [
            ("", "certificates missing"),
            ("%zz", "invalid URL escape"),
            ("%2", "invalid URL escape"),
            ("not%20a%20pem", "could not parse PEM"),
        ],
    )
    def test_rejects(self, value: str, match: str) -> None:
        with pytest.raises(CollateralError, match=match):
            parse_issuer_chain_header(value, "Tcb-Info-Issuer-Chain")

    def test_requires_exactly_two(self) -> None:
        intel = SCENARIO.intel
        with pytest.raises(CollateralError, match="should contain 2 PEM certificates, found 1"):
            parse_issuer_chain_header(tb.issuer_chain_header(intel.pem(intel.root)), "X")
        with pytest.raises(CollateralError, match="unexpected trailing bytes"):
            parse_issuer_chain_header(
                tb.issuer_chain_header(intel.pem(intel.tcb_signing), intel.pem(intel.root), b"\n"), "X"
            )


# --- response verification -------------------------------------------------------------------


class TestVerifyResponse:
    def test_verifies(self) -> None:
        c = collateral()
        verify_tcb_info(c, ROOTS, tb.NOW)
        verify_qe_identity(c, ROOTS, tb.NOW)

    def test_id_version_and_levels(self) -> None:
        for body, match in (
            (edited(tcb_info_body(), id="SGX"), "tcbInfo ID 'SGX'"),
            (edited(tcb_info_body(), version=2), "tcbInfo version 2"),
            (edited(tcb_info_body(), tcbLevels=[]), "empty TcbLevels"),
        ):
            with pytest.raises(CollateralError, match=match):
                verify_tcb_info(collateral(SCENARIO.with_(tcb_info=json.loads(body)["tcbInfo"])), ROOTS, tb.NOW)
        for body, match in (
            (edited(qe_identity_body(), id="QE"), "QeIdentity ID 'QE'"),
            (edited(qe_identity_body(), version=3), "QeIdentity version 3"),
            (edited(qe_identity_body(), tcbLevels=[]), "empty TcbLevels"),
        ):
            with pytest.raises(CollateralError, match=match):
                verify_qe_identity(
                    collateral(SCENARIO.with_(qe_identity=json.loads(body)["enclaveIdentity"])), ROOTS, tb.NOW
                )

    def test_signature_and_chain(self) -> None:
        c = collateral()
        intel = SCENARIO.intel
        root, signing = c.tcb_info_issuer_root, c.tcb_info_issuer_intermediate
        args = (c.tcb_info_body, c.tcb_info.signature, c.root_crl.crl, ROOTS, tb.NOW)
        verify_response("Intel SGX TCB Signing", root, signing, *args)
        with pytest.raises(CollateralError, match="unable to validate root certificate"):
            verify_response("Intel SGX TCB Signing", signing, signing, *args)
        with pytest.raises(CollateralError, match="unable to validate signing certificate"):
            verify_response("Intel SGX PCK Certificate", root, signing, *args)
        with pytest.raises(CollateralError, match="unable to verify signing certificate"):
            verify_response(
                "Intel SGX TCB Signing", root, signing, *args[:3], (pki.load(tb.intel_pki().root.der),), tb.NOW
            )
        with pytest.raises(CollateralError, match="unable to verify signing certificate"):
            verify_response("Intel SGX TCB Signing", root, signing, *args[:4], tb.NOW + timedelta(days=400))
        with pytest.raises(CollateralError, match="unable to decode signature string"):
            verify_response("Intel SGX TCB Signing", root, signing, c.tcb_info_body, "xy", *args[2:])
        with pytest.raises(CollateralError, match="unable to convert signature to DER"):
            verify_response("Intel SGX TCB Signing", root, signing, c.tcb_info_body, "ab" * 63, *args[2:])
        with pytest.raises(CollateralError, match="could not verify response body"):
            verify_response("Intel SGX TCB Signing", root, signing, c.tcb_info_body + b" ", *args[1:])
        other_crl = parse_revocation_list(
            pki.crl(intel.platform_ca, this_update=tb.NOW - timedelta(days=1), next_update=tb.NOW + timedelta(days=1))
        )
        with pytest.raises(CollateralError, match="root CA CRL verification failed"):
            verify_response(
                "Intel SGX TCB Signing", root, signing, c.tcb_info_body, c.tcb_info.signature, other_crl, ROOTS, tb.NOW
            )
        revoked = parse_revocation_list(
            pki.crl(
                intel.root, this_update=tb.NOW - timedelta(days=1), next_update=tb.NOW + timedelta(days=1), revoked=[3]
            )
        )
        with pytest.raises(CollateralError, match="signing certificate was revoked"):
            verify_response(
                "Intel SGX TCB Signing", root, signing, c.tcb_info_body, c.tcb_info.signature, revoked, ROOTS, tb.NOW
            )


class TestCheckCollateralExpiration:
    def test_current(self) -> None:
        check_collateral_expiration(collateral(), tb.NOW)
        check_collateral_expiration(collateral(), tb.NOW + timedelta(days=30))

    def test_in_order(self) -> None:
        c = collateral()
        later = tb.NOW + timedelta(days=366)
        with pytest.raises(CollateralError, match="tcbInfo has expired"):
            check_collateral_expiration(c, later)
        c2 = collateral(SCENARIO.with_(tcb_info=tb.tcb_info_object(next_update=later + timedelta(days=1))))
        with pytest.raises(CollateralError, match="QeIdentity has expired"):
            check_collateral_expiration(c2, later)
        c3 = collateral(
            SCENARIO.with_(
                tcb_info=tb.tcb_info_object(next_update=later + timedelta(days=1)),
                qe_identity=tb.qe_identity_object(next_update=later + timedelta(days=1)),
            )
        )
        with pytest.raises(CollateralError, match="tcbInfo signing certificate has expired"):
            check_collateral_expiration(c3, later)
        with pytest.raises(CollateralError, match="root CA CRL has expired"):
            check_collateral_expiration(c, tb.NOW + timedelta(days=31))
        c4 = collateral(SCENARIO.with_(root_crl_window=(timedelta(0), timedelta(days=60))))
        with pytest.raises(CollateralError, match="PCK CRL has expired"):
            check_collateral_expiration(c4, tb.NOW + timedelta(days=31))

    def test_missing_next_update_is_expired(self) -> None:
        body = edited(tcb_info_body(), nextUpdate=None)
        c = collateral(SCENARIO.with_(tcb_info=json.loads(body)["tcbInfo"]))
        with pytest.raises(CollateralError, match="tcbInfo has expired"):
            check_collateral_expiration(c, tb.NOW)


# --- appraisal -------------------------------------------------------------------------------------


def components(values: list[int]) -> tuple[TcbComponent, ...]:
    return tuple(TcbComponent(svn=v) for v in values)


class TestSvnComparisons:
    def test_cpu_svn(self) -> None:
        assert is_cpu_svn_higher_or_equal(bytes([3] * 16), components([3] * 16))
        assert is_cpu_svn_higher_or_equal(bytes([4] * 16), components([3] * 16))
        assert not is_cpu_svn_higher_or_equal(bytes([3] * 15 + [2]), components([3] * 16))
        assert not is_cpu_svn_higher_or_equal(bytes(15), components([0] * 16))
        assert not is_cpu_svn_higher_or_equal(b"", components([0] * 16))
        assert is_cpu_svn_higher_or_equal(b"", ())

    def test_tdx_tcb_svn(self) -> None:
        assert is_tdx_tcb_svn_higher_or_equal(bytes([0, 0] + [5] * 14), components([0, 0] + [5] * 14))
        assert not is_tdx_tcb_svn_higher_or_equal(bytes([0, 0] + [4] * 14), components([0, 0] + [5] * 14))
        # A non-zero module version skips the first two components.
        assert is_tdx_tcb_svn_higher_or_equal(bytes([0, 3] + [5] * 14), components([9, 9] + [5] * 14))
        assert not is_tdx_tcb_svn_higher_or_equal(bytes([0, 0] + [5] * 14), components([9, 0] + [5] * 14))
        assert not is_tdx_tcb_svn_higher_or_equal(bytes(16), components([0] * 15))


class TestGetMatchingTcbLevel:
    def test_first_reachable_level(self) -> None:
        high = TcbLevel(tcb=Tcb(components([3] * 16), 13, components([5] * 16)), tcb_status=TcbStatus.UP_TO_DATE)
        low = TcbLevel(tcb=Tcb(components([2] * 16), 11, components([4] * 16)), tcb_status=TcbStatus.OUT_OF_DATE)
        assert get_matching_tcb_level([high, low], bytes([5] * 16), 13, bytes([3] * 16)) is high
        assert get_matching_tcb_level([high, low], bytes([5] * 16), 12, bytes([3] * 16)) is low
        assert get_matching_tcb_level([high, low], bytes([4] * 16), 13, bytes([3] * 16)) is low
        with pytest.raises(CollateralError, match="no matching TCB level found"):
            get_matching_tcb_level([high, low], bytes([4] * 16), 13, bytes([1] * 16))
        with pytest.raises(CollateralError, match="no matching TCB level found"):
            get_matching_tcb_level([], bytes(16), 0, bytes(16))


class TestVerifyTdQuoteBody:
    def info(self, **changes: Any) -> TcbInfo:
        return parse_tcb_info_response(tcb_info_body(**changes)).tcb_info

    def extensions(self, **changes: Any) -> PckExtensions:
        base = PckExtensions(
            ppid=tb.PPID.hex(),
            tcb=PckCertTCB(pce_svn=tb.PCE_SVN, cpu_svn=tb.CPU_SVN_COMPONENTS, cpu_svn_components=tb.CPU_SVN_COMPONENTS),
            pceid=tb.PCEID,
            fmspc=tb.FMSPC,
        )
        return replace(base, **changes) if changes else base

    def body(self, **changes: Any):
        return parse_quote(tb.quote_bytes(SCENARIO.pck_key, b"x", body=tb.body_bytes(**changes))).td_quote_body

    def test_matches(self) -> None:
        level = verify_td_quote_body(self.body(), self.info(), self.extensions())
        assert level.tcb_status == TcbStatus.UP_TO_DATE

    def test_fmspc_and_pceid_exact(self) -> None:
        with pytest.raises(CollateralError, match="FMSPC"):
            verify_td_quote_body(self.body(), self.info(fmspc=tb.FMSPC.upper()), self.extensions())
        with pytest.raises(CollateralError, match="FMSPC"):
            verify_td_quote_body(self.body(), self.info(), self.extensions(fmspc=""))
        with pytest.raises(CollateralError, match="PCEID"):
            verify_td_quote_body(self.body(), self.info(), self.extensions(pceid="0001"))

    def test_module_signer_and_attributes(self) -> None:
        with pytest.raises(CollateralError, match="MRSIGNERSEAM"):
            verify_td_quote_body(self.body(mr_signer_seam=bytes([1]) * 48), self.info(), self.extensions())
        with pytest.raises(CollateralError, match="size of SeamAttributes"):
            verify_td_quote_body(self.body(), self.info(attributes_mask=bytes(7)), self.extensions())
        with pytest.raises(CollateralError, match="AttributesMask value"):
            verify_td_quote_body(self.body(seam_attributes=bytes([1]) * 8), self.info(), self.extensions())
        masked = self.info(attributes_mask=bytes([0xFE]) + bytes([0xFF]) * 7)
        assert verify_td_quote_body(self.body(seam_attributes=b"\x01" + bytes(7)), masked, self.extensions())

    def test_missing_module_rejects(self) -> None:
        info = parse_tcb_info_response(edited(tcb_info_body(), tdxModule=None)).tcb_info
        with pytest.raises(CollateralError, match="MRSIGNERSEAM"):
            verify_td_quote_body(self.body(), info, self.extensions())

    def test_tcb_status(self) -> None:
        with pytest.raises(CollateralError, match="no matching TCB level found"):
            verify_td_quote_body(
                self.body(),
                self.info(),
                self.extensions(tcb=PckCertTCB(pce_svn=10, cpu_svn_components=tb.CPU_SVN_COMPONENTS)),
            )
        with pytest.raises(CollateralError, match="TCB Status is not 'UpToDate', found 'SWHardeningNeeded'"):
            verify_td_quote_body(self.body(), self.info(status="SWHardeningNeeded"), self.extensions())
        with pytest.raises(CollateralError, match="TDX Module TCB Status is not 'UpToDate', found 'Revoked'"):
            verify_td_quote_body(self.body(), self.info(module_status="Revoked"), self.extensions())
        level = tb.tcb_level(list(tb.CPU_SVN_COMPONENTS), tb.PCE_SVN, tb.TDX_COMPONENTS)
        del level["tcbStatus"]
        with pytest.raises(CollateralError, match="found ''"):
            verify_td_quote_body(self.body(), self.info(levels=[level]), self.extensions())

    def test_pck_without_tcb_matches_nothing(self) -> None:
        with pytest.raises(CollateralError, match="no matching TCB level found"):
            verify_td_quote_body(self.body(), self.info(), self.extensions(tcb=PckCertTCB()))


class TestVerifyQeReport:
    def identity(self, **changes: Any) -> EnclaveIdentity:
        return parse_qe_identity_response(qe_identity_body(**changes)).enclave_identity

    def report(self, **changes: Any):
        raw = tb.quote_bytes(SCENARIO.pck_key, b"x", qe_report_kwargs=changes)
        return parse_quote(raw).signed_data.certification_data.qe_report_data.qe_report_parsed

    def test_matches(self) -> None:
        verify_qe_report(self.report(), self.identity())

    def test_miscselect(self) -> None:
        with pytest.raises(CollateralError, match="MISCSELECTMask field size\\(3\\)"):
            verify_qe_report(self.report(), self.identity(miscselect_mask=bytes(3)))
        with pytest.raises(CollateralError, match="MISCSELECT field size\\(5\\)"):
            verify_qe_report(self.report(), self.identity(miscselect=bytes(5)))
        with pytest.raises(CollateralError, match="MISCSELECT value"):
            verify_qe_report(self.report(misc_select=1), self.identity())
        verify_qe_report(self.report(misc_select=0x100), self.identity(miscselect_mask=bytes.fromhex("ff00ffff")))
        # The published value is compared unmasked.
        with pytest.raises(CollateralError, match="MISCSELECT value"):
            verify_qe_report(
                self.report(misc_select=0x100),
                self.identity(miscselect=bytes.fromhex("00010000"), miscselect_mask=bytes.fromhex("ff00ffff")),
            )

    def test_attributes(self) -> None:
        with pytest.raises(CollateralError, match="size of AttributesMask value\\(15\\)"):
            verify_qe_report(self.report(), self.identity(attributes_mask=bytes(15)))
        with pytest.raises(CollateralError, match="AttributesMask value"):
            verify_qe_report(self.report(attributes=bytes([0x13]) + bytes(15)), self.identity())
        verify_qe_report(self.report(attributes=tb.QE_ATTRIBUTES[:8] + bytes([0xFF]) * 8), self.identity())
        with pytest.raises(CollateralError, match="AttributesMask value"):
            verify_qe_report(self.report(), self.identity(attributes=tb.QE_ATTRIBUTES[:15] + b"\x01"))
        with pytest.raises(CollateralError, match="AttributesMask value"):
            verify_qe_report(self.report(), self.identity(attributes=tb.QE_ATTRIBUTES[:15]))

    def test_mrsigner_and_prodid(self) -> None:
        with pytest.raises(CollateralError, match="MRSIGNER value"):
            verify_qe_report(self.report(mr_signer=bytes(32)), self.identity())
        with pytest.raises(CollateralError, match="MRSIGNER value"):
            verify_qe_report(self.report(), self.identity(mrsigner=tb.QE_MRSIGNER[:31]))
        with pytest.raises(CollateralError, match="ISV PRODID value\\(3\\)"):
            verify_qe_report(self.report(isv_prod_id=3), self.identity())

    def test_qe_tcb_status(self) -> None:
        levels = [
            TcbLevel(tcb=Tcb(isv_svn=8), tcb_status=TcbStatus.UP_TO_DATE),
            TcbLevel(tcb=Tcb(isv_svn=5), tcb_status=TcbStatus.OUT_OF_DATE),
        ]
        check_qe_tcb_status(levels, 8)
        check_qe_tcb_status(levels, 9)
        with pytest.raises(CollateralError, match="TCB Status is not 'UpToDate', found 'OutOfDate'"):
            check_qe_tcb_status(levels, 7)
        with pytest.raises(CollateralError, match="it is now OutOfDate"):
            check_qe_tcb_status(levels, 4)
        with pytest.raises(CollateralError, match="it is now OutOfDate"):
            check_qe_tcb_status([], 4)
        with pytest.raises(CollateralError, match="QE Identity reported by Intel PCS failed TCB status check"):
            verify_qe_report(self.report(isv_svn=7), self.identity())
        with pytest.raises(CollateralError, match="found ''"):
            verify_qe_report(self.report(), self.identity(levels=[{"tcb": {"isvsvn": 1}}]))

    def test_absent_isvsvn_never_reaches_appraisal(self) -> None:
        """A level without an ISV SVN would be reached by every QE; parsing rejects it before any comparison."""
        with pytest.raises(CollateralError, match="TCB has no 'isvsvn'"):
            self.identity(levels=[{"tcb": {}, "tcbStatus": "UpToDate"}])


def test_status_values() -> None:
    assert [s.value for s in TcbStatus] == [
        "UpToDate",
        "SWHardeningNeeded",
        "ConfigurationNeeded",
        "ConfigurationAndSWHardeningNeeded",
        "OutOfDate",
        "OutOfDateConfigurationNeeded",
        "Revoked",
    ]
    assert TdxModuleIdentity().tcb_levels == ()
