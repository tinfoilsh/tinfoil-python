"""Intel PCS parsers (tinfoil.v3.tdx.pcs): PCK SGX extension extraction, the
lenient typed JSON decoding of PCS bodies, and raw member extraction."""

import pytest

from tdx_material import (
    build_sgx_extension,
    build_synth_chain,
    build_tcb_info_response,
    build_qe_identity_response,
)
from tinfoil.v3.tdx.der import parse_certificate
from tinfoil.v3.tdx.pcs import (
    parse_qe_identity,
    parse_tdx_tcb_info,
    pck_certificate_extensions,
    pck_crl_url,
    qe_identity_url,
    raw_top_level_member,
    tcb_info_url,
)


@pytest.fixture(scope="module")
def chain():
    return build_synth_chain()


def test_urls():
    assert (
        pck_crl_url("platform")
        == "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
    )
    assert (
        tcb_info_url("50806f000000")
        == "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"
    )
    assert (
        qe_identity_url()
        == "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
    )


def test_pck_certificate_extensions(chain):
    leaf = parse_certificate(chain.pck_leaf.der)
    exts = pck_certificate_extensions(leaf)
    assert exts.ppid == "55" * 16
    assert exts.pceid == "0000"
    assert exts.fmspc == "50806f000000"
    assert exts.tcb.pce_svn == 11
    assert exts.tcb.cpu_svn.hex() == "05050202030100030000000000000000"
    assert exts.tcb.cpu_svn_components.hex() == "05050202030100030000000000000000"


def test_pck_extension_count_pinned(chain):
    # The root CA carries five extensions, not the PCK leaf's six.
    root = parse_certificate(chain.root_ca.der)
    with pytest.raises(ValueError, match="extensions length found 5. Expected 6"):
        pck_certificate_extensions(root)


def test_pck_extension_bad_ppid_size():
    # A truncated PPID octet string must reject with the pinned size error.
    bad = build_sgx_extension(ppid=b"\x55" * 15)
    chain = build_synth_chain(sgx_extension=bad)
    leaf = parse_certificate(chain.pck_leaf.der)
    with pytest.raises(ValueError, match="PPID extension's value size is 15, expected 16"):
        pck_certificate_extensions(leaf)


def test_parse_tdx_tcb_info(chain):
    body = build_tcb_info_response(chain).encode()
    parsed = parse_tdx_tcb_info(body)
    info = parsed.tcb_info
    assert info.id == "TDX"
    assert info.version == 3
    assert info.fmspc == "50806f000000"
    assert info.pce_id == "0000"
    assert info.tcb_evaluation_data_number == 18
    assert info.tdx_module.mrsigner == b"\x00" * 48
    assert info.tdx_module.attributes_mask == b"\xff" * 8
    assert len(info.tdx_module_identities) == 1
    assert info.tdx_module_identities[0].id == "TDX_03"
    level = info.tcb_levels[0]
    assert level.tcb_status == "UpToDate"
    assert level.tcb.pcesvn == 11
    assert [c.svn for c in level.tcb.tdx_tcbcomponents][:3] == [3, 0, 5]
    assert len(parsed.signature) == 128
    assert info.next_update.year == 2030


def test_parse_qe_identity(chain):
    body = build_qe_identity_response(chain).encode()
    parsed = parse_qe_identity(body)
    ident = parsed.enclave_identity
    assert ident.id == "TD_QE"
    assert ident.version == 2
    assert ident.miscselect == b"\x00" * 4
    assert ident.miscselect_mask == b"\xff" * 4
    assert ident.mrsigner == b"\xdc" * 32
    assert ident.isv_prod_id == 2
    assert ident.tcb_levels[0].tcb.isvsvn == 8


def test_unknown_tcb_status_rejects():
    body = b'{"tcbInfo":{"tcbLevels":[{"tcb":{},"tcbStatus":"Fresh"}]}}'
    with pytest.raises(ValueError, match="unexpected tcb status found"):
        parse_tdx_tcb_info(body)


def test_wrong_member_types_reject():
    with pytest.raises(ValueError, match="not an integer in range"):
        parse_tdx_tcb_info(b'{"tcbInfo":{"version":"3"}}')
    with pytest.raises(ValueError, match="not an integer in range"):
        parse_tdx_tcb_info(b'{"tcbInfo":{"version":3.0}}')  # Go rejects fractions
    with pytest.raises(ValueError, match="not an RFC 3339 time"):
        parse_tdx_tcb_info(b'{"tcbInfo":{"issueDate":"June 18"}}')
    with pytest.raises(ValueError, match="not hex"):
        parse_tdx_tcb_info(b'{"tcbInfo":{"tdxModule":{"mrsigner":"zz"}}}')
    with pytest.raises(ValueError, match="not a string"):
        parse_qe_identity(b'{"enclaveIdentity":{"id":7}}')
    with pytest.raises(ValueError, match="unable to unmarshal tcbInfo response"):
        parse_tdx_tcb_info(b"{")
    with pytest.raises(ValueError, match="unable to unmarshal tcbInfo response"):
        parse_tdx_tcb_info(b'{"tcbInfo":{"tcbEvaluationDataNumber":NaN}}')


def test_absent_members_are_zero_values():
    parsed = parse_tdx_tcb_info(b"{}")
    assert parsed.tcb_info.id == ""
    assert parsed.tcb_info.version == 0
    assert parsed.tcb_info.tcb_levels == []
    assert parsed.signature == ""


def test_raw_top_level_member_exact_bytes():
    body = b'{ "tcbInfo" : {"a": [1, {"b":"}"}] } , "signature":"ab"}'
    raw = raw_top_level_member(body, "tcbInfo")
    assert raw == b'{"a": [1, {"b":"}"}] }'
    assert raw_top_level_member(body, "signature") == b'"ab"'
    assert raw_top_level_member(body, "absent") is None


def test_raw_top_level_member_last_duplicate_wins():
    body = b'{"a":1,"a":2}'
    assert raw_top_level_member(body, "a") == b"2"


def test_raw_top_level_member_malformed():
    with pytest.raises(ValueError, match="could not convert"):
        raw_top_level_member(b"[1]", "a")
    with pytest.raises(ValueError, match="could not convert"):
        raw_top_level_member(b'{"a" 1}', "a")
