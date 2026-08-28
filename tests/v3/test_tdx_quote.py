"""Quote v4 ABI parsing (tinfoil.v3.tdx.quote), against synthetic quotes."""

import pytest

from tdx_material import TdBodyFields, build_synth_chain, build_tdx_quote_v4
from tinfoil.v3.tdx.quote import QUOTE_MIN_SIZE, quote_to_proto_v4


@pytest.fixture(scope="module")
def raw_quote() -> bytes:
    chain = build_synth_chain()
    return build_tdx_quote_v4(chain)


def test_parse_happy(raw_quote):
    q = quote_to_proto_v4(raw_quote)
    assert q.header.version == 4
    assert q.header.attestation_key_type == 2
    assert q.header.tee_type == 0x81
    assert q.header.qe_svn == b"\x00\x00"
    assert q.header.pce_svn == b"\x00\x00"
    assert q.header.qe_vendor_id.hex() == "939a7233f79c4ca9940a0db3957f0607"
    body = TdBodyFields()
    assert q.td_quote_body.mr_td == body.mr_td
    assert q.td_quote_body.mr_seam == body.mr_seam
    assert q.td_quote_body.tee_tcb_svn == body.tee_tcb_svn
    assert q.td_quote_body.rtmrs == [body.rtmr0, body.rtmr1, body.rtmr2, body.rtmr3]
    assert q.td_quote_body.report_data == body.report_data
    assert q.header_and_body == raw_quote[:0x278]
    assert q.extra_bytes == b""
    assert q.signed_data.certification_data.certificate_data_type == 6
    chain_data = q.signed_data.certification_data.qe_report_certification_data.pck_certificate_chain_data
    assert chain_data.certificate_data_type == 5
    qe = q.signed_data.certification_data.qe_report_certification_data
    assert len(qe.qe_report_raw) == 384
    assert qe.qe_report.isv_prod_id == 2
    assert qe.qe_report.isv_svn == 8
    assert qe.qe_report.mr_signer == b"\xdc" * 32


def test_too_short_to_determine_format():
    with pytest.raises(ValueError, match="less than 2 bytes"):
        quote_to_proto_v4(b"\x04")


def test_unsupported_version(raw_quote):
    tampered = bytes([raw_quote[0] ^ 0xFF]) + raw_quote[1:]
    with pytest.raises(ValueError, match="quote format not supported"):
        quote_to_proto_v4(tampered)


def test_below_min_size():
    b = bytes([4, 0]) + b"\x00" * 16
    with pytest.raises(ValueError, match="minimum size"):
        quote_to_proto_v4(b)


def test_bad_attestation_key_type(raw_quote):
    tampered = raw_quote[:2] + b"\x03\x00" + raw_quote[4:]
    with pytest.raises(ValueError, match="attestation key type not supported"):
        quote_to_proto_v4(tampered)


def test_bad_tee_type(raw_quote):
    tampered = raw_quote[:4] + b"\x00\x00\x00\x00" + raw_quote[8:]
    with pytest.raises(ValueError, match="TEE type is not TDX"):
        quote_to_proto_v4(tampered)


def test_extra_bytes_retained(raw_quote):
    q = quote_to_proto_v4(raw_quote + b"\x00\x01")
    assert q.extra_bytes == b"\x00\x01"


def test_signed_data_truncated(raw_quote):
    with pytest.raises(ValueError, match="signed data|truncated|Expected size"):
        quote_to_proto_v4(raw_quote[:-7])


def test_bad_certification_data_type(raw_quote):
    # Certification data type lives at signed data offset 0x80.
    off = 0x27C + 0x80
    tampered = raw_quote[:off] + b"\x05\x00" + raw_quote[off + 2 :]
    with pytest.raises(ValueError, match="certification data type invalid"):
        quote_to_proto_v4(tampered)
