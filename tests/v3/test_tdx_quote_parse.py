"""Unit tests for the TDX quote v4 ABI parser (tinfoil.v3.tdx.quote): the
byte-layout slicing, size/type constraints, and extra-bytes retention."""

import struct

import pytest

from tinfoil.v3.tdx.quote import quote_to_proto_v4

QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")


def build_header(version=4, akt=2, tee=0x81, reserved=b"\x00" * 4) -> bytes:
    h = (
        struct.pack("<H", version)
        + struct.pack("<H", akt)
        + struct.pack("<I", tee)
        + reserved
        + QE_VENDOR_ID
        + b"\x00" * 20
    )
    assert len(h) == 48
    return h


def build_body() -> bytes:
    body = (
        b"\x00\x03\x05\x00" + b"\x00" * 12  # tee_tcb_svn
        + b"\xaa" * 48  # mr_seam
        + b"\xbb" * 48  # mr_signer_seam
        + b"\x01" * 8  # seam_attributes
        + b"\x02" * 8  # td_attributes
        + b"\x03" * 8  # xfam
        + b"\x11" * 48  # mr_td
        + b"\x00" * 48  # mr_config_id
        + b"\x00" * 48  # mr_owner
        + b"\x00" * 48  # mr_owner_config
        + b"\x22" * 48  # rtmr0
        + b"\x33" * 48  # rtmr1
        + b"\x44" * 48  # rtmr2
        + b"\x55" * 48  # rtmr3
        + b"\x66" * 64  # report_data
    )
    assert len(body) == 584
    return body


def build_quote(
    header=None,
    auth_data=b"",
    chain=b"-----FAKE-----",
    chain_type=5,
    chain_size=None,
    extra=b"",
) -> bytes:
    header = header if header is not None else build_header()
    qe_report = bytes(range(256)) + bytes(128)  # 384 arbitrary bytes
    qe_report_sig = b"\x77" * 64
    auth_section = struct.pack("<H", len(auth_data)) + auth_data
    chain_size = len(chain) if chain_size is None else chain_size
    inner = struct.pack("<H", chain_type) + struct.pack("<I", chain_size) + chain
    qe_cert_data = qe_report + qe_report_sig + auth_section + inner
    cert_section = struct.pack("<H", 6) + struct.pack("<I", len(qe_cert_data)) + qe_cert_data
    signed = b"\x88" * 64 + b"\x99" * 64 + cert_section
    return header + build_body() + struct.pack("<I", len(signed)) + signed + extra


def test_happy_layout_fields():
    q = quote_to_proto_v4(build_quote(auth_data=b"\xab\xcd"))
    assert q.header.version == 4
    assert q.header.attestation_key_type == 2
    assert q.header.tee_type == 0x81
    assert q.header.qe_vendor_id == QE_VENDOR_ID
    body = q.td_quote_body
    assert body.mr_seam == b"\xaa" * 48
    assert body.mr_td == b"\x11" * 48
    assert body.rtmrs == [b"\x22" * 48, b"\x33" * 48, b"\x44" * 48, b"\x55" * 48]
    assert body.report_data == b"\x66" * 64
    sd = q.signed_data
    assert sd.signature == b"\x88" * 64
    assert sd.ecdsa_attestation_key == b"\x99" * 64
    qrcd = sd.certification_data.qe_report_certification_data
    assert qrcd.qe_auth_data.data == b"\xab\xcd"
    assert qrcd.pck_certificate_chain_data.pck_cert_chain == b"-----FAKE-----"
    assert q.extra_bytes == b""
    assert q.header_and_body == build_quote(auth_data=b"\xab\xcd")[:0x278]


def test_too_short_for_version():
    with pytest.raises(ValueError, match="less than 2 bytes"):
        quote_to_proto_v4(b"\x04")


def test_wrong_version_rejects_before_size():
    with pytest.raises(ValueError, match="quote format not supported"):
        quote_to_proto_v4(b"\x03\x00" + b"\x00" * 10)


def test_below_minimum_size():
    with pytest.raises(ValueError, match="minimum size"):
        quote_to_proto_v4(b"\x04\x00" + b"\x00" * 100)


def test_wrong_attestation_key_type():
    with pytest.raises(ValueError, match="attestation key type not supported"):
        quote_to_proto_v4(build_quote(header=build_header(akt=3)))


def test_wrong_tee_type():
    with pytest.raises(ValueError, match="TEE type is not TDX"):
        quote_to_proto_v4(build_quote(header=build_header(tee=0x00)))


def test_reserved_bytes_are_parsed_not_rejected():
    # The parser exposes reserved bytes; authentication pins them to zero.
    q = quote_to_proto_v4(build_quote(header=build_header(reserved=b"\x01\x00\x00\x00")))
    assert q.header.pce_svn == b"\x01\x00"
    assert q.header.qe_svn == b"\x00\x00"


def test_extra_bytes_are_retained():
    q = quote_to_proto_v4(build_quote(extra=b"\x00\x01"))
    assert q.extra_bytes == b"\x00\x01"


def test_signed_data_truncated():
    full = build_quote()
    with pytest.raises(ValueError, match="size of signed data"):
        quote_to_proto_v4(full[:-1])


def test_pck_chain_wrong_type():
    with pytest.raises(ValueError, match="chain data type invalid"):
        quote_to_proto_v4(build_quote(chain_type=4))


def test_pck_chain_size_mismatch():
    with pytest.raises(ValueError, match="PCK certificate chain size"):
        quote_to_proto_v4(build_quote(chain_size=7))


def test_auth_data_size_overruns():
    # A declared auth-data size larger than the remaining bytes truncates.
    qe_report = bytes(384)
    auth_section = struct.pack("<H", 9999)
    qe_cert_data = qe_report + b"\x77" * 64 + auth_section
    cert_section = struct.pack("<H", 6) + struct.pack("<I", len(qe_cert_data)) + qe_cert_data
    signed = bytes(128) + cert_section
    raw = build_header() + build_body() + struct.pack("<I", len(signed)) + signed
    with pytest.raises(ValueError, match="truncated"):
        quote_to_proto_v4(raw)
