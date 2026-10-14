"""SEV-SNP authentication tests (Go: verifier/quote/sev authenticate path),
covering both product lines: Genoa (TCB struct version 0, 64-byte HWID) and
Turin (struct version 1, 8-byte HWID, fmc_spl)."""

import pytest

from tinfoil.v3 import envelope
from tinfoil.v3.errors import QUOTE_REJECTED, VerificationError
from tinfoil.v3.sev import PRODUCT_GENOA, PRODUCT_TURIN, sev_authenticate
from tinfoil.v3.sev.kds import OID_FMC_SPL, OID_SPL4

import sevsynth
from sevsynth import NOW, build_sev, der_integer, sev_doc_bytes

from cryptography import x509 as cx509


def authenticate(art, collateral_mut=None, root_pem="from-art", now=NOW):
    doc = envelope.parse_document(sev_doc_bytes(art, collateral_mut=collateral_mut))
    if root_pem == "from-art":
        root_pem = art["root_pem"]
    return sev_authenticate(doc, root_pem=root_pem, now=now)


def assert_quote_rejects(match=None, **kwargs):
    art_kwargs = {k: v for k, v in kwargs.items() if k not in ("collateral_mut", "now")}
    with pytest.raises(VerificationError, match=match) as ei:
        authenticate(
            build_sev(**art_kwargs),
            collateral_mut=kwargs.get("collateral_mut"),
            now=kwargs.get("now", NOW),
        )
    assert ei.value.layer == QUOTE_REJECTED


def test_happy_genoa():
    art = build_sev("Genoa")
    q = authenticate(art)
    assert q.product_line == PRODUCT_GENOA
    assert q.identity == ("11" * 64)
    assert q.measurement.type == "https://tinfoil.sh/predicate/sev-snp-guest/v2"
    assert q.measurement.registers == ["aa" * 48]
    assert q.report.version == 3


def test_happy_turin():
    art = build_sev("Turin")
    q = authenticate(art)
    assert q.product_line == PRODUCT_TURIN
    # Turin delivers the 8-byte hwID zero-padded; identity is the full field.
    assert q.identity == "22" * 8 + "00" * 56
    assert q.measurement.registers == ["aa" * 48]


def test_tampered_signature_rejects():
    assert_quote_rejects("report signature verification error", tamper_report_sig=True)


def test_masked_chip_id_rejects():
    assert_quote_rejects("masks CHIP_ID", signer_info=0x2)


def test_vlek_signer_rejects():
    assert_quote_rejects("VLEK certificate is missing", signer_info=0x4)


def test_none_signer_rejects():
    assert_quote_rejects("missing None certificate", signer_info=0x7 << 2)


def test_reserved_signer_rejects():
    assert_quote_rejects("signing_key values 2-6 are reserved", signer_info=0x2 << 2)


def test_unknown_product_rejects():
    assert_quote_rejects("unsupported SEV product", fms=(0x19, 0x22, 0x00))


def test_milan_rejects():
    # Milan parses as a product but is not a pinned product line.
    assert_quote_rejects("unsupported SEV product", fms=(0x19, 0x01, 0x00))


def test_report_version_2_rejects():
    assert_quote_rejects("no CPUID product identity", version=2, fms=(0, 0, 0))


def test_report_version_6_rejects():
    # Version 6 parses (fms present) but fails ValidateReportFormat's bounds.
    assert_quote_rejects("report version is: 6", version=6)


def test_mbz_violation_rejects():
    def mut(r):
        r[0x4C] = 1

    assert_quote_rejects("failed to parse report", report_mut=mut)


def test_wrong_root_rejects():
    assert_quote_rejects("not signed by the ASK", use_rogue_anchor=True)


def test_revoked_ask_rejects():
    assert_quote_rejects("ASK was revoked", revoke_serials=(2,))


def test_revoked_vcek_rejects():
    # Fail-closed extension of the library's ASK-only revocation check.
    assert_quote_rejects("VCEK was revoked", revoke_serials=(3,))


def test_crl_bad_signature_rejects():
    assert_quote_rejects("CRL is not signed by ARK", crl_signer="ask")


def test_crl_expired_rejects():
    assert_quote_rejects("outside its validity window", crl_expired=True)


def test_crl_window_pins_to_now():
    # The same document verifies at its capture time and rejects outside the
    # CRL window (frozen-time semantics).
    art = build_sev("Genoa", crl_expired=True)
    q = authenticate(art, now=sevsynth.NOT_BEFORE)
    assert q.product_line == PRODUCT_GENOA
    with pytest.raises(VerificationError, match="outside its validity window"):
        authenticate(art, now=NOW)


def test_empty_vcek_rejects():
    def mut(collateral):
        collateral[0]["data"]["vcek_der_base64"] = ""

    assert_quote_rejects("carries an empty VCEK", collateral_mut=mut)


def test_missing_crl_rejects():
    def mut(collateral):
        del collateral[1]

    assert_quote_rejects("no amd-crl endorsement collateral", collateral_mut=mut)


def test_single_cert_chain_rejects():
    art = build_sev("Genoa")

    def mut(collateral):
        # Only one certificate; the KDS chain is ASK then ARK.
        chain = art["cert_chain_pem"]
        collateral[0]["data"]["cert_chain_pem"] = chain[: chain.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")] + "\n"

    with pytest.raises(VerificationError, match="exactly the ASK and ARK"):
        authenticate(art, collateral_mut=mut)


def test_vcek_non_kds_extension_rejects():
    # A VCEK carrying any non-KDS extension (beyond the authority key id) is
    # not a KDS-wellformed certificate.
    ext = cx509.UnrecognizedExtension(cx509.ObjectIdentifier("1.2.3.4"), b"\x05\x00")
    assert_quote_rejects("not an AMD KDS OID", extra_vcek_exts=(ext,))


def test_genoa_cert_with_fmc_spl_rejects():
    ext = cx509.UnrecognizedExtension(cx509.ObjectIdentifier(OID_FMC_SPL), der_integer(1))
    assert_quote_rejects("FmcSpl extension is not valid for TCB struct version 0",
                         extra_vcek_exts=(ext,))


def test_turin_cert_with_spl4_rejects():
    ext = cx509.UnrecognizedExtension(cx509.ObjectIdentifier(OID_SPL4), der_integer(0))
    with pytest.raises(VerificationError, match="Spl4 extension is not valid"):
        authenticate(build_sev("Turin", extra_vcek_exts=(ext,)))


def test_cert_format_product_mismatch_rejects():
    # A Genoa report presented with a Turin-format VCEK (struct version 1,
    # 8-byte HWID, fmc_spl layout) uses a different TCB format.
    art = build_sev(
        "Genoa",
        cert_struct_version=1,
        vcek_hwid=b"\x11" * 8,
        vcek_tcb_parts={"fmc": 0, "bl": 7, "tee": 0, "snp": 20, "ucode": 72},
    )
    with pytest.raises(VerificationError, match="different TCB formats") as ei:
        authenticate(art)
    assert ei.value.layer == QUOTE_REJECTED


def test_turin_hwid_wrong_length_rejects():
    # A Turin-format VCEK must carry the 8-byte PSN HWID.
    with pytest.raises(VerificationError, match="size is 64, expected 8"):
        authenticate(build_sev("Turin", vcek_hwid=b"\x22" * 64))


def test_embedded_root_rejects_synthetic():
    # No override -> embedded production per-product anchor; the synthetic
    # chain cannot verify against it.
    art = build_sev("Genoa")
    with pytest.raises(VerificationError) as ei:
        authenticate(art, root_pem=None)
    assert ei.value.layer == QUOTE_REJECTED
    art = build_sev("Turin")
    with pytest.raises(VerificationError) as ei:
        authenticate(art, root_pem=None)
    assert ei.value.layer == QUOTE_REJECTED


def test_report_wrong_size_rejects():
    art = build_sev("Genoa")
    art = dict(art)
    art["report"] = art["report"][:-1]
    with pytest.raises(VerificationError, match="must be exactly 1184 bytes"):
        authenticate(art)


def test_turin_reserved_tcb_bits_pass_authenticate():
    # Authentication does not decompose the report's TCB fields; a Turin
    # report with reserved bits 55:32 set still authenticates (the TCB
    # relations reject it at validation, see test_sev_expectations).
    art = build_sev("Turin", reported_tcb_raw=(1 << 40) | 0x4800000014000701)
    q = authenticate(art)
    assert q.product_line == PRODUCT_TURIN
