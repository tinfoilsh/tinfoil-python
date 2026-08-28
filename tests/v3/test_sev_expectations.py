"""SEV-SNP policy assembly + validation tests (Go: verifier/quote/sev
expectations path with the configured go-sev-guest validate options),
covering the per-product Genoa/Turin rules: fmc_spl, iommu_write_safe, TCB
layouts, and the Turin 8-byte HWID binding."""

import pytest

from tinfoil.v3 import envelope
from tinfoil.v3.errors import POLICY_REJECTED, VerificationError
from tinfoil.v3.policy import TCB, GuestPolicy, SEVSNPPolicy, SNPPlatform
from tinfoil.v3.sev import sev_assemble, sev_authenticate, sev_validate

from sevsynth import NOW, build_sev, sev_doc_bytes

LAUNCH_DIGEST = b"\xaa" * 48
REPORT_DATA = b"\x00" * 64


def make_policy(product="Genoa", **over) -> SEVSNPPolicy:
    """A policy matching sevsynth's default report for the product."""
    fmc = 1 if product == "Turin" else None
    fields = dict(
        minimum_build=21,
        minimum_api_version="1.55",
        minimum_abi_version="0.0",
        minimum_guest_svn=0,
        minimum_tcb=TCB(fmc_spl=fmc, bl_spl=7, tee_spl=0, snp_spl=20, ucode_spl=72),
        minimum_launch_tcb=TCB(fmc_spl=fmc, bl_spl=7, tee_spl=0, snp_spl=20, ucode_spl=72),
        guest_policy=GuestPolicy(
            debug=False, smt=True, migrate_ma=False, single_socket=False,
            cxl_allowed=False, mem_aes256_xts=False, rapl_dis=False,
            ciphertext_hiding_dram=False, page_swap_disable=False,
        ),
        platform_info=SNPPlatform(
            smt_enabled=False, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=False, ciphertext_hiding_dram=False,
            alias_check_complete=False,
            iommu_write_safe=(product == "Turin"),
            tio_enabled=False,
        ),
        permit_provisional_firmware=False,
        vmpl=0,
        host_data="00" * 32,
        image_id="00" * 16,
        family_id="00" * 16,
        require_author_key=False,
        require_id_block=False,
        minimum_launch_mitigation_vector=0,
        minimum_current_mitigation_vector=0,
    )
    fields.update(over)
    return SEVSNPPolicy(**fields)


def authenticate(art):
    doc = envelope.parse_document(sev_doc_bytes(art))
    return sev_authenticate(doc, root_pem=art["root_pem"], now=NOW)


def validate(product="Genoa", policy=None, launch_digest=LAUNCH_DIGEST,
             report_data=REPORT_DATA, **art_kwargs):
    # `policy` names the SEVSNPPolicy here; the report's guest-policy bits
    # ride in as `policy_report`.
    if "policy_report" in art_kwargs:
        art_kwargs["policy"] = art_kwargs.pop("policy_report")
    q = authenticate(build_sev(product, **art_kwargs))
    p = policy if policy is not None else make_policy(product)
    e = sev_assemble(p, q, launch_digest, report_data)
    sev_validate(e, q)
    return q


def assert_policy_rejects(match=None, **kwargs):
    with pytest.raises(VerificationError, match=match) as ei:
        validate(**kwargs)
    assert ei.value.layer == POLICY_REJECTED


def test_happy_genoa_validates():
    validate("Genoa")


def test_happy_turin_validates():
    validate("Turin")


# --- per-product policy translation rules -------------------------------------


def test_genoa_fmc_spl_invalid():
    p = make_policy("Genoa")
    p.minimum_tcb = TCB(fmc_spl=0, bl_spl=7, tee_spl=0, snp_spl=20, ucode_spl=72)
    assert_policy_rejects("fmc_spl is not valid for product line Genoa",
                          product="Genoa", policy=p)


def test_genoa_iommu_write_safe_invalid():
    p = make_policy("Genoa")
    p.platform_info.iommu_write_safe = True
    assert_policy_rejects("iommu_write_safe is not valid for product line Genoa",
                          product="Genoa", policy=p)


def test_turin_fmc_spl_required():
    p = make_policy("Turin")
    p.minimum_launch_tcb = TCB(fmc_spl=None, bl_spl=7, tee_spl=0, snp_spl=20, ucode_spl=72)
    assert_policy_rejects("fmc_spl is required for product line Turin",
                          product="Turin", policy=p)


def test_turin_iommu_write_safe_required():
    p = make_policy("Turin")
    p.platform_info.iommu_write_safe = False
    assert_policy_rejects("iommu_write_safe is required for product line Turin",
                          product="Turin", policy=p)


def test_bad_version_string():
    p = make_policy("Genoa", minimum_api_version="1x55")
    assert_policy_rejects("is not maj.min", product="Genoa", policy=p)


def test_tcb_part_over_127():
    p = make_policy("Genoa")
    p.minimum_tcb = TCB(fmc_spl=None, bl_spl=200, tee_spl=0, snp_spl=20, ucode_spl=72)
    assert_policy_rejects("BlSpl TCB part is 200", product="Genoa", policy=p)


def test_incomplete_policy_rejects():
    p = make_policy("Genoa", vmpl=None)
    assert_policy_rejects("vmpl is required", product="Genoa", policy=p)


# --- TCB relations -------------------------------------------------------------


def test_reported_tcb_differs_from_cert():
    assert_policy_rejects(
        "does not match the TCB of the V\\[CL\\]EK certificate",
        product="Genoa",
        vcek_tcb_parts={"bl": 7, "tee": 0, "snp": 21, "ucode": 72},
    )


def test_cert_tcb_above_current():
    assert_policy_rejects(
        "CURRENT_TCB is lower than the TCB of the V\\[CL\\]EK certificate",
        product="Genoa",
        current_tcb_parts={"bl": 6, "tee": 0, "snp": 20, "ucode": 72},
        committed_tcb_parts={"bl": 6, "tee": 0, "snp": 20, "ucode": 72},
    )


def test_committed_must_equal_current_without_provisional():
    assert_policy_rejects(
        "COMMITTED_TCB .* does not match the report's CURRENT_TCB",
        product="Genoa",
        committed_tcb_parts={"bl": 6, "tee": 0, "snp": 20, "ucode": 72},
    )


def test_provisional_allows_lower_committed():
    p = make_policy("Genoa", permit_provisional_firmware=True)
    validate("Genoa", policy=p,
             committed_tcb_parts={"bl": 6, "tee": 0, "snp": 20, "ucode": 72})


def test_minimum_tcb_floor():
    p = make_policy("Genoa")
    p.minimum_tcb = TCB(fmc_spl=None, bl_spl=8, tee_spl=0, snp_spl=20, ucode_spl=72)
    assert_policy_rejects("REPORTED_TCB is lower than the policy minimum TCB",
                          product="Genoa", policy=p)


def test_minimum_launch_tcb_floor():
    p = make_policy("Genoa")
    p.minimum_launch_tcb = TCB(fmc_spl=None, bl_spl=7, tee_spl=0, snp_spl=21, ucode_spl=72)
    assert_policy_rejects("LAUNCH_TCB is lower than the policy minimum launch TCB",
                          product="Genoa", policy=p)


def test_turin_fmc_floor_enforced():
    # The Turin-only fmc_spl component participates in the TCB comparisons.
    p = make_policy("Turin")
    p.minimum_tcb = TCB(fmc_spl=2, bl_spl=7, tee_spl=0, snp_spl=20, ucode_spl=72)
    assert_policy_rejects("REPORTED_TCB is lower than the policy minimum TCB",
                          product="Turin", policy=p)


def test_turin_reserved_tcb_bits_reject():
    # Reserved bits 55:32 of a Turin TCB must be zero when decomposed.
    assert_policy_rejects(
        "non-zero reserved bits in Turin TCB",
        product="Turin",
        reported_tcb_raw=(1 << 40) | 0x4800000014000701,
    )


# --- guest policy / platform info -----------------------------------------------


def test_unauthorized_debug_bit():
    # Report guest policy with the debug bit set, not endorsed.
    assert_policy_rejects("found unauthorized debug capability",
                          product="Genoa", policy_report=0x30000 | (1 << 19))


def test_guest_policy_strict_equality():
    # The mask allows a clear bit, but strict equality requires the endorsed
    # value: policy smt=True with a report smt=0 rejects.
    assert_policy_rejects("does not equal the endorsed policy",
                          product="Genoa", policy_report=0x20000)


def test_platform_info_mask():
    # TSME set in the report but not endorsed: rejected by the library mask.
    assert_policy_rejects("unauthorized platform feature TSME enabled",
                          product="Genoa", platform_info=0x2)


def test_platform_info_strict_equality():
    # Endorsed tsme_enabled=True with a clear report bit passes the mask but
    # fails strict equality.
    p = make_policy("Genoa")
    p.platform_info.tsme_enabled = True
    assert_policy_rejects("PLATFORM_INFO .* does not equal the endorsed policy",
                          product="Genoa", policy=p)


def test_abi_version_floor():
    p = make_policy("Genoa", minimum_abi_version="2.0")
    assert_policy_rejects("required policy ABI version", product="Genoa", policy=p)


# --- verbatim fields / floors ----------------------------------------------------


def test_measurement_mismatch():
    assert_policy_rejects("report field MEASUREMENT",
                          product="Genoa", launch_digest=b"\xbb" * 48)


def test_report_data_mismatch():
    assert_policy_rejects("report field REPORT_DATA",
                          product="Genoa", report_data=b"\x01" + b"\x00" * 63)


def test_host_data_mismatch():
    p = make_policy("Genoa", host_data="11" * 32)
    assert_policy_rejects("report field HOST_DATA", product="Genoa", policy=p)


def test_minimum_build_floor():
    p = make_policy("Genoa", minimum_build=22)
    assert_policy_rejects("firmware build number 21 is less than", product="Genoa", policy=p)


def test_minimum_api_version_floor():
    p = make_policy("Genoa", minimum_api_version="1.56")
    assert_policy_rejects("less than the required minimum", product="Genoa", policy=p)


def test_guest_svn_floor():
    p = make_policy("Genoa", minimum_guest_svn=1)
    assert_policy_rejects("GUEST_SVN 0 is less than", product="Genoa", policy=p)


def test_vmpl_mismatch():
    assert_policy_rejects("report VMPL 1 is not 0", product="Genoa", vmpl=1)


def test_mitigation_vector_floor():
    p = make_policy("Genoa", minimum_launch_mitigation_vector=1)
    assert_policy_rejects("launch mitigation vector", product="Genoa", policy=p)


def test_mitigation_vector_superset_passes():
    p = make_policy("Genoa", minimum_current_mitigation_vector=0x5)
    validate("Genoa", policy=p, current_mit_vector=0x7, launch_mit_vector=0x7)


# --- signer / identity binding ----------------------------------------------------


def test_author_key_rejects():
    assert_policy_rejects("carries an author key", product="Genoa", signer_info=0x1)


def test_id_block_rejects():
    assert_policy_rejects("carries an ID block", product="Genoa",
                          id_key_digest=b"\x01" * 48)


def test_author_key_digest_rejects():
    assert_policy_rejects("carries an author key digest", product="Genoa",
                          author_key_digest=b"\x01" * 48)


def test_turin_hwid_binding():
    # The report CHIP_ID's first 8 bytes must equal the Turin VCEK's HWID.
    assert_policy_rejects(
        "is not the same as the VCEK certificate's HWID",
        product="Turin",
        vcek_hwid=b"\x33" * 8,
    )


def test_genoa_hwid_binding():
    assert_policy_rejects(
        "is not the same as the VCEK certificate's HWID",
        product="Genoa",
        vcek_hwid=b"\x33" * 64,
    )


def test_chip_id_from_wrong_quote():
    # Expectations bind the endorsed CHIP_ID; a different machine's report
    # fails the verbatim comparison.
    q_other = authenticate(build_sev("Genoa", chip_id=b"\x44" * 64,
                                     vcek_hwid=b"\x44" * 64))
    q = authenticate(build_sev("Genoa"))
    e = sev_assemble(make_policy("Genoa"), q, LAUNCH_DIGEST, REPORT_DATA)
    with pytest.raises(VerificationError, match="report field CHIP_ID") as ei:
        sev_validate(e, q_other)
    assert ei.value.layer == POLICY_REJECTED


def test_assemble_rejects_bad_launch_digest():
    q = authenticate(build_sev("Genoa"))
    with pytest.raises(VerificationError, match="launch digest must be 48 bytes") as ei:
        sev_assemble(make_policy("Genoa"), q, b"\xaa" * 32, REPORT_DATA)
    assert ei.value.layer == POLICY_REJECTED
