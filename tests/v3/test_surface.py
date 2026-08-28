"""Tier-1 public surface presence (SDK_SURFACE_SPEC §1-2): the v3 names must
be importable from the package root, so the conformance adapter tests what
applications can actually reach."""

import inspect

import tinfoil


def test_tier1_names_importable_from_package_root():
    for name in (
        "verify_document_v3",
        "VerifiedDocumentV3",
        "tls_public_key_fp",
        "hpke_public_key",
        "fetch_attestation",
        "random_nonce",
        "NONCE_SIZE",
        "VerificationError",
    ):
        assert hasattr(tinfoil, name), f"tinfoil.{name} is missing"
        assert name in tinfoil.__all__, f"tinfoil.{name} not in __all__"


def test_nonce_size_and_random_nonce():
    assert tinfoil.NONCE_SIZE == 32
    nonce = tinfoil.random_nonce()
    assert isinstance(nonce, bytes) and len(nonce) == tinfoil.NONCE_SIZE
    assert nonce != tinfoil.random_nonce()


def test_verification_error_exposes_layer():
    err = tinfoil.VerificationError("QUOTE_REJECTED", "boom")
    assert isinstance(err, Exception)
    assert err.layer == "QUOTE_REJECTED"


def test_verify_document_v3_signature():
    sig = inspect.signature(tinfoil.verify_document_v3)
    params = list(sig.parameters)
    assert params[:3] == ["doc_bytes", "nonce", "repo"]
    for kw in ("sigstore_root_json", "amd_root_pem", "intel_root_pem", "verification_time"):
        assert sig.parameters[kw].kind is inspect.Parameter.KEYWORD_ONLY


def test_key_accessors_raise_on_absent_material():
    from tinfoil.v3.measurement import SEV_GUEST_V2, Measurement

    v = tinfoil.VerifiedDocumentV3(
        code_digest="",
        code_tag="",
        code_measurement=Measurement(type=SEV_GUEST_V2, registers=["aa" * 48]),
        enclave_measurement=Measurement(type=SEV_GUEST_V2, registers=["aa" * 48]),
        crypto_material=[],
    )
    for accessor in (tinfoil.tls_public_key_fp, tinfoil.hpke_public_key):
        try:
            accessor(v)
        except ValueError:
            continue
        raise AssertionError(f"{accessor.__name__} did not raise on absent material")
