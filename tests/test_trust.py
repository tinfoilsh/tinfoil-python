"""The generated trust constants parse as what they claim to be."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil.verifier import _json
from tinfoil.verifier._trust import (
    AMD_GENOA_CERT_CHAIN_PEM,
    AMD_TURIN_CERT_CHAIN_PEM,
    INTEL_SGX_ROOT_CA_PEM,
    PUBLIC_SIGNING_KEYS_PEM,
    SIGSTORE_TRUSTED_ROOT_JSON,
)


def test_sigstore_root_is_strict_json_trusted_root() -> None:
    root = _json.strict_parse(SIGSTORE_TRUSTED_ROOT_JSON)
    assert isinstance(root, _json.JsonObject)
    assert root["mediaType"] == "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
    for member in ("tlogs", "certificateAuthorities", "ctlogs", "timestampAuthorities"):
        value = root[member]
        assert isinstance(value, tuple)
        assert value


@pytest.mark.parametrize(
    ("chain_pem", "product"),
    [(AMD_GENOA_CERT_CHAIN_PEM, "Genoa"), (AMD_TURIN_CERT_CHAIN_PEM, "Turin")],
    ids=["genoa", "turin"],
)
def test_amd_chain_is_ask_then_ark(chain_pem: bytes, product: str) -> None:
    ask, ark = x509.load_pem_x509_certificates(chain_pem)
    assert _common_name(ask) == f"SEV-{product}"
    assert _common_name(ark) == f"ARK-{product}"
    ark.verify_directly_issued_by(ark)
    ask.verify_directly_issued_by(ark)


def test_intel_sgx_root_is_self_signed() -> None:
    (root,) = x509.load_pem_x509_certificates(INTEL_SGX_ROOT_CA_PEM)
    assert _common_name(root) == "Intel SGX Root CA"
    root.verify_directly_issued_by(root)
    assert isinstance(root.public_key(), ec.EllipticCurvePublicKey)


def test_signing_keys_are_ecdsa_p256_public_keys() -> None:
    assert PUBLIC_SIGNING_KEYS_PEM
    for pem in PUBLIC_SIGNING_KEYS_PEM:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert isinstance(key.curve, ec.SECP256R1)


def _common_name(certificate: x509.Certificate) -> str:
    (attribute,) = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    value = attribute.value
    assert isinstance(value, str)
    return value
