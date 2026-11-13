"""SPKI fingerprints of TLS certificates, in the form that attestation documents endorse."""

from __future__ import annotations

import hashlib

import pytest

from tests import pki
from tinfoil.verifier._errors import UsageError
from tinfoil.verifier._fingerprint import cert_pubkey_fp


@pytest.mark.parametrize("key", [pki.p256(), pki.p384(), pki.rsa_key(), pki.ed25519_key()])
def test_cert_pubkey_fp_is_the_spki_sha256(key: pki.PrivateKey) -> None:
    issued = pki.certificate("leaf", key)
    assert cert_pubkey_fp(issued.der) == hashlib.sha256(pki.spki(key)).hexdigest()


def test_cert_pubkey_fp_rejects_missing_input() -> None:
    with pytest.raises(UsageError, match="no certificate"):
        cert_pubkey_fp(b"")
    with pytest.raises(UsageError, match="parsing certificate"):
        cert_pubkey_fp(b"not a certificate")
