"""SPKI fingerprints of TLS leaves and the key pin built on them."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from tests import pki
from tinfoil.verifier._errors import LAYER_POLICY, UsageError, VerificationError
from tinfoil.verifier._fingerprint import cert_pubkey_fp, connection_cert_fp, pin_tls_key


@dataclass(frozen=True)
class Connection:
    """What the pin reads from a TLS connection: the peer's leaf certificate in DER."""

    leaf: bytes | None

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        assert binary_form
        return self.leaf


@pytest.mark.parametrize("key", [pki.p256(), pki.p384(), pki.rsa_key(), pki.ed25519_key()])
def test_cert_pubkey_fp_is_the_spki_sha256(key: pki.PrivateKey) -> None:
    issued = pki.certificate("leaf", key)
    want = hashlib.sha256(pki.spki(key)).hexdigest()
    assert cert_pubkey_fp(issued.der) == want
    assert connection_cert_fp(Connection(issued.der)) == want  # type: ignore[arg-type]


def test_cert_pubkey_fp_rejects_missing_input() -> None:
    with pytest.raises(UsageError, match="no certificate"):
        cert_pubkey_fp(b"")
    with pytest.raises(UsageError, match="parsing certificate"):
        cert_pubkey_fp(b"not a certificate")
    with pytest.raises(UsageError, match="no peer certificates"):
        connection_cert_fp(Connection(None))  # type: ignore[arg-type]


def test_pin_tls_key() -> None:
    issued = pki.certificate("leaf", pki.p256())
    fp = cert_pubkey_fp(issued.der)
    pin_tls_key(fp)(Connection(issued.der))  # type: ignore[arg-type]
    with pytest.raises(VerificationError) as rejected:
        pin_tls_key("00" * 32)(Connection(issued.der))  # type: ignore[arg-type]
    assert rejected.value.layer == LAYER_POLICY
    assert fp in str(rejected.value)
    with pytest.raises(UsageError):
        pin_tls_key(fp)(Connection(None))  # type: ignore[arg-type]


def test_pin_tls_key_rejects_a_malformed_fingerprint_when_built() -> None:
    # The pin is checked once, so that a record without an endorsed TLS key, or a fingerprint in another form,
    # cannot be mistaken for a mismatch on every connection.
    issued = pki.certificate("leaf", pki.p256())
    fp = cert_pubkey_fp(issued.der)
    for bad in (None, b"", 42):
        with pytest.raises(UsageError, match="lowercase hex string"):
            pin_tls_key(bad)  # type: ignore[arg-type]
    for malformed in ("", fp[:-2], fp + "00", fp.upper(), fp[:-1] + "g", "sha256:" + fp[7:]):
        with pytest.raises(UsageError, match="32 bytes as lowercase hex"):
            pin_tls_key(malformed)
    pin_tls_key(fp)(Connection(issued.der))  # type: ignore[arg-type]
