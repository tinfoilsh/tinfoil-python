"""The private TLS connection check built on the verifier's SPKI fingerprint: the fingerprint of a connection's
leaf, and the pinned transport's comparison of it with the endorsed fingerprint."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from tests import pki
from tinfoil._pin import connection_cert_fp
from tinfoil._tls import CERT_MISMATCH, NO_PEER_CERTIFICATE, PinMismatchError, _pin
from tinfoil.verifier import UsageError, cert_pubkey_fp


@dataclass(frozen=True)
class Connection:
    """What the pin reads from a TLS connection: the peer's leaf certificate in DER."""

    leaf: bytes | None

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        assert binary_form
        return self.leaf


@pytest.mark.parametrize("key", [pki.p256(), pki.p384(), pki.rsa_key(), pki.ed25519_key()])
def test_connection_cert_fp_is_the_spki_sha256_of_the_leaf(key: pki.PrivateKey) -> None:
    issued = pki.certificate("leaf", key)
    want = hashlib.sha256(pki.spki(key)).hexdigest()
    assert connection_cert_fp(Connection(issued.der)) == want  # type: ignore[arg-type]
    assert connection_cert_fp(Connection(issued.der)) == cert_pubkey_fp(issued.der)  # type: ignore[arg-type]


def test_connection_cert_fp_rejects_a_connection_without_a_peer_certificate() -> None:
    with pytest.raises(UsageError, match="no peer certificates"):
        connection_cert_fp(Connection(None))  # type: ignore[arg-type]


def test_pin_accepts_the_endorsed_key_and_rejects_another() -> None:
    issued = pki.certificate("leaf", pki.p256())
    _pin(cert_pubkey_fp(issued.der))(Connection(issued.der))  # type: ignore[arg-type]
    with pytest.raises(PinMismatchError, match=CERT_MISMATCH):
        _pin("00" * 32)(Connection(issued.der))  # type: ignore[arg-type]


@pytest.mark.parametrize("leaf", [None, b"", b"not a certificate"])
def test_pin_rejects_a_peer_certificate_that_it_cannot_read(leaf: bytes | None) -> None:
    fp = cert_pubkey_fp(pki.certificate("leaf", pki.p256()).der)
    with pytest.raises(PinMismatchError, match=NO_PEER_CERTIFICATE):
        _pin(fp)(Connection(leaf))  # type: ignore[arg-type]
