"""The fingerprint of the key that a TLS connection presents, for binding it to the key that an attestation
document endorses. It is private: the pinned transport in ``tinfoil._tls`` compares it with the endorsed
fingerprint, and the conformance adapter's live-verify check uses it.

The verifier reports the fingerprint (``Verification.tls_public_key_fp``) and computes it from certificate bytes
(``cert_pubkey_fp``); reading the peer certificate off a connection and building the check on it is the
transport's job, so that the verifier never takes a socket or a connection object.
"""

from __future__ import annotations

import ssl

from tinfoil.verifier import UsageError, cert_pubkey_fp


def connection_cert_fp(connection: ssl.SSLSocket | ssl.SSLObject) -> str:
    """``cert_pubkey_fp`` of the leaf certificate that a TLS connection presented. A connection without a peer
    certificate is a UsageError."""
    leaf = connection.getpeercert(binary_form=True)
    if not leaf:
        raise UsageError("no peer certificates")
    return cert_pubkey_fp(leaf)


__all__ = ["connection_cert_fp"]
