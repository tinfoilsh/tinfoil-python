"""Offline verification of v3 attestation documents.

A ``Verifier`` appraises an attestation document that the caller fetched from
an enclave: it parses the envelope and checks the nonce binding, authenticates
the code or config reference values and their freshness witnesses against the
embedded Sigstore trust root, authenticates the CPU quote against the embedded
AMD and Intel roots, and enforces the assembled platform policy. The result is
a ``Verification``: the facts that the document proved, including the endorsed
TLS key fingerprint and HPKE public key that a client binds its connection
to, and the deadline after which a cached result must not authorize new
requests.

The verifier opens no connections and keeps no state between calls. Fetching
documents, caching a verification and enforcing its expiry belong to the
caller. The only clock it reads is the appraisal time of ``verify_v3``;
``verify_v3_at`` takes that instant from the caller instead.

Every rejection is a ``VerificationError`` tagged with the layer that
rejected the document; a verifier built or called with invalid inputs raises
a ``UsageError``. Both derive from ``VerifyError``.

Measurements are closed sets with one frozen record per platform:
``SEVSNP`` or ``TDX`` for what the hardware measured, ``ExpectedSEVSNP`` or
``ExpectedTDX`` for the registers a release or a caller expects. Registers are
48-byte ``bytes`` values; ``parse_register`` and the ``parse_expected_*``
helpers decode them from hex.

``cert_pubkey_fp``, ``connection_cert_fp`` and ``pin_tls_key`` compute and
check the SPKI fingerprint form in which documents endorse TLS keys.
"""

from tinfoil._v3.verifier._document.collateral.config import ConfigEndorsement
from tinfoil._v3.verifier._document.collateral.runtime import RuntimeReference
from tinfoil._v3.verifier._document.document import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_SPKI_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    NONCE_SIZE,
    CryptoMaterialItem,
    random_nonce,
)
from tinfoil._v3.verifier._embedded import EmbeddedConfig, EmbeddedConfigReference, EmbeddedReferences
from tinfoil._v3.verifier._endorsement.approval import PUBLIC_REGISTRY_ID
from tinfoil._v3.verifier._endorsement.reference import Reference
from tinfoil._v3.verifier._errors import (
    LAYER_ENVELOPE,
    LAYER_POLICY,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    UsageError,
    VerificationError,
    VerifyError,
)
from tinfoil._v3.verifier._fingerprint import cert_pubkey_fp, connection_cert_fp, pin_tls_key
from tinfoil._v3.verifier._measurement import (
    REGISTER_SIZE,
    SEVSNP,
    TDX,
    Expected,
    ExpectedSEVSNP,
    ExpectedTDX,
    Measurement,
    parse_expected_sevsnp,
    parse_expected_tdx,
    parse_register,
)
from tinfoil._v3.verifier._verification import (
    SOURCE_EMBEDDED,
    SOURCE_ENDORSEMENT,
    SOURCE_POLICY,
    ArtifactVerification,
    ConfigVerification,
    SoftwareIdentity,
    Verification,
    VerificationMetadata,
    crypto_material_data,
)
from tinfoil._v3.verifier._verifier import Verifier, parse_reference

Register = bytes
"""A measurement register: exactly ``REGISTER_SIZE`` bytes. Its text form is lowercase hex; ``parse_register``
decodes one and ``bytes.hex()`` encodes one."""

__all__ = [
    "CRYPTO_MATERIAL_ID_HPKE",
    "CRYPTO_MATERIAL_ID_TLS",
    "KEY_SPKI_FP_SHA256_V1_FORMAT",
    "KEY_SPKI_V1_FORMAT",
    "KEY_X25519_HPKE_V1_FORMAT",
    "LAYER_ENVELOPE",
    "LAYER_POLICY",
    "LAYER_PROVENANCE",
    "LAYER_QUOTE",
    "NONCE_SIZE",
    "PUBLIC_REGISTRY_ID",
    "REGISTER_SIZE",
    "SEVSNP",
    "SOURCE_EMBEDDED",
    "SOURCE_ENDORSEMENT",
    "SOURCE_POLICY",
    "TDX",
    "ArtifactVerification",
    "ConfigEndorsement",
    "ConfigVerification",
    "CryptoMaterialItem",
    "EmbeddedConfig",
    "EmbeddedConfigReference",
    "EmbeddedReferences",
    "Expected",
    "ExpectedSEVSNP",
    "ExpectedTDX",
    "Measurement",
    "Reference",
    "Register",
    "RuntimeReference",
    "SoftwareIdentity",
    "UsageError",
    "Verification",
    "VerificationError",
    "VerificationMetadata",
    "Verifier",
    "VerifyError",
    "cert_pubkey_fp",
    "connection_cert_fp",
    "crypto_material_data",
    "parse_expected_sevsnp",
    "parse_expected_tdx",
    "parse_reference",
    "parse_register",
    "pin_tls_key",
    "random_nonce",
]
