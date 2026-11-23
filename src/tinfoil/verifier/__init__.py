"""Offline verification of v3 attestation documents.

A ``Verifier`` appraises an attestation document that the caller fetched from
an enclave: it parses the envelope and checks the nonce binding, establishes
the code or config reference values and their freshness witnesses through
the trust path that its options select, authenticates the CPU quote against
the embedded AMD and Intel roots, and enforces the assembled platform
policy. By default the reference values are signed bundles, verified against
the embedded Sigstore trust root and the public registry and release signing
keys; a verifier may instead be built with the caller's own signing keys, with
a config authorizer that applies the caller's policy to the config bytes, or
with embedded references that the caller trusts outright, and then no bundle
authenticates the component that the caller supplied. The result is
a ``VerificationReport``: the outcome of each step (``envelope``,
``provenance``, ``quote`` and ``policy``) and its ``verified_facts``, a
``VerifiedFacts`` that holds the facts that the document proved, including
the endorsed TLS key fingerprint and HPKE public key that a client binds its
connection to, and the deadline after which a cached result must not
authorize new requests.

The verifier opens no connections and keeps no state between calls. Fetching
documents, caching a verification and enforcing its expiry belong to the
caller. The only clock it reads is the appraisal time of ``verify_v3``;
``verify_v3_at`` takes that instant from the caller instead.

Every rejection is a ``VerificationError`` tagged with the layer that
rejected the document. Its ``report`` is the ``VerificationReport`` of the
rejected verification, with the step that failed and the ``PartialFacts``
that the steps before it established: the ``ExpectedFacts`` that provenance
authenticated and the ``MeasuredFacts`` that the document and its hardware
evidence claim. Partial facts hold the channel keys only as fingerprints;
the keys themselves are only in ``verified_facts``, which alone may bind a
channel. A verifier built or called with
invalid inputs raises a ``UsageError``, which carries no report. Both derive
from ``VerifyError``. The measurement parsers (``parse_register`` and the
``parse_expected_*`` helpers) and the measurement records raise a plain
``ValueError`` for a malformed register.

Measurements are closed sets with one frozen record per platform:
``SEVSNP`` or ``TDX`` for what the hardware measured, ``ExpectedSEVSNP`` or
``ExpectedTDX`` for the registers a release or a caller expects. Registers are
48-byte ``bytes`` values (``Register``); ``parse_register`` and the
``parse_expected_*`` helpers decode them from hex.

``cert_pubkey_fp`` computes the SPKI fingerprint form in which documents
endorse TLS keys. Checking that a TLS connection presents the endorsed key is
the transport's job: compare ``cert_pubkey_fp`` of the peer certificate with
``VerifiedFacts.tls_public_key_fp`` after the handshake and before the first
byte is written.

A ``Verifier`` is built from a config trust and a ``Policy``, which are plain
data. The config trust, ``ConfigTrust``, is one of ``Registries``,
``ConfigSigningKeys``, ``ConfigAuthorizer``, ``EmbeddedConfig`` or
``EmbeddedConfigReference``, or None for the public registry. The policy holds
the register pins, the freshness bound and the artifact trust,
``ArtifactTrust``: ``EndorsedArtifacts`` or ``EmbeddedArtifacts``. Each trust
choice is one value, so that choices that exclude each other cannot be
combined. ``PublicKey`` is the ECDSA P-256 key type that the config and
freshness signing keys take, and ``load_public_key`` decodes one from PEM or
DER.
"""

from tinfoil.verifier._config import load_public_key
from tinfoil.verifier._document.collateral.config import ConfigEndorsement
from tinfoil.verifier._document.collateral.runtime import RuntimeReference
from tinfoil.verifier._document.document import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_SPKI_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    NONCE_SIZE,
    CryptoMaterialItem,
    random_nonce,
)
from tinfoil.verifier._endorsement.approval import PUBLIC_REGISTRY_ID
from tinfoil.verifier._endorsement.reference import Reference
from tinfoil.verifier._errors import (
    LAYER_ENVELOPE,
    LAYER_POLICY,
    LAYER_PROVENANCE,
    LAYER_QUOTE,
    Layer,
    UsageError,
    VerificationError,
    VerifyError,
)
from tinfoil.verifier._fingerprint import cert_pubkey_fp
from tinfoil.verifier._measurement import (
    REGISTER_SIZE,
    SEVSNP,
    TDX,
    Expected,
    ExpectedSEVSNP,
    ExpectedTDX,
    Measurement,
    Register,
    parse_expected_sevsnp,
    parse_expected_tdx,
    parse_register,
)
from tinfoil.verifier._options import (
    ArtifactTrust,
    ConfigAuthorizer,
    ConfigSigningKeys,
    ConfigTrust,
    EmbeddedArtifacts,
    EmbeddedConfig,
    EmbeddedConfigReference,
    EndorsedArtifacts,
    Policy,
    PublicKey,
    Registries,
)
from tinfoil.verifier._report import (
    STEP_FAILED,
    STEP_NOT_RUN,
    STEP_PASSED,
    STEP_SKIPPED,
    CPUEvidence,
    ExpectedFacts,
    MeasuredFacts,
    PartialFacts,
    Step,
    StepStatus,
    VerificationReport,
    hpke_public_key_fp,
)
from tinfoil.verifier._verification import (
    SOURCE_EMBEDDED,
    SOURCE_ENDORSEMENT,
    SOURCE_POLICY,
    ArtifactVerification,
    ConfigVerification,
    ReferenceSource,
    SoftwareIdentity,
    VerificationMetadata,
    VerifiedFacts,
    crypto_material_data,
)
from tinfoil.verifier._verifier import Pin, Verifier, parse_reference

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
    "STEP_FAILED",
    "STEP_NOT_RUN",
    "STEP_PASSED",
    "STEP_SKIPPED",
    "TDX",
    "ArtifactTrust",
    "ArtifactVerification",
    "CPUEvidence",
    "ConfigAuthorizer",
    "ConfigEndorsement",
    "ConfigSigningKeys",
    "ConfigTrust",
    "ConfigVerification",
    "CryptoMaterialItem",
    "EmbeddedArtifacts",
    "EmbeddedConfig",
    "EmbeddedConfigReference",
    "EndorsedArtifacts",
    "Expected",
    "ExpectedFacts",
    "ExpectedSEVSNP",
    "ExpectedTDX",
    "Layer",
    "MeasuredFacts",
    "Measurement",
    "PartialFacts",
    "Pin",
    "Policy",
    "PublicKey",
    "Reference",
    "ReferenceSource",
    "Register",
    "Registries",
    "RuntimeReference",
    "SoftwareIdentity",
    "Step",
    "StepStatus",
    "UsageError",
    "VerificationError",
    "VerificationMetadata",
    "VerificationReport",
    "VerifiedFacts",
    "Verifier",
    "VerifyError",
    "cert_pubkey_fp",
    "crypto_material_data",
    "hpke_public_key_fp",
    "load_public_key",
    "parse_expected_sevsnp",
    "parse_expected_tdx",
    "parse_reference",
    "parse_register",
    "random_nonce",
]
