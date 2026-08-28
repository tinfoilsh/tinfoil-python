"""v3 document verification flow (Go: verifier/client/verify.go):
envelope check → reference-values authentication (code + platform, each
with its freshness proof) → CPU quote verification. Every rejection raises
VerificationError tagged with the failing layer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .envelope import (
    COLLATERAL_SIGSTORE_CODE_V1_FORMAT,
    COLLATERAL_SIGSTORE_PLATFORM_V1_FORMAT,
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    FRESHNESS_COLLATERAL_ID_CODE,
    FRESHNESS_COLLATERAL_ID_PLATFORM,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    CryptoMaterialItem,
    Document,
    check,
    crypto_material_items,
    freshness_collateral,
    reference_values_collateral,
)
from .errors import PROVENANCE_REJECTED, VerificationError
from .measurement import Measurement
from .provenance import (
    Code,
    PlatformEndorsements,
    authenticate_code,
    authenticate_freshness,
    authenticate_platform_endorsements,
)
from .quote import assemble_and_validate, quote_authenticate


@dataclass
class VerifiedDocumentV3:
    """What a verified v3 document proves. The operative output is
    crypto_material — the endorsed keys a caller may bind a channel to; it is
    the only field that authorizes an action (Go: client.VerifiedDocumentV3)."""

    # code_digest names the verified code artifact; code_measurement is the
    # expected measurement applied from it.
    code_digest: str
    code_tag: str
    code_measurement: Measurement
    # enclave_measurement carries the quote's authenticated registers, proven
    # to match the expectations.
    enclave_measurement: Measurement
    # crypto_material holds the endorsed key items (hash-bound into the quote).
    crypto_material: list[CryptoMaterialItem]


def tls_public_key_fp(v: VerifiedDocumentV3) -> str:
    """The endorsed TLS key fingerprint (the id=tls crypto_material entry);
    raises when the document does not endorse one (Go: TLSPublicKeyFP)."""
    return _crypto_material_data(v, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT)


def hpke_public_key(v: VerifiedDocumentV3) -> str:
    """The endorsed HPKE public key (the id=hpke crypto_material entry);
    raises when the document does not endorse one (Go: HPKEPublicKey)."""
    return _crypto_material_data(v, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT)


def _crypto_material_data(v: VerifiedDocumentV3, id_: str, format_: str) -> str:
    for item in v.crypto_material:
        if item.id != id_:
            continue
        if item.format != format_:
            raise ValueError(
                f"crypto_material item {id_!r} has format {item.format!r}, want {format_!r}"
            )
        return item.data
    raise ValueError(f"document endorses no {id_!r} crypto material")


def verify_document_v3(
    doc_bytes: bytes,
    nonce: bytes,
    repo: str,
    *,
    sigstore_root_json: Optional[bytes] = None,
    amd_root_pem: Optional[str] = None,
    intel_root_pem: Optional[str] = None,
    verification_time: Optional[datetime] = None,
) -> VerifiedDocumentV3:
    """Verify a v3 attestation document from its transmitted bytes (Go:
    client.VerifyDocumentV3):

     1. Check the envelope: format, nonce equality, endorsed-section hash
        recomputation, REPORT_DATA recomputation (no authentication).
     2. Authenticate the reference values: the sigstore-code,
        sigstore-platform, and sigstore-freshness entries against pinned
        signing identities, at one appraisal time.
     3. Verify the CPU quote: authenticate against the pinned vendor roots,
        assemble the complete policy from the reference values, validate in
        one call.

    repo is the code repository the caller trusts (pins the sigstore-code
    signing identity); the repo named inside the document is not trusted.
    The keyword overrides are the conformance seams; defaults are the
    embedded production roots and the current time. Channel binding (TLS
    fingerprint / HPKE key) is the caller's responsibility, using the
    returned endorsed crypto material."""
    doc, report_data = check(doc_bytes, nonce)

    # One appraisal datetime pins both freshness proofs and the quote clock.
    appraisal = verification_time if verification_time is not None else datetime.now(timezone.utc)
    code, endorsements = _authenticate_reference_values(
        doc, repo, appraisal, sigstore_root_json
    )

    authenticated = quote_authenticate(
        doc,
        amd_root_pem=amd_root_pem,
        intel_root_pem=intel_root_pem,
        now=verification_time,
    )
    assemble_and_validate(
        endorsements.artifact, code.measurement, code.shape, report_data, authenticated
    )

    return VerifiedDocumentV3(
        code_digest=code.digest,
        code_tag=code.tag,
        code_measurement=code.measurement,
        enclave_measurement=authenticated.measurement,
        crypto_material=crypto_material_items(doc),
    )


def _authenticate_reference_values(
    doc: Document,
    repo: str,
    appraisal: datetime,
    trust_root_json: Optional[bytes],
) -> tuple[Code, PlatformEndorsements]:
    """Authenticate the document's required code and platform Sigstore
    artifacts plus the matching freshness proof for each, both appraised at
    one time (Go: client.authenticateReferenceValues)."""
    code_ref = reference_values_collateral(doc, COLLATERAL_SIGSTORE_CODE_V1_FORMAT)
    try:
        code = authenticate_code(
            code_ref.sigstore_bundle, repo, code_ref.tag, code_ref.digest,
            trust_root_json=trust_root_json,
        )
    except VerificationError as e:
        raise _wrap("verifying code measurement", e) from None
    code_fresh = freshness_collateral(doc, FRESHNESS_COLLATERAL_ID_CODE)
    try:
        authenticate_freshness(code_fresh, code, appraisal, trust_root_json=trust_root_json)
    except VerificationError as e:
        raise _wrap("verifying code freshness", e) from None

    plat_ref = reference_values_collateral(doc, COLLATERAL_SIGSTORE_PLATFORM_V1_FORMAT)
    try:
        endorsements = authenticate_platform_endorsements(
            plat_ref.sigstore_bundle, plat_ref.repo, plat_ref.tag, plat_ref.digest,
            trust_root_json=trust_root_json,
        )
    except VerificationError as e:
        raise _wrap("verifying platform endorsements", e) from None
    plat_fresh = freshness_collateral(doc, FRESHNESS_COLLATERAL_ID_PLATFORM)
    try:
        authenticate_freshness(
            plat_fresh, endorsements, appraisal, trust_root_json=trust_root_json
        )
    except VerificationError as e:
        raise _wrap("verifying platform freshness", e) from None

    return code, endorsements


def _wrap(context: str, err: VerificationError) -> VerificationError:
    """Prefix a step's context onto a rejection, preserving its layer."""
    layer = err.layer if isinstance(err, VerificationError) else PROVENANCE_REJECTED
    return VerificationError(layer, f"{context}: {err}")
