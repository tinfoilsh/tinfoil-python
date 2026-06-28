from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass

from sigstore.errors import VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier
from sigstore.verify.policy import (
    AllOf,
    Certificate,
    ExtensionNotFound,
    GitHubWorkflowRepository,
    _OIDC_GITHUB_WORKFLOW_REF_OID,
)

from ..attestation import Measurement, PredicateType
from ..sigstore import OIDCIssuerV2Preferred, reject_duplicate_sct_logs

OIDC_ISSUER = "https://token.actions.githubusercontent.com"


@dataclass
class SigstorePolicy:
    oidc_issuer: str
    workflow_ref_prefix: str
    workflow_repository: str
    predicate_types_allowed: list[str] | None
    in_toto_statement_types_allowed: list[str] | None
    payload_type: str


def default_sigstore_policy(repo: str) -> SigstorePolicy:
    return SigstorePolicy(
        oidc_issuer=OIDC_ISSUER,
        workflow_ref_prefix="refs/tags/",
        workflow_repository=repo,
        predicate_types_allowed=[
            "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
        ],
        in_toto_statement_types_allowed=[
            "https://in-toto.io/Statement/v0.1",
            "https://in-toto.io/Statement/v1",
        ],
        payload_type="application/vnd.in-toto+json",
    )


@dataclass
class SigstoreVerification:
    measurement: Measurement
    predicate_type: str
    in_toto_statement_type: str
    subject_name: str
    subject_digest_sha256_hex: str
    cert_oidc_issuer: str
    cert_workflow_repository: str
    cert_workflow_signer_uri: str
    rekor_log_id_hex: str | None = None
    rekor_integrated_time_unix: int | None = None
    tlog_entry_count: int = 0
    sct_count: int | None = None


class GitHubWorkflowRefPrefix:
    def __init__(self, prefix: str) -> None:
        self._prefix = prefix

    def verify(self, cert: Certificate) -> None:
        try:
            ext = cert.extensions.get_extension_for_oid(
                _OIDC_GITHUB_WORKFLOW_REF_OID
            ).value
            ext_value = ext.value.decode()
            if not ext_value.startswith(self._prefix):
                raise VerificationError(
                    "WORKFLOW_REF_PREFIX_MISMATCH: cert workflow ref "
                    f"{ext_value!r} does not start with policy.workflow_ref_prefix "
                    f"{self._prefix!r}"
                )
        except ExtensionNotFound:
            raise VerificationError(
                "WORKFLOW_REF_PREFIX_MISMATCH: Certificate does not contain "
                "GitHubWorkflowRef "
                f"({_OIDC_GITHUB_WORKFLOW_REF_OID.dotted_string}) extension"
            )


def verify_sigstore_bundle_with_policy(
    bundle_bytes: bytes,
    expected_digest_sha256_hex: str,
    policy: SigstorePolicy,
    trust_root_json: str,
) -> SigstoreVerification:
    """Conformance-only Sigstore verifier with injected policy and trust root."""
    with tempfile.TemporaryDirectory(prefix="tinfoil-conformance-") as tdir:
        tr_path = os.path.join(tdir, "trusted_root.json")
        with open(tr_path, "w") as f:
            f.write(trust_root_json)
        trusted_root = TrustedRoot.from_file(tr_path)

    verifier = Verifier(trusted_root=trusted_root)
    bundle = Bundle.from_json(bundle_bytes)

    # SPEC §5.2: reject duplicate-log SCTs before signature/SCT verification.
    reject_duplicate_sct_logs(bundle)

    cert_policy = AllOf(
        [
            OIDCIssuerV2Preferred(policy.oidc_issuer),
            GitHubWorkflowRepository(policy.workflow_repository),
            GitHubWorkflowRefPrefix(policy.workflow_ref_prefix),
        ]
    )
    payload_type, payload_bytes = verifier.verify_dsse(bundle, cert_policy)

    if payload_type != policy.payload_type:
        raise ValueError(
            f"PAYLOAD_TYPE_MISMATCH: DSSE payload_type {payload_type!r} does "
            f"not equal policy.payload_type {policy.payload_type!r}"
        )

    statement = json.loads(payload_bytes)
    stmt_type = statement.get("_type")
    if (
        policy.in_toto_statement_types_allowed is not None
        and stmt_type not in policy.in_toto_statement_types_allowed
    ):
        raise ValueError(
            "IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED: in-toto statement _type "
            f"{stmt_type!r} not in policy.in_toto_statement_types_allowed"
        )

    subjects = statement.get("subject")
    if not subjects or not isinstance(subjects, list):
        raise ValueError("SUBJECT_MISSING: in-toto statement has no subject array")
    subject0 = subjects[0]
    if (
        not isinstance(subject0, dict)
        or not isinstance(subject0.get("digest"), dict)
        or "sha256" not in subject0["digest"]
    ):
        raise ValueError("SUBJECT_MISSING: subject[0].digest.sha256 missing")

    bundle_digest = subject0["digest"]["sha256"]
    if bundle_digest.lower() != expected_digest_sha256_hex.lower():
        raise ValueError(
            "SUBJECT_DIGEST_MISMATCH: bundle subject digest "
            f"{bundle_digest!r} does not equal expected "
            f"{expected_digest_sha256_hex!r}"
        )

    predicate_type = statement.get("predicateType")
    if (
        policy.predicate_types_allowed is not None
        and predicate_type not in policy.predicate_types_allowed
    ):
        raise ValueError(
            f"PREDICATE_TYPE_NOT_ALLOWED: predicate type {predicate_type!r} "
            "not in policy.predicate_types_allowed"
        )

    predicate_fields = statement.get("predicate") or {}
    if predicate_type == "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1":
        measurement = _extract_multiplatform_measurement(predicate_fields)
    else:
        raise ValueError(
            "PREDICATE_MEASUREMENT_INVALID: predicate type "
            f"{predicate_type!r} allowed by policy but extraction not implemented "
            "in tinfoil-python"
        )

    cert_oidc, cert_repo, cert_signer_uri = _extract_cert_info(bundle_bytes)
    rekor_log_id_hex, rekor_integrated_time, tlog_count = (
        _extract_tlog_observables(bundle_bytes)
    )

    return SigstoreVerification(
        measurement=measurement,
        predicate_type=predicate_type,
        in_toto_statement_type=stmt_type or "",
        subject_name=subject0.get("name", "") if isinstance(subject0, dict) else "",
        subject_digest_sha256_hex=bundle_digest.lower(),
        cert_oidc_issuer=cert_oidc,
        cert_workflow_repository=cert_repo,
        cert_workflow_signer_uri=cert_signer_uri,
        rekor_log_id_hex=rekor_log_id_hex,
        rekor_integrated_time_unix=rekor_integrated_time,
        tlog_entry_count=tlog_count,
        sct_count=_extract_sct_count(bundle_bytes),
    )


def _extract_multiplatform_measurement(predicate: dict) -> Measurement:
    snp = predicate.get("snp_measurement")
    if not isinstance(snp, str):
        raise ValueError(
            "PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiPlatformV1 "
            "missing snp_measurement"
        )
    tdx = predicate.get("tdx_measurement") or {}
    rtmr1 = tdx.get("rtmr1")
    rtmr2 = tdx.get("rtmr2")
    if not isinstance(rtmr1, str):
        raise ValueError(
            "PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiPlatformV1 "
            "missing tdx_measurement.rtmr1"
        )
    if not isinstance(rtmr2, str):
        raise ValueError(
            "PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiPlatformV1 "
            "missing tdx_measurement.rtmr2"
        )
    return Measurement(
        type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
        registers=[snp, rtmr1, rtmr2],
    )


def _extract_cert_info(bundle_bytes: bytes) -> tuple[str, str, str]:
    from cryptography import x509 as _x509

    try:
        bundle = json.loads(bundle_bytes)
        cert_b64 = (
            bundle.get("verificationMaterial", {})
            .get("certificate", {})
            .get("rawBytes")
        )
        if not isinstance(cert_b64, str):
            return ("", "", "")
        cert = _x509.load_der_x509_certificate(base64.b64decode(cert_b64))
        oidc = _read_str_ext(cert, "1.3.6.1.4.1.57264.1.8") or _read_str_ext(
            cert, "1.3.6.1.4.1.57264.1.1"
        )
        repo = _read_str_ext(cert, "1.3.6.1.4.1.57264.1.5")
        signer = _read_str_ext(cert, "1.3.6.1.4.1.57264.1.9")
        return (oidc or "", repo or "", signer or "")
    except Exception:
        return ("", "", "")


def _read_str_ext(cert, oid_dotted: str) -> str | None:
    from cryptography.x509 import ObjectIdentifier

    try:
        ext = cert.extensions.get_extension_for_oid(ObjectIdentifier(oid_dotted))
    except Exception:
        return None
    raw = ext.value.value
    if raw.startswith(b"\x0c"):
        if len(raw) < 2:
            return raw.decode(errors="ignore")
        n = raw[1]
        if n < 0x80:
            return raw[2 : 2 + n].decode(errors="ignore")
        nb = n & 0x7F
        if len(raw) < 2 + nb:
            return raw.decode(errors="ignore")
        total = int.from_bytes(raw[2 : 2 + nb], "big")
        return raw[2 + nb : 2 + nb + total].decode(errors="ignore")
    return raw.decode(errors="ignore")


def _extract_tlog_observables(
    bundle_bytes: bytes,
) -> tuple[str | None, int | None, int]:
    try:
        bundle = json.loads(bundle_bytes)
        entries = bundle.get("verificationMaterial", {}).get("tlogEntries") or []
        if len(entries) == 0:
            return (None, None, 0)
        first = entries[0]
        log_id_b64 = (first.get("logId") or {}).get("keyId")
        log_id_hex = (
            base64.b64decode(log_id_b64).hex()
            if isinstance(log_id_b64, str)
            else None
        )
        integrated_time = first.get("integratedTime")
        if isinstance(integrated_time, str):
            try:
                integrated_time = int(integrated_time)
            except ValueError:
                integrated_time = None
        elif not isinstance(integrated_time, int):
            integrated_time = None
        return (log_id_hex, integrated_time, len(entries))
    except Exception:
        return (None, None, 0)


def _extract_sct_count(bundle_bytes: bytes) -> int | None:
    try:
        bundle = json.loads(bundle_bytes)
        cert_b64 = (
            bundle.get("verificationMaterial", {})
            .get("certificate", {})
            .get("rawBytes")
        )
        if not isinstance(cert_b64, str):
            return None
        from cryptography import x509 as _x509
        from cryptography.x509 import ObjectIdentifier

        cert = _x509.load_der_x509_certificate(base64.b64decode(cert_b64))
        try:
            ext = cert.extensions.get_extension_for_oid(
                ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
            )
        except Exception:
            return 0
        if hasattr(ext.value, "__iter__"):
            return len(list(ext.value))
        return None
    except Exception:
        return None
