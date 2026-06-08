"""tinfoil-conformance CLI entry point for tinfoil-python.

Subcommands:
    tinfoil-conformance capabilities                # stdin: none, stdout: JSON
    tinfoil-conformance verify-sigstore             # stdin: JSON, stdout: JSON

Exit codes:
    0   accepted
    10  rejected (rejection.code populated)
    20  stage/capability not supported
    30  malformed input
    1   internal error

See tinfoil-conformance/schemas/ for the I/O schemas.
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Any, Tuple

from ..attestation import verify_tdx_hardware
from ..attestation.abi_tdx import parse_quote as parse_tdx_quote
from ..attestation.attestation_tdx import (
    TdxAttestationError,
    TdxVerificationConfig,
    verify_tdx_attestation,
)
from ..attestation.verify_tdx import (
    TdxVerificationError,
    extract_pck_cert_chain,
    verify_tdx_quote as verify_tdx_quote_crypto,
)
from ..attestation import collateral_tdx as _coll
from ..attestation.collateral_tdx import (
    CollateralError,
    PckCrl,
    RootCrl,
    TdxCollateral,
    check_collateral_freshness,
    parse_qe_identity_response,
    parse_tcb_info_response,
    validate_certificate_revocation,
    validate_qe_identity,
    validate_tcb_status,
    validate_tdx_module_identity,
    verify_qe_identity_signature,
    verify_tcb_info_signature,
)
from ..attestation.cert_utils import parse_pem_chain
from ..attestation.pck_extensions import extract_pck_extensions
from ..attestation import intel_root_ca as _intel_root_mod
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone
import contextlib
from ..attestation.types import (
    FormatMismatchError,
    HardwareMeasurement,
    HardwareMeasurementError,
    Measurement,
    MeasurementMismatchError,
    PredicateType,
    Rtmr3NotZeroError,
    MULTIPLATFORM_REGISTER_COUNT,
    SEV_REGISTER_COUNT,
    TDX_REGISTER_COUNT,
)
from .sigstore import (
    SigstorePolicy,
    SigstoreVerification,
    default_sigstore_policy,
    verify_sigstore_bundle_with_policy,
)


EXIT_ACCEPT = 0
EXIT_REJECT = 10
EXIT_UNSUPPORTED = 20
EXIT_BAD_INPUT = 30
EXIT_INTERNAL = 1

SDK_NAME = "tinfoil-python"


def _sdk_version() -> str:
    try:
        from importlib.metadata import version
        return version("tinfoil")
    except Exception:
        return "0.0.0"


def _capabilities() -> dict[str, Any]:
    """Self-description for the conformance harness. Keep
    `stages_supported` honest — fixtures targeting stages not listed
    here are auto-skipped by the harness."""
    return {
        "schema_version": "1",
        "sdk": SDK_NAME,
        "sdk_version": _sdk_version(),
        "stages_supported": [
            "verify-sigstore",
            "verify-measurement",
            "verify-hardware-measurements",
            "verify-attestation-tdx",
            "verify-attestation-sev",
            "verify-full",
        ],
        "sigstore": {
            "trust_root_loading": "configurable",
            # `sigstore` 4.2 verifies cert chain validity against the
            # cert.NotBefore from the bundle, not the system clock.
            # Hermetic on system clock; the supplied verification_time_unix
            # parameter isn't currently consulted.
            "verification_time_override": "bundle-supplied-only",
            "policy_fields_configurable": {
                "oidc_issuer": True,
                "workflow_ref_prefix": True,
                "workflow_repository": True,
                "predicate_types_allowed": True,
                "in_toto_statement_types_allowed": True,
                "payload_type": True,
                # The sigstore PyPI lib hardcodes minimum tlog/sct/observer
                # thresholds (== 1). Not configurable through its public
                # API today.
                "tlog_entries_min": False,
                "tlog_entries_max": False,
                "sct_min": False,
                "observer_timestamps_min": False,
            },
            "predicate_types_understood": [
                "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
            ],
            # sigstore-python 4.x normalizes bundles via Bundle.from_json
            # which only accepts the v0.3 mediaType; the older
            # x509CertificateChain layout would need conversion before load.
            "legacy_bundle_format_supported": False,
            # sigstore-python hardcodes len(tlog_entries) == 1.
            "accepts_multi_tlog_entries": False,
            # sigstore-python's policy.OIDCIssuer reads V1 (.1.1) before V2.
            "oidc_issuer_v2_preferred": False,
            # sigstore-python collapses missing-SCT and duplicate-SCT into
            # the same "Expected one certificate timestamp" error.
            "scts_count_distinguish_missing_vs_duplicate": False,
            # sigstore-python rejects duplicate SCTs via the same
            # count-based check (it rejects either case as
            # "Expected one certificate timestamp").
            "rejects_duplicate_sct_log": True,
            # sigstore-python's verify_dsse checks subject[0] only.
            "checks_only_subject_0": True,
            # sigstore-python's in-toto parser tolerates extra top-level
            # fields (pydantic's extra=allow on the statement model).
            "in_toto_statement_tolerates_extra_fields": True,
        },
        "measurement": {
            "compare_multiplatform_to_tdx_supported": True,
        },
        "attestation_tdx": {
            # tinfoil-python ships a native TDX verifier with clean
            # injection-friendly APIs:
            #   * verify_tdx_quote(quote, raw_quote)  — does Intel §4.1.2
            #     steps 1-4 (PCK chain, quote sig, QE report sig, AK ↔ QE
            #     report data binding) with no network calls
            #   * verify_tcb_info_signature / verify_qe_identity_signature
            #     accept the raw collateral bytes + issuer chain as args
            # Phase 1.5 wires the structural verification path
            # (tcb_evaluation_required=false fixtures). Full TCB evaluation
            # lands when Phase 3 fixtures need it.
            "supported": True,
            "injected_collateral_supported": True,
            # cert_utils.verify_intel_chain et al. call datetime.now()
            # unconditionally — the lib has no public time-injection API.
            # cmd_verify_attestation_tdx works around this by monkey-
            # patching the module-level datetime for the duration of
            # verification, so functionally the conformance binary
            # honors policy.expiration_check_date_unix end-to-end.
            "verification_time_override": "supported",
            # Phase 2B/3 wired: cmd_verify_attestation_tdx now orchestrates
            # the lib's pure validation functions (verify_tcb_info_signature
            # + verify_qe_identity_signature + check_collateral_freshness +
            # validate_certificate_revocation + validate_tcb_status +
            # validate_tdx_module_identity + validate_qe_identity) using
            # the fixture-injected collateral bytes — no Intel PCS fetch.
            "tcb_evaluation_supported": True,
            # execution_mode=public_api calls the public verify_tdx_attestation
            # path and monkey-patches only the collateral fetch boundary inside
            # this conformance process, so production attestation modules do
            # not need test-only hook parameters.
            "public_api_hooks_supported": True,
            # Phase 4: cmd_verify_attestation_tdx applies SPEC §4.8 /
            # Intel §2.3.2 checks against every policy.expected_*_hex pin
            # the fixture sets — the unmutated quote's body fields are
            # parsed and compared without needing any sigstore-python or
            # lib API surface (pure post-parse Python).
            "extended_td_checks_supported": True,
            "enforces_tcb_evaluation_data_number_minimum": True,
            "policy_fields_supported": {
                "expected_fmspc_hex": False,
                "accepted_qv_results": True,
            },
            # validate_tcb_status rejects only the terminal statuses
            # (OutOfDate, OutOfDateConfigurationNeeded, Revoked); the
            # three non-terminal statuses (SWHardeningNeeded, Config-
            # urationNeeded, ConfigurationAndSWHardeningNeeded) pass
            # through per SPEC §4.7.7 default.
            "accepts_non_terminal_tcb_statuses": True,
        },
        "attestation_sev": {
            # cmd_verify_attestation_sev builds CertificateChain directly
            # with the fixture-supplied VCEK + lib's embedded ARK/ASK
            # (bypassing CertificateChain.from_report's KDS fetch).
            "supported": True,
            "injected_collateral_supported": True,
            # _enforce_sev_policy applies SPEC §3.7/§3.8/§8.2-3 pins from
            # policy.expected_*_hex and enforce_spec_defaults checks.
            "extended_checks_supported": True,
            # Python's verify_chain uses pyOpenSSL X509Store.verify_certificate
            # which delegates cert validity to OpenSSL's internal system-clock
            # check. No Python-level monkey-patch can override it; fixture
            # 240-vcek-expired skips on tinfoil-python.
            "verification_time_override": "system-clock-only",
            # cmd_verify_attestation_sev parses input.amd_root_ca_pem /
            # input.ask_pem when set and passes them into CertificateChain
            # instead of the lib's embedded ARK_CERT/ASK_CERT constants.
            # No lib changes required — the conformance binary owns the
            # construction of CertificateChain.
            "amd_root_ca_injection_supported": True,
        },
        "platforms_supported": ["sev-snp", "tdx"],
        "transport_modes_supported": ["tls-pinning"],
        "flow_modes_supported": ["standard", "pinned"],
        "known_quirks": {
            "sigstore.workflow_ref_check_via_startswith":
                "We replaced sigstore.verify.policy's regex-based GitHubWorkflowRefPattern with a strict-prefix startswith() check (SPEC §5.3 reads as prefix, not regex).",
            "sigstore.lib_pyca_sigstore":
                "Verification delegated to the sigstore PyPI package; only its public API surface is exercised.",
        },
    }


def _emit_accept(v: SigstoreVerification) -> int:
    body = {
        "stage": "verify-sigstore",
        "accepted": True,
        "outputs": {
            "predicate_type": v.predicate_type,
            "in_toto_statement_type": v.in_toto_statement_type,
            "subject_name": v.subject_name,
            "subject_digest_sha256_hex": v.subject_digest_sha256_hex,
            "measurement": {
                # Measurement.type is a PredicateType enum whose .value is
                # the canonical URI. Match the Rust/JS output shape.
                "type": v.measurement.type.value
                if hasattr(v.measurement.type, "value")
                else str(v.measurement.type),
                "registers": v.measurement.registers,
            },
            "cert_oidc_issuer": v.cert_oidc_issuer,
            "cert_workflow_repository": v.cert_workflow_repository,
            "cert_workflow_signer_uri": v.cert_workflow_signer_uri,
            "rekor_log_id_hex": v.rekor_log_id_hex,
            "rekor_integrated_time_unix": v.rekor_integrated_time_unix,
            "tlog_entry_count": v.tlog_entry_count,
            "sct_count": v.sct_count,
        },
    }
    json.dump(body, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return EXIT_ACCEPT


def _emit_rejection(code: str, spec_ref: str, message: str, exit_code: int) -> int:
    body = {
        "stage": "verify-sigstore",
        "accepted": False,
        "rejection": {"code": code, "spec_ref": spec_ref, "message": message},
    }
    json.dump(body, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return exit_code


# Stable rejection-code prefixes the verifier helpers emit. Order matters —
# most specific first (e.g. CERT_EXPIRED before generic FULCIO_CHAIN_INVALID).
_PREFIX_MAP: list[tuple[str, str, str]] = [
    ("TLOG_COUNT_OUT_OF_RANGE:", "TLOG_COUNT_OUT_OF_RANGE", "5.2"),
    ("OIDC_ISSUER_MISMATCH:", "OIDC_ISSUER_MISMATCH", "5.3"),
    ("WORKFLOW_REPOSITORY_MISMATCH:", "WORKFLOW_REPOSITORY_MISMATCH", "5.3"),
    ("WORKFLOW_REF_PREFIX_MISMATCH:", "WORKFLOW_REF_PREFIX_MISMATCH", "5.3"),
    ("PAYLOAD_TYPE_MISMATCH:", "PAYLOAD_TYPE_MISMATCH", "5.4"),
    ("IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED:", "IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED", "5.4"),
    ("PREDICATE_TYPE_NOT_ALLOWED:", "PREDICATE_TYPE_NOT_ALLOWED", "5.5"),
    ("SUBJECT_DIGEST_MISMATCH:", "SUBJECT_DIGEST_MISMATCH", "5.4"),
    ("SUBJECT_MISSING:", "SUBJECT_MISSING", "5.4"),
    ("PREDICATE_MEASUREMENT_INVALID:", "PREDICATE_MEASUREMENT_INVALID", "5.5"),
    ("BUNDLE_MALFORMED:", "BUNDLE_MALFORMED", "5.2"),
]


def _classify(message: str) -> Tuple[str, str]:
    """Map a verification-failure message string to a (rejection_code,
    spec_ref) pair. The verifier's policy-driven helpers lead with stable
    code prefixes; sigstore-python's own VerificationError messages come
    through unprefixed and need substring matching.

    Order matters — most specific patterns first.
    """
    for prefix, code, spec_ref in _PREFIX_MAP:
        if message.startswith(prefix) or prefix in message:
            return (code, spec_ref)
    low = message.lower()

    # sigstore-python's `policy.OIDCIssuer.verify` raises with a stable
    # English message form. Catch it before generic patterns.
    if "oidcissuer does not match" in low or "oidc issuer does not match" in low:
        return ("OIDC_ISSUER_MISMATCH", "5.3")
    if "githubworkflowrepository does not match" in low:
        return ("WORKFLOW_REPOSITORY_MISMATCH", "5.3")
    if "githubworkflowref" in low and (
        "does not match" in low or "does not contain" in low
    ):
        return ("WORKFLOW_REF_PREFIX_MISMATCH", "5.3")

    # CERT_EXPIRED catches both "outside cert validity" (Rust phrasing) and
    # "certificate has expired" (sigstore-python's certvalidator phrasing).
    if (
        ("outside" in low and "validity" in low)
        or "certificate has expired" in low
        or "certificate is expired" in low
    ):
        return ("CERT_EXPIRED", "5.2")

    # SCT count: sigstore-python emits "Expected one certificate timestamp"
    # for both zero-SCT and N-SCT cases (it doesn't distinguish duplicate
    # from missing). Bucket as SCT_INSUFFICIENT — the fixture for duplicate
    # SCTs (066) accepts a list including this code when running on Python.
    if "certificate timestamp" in low and (
        "expected" in low or "one" in low
    ):
        return ("SCT_INSUFFICIENT", "5.2")
    if "duplicate sct" in low or ("duplicate" in low and "sct" in low):
        return ("SCT_DUPLICATE_LOG", "5.2")
    if "sct" in low and (
        "no valid" in low or "missing" in low or "no sct" in low or "no scts" in low
    ):
        return ("SCT_INSUFFICIENT", "5.2")

    # Trust root with no Fulcio CAs — sigstore-python's TrustedRoot raises
    # "Fulcio certificates not found in trusted root". This is a chain
    # failure (no CA = can't verify the chain), bucket as FULCIO_CHAIN_INVALID
    # to match Rust/JS canonical mapping.
    if "fulcio certificates not found" in low or "no fulcio" in low:
        return ("FULCIO_CHAIN_INVALID", "5.2")

    # sigstore-python raises a bare IndexError ("list index out of range")
    # when the trust root has no tlogs — internal bug, but the symptom is
    # "no Rekor key to look up against", semantically REKOR_KEY_NOT_TRUSTED.
    if "list index out of range" in low:
        return ("REKOR_KEY_NOT_TRUSTED", "5.1")

    # Inclusion proof / checkpoint / rekor — order before the generic
    # "log entry" tlog-count check so "inclusion proof contains invalid
    # root hash" (sigstore-python's phrasing) gets the right code.
    if "inclusion proof" in low and ("invalid" in low or "root hash" in low):
        return ("REKOR_INCLUSION_INVALID", "5.2")
    if "rekor" in low or "checkpoint" in low:
        return ("REKOR_INCLUSION_INVALID", "5.2")

    # sigstore-python hardcodes `len(tlog_entries) == 1`, emits
    # "expected exactly one log entry". Map to TLOG_COUNT_OUT_OF_RANGE.
    if "expected exactly one log entry" in low or "expected one log entry" in low:
        return ("TLOG_COUNT_OUT_OF_RANGE", "5.2")
    if "tlog" in low or "log entry" in low or "log entries" in low:
        return ("TLOG_COUNT_OUT_OF_RANGE", "5.2")

    if "trust root" in low or "trusted root" in low:
        return ("TRUST_ROOT_INVALID", "5.1")
    if "fulcio" in low or "certificate chain" in low or "no valid ca" in low:
        return ("FULCIO_CHAIN_INVALID", "5.2")
    # sigstore-python's pydantic validation message for a bundle missing
    # both DSSE envelope and message signature.
    if "exactly one of messagesignature or dsseenvelope" in low or (
        "dsseenvelope" in low and "must be set" in low
    ):
        return ("BUNDLE_MALFORMED", "5.2")
    if "signature" in low and (
        "invalid" in low or "verification" in low or "failed" in low
    ):
        return ("DSSE_SIGNATURE_INVALID", "5.2")
    return ("BUNDLE_MALFORMED", "5.2")


def _run_verify_sigstore_inner(inp: dict[str, Any]) -> "SigstoreVerification | tuple[str, str, str]":
    """Inner sigstore verification logic — shared by cmd_verify_sigstore and
    cmd_verify_full. Returns the SigstoreVerification on success, or a
    (code, spec_ref, message) rejection triple on failure.

    The verify-full envelope's nested sigstore block omits schema_version
    (the envelope carries it), so this helper accepts missing schema_version
    as "1"."""
    sv = inp.get("schema_version", "1")
    if sv != "1":
        return ("BUNDLE_MALFORMED", "5.2", 'input.schema_version != "1"')
    try:
        bundle_bytes = base64.b64decode(inp["bundle_b64"])
    except Exception as e:
        return ("BUNDLE_MALFORMED", "5.2", f"bundle_b64 not valid base64: {e}")
    try:
        trust_root_bytes = base64.b64decode(inp["trust_root_b64"])
    except Exception as e:
        return ("TRUST_ROOT_INVALID", "5.1", f"trust_root_b64 not valid base64: {e}")
    try:
        trust_root_json = trust_root_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        return ("TRUST_ROOT_INVALID", "5.1", f"trust_root is not valid UTF-8: {e}")

    policy_in = inp.get("policy") or {}
    defaults = default_sigstore_policy(inp.get("repo", ""))
    policy = SigstorePolicy(
        oidc_issuer=policy_in.get("oidc_issuer", defaults.oidc_issuer),
        workflow_ref_prefix=policy_in.get(
            "workflow_ref_prefix", defaults.workflow_ref_prefix
        ),
        workflow_repository=inp["repo"],
        predicate_types_allowed=(
            policy_in["predicate_types_allowed"]
            if "predicate_types_allowed" in policy_in
            else defaults.predicate_types_allowed
        ),
        in_toto_statement_types_allowed=(
            policy_in["in_toto_statement_types_allowed"]
            if "in_toto_statement_types_allowed" in policy_in
            else defaults.in_toto_statement_types_allowed
        ),
        payload_type=policy_in.get("payload_type", defaults.payload_type),
    )

    try:
        return verify_sigstore_bundle_with_policy(
            bundle_bytes=bundle_bytes,
            expected_digest_sha256_hex=inp["expected_digest_sha256_hex"],
            policy=policy,
            trust_root_json=trust_root_json,
        )
    except Exception as e:
        parts = []
        cur: BaseException | None = e
        while cur is not None and len(parts) < 8:
            parts.append(str(cur))
            cur = cur.__cause__
        message = " | ".join(parts)
        code, spec_ref = _classify(message)
        return (code, spec_ref, message)


def cmd_verify_sigstore() -> int:
    """Read stdin JSON, run verify_sigstore_bundle_with_policy, emit output."""
    try:
        raw = sys.stdin.read()
    except Exception as e:
        sys.stderr.write(f"error reading stdin: {e}\n")
        return EXIT_INTERNAL

    try:
        inp = json.loads(raw)
    except json.JSONDecodeError as e:
        return _emit_rejection(
            "BUNDLE_MALFORMED",
            "5.2",
            f"input is not valid JSON: {e}",
            EXIT_BAD_INPUT,
        )

    # cmd_verify_sigstore requires schema_version explicitly (the verify-full
    # envelope's sigstore sub-block defaults it instead — see inner helper).
    if inp.get("schema_version") != "1":
        return _emit_rejection(
            "BUNDLE_MALFORMED",
            "5.2",
            'input.schema_version != "1"',
            EXIT_BAD_INPUT,
        )

    result = _run_verify_sigstore_inner(inp)
    if isinstance(result, tuple):
        code, spec_ref, message = result
        return _emit_rejection(code, spec_ref, message, EXIT_REJECT)
    return _emit_accept(result)


def _print_help() -> None:
    sys.stderr.write(
        "tinfoil-conformance: Tinfoil cross-SDK conformance binary "
        f"({SDK_NAME} {_sdk_version()})\n\n"
        "Subcommands:\n"
        "  capabilities      Print SDK capabilities JSON\n"
        "  verify-sigstore   Verify a Sigstore bundle (SPEC §5)\n\n"
        "I/O contract: stdin JSON, stdout JSON. See tinfoil-conformance/schemas/.\n"
    )


# -----------------------------------------------------------------------------
# verify-measurement (SPEC §7)
# -----------------------------------------------------------------------------

_EXPECTED_REGISTER_COUNT = {
    PredicateType.SEV_GUEST_V2: SEV_REGISTER_COUNT,
    PredicateType.TDX_GUEST_V2: TDX_REGISTER_COUNT,
    PredicateType.SNP_TDX_MULTIPLATFORM_v1: MULTIPLATFORM_REGISTER_COUNT,
}


def _parse_predicate_type(uri: str) -> PredicateType | None:
    for pt in PredicateType:
        if pt.value == uri:
            return pt
    return None


def _normalize_measurement(m: dict[str, Any]) -> Tuple[Measurement | None, str, str]:
    """Validate type + register count and lowercase-normalize registers per
    SPEC §7.3. Returns (measurement, code, spec_ref); on success code/spec_ref
    are empty strings."""
    t = _parse_predicate_type(m.get("type", ""))
    if t is None:
        return None, "MEASUREMENT_TYPE_UNKNOWN", "2.3"
    expected = _EXPECTED_REGISTER_COUNT.get(t)
    regs = m.get("registers", [])
    if expected is None or not isinstance(regs, list) or len(regs) != expected:
        return None, "MEASUREMENT_REGISTER_COUNT_INVALID", "7.1"
    normalized = [r.lower() for r in regs]
    return Measurement(type=t, registers=normalized), "", ""


def _emit_measurement_rejection(code: str, spec_ref: str, message: str) -> int:
    body = {
        "stage": "verify-measurement",
        "accepted": False,
        "rejection": {
            "code": code,
            "spec_ref": spec_ref,
            "message": message,
        },
    }
    json.dump(body, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_REJECT


def cmd_verify_measurement() -> int:
    raw = sys.stdin.read()
    try:
        inp = json.loads(raw)
    except Exception as e:
        sys.stderr.write(f"input schema violation: {e}\n")
        return EXIT_BAD_INPUT
    if inp.get("schema_version") != "1":
        sys.stderr.write('schema_version must be "1"\n')
        return EXIT_BAD_INPUT

    source_in = inp.get("source")
    if not isinstance(source_in, dict):
        return _emit_measurement_rejection(
            "MEASUREMENT_TYPE_UNKNOWN", "7", "missing source measurement"
        )
    source, code, spec_ref = _normalize_measurement(source_in)
    if source is None:
        return _emit_measurement_rejection(code, spec_ref, "source measurement invalid")

    target = None
    target_in = inp.get("target")
    if target_in is not None:
        target, code, spec_ref = _normalize_measurement(target_in)
        if target is None:
            return _emit_measurement_rejection(
                code, spec_ref, "target measurement invalid"
            )

    source_fp = source.fingerprint()
    target_fp = target.fingerprint() if target is not None else None

    if target is not None:
        try:
            source.assert_equal(target)
        except Rtmr3NotZeroError as e:
            return _emit_measurement_rejection(
                "MEASUREMENT_RTMR3_NONZERO", "7.3.2", str(e)
            )
        except MeasurementMismatchError as e:
            return _emit_measurement_rejection(
                "MEASUREMENT_MISMATCH", "7.3", str(e) or "registers mismatch"
            )
        except FormatMismatchError as e:
            return _emit_measurement_rejection(
                "MEASUREMENT_TYPE_COMBINATION_UNSUPPORTED", "7.3.5",
                str(e) or "incompatible measurement types",
            )

    body = {
        "stage": "verify-measurement",
        "accepted": True,
        "outputs": {
            "source_fingerprint_hex": source_fp,
            "target_fingerprint_hex": target_fp,
        },
    }
    json.dump(body, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_ACCEPT


# -----------------------------------------------------------------------------
# verify-hardware-measurements (SPEC §6)
# -----------------------------------------------------------------------------

TDX_URI = "https://tinfoil.sh/predicate/tdx-guest/v2"


def _emit_hardware_rejection(code: str, spec_ref: str, message: str) -> int:
    body = {
        "stage": "verify-hardware-measurements",
        "accepted": False,
        "rejection": {"code": code, "spec_ref": spec_ref, "message": message},
    }
    json.dump(body, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_REJECT


def cmd_verify_hardware_measurements() -> int:
    raw = sys.stdin.read()
    try:
        inp = json.loads(raw)
    except Exception as e:
        sys.stderr.write(f"input schema violation: {e}\n")
        return EXIT_BAD_INPUT
    if inp.get("schema_version") != "1":
        sys.stderr.write('schema_version must be "1"\n')
        return EXIT_BAD_INPUT

    enc = inp.get("enclave_measurement") or {}
    if enc.get("type") != TDX_URI:
        return _emit_hardware_rejection(
            "ENCLAVE_MEASUREMENT_TYPE_INVALID", "6.3",
            "enclave measurement type is not TdxGuestV2",
        )
    regs = enc.get("registers", [])
    if not isinstance(regs, list) or len(regs) != TDX_REGISTER_COUNT:
        return _emit_hardware_rejection(
            "ENCLAVE_REGISTER_COUNT_INVALID", "6.3",
            f"TDX enclave measurement must have {TDX_REGISTER_COUNT} registers, got {len(regs)}",
        )

    # SPEC §7.3 lowercase normalization.
    enclave_lower = [r.lower() for r in regs]
    enclave = Measurement(type=PredicateType.TDX_GUEST_V2, registers=enclave_lower)
    hw_list = [
        HardwareMeasurement(id=h["id"], mrtd=h["mrtd"].lower(), rtmr0=h["rtmr0"].lower())
        for h in inp.get("hardware_measurements", [])
    ]

    try:
        match = verify_tdx_hardware(hw_list, enclave)
    except HardwareMeasurementError as e:
        return _emit_hardware_rejection("HARDWARE_NO_MATCH", "6.3", str(e))

    body = {
        "stage": "verify-hardware-measurements",
        "accepted": True,
        "outputs": {
            "matched_id": match.id,
            "matched_mrtd": match.mrtd,
            "matched_rtmr0": match.rtmr0,
        },
    }
    json.dump(body, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_ACCEPT


# -----------------------------------------------------------------------------
# verify-attestation-tdx (SPEC §4 / Intel TDX DCAP §A.3)
# -----------------------------------------------------------------------------

TDX_GUEST_V2_URI = "https://tinfoil.sh/predicate/tdx-guest/v2"


def _emit_tdx_rejection(code: str, spec_ref: str, message: str) -> int:
    body = {
        "stage": "verify-attestation-tdx",
        "accepted": False,
        "rejection": {"code": code, "spec_ref": spec_ref, "message": message},
    }
    json.dump(body, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_REJECT


def _classify_tdx_error(err: Exception) -> Tuple[str, str]:
    msg = str(err).lower()
    # Order matters: chain errors mention "signature" but should map to
    # PCK_CHAIN_INVALID, not QUOTE_SIGNATURE_INVALID.

    # Collateral-layer failures as surfaced by the public verifier.
    if "pck crl" in msg and "expired" in msg:
        return "PCK_CRL_EXPIRED", "4.7.4"
    if ("root ca crl" in msg or "root crl" in msg) and "expired" in msg:
        return "ROOT_CRL_EXPIRED", "4.7.4"
    if "tcb info" in msg and "expired" in msg:
        return "TCB_INFO_EXPIRED", "4.7"
    if ("qe identity" in msg or "enclave identity" in msg) and "expired" in msg:
        return "QE_IDENTITY_EXPIRED", "4.7"
    if "tcbevaluationdatanumber" in msg or "tcb evaluation data number" in msg:
        return "TCB_EVAL_DATA_NUMBER_TOO_LOW", "4.7.11"
    if "intermediate ca" in msg and "revoked" in msg:
        return "INTERMEDIATE_REVOKED", "4.7.4"
    if "pck certificate" in msg and "revoked" in msg:
        return "PCK_REVOKED", "4.7.4"
    if "tcb info issuer chain" in msg and (
        "chain" in msg or "certificate" in msg or "root" in msg
    ):
        return "TCB_INFO_CHAIN_INVALID", "4.7.3"
    if "qe identity id" in msg and ("td_qe" in msg or "must" in msg):
        return "QE_IDENTITY_ID_INVALID", "4.7.9"
    if "qe identity version" in msg and "must" in msg:
        return "QE_IDENTITY_VERSION_INVALID", "4.7.9"
    if ("qe identity" in msg or "enclave identity" in msg) and (
        "mrsigner" in msg or "mr_signer" in msg
    ):
        return "QE_IDENTITY_MRSIGNER_MISMATCH", "4.7.9"
    if ("qe identity" in msg or "enclave identity" in msg) and (
        "miscselect" in msg or "attributes" in msg or "isv prodid" in msg
    ):
        return "QE_IDENTITY_FIELD_MISMATCH", "4.7.9"
    if "tcb status" in msg or "no matching tcb" in msg or "tcb is revoked" in msg:
        return "TCB_REVOKED", "4.7.7"

    # Quote header / structural parse failures
    if "invalid tee type" in msg or "tee type" in msg:
        return "WRONG_TEE_TYPE", "A.3.1"
    if "attestation key type" in msg or "unsupported.*key type" in msg:
        return "ATTESTATION_KEY_TYPE_UNSUPPORTED", "A.3.1"
    if "qe vendor" in msg or "unknown qe" in msg:
        return "QE_VENDOR_UNKNOWN", "A.3.1"
    if "quote too short" in msg or "minimum" in msg and "size" in msg:
        return "QUOTE_TRUNCATED", "A.3"
    if "certification data" in msg or "size mismatch" in msg or "data size" in msg:
        return "QUOTE_FORMAT_UNSUPPORTED", "A.3.9"
    if "unsupported quote version" in msg or "quote version" in msg or "version" in msg and "supported" in msg:
        return "QUOTE_FORMAT_UNSUPPORTED", "A.3.1"

    # QE-report signature failures mention the PCK certificate because the
    # PCK leaf is the verification key; classify them before chain errors.
    if ("qe report" in msg or "qe_report" in msg) and "signature" in msg:
        return "QE_REPORT_SIGNATURE_INVALID", "4.4"

    # PCK chain (BEFORE the generic "signature" check)
    if "pck" in msg and "chain" in msg:
        return "PCK_CHAIN_INVALID", "4.2"
    if "certificate chain" in msg or "cert chain" in msg:
        return "PCK_CHAIN_INVALID", "4.2"
    if "expired" in msg or "not yet valid" in msg:
        return "PCK_EXPIRED", "4.2"
    if ("pck" in msg or "intermediate" in msg or "root" in msg) and "certificate" in msg:
        return "PCK_CHAIN_INVALID", "4.2"

    # AK / quote signature (generic — must come after chain)
    if (
        "ak" in msg and ("bind" in msg or "report data" in msg)
        or "attestation key" in msg and ("bind" in msg or "report data" in msg)
    ):
        return "AK_BINDING_INVALID", "4.5"
    if "qe report" in msg or "qe_report" in msg:
        return "QE_REPORT_SIGNATURE_INVALID", "4.4"
    if "signature" in msg:
        return "QUOTE_SIGNATURE_INVALID", "4.3"
    if "root" in msg and ("trust" in msg or "ca" in msg):
        return "ROOT_CA_UNTRUSTED", "4.2"
    if "format" in msg:
        return "QUOTE_FORMAT_UNSUPPORTED", "A.3"
    return "QV_RESULT_TERMINAL_UNSPECIFIED", "4.1.2"


def _decode_td_attributes(td_attrs: bytes) -> dict[str, bool]:
    n = int.from_bytes(td_attrs, byteorder="little")
    return {
        "tud_debug":                 bool(n & (1 << 0)),
        "tud_reserved_nonzero":      bool(n & 0xFE),
        "sec_reserved_lower_nonzero":bool(n & 0x0FFFFF00),
        "sec_sept_ve_disable":       bool(n & (1 << 28)),
        "sec_reserved_bit29":        bool(n & (1 << 29)),
        "sec_pks":                   bool(n & (1 << 30)),
        "sec_kl":                    bool(n & (1 << 31)),
        "other_reserved_nonzero":    bool(n & 0x7FFFFFFF00000000),
        "other_perfmon":             bool(n & (1 << 63)),
    }


def _tdx_acceptance_output(quote) -> dict[str, Any]:
    body = quote.td_quote_body
    header = quote.header
    tee_type_str = "TDX" if header.tee_type == 0x81 else f"0x{header.tee_type:08x}"

    return {
        "stage": "verify-attestation-tdx",
        "accepted": True,
        "outputs": {
            "quote_version": header.version,
            "tee_type": tee_type_str,
            "qv_result": "OK",
            "measurement": {
                "type": TDX_GUEST_V2_URI,
                "registers": [
                    body.mr_td.hex(),
                    body.rtmrs[0].hex(),
                    body.rtmrs[1].hex(),
                    body.rtmrs[2].hex(),
                    body.rtmrs[3].hex(),
                ],
            },
            "header_fields": {
                "attestation_key_type": header.attestation_key_type,
                "qe_vendor_id_hex": header.qe_vendor_id.hex(),
                "user_data_hex": header.user_data.hex(),
            },
            "body_fields": {
                "tee_tcb_svn_hex": body.tee_tcb_svn.hex(),
                "mrseam_hex": body.mr_seam.hex(),
                "mrsignerseam_hex": body.mr_signer_seam.hex(),
                "seam_attributes_hex": body.seam_attributes.hex(),
                "td_attributes_hex": body.td_attributes.hex(),
                "td_attributes_decoded": _decode_td_attributes(body.td_attributes),
                "xfam_hex": body.xfam.hex(),
                "mrtd_hex": body.mr_td.hex(),
                "mrconfigid_hex": body.mr_config_id.hex(),
                "mrowner_hex": body.mr_owner.hex(),
                "mrownerconfig_hex": body.mr_owner_config.hex(),
                "rtmrs_hex": [r.hex() for r in body.rtmrs],
                "report_data_hex": body.report_data.hex(),
            },
        },
    }


def _tdx_fixture_collateral(
    collateral_in: dict[str, Any],
    pck_cert,
) -> TdxCollateral:
    tcb_info_raw = (collateral_in.get("tcb_info_json") or "").encode()
    qe_identity_raw = (collateral_in.get("qe_identity_json") or "").encode()
    tcb_info = parse_tcb_info_response(tcb_info_raw)
    qe_identity = parse_qe_identity_response(qe_identity_raw)

    tcb_issuer_chain_pem = (collateral_in.get("tcb_info_issuer_chain_pem") or "").encode()
    qe_issuer_chain_pem = (collateral_in.get("qe_identity_issuer_chain_pem") or "").encode()
    pck_crl_issuer_chain_pem = (collateral_in.get("pck_crl_issuer_chain_pem") or "").encode()

    tcb_issuer_chain = parse_pem_chain(tcb_issuer_chain_pem) if tcb_issuer_chain_pem else []
    qe_issuer_chain = parse_pem_chain(qe_issuer_chain_pem) if qe_issuer_chain_pem else []
    pck_crl_issuer_chain = (
        parse_pem_chain(pck_crl_issuer_chain_pem) if pck_crl_issuer_chain_pem else []
    )

    if tcb_issuer_chain:
        verify_tcb_info_signature(tcb_info_raw, tcb_info, tcb_issuer_chain)
    if qe_issuer_chain:
        verify_qe_identity_signature(qe_identity_raw, qe_identity, qe_issuer_chain)

    pck_crl_obj = None
    pck_crl_der = base64.b64decode(collateral_in.get("pck_crl_der_b64") or "")
    if pck_crl_der:
        pck_crl = x509.load_der_x509_crl(pck_crl_der)
        ca_type = _coll._determine_pck_ca_type(pck_cert)
        if pck_crl_issuer_chain:
            _coll._verify_crl_signature(pck_crl, pck_crl_issuer_chain, ca_type)
        pck_crl_obj = PckCrl(
            crl=pck_crl,
            ca_type=ca_type,
            next_update=pck_crl.next_update_utc or datetime.now(timezone.utc),
        )

    root_crl_obj = None
    root_crl_der = base64.b64decode(collateral_in.get("root_crl_der_b64") or "")
    if root_crl_der:
        root_crl = x509.load_der_x509_crl(root_crl_der)
        _coll._verify_root_crl_signature(root_crl)
        root_crl_obj = RootCrl(
            crl=root_crl,
            next_update=root_crl.next_update_utc or datetime.now(timezone.utc),
        )

    return TdxCollateral(
        tcb_info=tcb_info,
        qe_identity=qe_identity,
        tcb_info_raw=tcb_info_raw,
        qe_identity_raw=qe_identity_raw,
        pck_crl=pck_crl_obj,
        root_crl=root_crl_obj,
        tcb_info_issuer_chain=tcb_issuer_chain or None,
        qe_identity_issuer_chain=qe_issuer_chain or None,
    )


@contextlib.contextmanager
def _maybe_override_tdx_fetch_collateral(collateral_in: dict[str, Any]):
    orig_fetch_collateral = _coll.fetch_collateral

    def _fixture_fetch_collateral(pck_extensions, pck_cert, *args, **kwargs):
        return _tdx_fixture_collateral(collateral_in, pck_cert)

    _coll.fetch_collateral = _fixture_fetch_collateral
    try:
        yield
    finally:
        _coll.fetch_collateral = orig_fetch_collateral


@contextlib.contextmanager
def _maybe_override_time(timestamp: int | None):
    """Temporarily replace datetime.now() inside collateral_tdx and
    cert_utils so all internal freshness/validity checks use the fixture's
    expiration_check_date instead of real system time. The lib has no
    public time-injection API; this monkey-patch is the cleanest
    workaround until verify_intel_chain / check_collateral_freshness /
    validate_certificate_revocation gain a `now` parameter."""
    if timestamp is None:
        yield
        return
    import datetime as _dt_module
    fixed_now = _dt_module.datetime.fromtimestamp(int(timestamp), tz=_dt_module.timezone.utc)

    class _FixedDatetime(_dt_module.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is None else fixed_now.astimezone(tz)

    from ..attestation import collateral_tdx as _coll_mod
    from ..attestation import cert_utils as _cert_mod
    orig_coll_dt = _coll_mod.datetime
    orig_cert_dt = _cert_mod.datetime
    _coll_mod.datetime = _FixedDatetime
    _cert_mod.datetime = _FixedDatetime
    try:
        yield
    finally:
        _coll_mod.datetime = orig_coll_dt
        _cert_mod.datetime = orig_cert_dt


@contextlib.contextmanager
def _maybe_override_intel_root(pem: str | None):
    """Temporarily replace the embedded Intel SGX Root CA with a synthetic
    one for the duration of the `with` block. Phase 3 synthetic-chain
    fixtures rely on this so their self-issued root is accepted by
    cert_utils.verify_intel_chain (which reads the module-level
    INTEL_SGX_ROOT_CA_PEM via get_intel_root_ca)."""
    if not pem:
        yield
        return
    orig_pem = _intel_root_mod.INTEL_SGX_ROOT_CA_PEM
    _intel_root_mod.INTEL_SGX_ROOT_CA_PEM = pem.encode()
    try:
        yield
    finally:
        _intel_root_mod.INTEL_SGX_ROOT_CA_PEM = orig_pem


def _evaluate_collateral(
    quote, pck_chain, collateral_in: dict, expiration_check_date_unix,
    policy: dict | None = None,
) -> tuple[str, str, str]:
    """Run Intel §4.7 collateral evaluation against fixture-injected bytes.

    Orchestrates the lib's pure validation functions in the order specified
    by SPEC §4.9 step 10. Returns (rejection_code, spec_ref, message); empty
    string code means everything passed."""
    try:
        # Step 1: PCK extensions
        pck_extensions = extract_pck_extensions(pck_chain.pck_cert)

        # Step 2: Parse injected collateral
        tcb_info_raw = (collateral_in.get("tcb_info_json") or "").encode()
        qe_identity_raw = (collateral_in.get("qe_identity_json") or "").encode()
        tcb_info = parse_tcb_info_response(tcb_info_raw)
        qe_identity = parse_qe_identity_response(qe_identity_raw)

        tcb_issuer_chain_pem = (collateral_in.get("tcb_info_issuer_chain_pem") or "").encode()
        qe_issuer_chain_pem = (collateral_in.get("qe_identity_issuer_chain_pem") or "").encode()
        tcb_issuer_chain = parse_pem_chain(tcb_issuer_chain_pem) if tcb_issuer_chain_pem else []
        qe_issuer_chain = parse_pem_chain(qe_issuer_chain_pem) if qe_issuer_chain_pem else []

        # Step 3: Verify collateral signatures
        if tcb_issuer_chain:
            verify_tcb_info_signature(tcb_info_raw, tcb_info, tcb_issuer_chain)
        if qe_issuer_chain:
            verify_qe_identity_signature(qe_identity_raw, qe_identity, qe_issuer_chain)

        # Step 4: CRLs
        pck_crl_der = base64.b64decode(collateral_in.get("pck_crl_der_b64") or "")
        root_crl_der = base64.b64decode(collateral_in.get("root_crl_der_b64") or "")
        pck_crl_obj = None
        root_crl_obj = None
        if pck_crl_der:
            crl = x509.load_der_x509_crl(pck_crl_der)
            pck_crl_obj = PckCrl(crl=crl, ca_type="platform",
                                 next_update=crl.next_update_utc or datetime.now(timezone.utc))
        if root_crl_der:
            crl = x509.load_der_x509_crl(root_crl_der)
            root_crl_obj = RootCrl(crl=crl,
                                   next_update=crl.next_update_utc or datetime.now(timezone.utc))

        collateral = TdxCollateral(
            tcb_info=tcb_info, qe_identity=qe_identity,
            tcb_info_raw=tcb_info_raw, qe_identity_raw=qe_identity_raw,
            pck_crl=pck_crl_obj, root_crl=root_crl_obj,
            tcb_info_issuer_chain=tcb_issuer_chain or None,
            qe_identity_issuer_chain=qe_issuer_chain or None,
        )

        # Step 5: Freshness — inline so we can use the fixture-provided
        # expiration_check_date_unix instead of datetime.now(). The lib's
        # check_collateral_freshness reads system time directly which
        # would fire on any older testdata.
        if expiration_check_date_unix is not None:
            now_t = datetime.fromtimestamp(int(expiration_check_date_unix), tz=timezone.utc)
        else:
            now_t = datetime.now(timezone.utc)
        if now_t > tcb_info.tcb_info.next_update:
            return "TCB_INFO_EXPIRED", "4.7", (
                f"TCB Info nextUpdate {tcb_info.tcb_info.next_update} is past "
                f"verification_time {now_t}"
            )
        if now_t > qe_identity.enclave_identity.next_update:
            return "QE_IDENTITY_EXPIRED", "4.7", (
                f"QE Identity nextUpdate {qe_identity.enclave_identity.next_update} "
                f"is past verification_time {now_t}"
            )

        # SPEC §4.7.11 lets policy require a minimum collateral
        # tcbEvaluationDataNumber. The underlying lib exposes this in
        # freshness helpers, but we enforce it inline so injected-collateral
        # conformance runs stay deterministic.
        min_eval = (policy or {}).get("min_tcb_evaluation_data_number")
        if min_eval is not None:
            min_eval_int = int(min_eval)
            tcb_eval_num = tcb_info.tcb_info.tcb_evaluation_data_number
            qe_eval_num = qe_identity.enclave_identity.tcb_evaluation_data_number
            if tcb_eval_num < min_eval_int:
                return "TCB_EVAL_DATA_NUMBER_TOO_LOW", "4.7.11", (
                    f"TCB Info tcbEvaluationDataNumber {tcb_eval_num} "
                    f"below minimum {min_eval_int}"
                )
            if qe_eval_num < min_eval_int:
                return "TCB_EVAL_DATA_NUMBER_TOO_LOW", "4.7.11", (
                    f"QE Identity tcbEvaluationDataNumber {qe_eval_num} "
                    f"below minimum {min_eval_int}"
                )

        # Step 6: Cert revocation
        validate_certificate_revocation(
            collateral, pck_chain.pck_cert, pck_chain.intermediate_cert,
        )

        # Step 7: TCB status (matches level + rejects non-acceptable status)
        matching_tcb_level = validate_tcb_status(
            tcb_info.tcb_info,
            quote.td_quote_body.tee_tcb_svn,
            pck_extensions,
        )
        accepted_qv_results = (policy or {}).get("accepted_qv_results")
        if accepted_qv_results:
            tcb_status_to_qv_result = {
                "UpToDate": "OK",
                "SWHardeningNeeded": "SW_HARDENING_NEEDED",
                "ConfigurationNeeded": "CONFIG_NEEDED",
                "ConfigurationAndSWHardeningNeeded": "CONFIG_AND_SW_HARDENING_NEEDED",
                "OutOfDate": "OUT_OF_DATE",
                "OutOfDateConfigurationNeeded": "OUT_OF_DATE_CONFIG_NEEDED",
                "Revoked": "REVOKED",
            }
            tcb_status = str(getattr(
                matching_tcb_level.tcb_status,
                "value",
                matching_tcb_level.tcb_status,
            ))
            qv_result = tcb_status_to_qv_result.get(tcb_status, tcb_status)
            if qv_result not in set(accepted_qv_results):
                return "QV_RESULT_NOT_ACCEPTED_BY_POLICY", "4.7.7", (
                    f"qv_result {qv_result} from TCB status {tcb_status} "
                    f"not in accepted_qv_results {accepted_qv_results}"
                )

        # Step 8: TDX module identity
        validate_tdx_module_identity(
            tcb_info.tcb_info,
            quote.td_quote_body.tee_tcb_svn,
            quote.td_quote_body.mr_signer_seam,
            quote.td_quote_body.seam_attributes,
        )

        # Step 9: QE identity
        qe_report = quote.signed_data.certification_data.qe_report_data
        if qe_report is None:
            return "QE_IDENTITY_FIELD_MISMATCH", "4.4", "Quote missing QE report"
        qe_parsed = qe_report.qe_report_parsed
        miscselect_bytes = qe_parsed.misc_select.to_bytes(4, byteorder='little')
        validate_qe_identity(
            qe_identity.enclave_identity,
            qe_parsed.isv_svn, qe_parsed.mr_signer,
            miscselect_bytes, qe_parsed.attributes, qe_parsed.isv_prod_id,
        )

    except CollateralError as e:
        msg = str(e)
        msg_low = msg.lower()
        if "pck crl" in msg_low and "expired" in msg_low:
            return "PCK_CRL_EXPIRED", "4.7.4", msg
        if (
            ("root ca crl" in msg_low or "root crl" in msg_low)
            and "expired" in msg_low
        ):
            return "ROOT_CRL_EXPIRED", "4.7.4", msg
        if "intermediate ca" in msg_low and "revoked" in msg_low:
            return "INTERMEDIATE_REVOKED", "4.7.4", msg
        if "pck certificate" in msg_low and "revoked" in msg_low:
            return "PCK_REVOKED", "4.7.4", msg
        if "tcb info issuer chain" in msg_low and (
            "chain" in msg_low or "certificate" in msg_low or "root" in msg_low
        ):
            return "TCB_INFO_CHAIN_INVALID", "4.7.3", msg
        if "qe identity id" in msg_low and ("td_qe" in msg_low or "must" in msg_low):
            return "QE_IDENTITY_ID_INVALID", "4.7.9", msg
        if "qe identity version" in msg_low and "must" in msg_low:
            return "QE_IDENTITY_VERSION_INVALID", "4.7.9", msg
        if "mrsigner" in msg_low or "mr_signer" in msg_low:
            return "QE_IDENTITY_MRSIGNER_MISMATCH", "4.7.9", msg
        if "miscselect" in msg_low or "attributes" in msg_low or "isv prodid" in msg_low:
            return "QE_IDENTITY_FIELD_MISMATCH", "4.7.9", msg
        if "tcb status" in msg_low or "no matching tcb" in msg_low or "revoked" in msg_low:
            return "TCB_REVOKED", "4.7.7", msg
        if "signature" in msg_low and ("tcb info" in msg_low or "tcbinfo" in msg_low):
            return "TCB_INFO_SIGNATURE_INVALID", "4.7", msg
        if "signature" in msg_low and ("qe identity" in msg_low or "enclave identity" in msg_low):
            return "QE_IDENTITY_SIGNATURE_INVALID", "4.7", msg
        if "expired" in msg_low and ("tcb" in msg_low or "tcbinfo" in msg_low):
            return "TCB_INFO_EXPIRED", "4.7", msg
        if "expired" in msg_low and ("qe" in msg_low or "identity" in msg_low):
            return "QE_IDENTITY_EXPIRED", "4.7", msg
        if "qe identity" in msg_low or "enclave identity" in msg_low:
            return "QE_IDENTITY_FIELD_MISMATCH", "4.7.9", msg
        if "crl" in msg_low or "revocation" in msg_low:
            return "PCK_REVOKED", "4.7.4", msg
        return "QV_RESULT_TERMINAL_UNSPECIFIED", "4.7", msg
    except Exception as e:
        return "QV_RESULT_TERMINAL_UNSPECIFIED", "4.7", f"unexpected: {e}"

    return "", "", ""


def _enforce_extended_policy(
    raw_quote: bytes, policy: dict
) -> tuple[str, str]:
    """Apply SPEC §4.8 / Intel §2.3.2 checks against quote body fields.

    Each policy.expected_*_hex pin is optional; only enforced when set.
    Returns ("", "") on success, otherwise (rejection_code, message).
    """
    if len(raw_quote) < 48 + 584:
        return "", ""
    header = raw_quote[:48]
    body = raw_quote[48:48 + 584]

    qe_vendor = header[12:28]
    tee_tcb_svn = body[0:16]
    mr_seam = body[16:64]
    mr_signer_seam = body[64:112]
    seam_attrs = body[112:120]
    td_attrs = body[120:128]
    xfam = body[128:136]
    mr_td = body[136:184]
    mr_config_id = body[184:232]
    mr_owner = body[232:280]
    mr_owner_config = body[280:328]
    rtmr3 = body[472:520]
    report_data = body[520:584]

    def match_hex(expected_hex: str | None, got: bytes) -> bool:
        if not expected_hex:
            return True
        try:
            expected = bytes.fromhex(expected_hex.strip().lower())
        except ValueError:
            return False
        if len(expected) != len(got):
            return False
        return got == expected

    pins = [
        ("expected_td_attributes_hex",      td_attrs,        "TD_ATTRIBUTES_MISMATCH",      "td_attributes"),
        ("expected_xfam_hex",               xfam,            "XFAM_MISMATCH",               "xfam"),
        ("expected_mr_signer_seam_hex",     mr_signer_seam,  "MR_SIGNER_SEAM_MISMATCH",     "mr_signer_seam"),
        ("expected_seam_attributes_hex",    seam_attrs,      "SEAM_ATTRIBUTES_MISMATCH",    "seam_attributes"),
        ("expected_mrtd_hex",               mr_td,           "MRTD_MISMATCH",               "mrtd"),
        ("expected_mr_config_id_hex",       mr_config_id,    "MR_CONFIG_ID_MISMATCH",       "mr_config_id"),
        ("expected_mr_owner_hex",           mr_owner,        "MR_OWNER_MISMATCH",           "mr_owner"),
        ("expected_mr_owner_config_hex",    mr_owner_config, "MR_OWNER_CONFIG_MISMATCH",    "mr_owner_config"),
        ("expected_rtmr3_hex",              rtmr3,           "RTMR3_NONZERO",               "rtmr3"),
        ("expected_report_data_hex",        report_data,     "REPORT_DATA_MISMATCH",        "report_data"),
        ("expected_qe_vendor_id_hex",       qe_vendor,       "QE_VENDOR_ID_MISMATCH",       "qe_vendor_id"),
    ]
    for field_name, got, code, label in pins:
        expected_hex = policy.get(field_name)
        if expected_hex is not None and not match_hex(expected_hex, got):
            return code, f"{label} {got.hex()} != policy expected {expected_hex.strip().lower()}"

    # MR_SEAM allowlist
    allowlist = policy.get("expected_mrseam_allowlist")
    if allowlist:
        got_hex = mr_seam.hex()
        if not any(got_hex == entry.strip().lower() for entry in allowlist):
            return ("MR_SEAM_NOT_ALLOWED",
                    f"mr_seam {got_hex} not in policy allowlist ({len(allowlist)} entries)")

    # SPEC §4.8.1 / §4.8.2 normative defaults — applied regardless of pin
    # presence when enforce_spec_defaults=true.
    if policy.get("enforce_spec_defaults"):
        TD_ATTR_DEBUG  = 1 << 0
        TD_ATTR_FIXED0 = (1 << 0) | (1 << 28) | (1 << 30) | (1 << 63)
        XFAM_FIXED1    = 0x3
        XFAM_FIXED0    = 0x6DBE7
        td_attr_int = int.from_bytes(td_attrs, byteorder="little")
        if td_attr_int & TD_ATTR_DEBUG:
            return ("TD_ATTRIBUTES_DEBUG_SET",
                    f"TD Attributes DEBUG bit is set (td_attributes={td_attrs.hex()})")
        if td_attr_int & ~TD_ATTR_FIXED0:
            return ("TD_ATTRIBUTES_RESERVED_BIT_SET",
                    f"TD Attributes has bit(s) outside FIXED0 set (td_attributes={td_attrs.hex()})")
        xfam_int = int.from_bytes(xfam, byteorder="little")
        if (xfam_int & XFAM_FIXED1) != XFAM_FIXED1:
            return ("XFAM_REQUIRED_BIT_CLEAR",
                    f"XFAM required bits 0 (FP) + 1 (SSE) not both set (xfam={xfam.hex()})")
        if xfam_int & ~XFAM_FIXED0:
            return ("XFAM_FORBIDDEN_BIT_SET",
                    f"XFAM has bit(s) outside FIXED0 set (xfam={xfam.hex()})")

    # Min TEE_TCB_SVN — component-wise comparison (SPEC §4.8.7).
    min_hex = policy.get("min_tee_tcb_svn_hex")
    if min_hex:
        try:
            minimum = bytes.fromhex(min_hex.strip().lower())
            if len(minimum) == 16:
                for i in range(16):
                    if tee_tcb_svn[i] < minimum[i]:
                        return ("TEE_TCB_SVN_BELOW_MINIMUM",
                                f"tee_tcb_svn[{i}]={tee_tcb_svn[i]} < min[{i}]={minimum[i]} "
                                f"(quote={tee_tcb_svn.hex()}, minimum={minimum.hex()})")
        except ValueError:
            pass

    return "", ""


def _cmd_verify_attestation_tdx_public(inp: dict[str, Any], policy: dict[str, Any]) -> int:
    collateral_in = inp.get("collateral") or {}
    custom_root_pem = collateral_in.get("intel_root_ca_pem")
    fixture_date = inp.get("expiration_check_date_unix")

    config_kwargs: dict[str, Any] = {}
    if policy.get("min_tcb_evaluation_data_number") is not None:
        config_kwargs["min_tcb_evaluation_data_number"] = int(
            policy["min_tcb_evaluation_data_number"]
        )

    with (
        _maybe_override_intel_root(custom_root_pem),
        _maybe_override_time(fixture_date),
        _maybe_override_tdx_fetch_collateral(collateral_in),
    ):
        try:
            result = verify_tdx_attestation(
                inp["quote_b64"],
                is_compressed=False,
                config=TdxVerificationConfig(**config_kwargs),
            )
        except (TdxAttestationError, TdxVerificationError, CollateralError) as e:
            code, ref = _classify_tdx_error(e)
            return _emit_tdx_rejection(code, ref, str(e))
        except Exception as e:
            code, ref = _classify_tdx_error(e)
            return _emit_tdx_rejection(code, ref, f"unexpected: {e}")

    quote_bytes = base64.b64decode(inp["quote_b64"])
    code, msg = _enforce_extended_policy(quote_bytes, policy)
    if code:
        return _emit_tdx_rejection(code, "4.8", msg)

    json.dump(_tdx_acceptance_output(result.quote), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_ACCEPT


def cmd_verify_attestation_tdx() -> int:
    raw = sys.stdin.read()
    try:
        inp = json.loads(raw)
    except Exception as e:
        sys.stderr.write(f"input schema violation: {e}\n")
        return EXIT_BAD_INPUT
    if inp.get("schema_version") != "1":
        sys.stderr.write('schema_version must be "1"\n')
        return EXIT_BAD_INPUT

    try:
        quote_bytes = base64.b64decode(inp["quote_b64"])
    except Exception as e:
        return _emit_tdx_rejection(
            "QUOTE_FORMAT_UNSUPPORTED", "A.3", f"quote_b64 not valid base64: {e}"
        )

    try:
        quote = parse_tdx_quote(quote_bytes)
    except Exception as e:
        code, ref = _classify_tdx_error(e)
        return _emit_tdx_rejection(code, ref, str(e))

    policy = inp.get("policy") or {}
    # Default true (full §4.7 collateral evaluation). False = structural-only
    # verification (PCK chain + AK + sig + QE report). Matches the Go binary's
    # semantics and fixture 300's calibration.
    tcb_eval_required = policy.get("tcb_evaluation_required", True)
    if inp.get("execution_mode") == "public_api":
        return _cmd_verify_attestation_tdx_public(inp, policy)

    # Structural verification (Intel §4.1.2 steps 1-4) always runs.
    # When collateral.intel_root_ca_pem is set (Phase 3 synthetic chain
    # fixtures), temporarily swap the embedded Intel root for the
    # synthetic one so chain validation accepts the self-issued chain.
    collateral_in = inp.get("collateral") or {}
    custom_root_pem = collateral_in.get("intel_root_ca_pem")
    # Inject the fixture's verification time into the lib's freshness +
    # cert-validity checks. This effectively makes
    # verification_time_override="supported" for the collateral path,
    # which the structural-only path (verify_tdx_quote) still doesn't honor.
    fixture_date = inp.get("expiration_check_date_unix")
    with _maybe_override_intel_root(custom_root_pem), _maybe_override_time(fixture_date):
        try:
            pck_chain = verify_tdx_quote_crypto(quote, quote_bytes)
        except TdxVerificationError as e:
            code, ref = _classify_tdx_error(e)
            return _emit_tdx_rejection(code, ref, str(e))
        except Exception as e:
            code, ref = _classify_tdx_error(e)
            return _emit_tdx_rejection(code, ref, f"unexpected: {e}")

        if tcb_eval_required:
            code, ref, msg = _evaluate_collateral(
                quote, pck_chain, collateral_in,
                inp.get("expiration_check_date_unix"),
                policy,
            )
            if code:
                return _emit_tdx_rejection(code, ref, msg)

    # Phase 4: extended-TD policy checks (SPEC §4.8 / Intel §2.3.2).
    code, msg = _enforce_extended_policy(quote_bytes, policy)
    if code:
        return _emit_tdx_rejection(code, "4.8", msg)

    json.dump(_tdx_acceptance_output(quote), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_ACCEPT


# =============================================================================
# verify-attestation-sev (SPEC §3 / AMD SEV-SNP)
# =============================================================================

SEV_GUEST_V2_URI = "https://tinfoil.sh/predicate/sev-snp-guest/v2"


def _emit_sev_rejection(code: str, spec_ref: str, message: str) -> int:
    body = {
        "stage": "verify-attestation-sev",
        "accepted": False,
        "rejection": {"code": code, "spec_ref": spec_ref, "message": message},
    }
    json.dump(body, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return EXIT_REJECT


_SEV_REPORT_LEN = 1184


def _decode_sev_body_fields(report: bytes) -> dict[str, Any]:
    """Decode the 1184-byte SEV-SNP v3 report into the same shape as the
    Go conformance binary's buildSevOutputs, so expected.json pinned
    outputs are cross-SDK comparable byte-for-byte."""
    def u32(off: int) -> int:
        return int.from_bytes(report[off:off + 4], "little")

    def u64(off: int) -> int:
        return int.from_bytes(report[off:off + 8], "little")

    policy = u64(0x08)
    current_tcb = u64(0x38)
    platform_info = u64(0x40)

    def b(n: int, i: int) -> bool:
        return bool((n >> i) & 1)

    return {
        "version": u32(0x00),
        "guest_svn": u32(0x04),
        "policy_hex": f"{policy:016x}",
        "policy_decoded": {
            "abi_minor": policy & 0xff,
            "abi_major": (policy >> 8) & 0xff,
            "smt": b(policy, 16),
            "reserved_mbo": b(policy, 17),
            "migrate_ma": b(policy, 18),
            "debug": b(policy, 19),
            "single_socket": b(policy, 20),
            "cxl_allow": b(policy, 21),
            "mem_aes_256_xts": b(policy, 22),
            "raplmsr_dis": b(policy, 23),
            "ciphertext_hiding_dram": b(policy, 24),
        },
        "family_id_hex": report[0x10:0x20].hex(),
        "image_id_hex": report[0x20:0x30].hex(),
        "vmpl": u32(0x30),
        "signature_algo": u32(0x34),
        "current_tcb_hex": f"{current_tcb:016x}",
        "current_tcb_decoded": {
            "bl_spl": current_tcb & 0xff,
            "tee_spl": (current_tcb >> 8) & 0xff,
            "snp_spl": (current_tcb >> 48) & 0xff,
            "ucode_spl": (current_tcb >> 56) & 0xff,
        },
        "platform_info_hex": f"{platform_info:016x}",
        "platform_info_decoded": {
            "smt_en": b(platform_info, 0),
            "tsme_en": b(platform_info, 1),
            "ecc_en": b(platform_info, 2),
            "rapl_dis": b(platform_info, 3),
            "ciphertext_hiding": b(platform_info, 4),
        },
        "signer_info_hex": f"{u32(0x48):08x}",
        "report_data_hex": report[0x50:0x90].hex(),
        "measurement_hex": report[0x90:0x90 + 48].hex(),
        "host_data_hex": report[0xC0:0xC0 + 32].hex(),
        "id_key_digest_hex": report[0xE0:0xE0 + 48].hex(),
        "author_key_digest_hex": report[0x110:0x110 + 48].hex(),
        "report_id_hex": report[0x140:0x140 + 32].hex(),
        "report_id_ma_hex": report[0x160:0x160 + 32].hex(),
        "reported_tcb_hex": report[0x180:0x180 + 8].hex(),
        "chip_id_hex": report[0x1A0:0x1A0 + 64].hex(),
        "committed_tcb_hex": report[0x1E8:0x1E8 + 8].hex(),
        "current_build": report[0x1F0],
        "current_minor": report[0x1F1],
        "current_major": report[0x1F2],
        "committed_build": report[0x1F4],
        "committed_minor": report[0x1F5],
        "committed_major": report[0x1F6],
        "launch_tcb_hex": report[0x1F8:0x1F8 + 8].hex(),
    }


def _classify_sev_error(msg: str) -> tuple[str, str]:
    low = msg.lower()
    # Order matters — specific before generic.
    # SPEC §3.2.2: tinfoil-python's Report parser raises various phrasings
    # for guest_policy bit violations:
    #   "policy[17] is reserved, must be 1, got 0"   (reserved-MBO at bit 17)
    #   "policy bits 63-26 must be zero"             (reserved-MBZ at bits 25+)
    if ("policy[" in low or "guest policy" in low or "policy bit" in low) and (
        "reserved" in low or "mbz" in low or "must be" in low
    ):
        return "GUEST_POLICY_RESERVED_BIT_SET", "3.2.2"
    if "expired" in low or "not yet valid" in low:
        return "VCEK_EXPIRED", "3.3.3"
    if "hwid" in low:
        return "VCEK_HWID_MISMATCH", "3.4.4"
    if "vcek" in low and "tcb" in low:
        return "VCEK_TCB_MISMATCH", "3.4.3"
    if "report signature" in low or "signature verification failed" in low \
            or "signature is invalid" in low or "report was not signed" in low:
        return "REPORT_SIGNATURE_INVALID", "3.6"
    if "ark" in low and "self-sign" in low:
        return "ARK_UNTRUSTED", "3.3.1"
    if ("ask" in low and "not signed" in low) or "ask invalid" in low:
        return "ASK_INVALID", "3.3.2"
    if ("vcek" in low and ("chain" in low or "verify" in low or "signed" in low)) \
            or "amd certificate chain" in low or "certificate chain verification" in low \
            or "certificate signature failure" in low \
            or "malformed certificate" in low \
            or "could not interpret vcek" in low or "failed to build certificate chain" in low \
            or "invalid vcek" in low or "x509" in low:
        return "VCEK_CHAIN_INVALID", "3.3.5"
    if "report length" in low or "less than" in low and "byte" in low:
        return "REPORT_TRUNCATED", "3.1"
    if "failed to decompress" in low or "failed to decode base64" in low \
            or "failed to parse report" in low or "format" in low:
        return "REPORT_FORMAT_UNSUPPORTED", "3.1"
    return "QV_RESULT_TERMINAL_UNSPECIFIED", "3"


_AMD_OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
_AMD_OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
_AMD_OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
_AMD_OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
_AMD_OID_HWID = "1.3.6.1.4.1.3704.1.4"


def _decode_int_ext_value(raw: bytes) -> int | None:
    """Decode an AMD KDS SPL extension value (DER INTEGER) to a Python int."""
    # raw is the extension OCTET STRING contents — an INTEGER TLV: 02 LL VV...
    if len(raw) < 3 or raw[0] != 0x02:
        return None
    length = raw[1]
    if len(raw) < 2 + length:
        return None
    return int.from_bytes(raw[2:2 + length], "big", signed=False)


def _enforce_sev_vcek_cross_checks(
    report: bytes,
    vcek_cert,
) -> tuple[str, str, str] | None:
    """SPEC §3.4 mandatory cross-checks: VCEK extensions ↔ report fields.
    The lib's validate_report has these, but we bypass that call so we
    can run fixture-specific policy enforcement separately. Replicate
    the mandatory checks here so synth-chain mismatches don't slip
    through as ACCEPTED."""
    from cryptography.x509 import ObjectIdentifier as _OID
    try:
        ext_map: dict[str, bytes] = {}
        for ext in vcek_cert.extensions:
            try:
                ext_map[ext.oid.dotted_string] = bytes(ext.value.value)
            except Exception:
                pass
    except Exception:
        return None

    # HWID cross-check
    hwid_raw = ext_map.get(_AMD_OID_HWID)
    if hwid_raw is None:
        return "VCEK_HWID_MISMATCH", "3.4.4", "VCEK certificate missing HWID extension"
    if hwid_raw != report[0x1A0:0x1A0 + 64]:
        return ("VCEK_HWID_MISMATCH", "3.4.4",
                f"VCEK HWID {hwid_raw.hex()} != report chip_id {report[0x1A0:0x1A0 + 64].hex()}")

    # TCB cross-check: each SPL extension must match the corresponding byte
    # of report.reported_tcb (TCBVersion decomposition per SPEC §3.4.3).
    reported_tcb = int.from_bytes(report[0x180:0x188], "little")
    tcb_pairs = [
        ("bl_spl",    _AMD_OID_BL_SPL,    reported_tcb & 0xff),
        ("tee_spl",   _AMD_OID_TEE_SPL,   (reported_tcb >> 8) & 0xff),
        ("snp_spl",   _AMD_OID_SNP_SPL,   (reported_tcb >> 48) & 0xff),
        ("ucode_spl", _AMD_OID_UCODE_SPL, (reported_tcb >> 56) & 0xff),
    ]
    for name, oid, report_val in tcb_pairs:
        raw = ext_map.get(oid)
        if raw is None:
            continue
        cert_val = _decode_int_ext_value(raw)
        if cert_val is None:
            continue
        if cert_val != report_val:
            return ("VCEK_TCB_MISMATCH", "3.4.3",
                    f"VCEK {name}={cert_val} != report.reported_tcb.{name}={report_val}")
    return None


def _enforce_sev_policy(report: bytes, policy: dict[str, Any] | None) -> tuple[str, str, str] | None:
    # SPEC §3.7 / Tinfoil-policy: migrate_ma=1 MUST be rejected. Run
    # unconditionally — independent of fixture policy — to mirror what
    # the lib's validate_report would have caught.
    guest_policy_pre = int.from_bytes(report[0x08:0x10], "little")
    if (guest_policy_pre >> 18) & 1:
        return ("GUEST_POLICY_MIGRATE_MA_SET", "3.7",
                f"guest_policy MIGRATE_MA bit (18) is set (policy={guest_policy_pre:016x})")

    if not policy:
        return None

    measurement = report[0x90:0x90 + 48]
    host_data = report[0xC0:0xC0 + 32]
    report_data = report[0x50:0x90]
    id_key_digest = report[0xE0:0xE0 + 48]
    author_key_digest = report[0x110:0x110 + 48]
    guest_policy = int.from_bytes(report[0x08:0x10], "little")
    current_tcb = int.from_bytes(report[0x38:0x40], "little")
    tcb_bl = current_tcb & 0xff
    tcb_tee = (current_tcb >> 8) & 0xff
    tcb_snp = (current_tcb >> 48) & 0xff
    tcb_ucode = (current_tcb >> 56) & 0xff

    pairs: list[tuple[str, str, str, bytes, str]] = [
        ("MEASUREMENT_MISMATCH", "3.8", "measurement",
         measurement, policy.get("expected_measurement_hex", "")),
        ("HOST_DATA_MISMATCH", "8.3", "host_data",
         host_data, policy.get("expected_host_data_hex", "")),
        ("REPORT_DATA_MISMATCH", "8.2", "report_data",
         report_data, policy.get("expected_report_data_hex", "")),
        ("ID_KEY_DIGEST_MISMATCH", "3.1.1", "id_key_digest",
         id_key_digest, policy.get("expected_id_key_digest_hex", "")),
        ("AUTHOR_KEY_DIGEST_MISMATCH", "3.1.1", "author_key_digest",
         author_key_digest, policy.get("expected_author_key_digest_hex", "")),
    ]
    for code, ref, name, actual, expected in pairs:
        exp = (expected or "").strip().lower()
        if not exp:
            continue
        if actual.hex() != exp:
            return code, ref, f"{name} {actual.hex()} != policy expected {exp}"

    for name, actual, min_key in (
        ("bl_spl", tcb_bl, "min_tcb_bl_spl"),
        ("tee_spl", tcb_tee, "min_tcb_tee_spl"),
        ("snp_spl", tcb_snp, "min_tcb_snp_spl"),
        ("ucode_spl", tcb_ucode, "min_tcb_ucode_spl"),
    ):
        m = policy.get(min_key)
        if m is not None and actual < int(m):
            return "TCB_OUT_OF_DATE", "3.7", f"tcb.{name}={actual} below minimum {m}"

    if policy.get("enforce_spec_defaults"):
        if (guest_policy >> 19) & 1:
            return ("GUEST_POLICY_DEBUG_SET", "3.7",
                    f"guest_policy DEBUG bit (19) is set (policy={guest_policy:016x})")
        if not ((guest_policy >> 17) & 1):
            return ("GUEST_POLICY_RESERVED_BIT_SET", "3.7",
                    f"guest_policy reserved-MBO bit (17) is clear (policy={guest_policy:016x})")
        if guest_policy & 0xFFFFFFFFFE000000:
            return ("GUEST_POLICY_RESERVED_BIT_SET", "3.7",
                    f"guest_policy reserved-MBZ bit (≥25) set (policy={guest_policy:016x})")
    return None


@contextlib.contextmanager
def _maybe_override_sev_time(_timestamp: int | None):
    """No-op for SEV on Python — the lib delegates VCEK NotBefore/NotAfter
    to pyOpenSSL's X509Store.verify_certificate which uses the OS clock
    via OpenSSL internals. No Python-level monkey-patch can override it.
    Fixtures that need time injection (e.g. 240-vcek-expired) gate on
    attestation_sev.verification_time_override=supported and skip cleanly
    on tinfoil-python."""
    yield


def _run_verify_attestation_sev_inner(
    data: dict[str, Any],
) -> "tuple[Measurement, bytes, dict[str, Any]] | tuple[str, str, str]":
    """Inner SEV verification logic — shared by cmd_verify_attestation_sev
    and cmd_verify_full. On success returns (measurement, report_bytes,
    body_fields_dict); on failure returns a (code, spec_ref, message) triple.

    Distinguish by tuple length: success is 3-tuple of (Measurement, bytes,
    dict); failure is 3-tuple of (str, str, str). Callers should isinstance
    on the first element.

    schema_version defaults to "1" when absent so the verify-full envelope's
    nested attestation_sev block (which omits it) works.
    """
    sv = data.get("schema_version", "1")
    if sv != "1":
        return ("REPORT_FORMAT_UNSUPPORTED", "3.1", 'schema_version != "1"')

    att_doc_b64 = data.get("attestation_doc_b64")
    vcek_b64 = data.get("vcek_der_b64")
    if not att_doc_b64 or not vcek_b64:
        return ("REPORT_FORMAT_UNSUPPORTED", "3.1",
                "attestation_doc_b64 and vcek_der_b64 are required")

    # Decompress + length-check locally so REPORT_TRUNCATED surfaces before
    # the lib's Report() constructor (which raises a generic parse error).
    import gzip as _gzip
    try:
        gz_bytes = base64.standard_b64decode(att_doc_b64)
    except Exception as e:
        return ("REPORT_FORMAT_UNSUPPORTED", "3.1",
                f"attestation_doc_b64 not valid base64: {e}")
    try:
        report_bytes = _gzip.decompress(gz_bytes)
    except Exception as e:
        return ("REPORT_FORMAT_UNSUPPORTED", "3.1",
                f"gzip decompress failed: {e}")
    if len(report_bytes) < _SEV_REPORT_LEN:
        return ("REPORT_TRUNCATED", "3.1",
                f"SEV report is {len(report_bytes)} bytes, expected ≥{_SEV_REPORT_LEN}")

    try:
        vcek_der = base64.standard_b64decode(vcek_b64)
    except Exception as e:
        return ("VCEK_CHAIN_INVALID", "3.3.3",
                f"vcek_der_b64 not valid base64: {e}")

    # Build the chain directly with the supplied VCEK + embedded ARK/ASK.
    # Bypasses CertificateChain.from_report which would fetch VCEK from KDS.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes  # noqa: F401
    from ..attestation.abi_sev import Report as _Report
    from ..attestation.verify_sev import (
        CertificateChain, verify_attestation, ARK_CERT, ASK_CERT,
    )
    import warnings as _warnings
    from cryptography.utils import CryptographyDeprecationWarning

    try:
        report = _Report(report_bytes)
    except Exception as e:
        code, ref = _classify_sev_error(f"failed to parse report: {e}")
        return (code, ref, str(e))

    # Phase 4B-SEV: if the fixture supplies synthetic ARK/ASK PEMs, parse
    # those instead of the lib's embedded production constants. Mirrors
    # the Go binary's TrustedRoots-injection path.
    fixture_ark_pem = data.get("amd_root_ca_pem", "") or ""
    fixture_ask_pem = data.get("ask_pem", "") or ""
    try:
        ark_pem_bytes = fixture_ark_pem.encode() if fixture_ark_pem else ARK_CERT
        ask_pem_bytes = fixture_ask_pem.encode() if fixture_ask_pem else ASK_CERT
        ark = x509.load_pem_x509_certificate(ark_pem_bytes)
        ask = x509.load_pem_x509_certificate(ask_pem_bytes)
    except Exception as e:
        return ("ARK_UNTRUSTED", "3.3.1",
                f"failed to parse AMD chain (fixture-supplied={bool(fixture_ark_pem)}): {e}")
    try:
        with _warnings.catch_warnings():
            _warnings.filterwarnings(
                "ignore",
                message=r"Parsed a serial number which wasn't positive",
                category=CryptographyDeprecationWarning,
            )
            vcek = x509.load_der_x509_certificate(vcek_der)
    except Exception as e:
        return ("VCEK_CHAIN_INVALID", "3.3.5",
                f"could not interpret VCEK DER: {e}")

    chain = CertificateChain(ark=ark, ask=ask, vcek=vcek)

    expiration_unix = data.get("expiration_check_date_unix")

    # tinfoil-python's verify_attestation / verify_chain print error
    # diagnostics via print() to stdout when verification fails. The
    # conformance binary's contract is JSON-only on stdout, so we capture
    # the lib's stdout and route it to stderr.
    import io as _io
    captured = _io.StringIO()
    orig_stdout = sys.stdout
    sys.stdout = captured
    try:
        with _maybe_override_sev_time(expiration_unix):
            ok = verify_attestation(chain, report)
    except Exception as e:
        sys.stdout = orig_stdout
        sys.stderr.write(captured.getvalue())
        code, ref = _classify_sev_error(str(e))
        return (code, ref, str(e))
    sys.stdout = orig_stdout
    lib_diag = captured.getvalue()
    if lib_diag:
        sys.stderr.write(lib_diag)
    if not ok:
        diag_msg = lib_diag or "verification returned False"
        code, ref = _classify_sev_error(diag_msg)
        if code == "QV_RESULT_TERMINAL_UNSPECIFIED":
            code, ref = "REPORT_SIGNATURE_INVALID", "3.6"
        return (code, ref, diag_msg.strip() or "verification returned False")

    # Skip the lib's validate_report — its hardcoded production policy
    # (MigrateMA=False, debug=False, smt=True, etc.) is mostly satisfied by
    # the bundle but we instead enforce the fixture's pinned policy below,
    # mirroring the Go binary's enforceSevPolicy.

    # SPEC §3.4 mandatory: VCEK ext ↔ report cross-checks. The lib's
    # validate_report does these but we bypass it to keep policy logic
    # in our hands. Run before fixture policy pins so VCEK_HWID_MISMATCH /
    # VCEK_TCB_MISMATCH surface cleanly.
    vcek_viol = _enforce_sev_vcek_cross_checks(report_bytes, vcek)
    if vcek_viol:
        return vcek_viol

    pol_viol = _enforce_sev_policy(report_bytes, data.get("policy"))
    if pol_viol:
        return pol_viol

    body_fields = _decode_sev_body_fields(report_bytes)
    measurement = Measurement(
        type=PredicateType.SEV_GUEST_V2,
        registers=[body_fields["measurement_hex"]],
    )
    return (measurement, report_bytes, body_fields)


def cmd_verify_attestation_sev() -> int:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"input schema violation: {e}\n")
        return EXIT_BAD_INPUT

    # cmd_verify_attestation_sev requires schema_version explicitly (the
    # verify-full envelope's attestation_sev sub-block omits it; the inner
    # helper defaults to "1").
    if data.get("schema_version") != "1":
        sys.stderr.write('schema_version must be "1"\n')
        return EXIT_BAD_INPUT

    result = _run_verify_attestation_sev_inner(data)
    # Disambiguate success (Measurement, bytes, dict) vs rejection (str, str, str).
    if isinstance(result[0], str):
        code, spec_ref, message = result  # type: ignore[misc]
        return _emit_sev_rejection(code, spec_ref, message)
    _measurement, _report_bytes, body_fields = result
    out_body = {
        "stage": "verify-attestation-sev",
        "accepted": True,
        "outputs": {
            "measurement": {
                "type": SEV_GUEST_V2_URI,
                "registers": [body_fields["measurement_hex"]],
            },
            "body_fields": body_fields,
        },
    }
    json.dump(out_body, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_ACCEPT


# =============================================================================
# verify-full (SPEC §11)
# =============================================================================

def _emit_full_rejection(code: str, stage: str, spec_ref: str, message: str) -> int:
    body = {
        "stage": "verify-full",
        "accepted": False,
        "rejection": {
            "code": code,
            "stage": stage,
            "spec_ref": spec_ref,
            "message": message,
        },
    }
    json.dump(body, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return EXIT_REJECT


def _classify_measurement_compare_error(e: Exception) -> tuple[str, str]:
    """Map measurement-comparison exceptions to SPEC-anchored rejection codes."""
    if isinstance(e, Rtmr3NotZeroError):
        return "MEASUREMENT_RTMR3_NONZERO", "7.3.2"
    if isinstance(e, FormatMismatchError):
        return "MEASUREMENT_TYPE_COMBINATION_UNSUPPORTED", "7.3.5"
    if isinstance(e, MeasurementMismatchError):
        return "MEASUREMENT_MISMATCH", "7.3"
    return "MEASUREMENT_MISMATCH", "7.3"


def cmd_verify_full() -> int:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return _emit_full_rejection(
            "BUNDLE_MALFORMED", "verify-full", "11",
            f"input is not valid JSON: {e}",
        )

    if data.get("schema_version") != "1":
        return _emit_full_rejection(
            "BUNDLE_MALFORMED", "verify-full", "11",
            'input.schema_version != "1"',
        )

    mode = data.get("mode", "")
    if mode in ("standard", "bundle"):
        sig_in = data.get("sigstore")
        if not isinstance(sig_in, dict):
            return _emit_full_rejection(
                "BUNDLE_MALFORMED", "verify-full", "11.1",
                'mode="standard"/"bundle" requires "sigstore" input block',
            )
        sig_result = _run_verify_sigstore_inner(sig_in)
        if isinstance(sig_result, tuple):
            code, spec_ref, msg = sig_result
            return _emit_full_rejection(code, "verify-sigstore", spec_ref, msg)
        sig_measurement = sig_result.measurement

        sev_in = data.get("attestation_sev")
        if not isinstance(sev_in, dict):
            return _emit_full_rejection(
                "BUNDLE_MALFORMED", "verify-full", "11.1",
                'mode="standard"/"bundle" requires attestation_sev '
                "(TDX path not wired yet on Python)",
            )
        sev_result = _run_verify_attestation_sev_inner(sev_in)
        if isinstance(sev_result[0], str):
            code, spec_ref, msg = sev_result  # type: ignore[misc]
            return _emit_full_rejection(code, "verify-attestation-sev", spec_ref, msg)
        att_measurement, _report, _body = sev_result

        try:
            sig_measurement.assert_equal(att_measurement)
        except Exception as e:
            code, spec_ref = _classify_measurement_compare_error(e)
            return _emit_full_rejection(code, "verify-measurement", spec_ref, str(e))

        fp = att_measurement.fingerprint()
        out_body = {
            "stage": "verify-full",
            "accepted": True,
            "outputs": {
                "mode": mode,
                "platform": "sev-snp",
                "sigstore_measurement": {
                    "type": sig_measurement.type.value
                    if hasattr(sig_measurement.type, "value")
                    else str(sig_measurement.type),
                    "registers": sig_measurement.registers,
                },
                "attestation_measurement": {
                    "type": att_measurement.type.value
                    if hasattr(att_measurement.type, "value")
                    else str(att_measurement.type),
                    "registers": att_measurement.registers,
                },
                "final_measurement_fingerprint_hex": fp,
            },
        }
        json.dump(out_body, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return EXIT_ACCEPT

    if mode == "pinned":
        pin_in = data.get("pinned_measurement")
        if not isinstance(pin_in, dict):
            return _emit_full_rejection(
                "BUNDLE_MALFORMED", "verify-full", "11.3",
                'mode="pinned" requires "pinned_measurement"',
            )
        pin_measurement, code, spec_ref = _normalize_measurement(pin_in)
        if pin_measurement is None:
            return _emit_full_rejection(code, "verify-full", spec_ref,
                                        "pinned_measurement invalid")

        sev_in = data.get("attestation_sev")
        if not isinstance(sev_in, dict):
            return _emit_full_rejection(
                "BUNDLE_MALFORMED", "verify-full", "11.3",
                'mode="pinned" requires attestation_sev',
            )
        sev_result = _run_verify_attestation_sev_inner(sev_in)
        if isinstance(sev_result[0], str):
            code, spec_ref, msg = sev_result  # type: ignore[misc]
            return _emit_full_rejection(code, "verify-attestation-sev", spec_ref, msg)
        att_measurement, _report, _body = sev_result

        try:
            pin_measurement.assert_equal(att_measurement)
        except Exception as e:
            code, spec_ref = _classify_measurement_compare_error(e)
            return _emit_full_rejection(code, "verify-measurement", spec_ref, str(e))

        fp = att_measurement.fingerprint()
        out_body = {
            "stage": "verify-full",
            "accepted": True,
            "outputs": {
                "mode": "pinned",
                "platform": "sev-snp",
                "attestation_measurement": {
                    "type": att_measurement.type.value
                    if hasattr(att_measurement.type, "value")
                    else str(att_measurement.type),
                    "registers": att_measurement.registers,
                },
                "final_measurement_fingerprint_hex": fp,
            },
        }
        json.dump(out_body, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return EXIT_ACCEPT

    return _emit_full_rejection(
        "BUNDLE_MALFORMED", "verify-full", "11",
        f"unknown mode {mode!r} (allowed: standard, bundle, pinned)",
    )


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    sub = argv[0] if argv else ""
    if sub == "capabilities":
        json.dump(_capabilities(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return EXIT_ACCEPT
    if sub == "verify-sigstore":
        return cmd_verify_sigstore()
    if sub == "verify-measurement":
        return cmd_verify_measurement()
    if sub == "verify-hardware-measurements":
        return cmd_verify_hardware_measurements()
    if sub == "verify-attestation-tdx":
        return cmd_verify_attestation_tdx()
    if sub == "verify-attestation-sev":
        return cmd_verify_attestation_sev()
    if sub == "verify-full":
        return cmd_verify_full()
    if sub in ("", "help", "-h", "--help"):
        _print_help()
        return EXIT_ACCEPT
    sys.stderr.write(f"tinfoil-conformance: unknown subcommand {sub!r}\n")
    _print_help()
    return EXIT_BAD_INPUT


if __name__ == "__main__":
    sys.exit(main())
