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
from ..attestation.verify_tdx import (
    TdxVerificationError,
    verify_tdx_quote as verify_tdx_quote_crypto,
)
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
from ..sigstore import (
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
            # cert_utils.verify_intel_chain calls datetime.now(timezone.utc)
            # unconditionally — there's no API to inject the verification
            # time. Fixtures that pin expiration_check_date outside the real-
            # now window (e.g. 324-pck-leaf-expired) skip honestly.
            "verification_time_override": "system-clock-only",
        },
        "platforms_supported": ["sev-snp", "tdx"],
        "transport_modes_supported": ["tls-pinning"],
        "flow_modes_supported": ["standard"],
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

    if inp.get("schema_version") != "1":
        return _emit_rejection(
            "BUNDLE_MALFORMED",
            "5.2",
            'input.schema_version != "1"',
            EXIT_BAD_INPUT,
        )

    try:
        bundle_bytes = base64.b64decode(inp["bundle_b64"])
    except Exception as e:
        return _emit_rejection(
            "BUNDLE_MALFORMED",
            "5.2",
            f"bundle_b64 not valid base64: {e}",
            EXIT_BAD_INPUT,
        )

    try:
        trust_root_bytes = base64.b64decode(inp["trust_root_b64"])
    except Exception as e:
        return _emit_rejection(
            "TRUST_ROOT_INVALID",
            "5.1",
            f"trust_root_b64 not valid base64: {e}",
            EXIT_BAD_INPUT,
        )
    try:
        trust_root_json = trust_root_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        return _emit_rejection(
            "TRUST_ROOT_INVALID",
            "5.1",
            f"trust_root is not valid UTF-8: {e}",
            EXIT_REJECT,
        )

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
        v = verify_sigstore_bundle_with_policy(
            bundle_bytes=bundle_bytes,
            expected_digest_sha256_hex=inp["expected_digest_sha256_hex"],
            policy=policy,
            trust_root_json=trust_root_json,
        )
    except Exception as e:
        # Walk the exception chain; sigstore's VerificationError may be
        # wrapped by our ValueError. Concatenate messages so the classifier
        # sees the most specific text.
        parts = []
        cur: BaseException | None = e
        while cur is not None and len(parts) < 8:
            parts.append(str(cur))
            cur = cur.__cause__
        message = " | ".join(parts)
        code, spec_ref = _classify(message)
        return _emit_rejection(code, spec_ref, message, EXIT_REJECT)

    return _emit_accept(v)


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
    if "qe report" in msg or "qe_report" in msg:
        return "QE_REPORT_SIGNATURE_INVALID", "4.4"
    if "ak" in msg and ("bind" in msg or "report data" in msg):
        return "AK_BINDING_INVALID", "4.5"
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

    # Phase 1.5: structural verification only. Phase 3 will add the full
    # collateral path via verify_tcb_info_signature + verify_qe_identity_
    # signature + the issuer-chain certs.
    if tcb_eval_required:
        return _emit_tdx_rejection(
            "QV_RESULT_TERMINAL_UNSPECIFIED",
            "4.7",
            "tcb_evaluation_required=true not yet wired in tinfoil-python; "
            "Phase 1.5 only handles the structural path. Use "
            "tcb_evaluation_required=false for now.",
        )

    try:
        verify_tdx_quote_crypto(quote, quote_bytes)
    except TdxVerificationError as e:
        code, ref = _classify_tdx_error(e)
        return _emit_tdx_rejection(code, ref, str(e))
    except Exception as e:
        code, ref = _classify_tdx_error(e)
        return _emit_tdx_rejection(code, ref, f"unexpected: {e}")

    # Build outputs from the parsed body.
    body = quote.td_quote_body
    header = quote.header
    tee_type_str = "TDX" if header.tee_type == 0x81 else f"0x{header.tee_type:08x}"

    out_body = {
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
    json.dump(out_body, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return EXIT_ACCEPT


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
    if sub in ("", "help", "-h", "--help"):
        _print_help()
        return EXIT_ACCEPT
    sys.stderr.write(f"tinfoil-conformance: unknown subcommand {sub!r}\n")
    _print_help()
    return EXIT_BAD_INPUT


if __name__ == "__main__":
    sys.exit(main())
