from sigstore.verify import Verifier 
from sigstore.verify.policy import AllOf, OIDCIssuer, GitHubWorkflowRepository, Certificate, _OIDC_GITHUB_WORKFLOW_REF_OID, ExtensionNotFound
from sigstore.models import Bundle
from sigstore.errors import VerificationError
import json
import re

from typing import List
from .attestation import Measurement, PredicateType, HardwareMeasurement
from .github import fetch_latest_digest, fetch_attestation_bundle

OIDC_ISSUER = "https://token.actions.githubusercontent.com"

class GitHubWorkflowRefPattern:
    """
    Verifies the certificate's GitHub Actions workflow ref using pattern matching.
    """
    def __init__(self, pattern: str) -> None:
        self._pattern = pattern
        
    def verify(self, cert: Certificate) -> None:
        try:
            ext = cert.extensions.get_extension_for_oid(_OIDC_GITHUB_WORKFLOW_REF_OID).value
            ext_value = ext.value.decode()
            if not re.match(self._pattern, ext_value):
                raise VerificationError(
                    f"Certificate's GitHubWorkflowRef does not match pattern "
                    f"(got '{ext_value}', expected pattern '{self._pattern}')"
                )
        except ExtensionNotFound:
            raise VerificationError(
                f"Certificate does not contain GitHubWorkflowRef "
                f"({_OIDC_GITHUB_WORKFLOW_REF_OID.dotted_string}) extension"
            )


def _verify_dsse_bundle(bundle_json: bytes, digest: str, repo: str) -> dict:
    """
    Verify a Sigstore DSSE bundle and return the parsed in-toto payload.

    Performs signature verification, certificate identity policy checks,
    Rekor log consistency, payload type validation, and digest matching.

    Args:
        bundle_json: Raw Sigstore bundle JSON
        digest: Expected SHA256 hex digest of the DSSE payload subject
        repo: GitHub repository (e.g. "tinfoilsh/confidential-router")

    Returns:
        Parsed in-toto statement dict with predicateType, predicate, subject, etc.

    Raises:
        ValueError: If any verification step fails
    """
    verifier = Verifier.production()
    bundle = Bundle.from_json(bundle_json)

    policy = AllOf([
        OIDCIssuer(OIDC_ISSUER),
        GitHubWorkflowRepository(repo),
        GitHubWorkflowRefPattern("refs/tags/.*")
    ])

    payload_type, payload_bytes = verifier.verify_dsse(bundle, policy)

    if payload_type != 'application/vnd.in-toto+json':
        raise ValueError(f"Unsupported payload type: {payload_type}")

    statement = json.loads(payload_bytes)

    subjects = statement.get("subject", [])
    if not subjects or "digest" not in subjects[0] or "sha256" not in subjects[0].get("digest", {}):
        raise ValueError("Invalid in-toto statement: missing or empty subject")

    if digest != subjects[0]["digest"]["sha256"]:
        raise ValueError(
            f"Digest mismatch: expected {digest}, "
            f"got {subjects[0]['digest']['sha256']}"
        )

    return statement


def verify_attestation(bundle_json: bytes, digest: str, repo: str) -> Measurement:
    """
    Verifies the attested measurements of an enclave image against a trusted root (Sigstore)
    and returns the measurement payload contained in the DSSE.
    
    Args:
        bundle_json: The bundle JSON data (bytes)
        digest: The expected hex-encoded SHA256 digest of the DSSE payload
        repo: The repository name
        
    Returns:
        Measurement: The verified measurement data
        
    Raises:
        ValueError: If verification fails or digests don't match
    """
    try:
        statement = _verify_dsse_bundle(bundle_json, digest, repo)

        predicate_type = PredicateType(statement["predicateType"])
        predicate_fields = statement["predicate"]

        if predicate_type == PredicateType.SNP_TDX_MULTIPLATFORM_v1:
            snp_measurement = predicate_fields.get("snp_measurement")
            if not snp_measurement:
                raise ValueError("Invalid multiplatform measurement: no snp_measurement")

            tdx_measurement = predicate_fields.get("tdx_measurement")
            if not tdx_measurement:
                raise ValueError("Invalid multiplatform measurement: no tdx_measurement")

            rtmr1 = tdx_measurement.get("rtmr1")
            rtmr2 = tdx_measurement.get("rtmr2")
            if not rtmr1 or not rtmr2:
                raise ValueError("Invalid multiplatform measurement: missing rtmr1 or rtmr2")

            registers = [snp_measurement, rtmr1, rtmr2]
        else:
            raise ValueError(f"Unsupported predicate type: {predicate_type}")

        return Measurement(
            type=predicate_type,
            registers=registers
        )

    except Exception as e:
        raise ValueError(f"Attestation processing failed: {e}") from e


HARDWARE_MEASUREMENTS_REPO = "tinfoilsh/hardware-measurements"


def verify_hardware_measurements(bundle_json: bytes, digest: str, repo: str) -> List[HardwareMeasurement]:
    """
    Verifies hardware measurements from a Sigstore bundle.

    Args:
        bundle_json: The bundle JSON data (bytes)
        digest: The expected hex-encoded SHA256 digest
        repo: The repository name

    Returns:
        List of HardwareMeasurement objects

    Raises:
        ValueError: If verification fails or predicate type is unexpected
    """
    try:
        statement = _verify_dsse_bundle(bundle_json, digest, repo)

        predicate_type = statement["predicateType"]
        if predicate_type != PredicateType.HARDWARE_MEASUREMENTS_V1.value:
            raise ValueError(f"Unexpected predicate type: {predicate_type}")

        predicate_fields = statement["predicate"]
        measurements = []

        for platform_id, platform_data in predicate_fields.items():
            if not isinstance(platform_data, dict):
                raise ValueError(f"Invalid hardware measurement for {platform_id}")

            mrtd = platform_data.get("mrtd")
            rtmr0 = platform_data.get("rtmr0")

            if not mrtd or not rtmr0:
                raise ValueError(f"Invalid hardware measurement for {platform_id}: missing mrtd or rtmr0")

            measurements.append(HardwareMeasurement(
                id=f"{platform_id}@{digest}",
                mrtd=mrtd,
                rtmr0=rtmr0,
            ))

        return measurements

    except Exception as e:
        raise ValueError(f"Hardware measurements processing failed: {e}") from e


def fetch_latest_hardware_measurements() -> List[HardwareMeasurement]:
    """
    Fetches the latest hardware measurements from GitHub + Sigstore.

    Returns:
        List of HardwareMeasurement objects

    Raises:
        ValueError: If fetching or verification fails
    """
    try:
        digest = fetch_latest_digest(HARDWARE_MEASUREMENTS_REPO)
        bundle_json = fetch_attestation_bundle(HARDWARE_MEASUREMENTS_REPO, digest)
        return verify_hardware_measurements(bundle_json, digest, HARDWARE_MEASUREMENTS_REPO)
    except Exception as e:
        raise ValueError(f"Hardware measurements fetching failed: {e}") from e
