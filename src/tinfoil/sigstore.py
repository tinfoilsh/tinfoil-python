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
        # Create verifier with the trusted root
        verifier = Verifier.production()
        
        # Parse the bundle
        bundle = Bundle.from_json(bundle_json)
        
        # Create verification policy for GitHub Actions certificate identity
        policy = AllOf([
            OIDCIssuer(OIDC_ISSUER),
            GitHubWorkflowRepository(repo),
            GitHubWorkflowRefPattern("refs/tags/.*")
        ])
        
        # --- Core DSSE Verification ---
        # This verifies the signature on the DSSE envelope, applies the
        # certificate identity policy, and checks Rekor log consistency.
        # It returns the verified payload from within the envelope.
        payload_type, payload_bytes = verifier.verify_dsse(bundle, policy)

        # --- Process the Verified Payload ---
        if payload_type != 'application/vnd.in-toto+json':
            raise ValueError(f"Unsupported payload type: {payload_type}. Only supports In-toto.")
        
        result_json = json.loads(payload_bytes)
        predicate_type = PredicateType(result_json["predicateType"])
        predicate_fields = result_json["predicate"]

        # --- Manual Payload Digest Verification ---
        # Now, verify that the provided external digest matches the
        # actual digest in the payload returned from the verified envelope.
        if digest != result_json["subject"][0]["digest"]["sha256"]:
            raise ValueError(
                f"Provided digest does not match verified DSSE payload digest. "
                f"Expected: {digest}, Got: {result_json['subject'][0]['digest']['sha256']}"
            )
        
        # Convert predicate type to measurement type
        if predicate_type == PredicateType.SNP_TDX_MULTIPLATFORM_v1:
            # Extract snp_measurement from root
            snp_measurement = predicate_fields.get("snp_measurement")
            if not snp_measurement:
                raise ValueError("Invalid multiplatform measurement: no snp_measurement")

            # Extract rtmr1 and rtmr2 from nested tdx_measurement struct
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


def fetch_hardware_measurements(bundle_json: bytes, digest: str, repo: str) -> List[HardwareMeasurement]:
    """
    Fetches and verifies hardware measurements from a Sigstore bundle.

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

        result_json = json.loads(payload_bytes)
        predicate_type = result_json["predicateType"]

        if predicate_type != PredicateType.HARDWARE_MEASUREMENTS_V1.value:
            raise ValueError(f"Unexpected predicate type: {predicate_type}")

        # Verify digest
        if digest != result_json["subject"][0]["digest"]["sha256"]:
            raise ValueError(
                f"Digest mismatch: expected {digest}, got {result_json['subject'][0]['digest']['sha256']}"
            )

        predicate_fields = result_json["predicate"]
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
    digest = fetch_latest_digest(HARDWARE_MEASUREMENTS_REPO)
    bundle_json = fetch_attestation_bundle(HARDWARE_MEASUREMENTS_REPO, digest)
    return fetch_hardware_measurements(bundle_json, digest, HARDWARE_MEASUREMENTS_REPO)
