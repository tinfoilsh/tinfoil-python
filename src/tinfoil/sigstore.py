from sigstore.verify import Verifier 
from sigstore.verify.policy import AllOf, OIDCIssuer, GitHubWorkflowRepository, Certificate, _OIDC_GITHUB_WORKFLOW_REF_OID, ExtensionNotFound
from sigstore.models import Bundle
from sigstore.errors import VerificationError
import json
import re

from .attestation import Measurement, PredicateType

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
        if predicate_type == PredicateType.SEV_GUEST_V1:
            try:
                registers = [predicate_fields["measurement"]]
            except KeyError:
                raise ValueError("SEV Guest V1 predicate does not contain measurement")
        elif predicate_type == PredicateType.SNP_TDX_MULTIPLATFORM_v1:
            registers = [predicate_fields["snp_measurement"]]
        else:
            raise ValueError(f"Unsupported predicate type: {predicate_type}")

        return Measurement(
            type=predicate_type,
            registers=registers
        )
        
    except Exception as e:
        raise ValueError(f"Attestation processing failed: {e}") from e
