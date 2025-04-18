import sigstore
from sigstore.verify import Verifier 
from sigstore.verify.policy import AllOf, OIDCIssuer, GitHubWorkflowRepository, GitHubWorkflowRef, GitHubWorkflowSHA, Certificate, _OIDC_GITHUB_WORKFLOW_REF_OID, ExtensionNotFound
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
        self._pattern = pattern.replace("*", ".*")  # Convert glob to regex pattern
        
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

def verify_attestation(bundle_json: bytes, hexdigest: str, repo: str) -> Measurement:
    """
    Verifies the attested measurements of an enclave image against a trusted root (Sigstore)
    and returns the measurement payload contained in the DSSE.
    
    Args:
        trusted_root: The trusted root JSON data
        bundle_json: The bundle JSON data
        hexdigest: The hex-encoded digest to verify
        repo: The repository name
        
    Returns:
        Measurement: The verified measurement data
        
    Raises:
        ValueError: If verification fails
    """
    try:
        # Create verifier with the trusted root
        verifier = Verifier.production()
        
        # Parse the bundle
        bundle = Bundle.from_json(bundle_json)
        
        # Create verification policy for GitHub Actions
        # TODO: missing hexdigest here
        policy = AllOf([
            OIDCIssuer(OIDC_ISSUER),
            #GitHubWorkflowSHA(hexdigest),
            GitHubWorkflowRepository(repo),
            GitHubWorkflowRefPattern("refs/tags/*")  # If you specifically want to verify tag-based workflows
        ])
        
        # Verify the bundle
        result = verifier.verify_dsse(bundle, policy)
        
        # Extract predicate type and fields from result
        if result[0] != 'application/vnd.in-toto+json':
            raise ValueError("Only supports In-toto format")
        
        result_json = json.loads(result[1])
        predicate_type = PredicateType(result_json["predicateType"])
        predicate_fields = result_json["predicate"]
        
        # Convert predicate type to measurement type
        if predicate_type == PredicateType.AWS_NITRO_ENCLAVE_V1:
            try:
                registers = [
                    predicate_fields["PCR0"],
                    predicate_fields["PCR1"],
                    predicate_fields["PCR2"],
                ]
            except KeyError:
                raise ValueError("AWS Nitro Enclave V1 predicate does not contain PCR0, PCR1, or PCR2")
        elif predicate_type == PredicateType.SEV_GUEST_V1:
            try:
                registers = [predicate_fields["measurement"]]
            except KeyError:
                raise ValueError("SEV Guest V1 predicate does not contain measurement")
        else:
            raise ValueError(f"Unsupported predicate type: {predicate_type}")
            
        return Measurement(
            type=predicate_type,
            registers=registers
        )
        
    except Exception as e:
        raise ValueError(f"Verification failed: {e}")
    
