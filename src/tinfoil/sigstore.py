import sigstore
from sigstore.verify import Verifier 
from sigstore.verify.policy import VerificationPolicy, AllOf, OIDCIssuer, GitHubWorkflowRepository, GitHubWorkflowRef
from sigstore.models import Bundle
import binascii

from .attestation import Measurement, PredicateType

OIDC_ISSUER = "https://token.actions.githubusercontent.com"

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
        bundle = Bundle.parse_raw(bundle_json)
        
        # Create verification policy for GitHub Actions
        policy = VerificationPolicy(
            artifact_digest=("sha256", binascii.unhexlify(hexdigest)),
            certificate_identity=AllOf([
                OIDCIssuer(OIDC_ISSUER),
                GitHubWorkflowRepository(repo),
                GitHubWorkflowRef("refs/tags/*")  # If you specifically want to verify tag-based workflows
            ])
        )
        
        # Verify the bundle
        result = verifier.verify_dsse(bundle, policy)
        
        # Extract predicate type and fields from result
        predicate_type = result.statement.predicate_type
        predicate_fields = result.statement.predicate.fields
        
        # Convert predicate type to measurement type
        if predicate_type == "AWS_NITRO_ENCLAVE_V1":
            measurement_type = PredicateType.AWS_NITRO_ENCLAVE_V1
            registers = [
                predicate_fields["PCR0"].string_value,
                predicate_fields["PCR1"].string_value,
                predicate_fields["PCR2"].string_value,
            ]
        elif predicate_type == "SEV_GUEST_V1":
            measurement_type = PredicateType.SEV_GUEST_V1
            registers = [predicate_fields["measurement"].string_value]
        else:
            raise ValueError(f"Unsupported predicate type: {predicate_type}")
            
        return Measurement(
            type=measurement_type,
            registers=registers
        )
        
    except Exception as e:
        raise ValueError(f"Verification failed: {e}")
    
