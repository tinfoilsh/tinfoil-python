import argparse
import logging
import sys

# Adjust these imports based on your project structure
from tinfoil.github import fetch_latest_digest, fetch_attestation_bundle
from tinfoil.sigstore import verify_attestation
from tinfoil.attestation import fetch_attestation

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--repo', 
                       default='tinfoilsh/provably-private-deepseek-r1',
                       help='Repository name')
    parser.add_argument('-e', '--enclave',
                       default='inference.delta.tinfoil.sh',
                       help='Enclave address')
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        format='%(message)s',
        level=logging.INFO
    )

    try:
        # Fetch latest release
        logging.info(f"Fetching latest release for {args.repo}")
        try:
            digest = fetch_latest_digest(args.repo)
        except Exception as e:
            logging.error(f"Error fetching latest digest: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

        # Fetch attestation bundle
        logging.info(f"Fetching attestation bundle for {args.repo}@{digest}")
        sigstore_bundle = fetch_attestation_bundle(args.repo, digest)

        # Verify attested measurements
        logging.info(f"Verifying attested measurements for {args.repo}@{digest}")
        code_measurements = verify_attestation(
            sigstore_bundle,
            digest,
            args.repo
        )

        # Fetch runtime attestation
        logging.info(f"Fetching runtime attestation from {args.enclave}")
        enclave_attestation = fetch_attestation(args.enclave)

        # Verify enclave measurements
        logging.info("Verifying enclave measurements")
        verification = enclave_attestation.verify()

        # Compare measurements
        logging.info("Comparing measurements")
        if not code_measurements.equals(verification.measurement):
            raise ValueError("Code measurements do not match")

        # Success output
        logging.info("Verification successful!")
        logging.info(f"Public key fingerprint: {verification.public_key_fp}")
        logging.info(f"Measurement: {code_measurements.fingerprint()}")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
