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
                       default='tinfoilsh/confidential-deepseek-r1-70b-prod',
                       help='Repository name')
    parser.add_argument('-e', '--enclave',
                       default='deepseek-r1-70b-p.model.tinfoil.sh',
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
        try:
            sigstore_bundle = fetch_attestation_bundle(args.repo, digest)
        except Exception as e:
            logging.error(f"Error fetching attestation bundle: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

        # Verify attested measurements
        logging.info(f"Verifying attested measurements for {args.repo}@{digest}")
        try:
            code_measurements = verify_attestation(
                sigstore_bundle,
                digest,
                args.repo
            )
        except Exception as e:
            logging.error(f"Error verifying attested measurements: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

        # Fetch runtime attestation
        logging.info(f"Fetching runtime attestation from {args.enclave}")
        try:
            enclave_attestation = fetch_attestation(args.enclave)
        except Exception as e:
            logging.error(f"Error fetching runtime attestation: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

        # Verify enclave measurements
        logging.info("Verifying enclave measurements")
        try:
            verification = enclave_attestation.verify()
        except Exception as e:
            logging.error(f"Error verifying enclave measurements: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

        print(code_measurements)
        print(verification.measurement)
        # Compare measurements
        logging.info("Comparing measurements")
        try:
            for (i, code_measurement) in enumerate(code_measurements.registers):
                if code_measurement != verification.measurement.registers[i]:
                    raise ValueError("Code measurements do not match")
        except Exception as e:
            logging.error(f"Error comparing measurements: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

        # Success output
        logging.info("Verification successful!")
        logging.info(f"Public key fingerprint: {verification.public_key_fp}")
        logging.info(f"Measurement: {code_measurements.fingerprint()}")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
