import base64
import binascii
from dataclasses import dataclass
from enum import Enum
import json
from verify import Report, verify_attestation, CertificateChain



class MeasurementType(Enum):
    SEV_GUEST_V1 = "SEV_GUEST_V1"

@dataclass
class Measurement:
    type: MeasurementType
    registers: list[str]

@dataclass
class Verification:
    measurement: Measurement
    cert_fp: bytes

def verify_sev_attestation(attestation_doc: str) -> Verification:
    """Verify SEV attestation document and return verification result."""
    try:
        att_doc_bytes = base64.b64decode(attestation_doc)
    except Exception as e:
        raise ValueError(f"Failed to decode base64: {e}")
    
    # Parse the report
    try:
        report = Report(att_doc_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse report: {e}")
    
    # Get attestation chain
    chain: CertificateChain = CertificateChain.from_report(report)

    # Verify attestation
    try:
        res = verify_attestation(chain, report)
    except Exception as e:
        raise ValueError(f"Failed to verify attestation: {e}")
    
    if res!= True:
        raise ValueError("Attestation verification failed!")

    # Create measurement object
    measurement = Measurement(
        type=MeasurementType.SEV_GUEST_V1,
        registers=[
            report.measurement.hex()
        ]
    )

    # The certificate fingerprint is at the start of the report (32 bytes)
    cfp = report.report_data.decode()

    return Verification(
        measurement=measurement,
        cert_fp=cfp
    )
