#!/usr/bin/env python3
"""
Simplified AMD SEV-SNP Attestation Verifier (VCEK Chain Only)
"""

import os
from dataclasses import dataclass
from typing import Dict, TypeAlias
import binascii
import requests
from OpenSSL import crypto
import platformdirs

from .abi_sevsnp import (Report, ReportSigner, TCBParts)
from .genoa_cert_chain import (ARK_CERT, ASK_CERT)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ObjectIdentifier
import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Type alias for certificate extensions
Extensions: TypeAlias = Dict[ObjectIdentifier, bytes]

# VCEK cache directory setup (can stay at module level)
_VCEK_CACHE_DIR = platformdirs.user_cache_dir("tinfoil", "tinfoil")
os.makedirs(_VCEK_CACHE_DIR, exist_ok=True)

class SnpOid:
    """OID extensions for the VCEK, used to verify attestation report"""
    BOOTLOADER = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.1")
    TEE = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.2")
    SNP = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.3")
    STRUCT_VERSION = ObjectIdentifier("1.3.6.1.4.1.3704.1.1")
    PRODUCT_NAME_1 = ObjectIdentifier("1.3.6.1.4.1.3704.1.2")
    BL_SPL = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.1")
    TEE_SPL = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.2")
    SNP_SPL = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.3")
    SPL4 = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.4")
    SPL5 = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.5")
    SPL6 = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.6")
    SPL7 = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.7")
    UCODE = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.8")
    HWID = ObjectIdentifier("1.3.6.1.4.1.3704.1.4")
    CSP_ID = ObjectIdentifier("1.3.6.1.4.1.3704.1.5")

class CertificateChain:
    """Represents the SEV certificate chain (ARK > ASK > VCEK)"""
    ark: x509.Certificate
    ask: x509.Certificate
    vcek: x509.Certificate

    def __init__(self, ark: x509.Certificate, ask: x509.Certificate, vcek: x509.Certificate):
        self.ark = ark
        self.ask = ask
        self.vcek = vcek
    
    @staticmethod
    def _vcek_cache_path(product_name: str, chip_id: bytes, reported_tcb: int) -> str:
        """
        Build a deterministic filename for a given (product, chip_id, tcb).
        Uses the module-level _VCEK_CACHE_DIR.
        """
        chip_hex = chip_id.hex()
        tcb_hex = f"{reported_tcb:016x}"
        filename = f"VCEK_{product_name}_{chip_hex}_{tcb_hex}.der"
        return os.path.join(_VCEK_CACHE_DIR, filename)
    
    @classmethod
    def from_files(cls, ark_path: str, ask_path: str, vcek_path: str) -> 'CertificateChain':
        """Alternative constructor to load certificates from files"""
        ark = cls._load_cert(ark_path)
        ask = cls._load_cert(ask_path)
        vcek = cls._load_cert(vcek_path)
        return cls(ark=ark, ask=ask, vcek=vcek)
    
    @classmethod
    def from_report(cls, report:Report) -> 'CertificateChain':
        productName: str = report.productName

        if productName != "Genoa":
            raise ValueError("This implementation only supports Genoa processors")
        
        # Use the hardcoded certificate chain
        ark = x509.load_pem_x509_certificate(ARK_CERT)
        ask = x509.load_pem_x509_certificate(ASK_CERT)
        
        signer_info = report.signer_info_parsed
        
        if signer_info.signingKey != ReportSigner.VcekReportSigner:
            raise ValueError("This implementation only supports VCEK signed reports")
        
        # Fetch (or load) the VCEK certificate
        vcek_url = _VCEKCertURL(productName, report.chip_id, report.reported_tcb)
        cache_path = cls._vcek_cache_path(productName, report.chip_id, report.reported_tcb)
        
        # 1. Try the on‑disk cache
        if os.path.isfile(cache_path):
            with open(cache_path, "rb") as fh:
                vcek_cert_data = fh.read()
        else:
            # 2. Cache miss → fetch from the KDS endpoint
            try:
                response = requests.get(vcek_url, timeout=10)
                response.raise_for_status()
                vcek_cert_data = response.content
                # Persist to cache so the next call is instant
                with open(cache_path, "wb") as fh:
                    fh.write(vcek_cert_data)
            except requests.RequestException as e:
                raise ValueError(f"Failed to fetch VCEK certificate: {e}") from e

        # Parse the (cached or freshly‑downloaded) certificate
        try:
            # cryptography 46+ emits a deprecation warning for non‑positive serial numbers.
            # Suppress this specific deprecation warning locally when parsing VCEK DER.
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=r"Parsed a serial number which wasn't positive",
                    category=CryptographyDeprecationWarning,
                )
                vcek = x509.load_der_x509_certificate(vcek_cert_data)
        except Exception as e:
            # Corrupted cache?  Remove and propagate error so caller can retry.
            if os.path.exists(cache_path):
                try:
                    os.remove(cache_path)
                except OSError:
                    pass
            raise ValueError(f"Failed to parse VCEK certificate: {e}") from e
        
        # Return the complete certificate chain
        return cls(ark=ark, ask=ask, vcek=vcek)
    
    @staticmethod
    def _load_cert(filepath: str) -> x509.Certificate:
        """Load an X.509 certificate from file"""
        _, ext = os.path.splitext(filepath)
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if ext.lower() == '.pem':
            return x509.load_pem_x509_certificate(data)
        else:
            # Suppress cryptography deprecation warnings for DER parsing as above.
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=r"Parsed a serial number which wasn't positive",
                    category=CryptographyDeprecationWarning,
                )
                return x509.load_der_x509_certificate(data)
        
    def verify_chain(self) -> bool:
        # Validate VCEK format
        try:
            self._validate_vcek_format()        
        except ValueError as e:
            print(f"VCEK certificate validation failed: {e}")
            return False

        # Validate ARK and ASK format
        try:
            self._validate_ark_format()
        except ValueError as e:
            print(f"ARK certificate validation failed: {e}")
            return False
        try:
            self._validate_ask_format()
        except ValueError as e:
            print(f"ASK certificate validation failed: {e}")
            return False
        
        # Verify the certificate chain using OpenSSL
        try:
            # Create a store and add the root (ARK) certificate
            store = crypto.X509Store()
            store.add_cert(crypto.X509.from_cryptography(self.ark))
            
            # Add the intermediate (ASK) certificate
            store.add_cert(crypto.X509.from_cryptography(self.ask))
            
            # Create a store context
            store_ctx = crypto.X509StoreContext(store, crypto.X509.from_cryptography(self.vcek))
            
            # Verify the certificate
            try:
                store_ctx.verify_certificate()
                return True
            except crypto.X509StoreContextError as e:
                print(f"Certificate chain verification failed: {e}")
                return False
                
        except Exception as e:
            print(f"Error during chain verification: {e}")
            return False
    
    def _validate_ark_format(self):
        if self.ark.version != x509.Version.v3:
            raise ValueError("ARK certificate version is not 3")
        if not _validateAmdLocation(self.ark.issuer):
            raise ValueError("ARK certificate issuer is not a valid AMD location")
        if not _validateAmdLocation(self.ark.subject):
            raise ValueError("ARK certificate subject is not a valid AMD location")
        
        cn = self.ark.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn != "SEV-Genoa":
            raise ValueError(f"ARK certificate subject common name is not SEV-Genoa but {cn}")
        
        # TODO add support for Certificate Revocation Lists        
        # NOTE Here the go implementation cross check Sev format with the X509 certificate but we only trust the certificate we ship with the code
    
    def _validate_ask_format(self):
             # Validate ASK format
        if self.ask.version != x509.Version.v3:
            raise ValueError("ASK certificate version is not 3")
        if not _validateAmdLocation(self.ask.issuer):
            raise ValueError("ASK certificate issuer is not a valid AMD location")
        if not _validateAmdLocation(self.ask.subject):
            raise ValueError("ASK certificate subject is not a valid AMD location")
        
        cn = self.ask.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn != "ARK-Genoa":
            raise ValueError(f"ASK certificate subject common name is not ARK-Genoa but {cn}")
        
        # TODO add support for Certificate Revocation Lists
        # NOTE Here the go implementation cross check Sev format with the X509 certificate but we only trust the certificate we ship with the code
    
    def _validate_vcek_format(self):
        """Validate the format of a VCEK certificate"""
        
        if self.vcek.version != x509.Version.v3:
            raise ValueError(f"VCEK certificate version is not 3 but {self.vcek.version}")
        
        if self.vcek.signature_algorithm_oid != x509.SignatureAlgorithmOID.RSASSA_PSS:
            raise ValueError(f"VCEK certificate signature algorithm is not RSASSA_PSS but {self.vcek.signature_algorithm_oid}")
        
        if self.vcek.public_key_algorithm_oid != x509.PublicKeyAlgorithmOID.EC_PUBLIC_KEY:
            raise ValueError(f"VCEK certificate public key algorithm is not ECDSA but {self.vcek.public_key_algorithm_oid}")
        
        if self.vcek.public_key().curve.name != "secp384r1":
            raise ValueError(f"VCEK certificate public key curve is not secp384r1 but {self.vcek.public_key().curve.name}")
        
        # Validate KDS Cert Subject
        if not _validateAmdLocation(self.vcek.subject):
            raise ValueError("VCEK certificate subject is not a valid AMD location")

        cn = self.vcek.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn != "SEV-VCEK":
            raise ValueError(f"VCEK certificate subject common name is not SEV-VCEK but {cn}")

        # Get KDS and validate Cert Extensions
        extensions = _get_certificate_extensions(self.vcek)
        if SnpOid.CSP_ID in extensions:
            raise ValueError(f"unexpected CSP_ID in VCEK certificate: {extensions[SnpOid.CSP_ID]}")

        if (SnpOid.HWID not in extensions) or len(extensions[SnpOid.HWID]) != 64: # ChipIDSize
            raise ValueError(f"missing HWID extension for VCEK certificate")

        if extensions[SnpOid.PRODUCT_NAME_1] != b'\x16\x05Genoa':
            raise ValueError(f"unexpected PRODUCT_NAME_1 in VCEK certificate: {extensions[SnpOid.PRODUCT_NAME_1]}")
        
    def validate_vcek_tcb(self, tcb: TCBParts):
        """Validate the TCB extension in the VCEK certificate matches a given TCB"""
        extensions = _get_certificate_extensions(self.vcek)
        
        if SnpOid.BL_SPL not in extensions:
            raise ValueError(f"missing BL_SPL extension for VCEK certificate")
        bl_spl = _decode_der_integer(extensions[SnpOid.BL_SPL])
        if bl_spl != tcb.bl_spl:
            raise ValueError(f"BL_SPL extension in VCEK certificate does not match tcb.bl_spl: {bl_spl} != {tcb.bl_spl}")
            
        if SnpOid.TEE_SPL not in extensions:
            raise ValueError(f"missing TEE_SPL extension for VCEK certificate")
        tee_spl = _decode_der_integer(extensions[SnpOid.TEE_SPL])
        if tee_spl != tcb.tee_spl:
            raise ValueError(f"TEE_SPL extension in VCEK certificate does not match tcb.tee_spl: {tee_spl} != {tcb.tee_spl}")
            
        if SnpOid.SNP_SPL not in extensions:
            raise ValueError(f"missing SNP_SPL extension for VCEK certificate")
        snp_spl = _decode_der_integer(extensions[SnpOid.SNP_SPL])
        if snp_spl != tcb.snp_spl:
            raise ValueError(f"SNP_SPL extension in VCEK certificate does not match tcb.snp_spl: {snp_spl} != {tcb.snp_spl}")
            
        if SnpOid.UCODE not in extensions:
            raise ValueError(f"missing UCODE extension for VCEK certificate")
        ucode_spl = _decode_der_integer(extensions[SnpOid.UCODE])
        if ucode_spl != tcb.ucode_spl:
            raise ValueError(f"UCODE extension in VCEK certificate does not match tcb.ucode_spl: {ucode_spl} != {tcb.ucode_spl}")
        
    def validate_vcek_hwid(self, chip_id: bytes):
        """Validate the HWID extension in the VCEK certificate matches a given chip id"""
        extensions = _get_certificate_extensions(self.vcek)
        if SnpOid.HWID not in extensions:
            raise ValueError(f"missing HWID extension for VCEK certificate")
        if extensions[SnpOid.HWID] != chip_id:
            raise ValueError(f"HWID extension in VCEK certificate does not match chip_id: {extensions[SnpOid.HWID]} != {chip_id}")
    

## HELPER FUNCTIONS

def _get_certificate_extensions(cert: x509.Certificate) -> Extensions:
    """Get the extensions from the VCEK certificate"""
    extensions = {}
    for ext in cert.extensions:
        extensions[ext.oid] = ext.value.value
    return extensions

def _decode_der_integer(der_bytes: bytes) -> int:
    """Decode a DER-encoded INTEGER"""
    if len(der_bytes) < 2 or der_bytes[0] != 0x02:
        raise ValueError(f"Invalid DER INTEGER: {der_bytes.hex()}")
    
    length = der_bytes[1]
    if len(der_bytes) != 2 + length:
        raise ValueError(f"Invalid DER INTEGER length: {der_bytes.hex()}")
    
    # Convert the integer bytes to int (big-endian)
    return int.from_bytes(der_bytes[2:2+length], byteorder='big')

def _validateAmdLocation(name: x509.Name) -> bool:
    """Validate that the certificate subject name matches AMD's expected values.
    
    Args:
        name: The x509.Name object to validate
        
    Returns:
        bool: True if all fields match expected values, False otherwise
    """
    def check_singleton_list(values: list[str], field_name: str, expected: str) -> bool:
        if len(values) != 1:
            print(f"Expected exactly one {field_name}, got {len(values)}")
            return False
        if values[0] != expected:
            print(f"Unexpected {field_name} value: '{values[0]}', expected '{expected}'")
            return False
        return True
    
    # Get the name attributes
    country = name.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
    locality = name.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)
    state = name.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)
    org = name.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    org_unit = name.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
    
    # Extract the values from the attributes
    country_values = [attr.value for attr in country]
    locality_values = [attr.value for attr in locality]
    state_values = [attr.value for attr in state]
    org_values = [attr.value for attr in org]
    org_unit_values = [attr.value for attr in org_unit]
    
    # Validate each field
    if not check_singleton_list(country_values, "country", "US"):
        return False
    if not check_singleton_list(locality_values, "locality", "Santa Clara"):
        return False
    if not check_singleton_list(state_values, "state", "CA"):
        return False
    if not check_singleton_list(org_values, "organization", "Advanced Micro Devices"):
        return False
    if not check_singleton_list(org_unit_values, "organizational unit", "Engineering"):
        return False
    
    return True

def _VCEKCertURL(productName: str, chip_id: bytes, reported_tcb: int) -> str:
    # TODO add support for other product names
    """Generate the VCEK certificate URL based on the product name, chip ID, and reported TCB"""
    parts = TCBParts.from_int(reported_tcb)
    base_url = "https://kds-proxy.tinfoil.sh/vcek/v1"
    chip_id_hex = binascii.hexlify(chip_id).decode('ascii')
    return f"{base_url}/{productName}/{chip_id_hex}?blSPL={parts.bl_spl}&teeSPL={parts.tee_spl}&snpSPL={parts.snp_spl}&ucodeSPL={parts.ucode_spl}"

def _verify_report_signature(vcek: x509.Certificate, report: Report) -> bool:
    """Verify the attestation report signature using VCEK's public key"""

    # Validate Report Format
    POLICY_RESERVED_1_BIT = 17

    if report.version < 2:
        raise ValueError(f"Report version is lower than 2: is {report.version}")

    # Check reserved bit must be 1
    if not (report.policy & (1 << POLICY_RESERVED_1_BIT)):
        raise ValueError(f"policy[{POLICY_RESERVED_1_BIT}] is reserved, must be 1, got 0")
    
    # Check bits 63-21 must be zero
    if report.policy >> 21:
        raise ValueError("policy bits 63-21 must be zero")

    try:
        # Check signature algorithm
        if report.signature_algo != 1:  # 1 = SignEcdsaP384Sha384
            print(f"Unknown SignatureAlgo: {report.signature_algo}")
            return False
            
        # Verify the public key is an EC key
        public_key = vcek.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            print("VCEK doesn't contain an EC public key")
            return False
        
        # Convert the raw signature to DER format
        # The signature in the report is in raw R||S format in AMD's little-endian format
        # Each component is 72 bytes (0x48) for P384
        r_bytes = bytes(reversed(report.signature[0:0x48]))  # Reverse bytes for big-endian
        s_bytes = bytes(reversed(report.signature[0x48:0x90]))  # Reverse bytes for big-endian
        
        r = int.from_bytes(r_bytes.lstrip(b'\x00'), byteorder='big')
        s = int.from_bytes(s_bytes.lstrip(b'\x00'), byteorder='big')
        
        der_signature = utils.encode_dss_signature(r, s)
        
        # Verify signature
        public_key.verify(
            der_signature,
            report.signed_data,
            ec.ECDSA(hashes.SHA384())
        )
        return True
    except Exception as e:
        print(f"Attestation signature verification failed: {e}")
        return False

def verify_attestation(chain: CertificateChain, report: Report) -> bool:
    """Verify attestation report with the certificate chain"""
    try:
        # Verify certificate chain
        if not chain.verify_chain():
            # Since verify_chain() already prints its own error messages
            return False

        # Verify report
        if not _verify_report_signature(chain.vcek, report):
            return False
        
        return True
    
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Simplified AMD SEV-SNP Attestation Verifier")
    parser.add_argument("--ark", required=True, help="Path to ARK certificate")
    parser.add_argument("--ask", required=True, help="Path to ASK certificate")
    parser.add_argument("--vcek", required=True, help="Path to VCEK certificate")
    parser.add_argument("--report", required=True, help="Path to attestation report")
    
    args = parser.parse_args()
    
    # Load certificate chain
    chain = CertificateChain.from_files(args.ark, args.ask, args.vcek)

    # Read and parse attestation report
    with open(args.report, 'rb') as f:
        report_data = f.read()
        
    report = Report(report_data)
    
    result = verify_attestation(chain, report)
    if result:
        print("Attestation verification successful")
        return 0
    else:
        print("Attestation verification failed")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())