"""The AMD VCEK certificate chain (ARK, ASK, VCEK): format checks, chain verification and the report signature.

The ARK and ASK come from the embedded AMD trust material; the VCEK comes
from the caller, who takes it from the attestation document.
"""

from __future__ import annotations

import warnings
from typing import TypeAlias

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import ObjectIdentifier
from OpenSSL import crypto
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type.char import IA5String as Asn1IA5String
from pyasn1.type.univ import Integer as Asn1Integer

from tinfoil._v3.verifier._quote.sev.lib.abi import Report, ReportSigner
from tinfoil._v3.verifier._quote.sev.lib.tcb import TCBParts
from tinfoil._v3.verifier._trust import AMD_GENOA_CERT_CHAIN_PEM

# Type alias for certificate extensions
Extensions: TypeAlias = dict[ObjectIdentifier, bytes]


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


def genoa_ask_ark() -> tuple[x509.Certificate, x509.Certificate]:
    """The embedded AMD Genoa ASK and ARK certificates, in that order."""
    ask, ark = x509.load_pem_x509_certificates(AMD_GENOA_CERT_CHAIN_PEM)
    return ask, ark


def load_vcek_der(vcek_der: bytes) -> x509.Certificate:
    """Parse a DER VCEK certificate.

    AMD issues VCEKs with a non-positive serial number, which the parser
    reports as a deprecation warning; the warning is suppressed here.
    """
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r"Parsed a serial number which wasn't positive",
                category=CryptographyDeprecationWarning,
            )
            return x509.load_der_x509_certificate(vcek_der)
    except Exception as e:
        raise ValueError(f"Failed to parse VCEK certificate: {e}") from e


class CertificateChain:
    """Represents the SEV certificate chain (ARK > ASK > VCEK)"""

    ark: x509.Certificate
    ask: x509.Certificate
    vcek: x509.Certificate

    def __init__(self, ark: x509.Certificate, ask: x509.Certificate, vcek: x509.Certificate):
        self.ark = ark
        self.ask = ask
        self.vcek = vcek

    @classmethod
    def from_report(cls, report: Report, vcek_der: bytes) -> CertificateChain:
        """Build the chain for a report from the embedded Genoa ASK and ARK and the supplied VCEK.

        The VCEK is validated against the AMD ARK/ASK root chain in
        ``verify_chain``, so accepting it here does not weaken trust.
        """
        productName: str = report.productName

        if productName != "Genoa":
            raise ValueError("This implementation only supports Genoa processors")

        ask, ark = genoa_ask_ark()

        signer_info = report.signer_info_parsed

        if signer_info.signingKey != ReportSigner.VcekReportSigner:
            raise ValueError("This implementation only supports VCEK signed reports")

        if not vcek_der:
            raise ValueError("A VCEK certificate is required")

        vcek = load_vcek_der(vcek_der)

        # Return the complete certificate chain
        return cls(ark=ark, ask=ask, vcek=vcek)

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

    def _validate_ark_format(self) -> None:
        if self.ark.version != x509.Version.v3:
            raise ValueError("ARK certificate version is not 3")
        if not _validateAmdLocation(self.ark.issuer):
            raise ValueError("ARK certificate issuer is not a valid AMD location")
        if not _validateAmdLocation(self.ark.subject):
            raise ValueError("ARK certificate subject is not a valid AMD location")

        cn = self.ark.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn != "ARK-Genoa":
            raise ValueError(f"ARK certificate subject common name is not ARK-Genoa but {cn!r}")

        # TODO add support for Certificate Revocation Lists
        # NOTE The ARK is embedded trust material, so its SEV format is not cross-checked against the certificate.

    def _validate_ask_format(self) -> None:
        # Validate ASK format
        if self.ask.version != x509.Version.v3:
            raise ValueError("ASK certificate version is not 3")
        if not _validateAmdLocation(self.ask.issuer):
            raise ValueError("ASK certificate issuer is not a valid AMD location")
        if not _validateAmdLocation(self.ask.subject):
            raise ValueError("ASK certificate subject is not a valid AMD location")

        cn = self.ask.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn != "SEV-Genoa":
            raise ValueError(f"ASK certificate subject common name is not SEV-Genoa but {cn!r}")

        # TODO add support for Certificate Revocation Lists
        # NOTE The ASK is embedded trust material, so its SEV format is not cross-checked against the certificate.

    def _validate_vcek_format(self) -> None:
        """Validate the format of a VCEK certificate"""

        if self.vcek.version != x509.Version.v3:
            raise ValueError(f"VCEK certificate version is not 3 but {self.vcek.version}")

        if self.vcek.signature_algorithm_oid != x509.SignatureAlgorithmOID.RSASSA_PSS:
            raise ValueError(
                f"VCEK certificate signature algorithm is not RSASSA_PSS but {self.vcek.signature_algorithm_oid}"
            )

        if self.vcek.public_key_algorithm_oid != x509.PublicKeyAlgorithmOID.EC_PUBLIC_KEY:
            raise ValueError(
                f"VCEK certificate public key algorithm is not ECDSA but {self.vcek.public_key_algorithm_oid}"
            )

        public_key = self.vcek.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.name != "secp384r1":
            raise ValueError("VCEK certificate public key curve is not secp384r1")

        # Validate KDS Cert Subject
        if not _validateAmdLocation(self.vcek.subject):
            raise ValueError("VCEK certificate subject is not a valid AMD location")

        cn = self.vcek.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn != "SEV-VCEK":
            raise ValueError(f"VCEK certificate subject common name is not SEV-VCEK but {cn!r}")

        # Get KDS and validate Cert Extensions
        extensions = _get_certificate_extensions(self.vcek)
        if SnpOid.CSP_ID in extensions:
            raise ValueError(f"unexpected CSP_ID in VCEK certificate: {extensions[SnpOid.CSP_ID]!r}")

        if (SnpOid.HWID not in extensions) or len(extensions[SnpOid.HWID]) != 64:  # ChipIDSize
            raise ValueError("missing HWID extension for VCEK certificate")

        product_name = _decode_der_ia5string(extensions[SnpOid.PRODUCT_NAME_1])
        if product_name != "Genoa":
            raise ValueError(f"unexpected PRODUCT_NAME_1 in VCEK certificate: {product_name}")

    def validate_vcek_tcb(self, tcb: TCBParts) -> None:
        """Validate the TCB extension in the VCEK certificate matches a given TCB"""
        extensions = _get_certificate_extensions(self.vcek)

        if SnpOid.BL_SPL not in extensions:
            raise ValueError("missing BL_SPL extension for VCEK certificate")
        bl_spl = _decode_der_integer(extensions[SnpOid.BL_SPL])
        if bl_spl != tcb.bl_spl:
            raise ValueError(
                f"BL_SPL extension in VCEK certificate does not match tcb.bl_spl: {bl_spl} != {tcb.bl_spl}"
            )

        if SnpOid.TEE_SPL not in extensions:
            raise ValueError("missing TEE_SPL extension for VCEK certificate")
        tee_spl = _decode_der_integer(extensions[SnpOid.TEE_SPL])
        if tee_spl != tcb.tee_spl:
            raise ValueError(
                f"TEE_SPL extension in VCEK certificate does not match tcb.tee_spl: {tee_spl} != {tcb.tee_spl}"
            )

        if SnpOid.SNP_SPL not in extensions:
            raise ValueError("missing SNP_SPL extension for VCEK certificate")
        snp_spl = _decode_der_integer(extensions[SnpOid.SNP_SPL])
        if snp_spl != tcb.snp_spl:
            raise ValueError(
                f"SNP_SPL extension in VCEK certificate does not match tcb.snp_spl: {snp_spl} != {tcb.snp_spl}"
            )

        if SnpOid.UCODE not in extensions:
            raise ValueError("missing UCODE extension for VCEK certificate")
        ucode_spl = _decode_der_integer(extensions[SnpOid.UCODE])
        if ucode_spl != tcb.ucode_spl:
            raise ValueError(
                f"UCODE extension in VCEK certificate does not match tcb.ucode_spl: {ucode_spl} != {tcb.ucode_spl}"
            )

    def validate_vcek_hwid(self, chip_id: bytes) -> None:
        """Validate the HWID extension in the VCEK certificate matches a given chip id"""
        extensions = _get_certificate_extensions(self.vcek)
        if SnpOid.HWID not in extensions:
            raise ValueError("missing HWID extension for VCEK certificate")
        if extensions[SnpOid.HWID] != chip_id:
            raise ValueError(
                f"HWID extension in VCEK certificate does not match chip_id: {extensions[SnpOid.HWID]!r} != {chip_id!r}"
            )


## HELPER FUNCTIONS


def _get_certificate_extensions(cert: x509.Certificate) -> Extensions:
    """Get the extensions from the VCEK certificate"""
    extensions: Extensions = {}
    for ext in cert.extensions:
        extensions[ext.oid] = ext.value.value
    return extensions


def _decode_der_integer(der_bytes: bytes) -> int:
    """Decode a DER-encoded INTEGER, rejecting non-INTEGER types and trailing bytes."""
    try:
        result, remainder = der_decoder.decode(der_bytes, asn1Spec=Asn1Integer())
    except Exception as e:
        raise ValueError(f"Failed to decode DER integer: {e}") from e
    if remainder:
        raise ValueError(f"Unexpected trailing bytes after DER integer: {len(remainder)} bytes")
    return int(result)


def _decode_der_ia5string(der_bytes: bytes) -> str:
    """Decode a DER-encoded IA5String, rejecting non-IA5String types and trailing bytes."""
    try:
        result, remainder = der_decoder.decode(der_bytes, asn1Spec=Asn1IA5String())
    except Exception as e:
        raise ValueError(f"Failed to decode DER IA5String: {e}") from e
    if remainder:
        raise ValueError(f"Unexpected trailing bytes after DER IA5String: {len(remainder)} bytes")
    return str(result)


def _validateAmdLocation(name: x509.Name) -> bool:
    """Validate that the certificate subject name matches AMD's expected values.

    Args:
        name: The x509.Name object to validate

    Returns:
        bool: True if all fields match expected values, False otherwise
    """

    def check_singleton_list(values: list[str | bytes], field_name: str, expected: str) -> bool:
        if len(values) != 1:
            print(f"Expected exactly one {field_name}, got {len(values)}")
            return False
        if values[0] != expected:
            print(f"Unexpected {field_name} value: '{values[0]!r}', expected '{expected}'")
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
    return check_singleton_list(org_unit_values, "organizational unit", "Engineering")


def _verify_report_signature(vcek: x509.Certificate, report: Report) -> bool:
    """Verify the attestation report signature using VCEK's public key"""

    # Validate Report Format
    POLICY_RESERVED_1_BIT = 17

    if report.version < 2:
        raise ValueError(f"Report version is lower than 2: is {report.version}")

    # Check reserved bit must be 1
    if not (report.policy & (1 << POLICY_RESERVED_1_BIT)):
        raise ValueError(f"policy[{POLICY_RESERVED_1_BIT}] is reserved, must be 1, got 0")

    # Check bits 63-26 must be zero
    if report.policy >> 26:
        raise ValueError("policy bits 63-26 must be zero")

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

        r = int.from_bytes(r_bytes.lstrip(b"\x00"), byteorder="big")
        s = int.from_bytes(s_bytes.lstrip(b"\x00"), byteorder="big")

        der_signature = utils.encode_dss_signature(r, s)

        # Verify signature
        public_key.verify(der_signature, report.signed_data, ec.ECDSA(hashes.SHA384()))
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
        return _verify_report_signature(chain.vcek, report)

    except Exception as e:
        print(f"Verification failed: {e}")
        return False
