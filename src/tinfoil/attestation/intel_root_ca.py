"""
Intel SGX Root CA certificate for TDX attestation verification.

This module provides the embedded Intel SGX Provisioning Certification Root CA
certificate, which is the trust anchor for verifying TDX attestation quotes.

Certificate chain for TDX:
    Intel SGX Root CA (this file - trust anchor)
        └─► Intel SGX PCK Platform CA (intermediate, from collateral)
            └─► Intel SGX PCK Certificate (leaf, embedded in quote)

Source: https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Intel SGX Provisioning Certification Root CA
# Subject: CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US
# Valid: 2018-05-21 to 2049-12-31
# Key: ECDSA P-256
INTEL_SGX_ROOT_CA_PEM = b"""-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
"""


def get_intel_root_ca() -> x509.Certificate:
    """
    Load and return the Intel SGX Root CA certificate.

    Returns:
        Parsed X.509 certificate object

    Example:
        >>> root_ca = get_intel_root_ca()
        >>> print(root_ca.subject)
        <Name(CN=Intel SGX Root CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US)>
    """
    return x509.load_pem_x509_certificate(INTEL_SGX_ROOT_CA_PEM)


def get_intel_root_ca_public_key_der() -> bytes:
    """
    Get the Intel SGX Root CA public key in DER format.

    This is useful for comparing against certificate chain anchors.

    Returns:
        DER-encoded public key bytes
    """
    cert = get_intel_root_ca()
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def get_intel_root_ca_der() -> bytes:
    """
    Get the Intel SGX Root CA certificate in DER format.

    Returns:
        DER-encoded certificate bytes
    """
    cert = get_intel_root_ca()
    return cert.public_bytes(serialization.Encoding.DER)
