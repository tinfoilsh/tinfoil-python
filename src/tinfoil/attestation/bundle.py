"""
Attestation bundles for single-request verification.

A bundle packages everything needed to verify an enclave (the enclave
attestation report, the release digest, the Sigstore bundle, the AMD VCEK, and
the enclave TLS certificate) so a client can attest by fetching a single
document. This mirrors the bundle model used by the Go and JavaScript SDKs and
lets attestation traffic flow through a proxy.
"""

import base64
import json
from dataclasses import dataclass
from urllib.parse import urlparse

import requests
from cryptography import x509

from .attestation import Document, REQUEST_TIMEOUT_SECONDS
from .types import PredicateType

ATTESTATION_BUNDLE_ENDPOINT = "/attestation"


@dataclass
class Bundle:
    """A complete attestation bundle for single-request verification."""
    domain: str
    enclave_attestation_report: Document
    digest: str
    sigstore_bundle: bytes
    vcek: str  # base64-encoded DER
    enclave_cert: str  # PEM


def fetch_bundle_from(
    attestation_bundle_url: str, enclave: str = "", repo: str = ""
) -> Bundle:
    """Fetches a complete attestation bundle from {url}/attestation.

    When an enclave host or a code repository is supplied, asks the bundle
    service to assemble a bundle for that specific enclave/repo (via POST)
    instead of returning the default router bundle (GET).
    """
    # The bundle is the entire trust root; fetching it over plaintext would let
    # an attacker substitute it (MITM).
    if urlparse(attestation_bundle_url).scheme != "https":
        raise ValueError(
            f"attestation bundle URL must use https; got {attestation_bundle_url!r}"
        )
    base = attestation_bundle_url.rstrip("/")
    url = f"{base}{ATTESTATION_BUNDLE_ENDPOINT}"
    if enclave or repo:
        body = {}
        if enclave:
            body["enclaveUrl"] = enclave if "://" in enclave else f"https://{enclave}"
        if repo:
            body["repo"] = repo
        response = requests.post(url, json=body, timeout=REQUEST_TIMEOUT_SECONDS)
    else:
        response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()

    try:
        data = response.json()
        report = data["enclaveAttestationReport"]
        return Bundle(
            domain=data["domain"],
            enclave_attestation_report=Document(
                format=PredicateType(report["format"]),
                body=report["body"],
            ),
            digest=data["digest"],
            sigstore_bundle=json.dumps(data["sigstoreBundle"]).encode(),
            vcek=data.get("vcek", ""),
            enclave_cert=data.get("enclaveCert", ""),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"Invalid attestation bundle from {base}: {e}") from e


def verify_certificate(
    cert_pem: str,
    expected_domain: str,
    attestation_doc: Document,
    expected_hpke_key: str,
) -> str:
    """
    Verifies an enclave TLS certificate against expected values, binding it to
    the verified attestation. Checks that the certificate is valid for the
    expected domain, that its SANs encode the attested HPKE key, and that its
    SANs encode the hash of the attestation document. Returns the HPKE public
    key extracted from the certificate.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as e:
        raise ValueError(f"failed to parse certificate: {e}") from e

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    if not sans:
        raise ValueError("certificate has no Subject Alternative Names")

    if not _matches_hostname(expected_domain, sans):
        raise ValueError(f"certificate not valid for domain {expected_domain!r}; SANs: {sans}")

    hpke_sans = [s for s in sans if ".hpke." in s]
    if not hpke_sans:
        raise ValueError("certificate SANs do not contain HPKE key")
    hpke_public_key = _decode_domains(hpke_sans, "hpke").hex()
    if hpke_public_key != expected_hpke_key:
        raise ValueError(
            f"HPKE key mismatch: certificate has {hpke_public_key}, expected {expected_hpke_key}"
        )

    hatt_sans = [s for s in sans if ".hatt." in s]
    if not hatt_sans:
        raise ValueError("certificate SANs do not contain attestation hash")
    cert_attestation_hash = _decode_domains(hatt_sans, "hatt").decode()
    computed_hash = attestation_doc.hash()
    if cert_attestation_hash != computed_hash:
        raise ValueError(
            f"attestation hash mismatch: certificate has {cert_attestation_hash}, computed {computed_hash}"
        )

    return hpke_public_key


def _matches_hostname(domain: str, sans: list) -> bool:
    """Reports whether domain matches one of the DNS SANs (exact or wildcard)."""
    domain = domain.lower()
    for san in sans:
        san = san.lower()
        if san == domain:
            return True
        if san.startswith("*."):
            suffix = san[1:]  # ".example.com"
            if domain.endswith(suffix):
                left = domain[: -len(suffix)]
                if left and "." not in left:
                    return True
    return False


def _decode_domains(domains: list, prefix: str) -> bytes:
    """
    Decodes dcode-encoded data spread across certificate SANs. Each SAN has the
    form NN<base32-chunk>.<prefix>.<domain> where NN is the chunk index; chunks
    are ordered by index, concatenated, and base32-decoded.
    """
    pattern = "." + prefix + "."
    chunks = []
    for d in domains:
        if pattern not in d:
            continue
        first_part = d.split(".")[0]
        if len(first_part) < 2:
            continue
        try:
            idx = int(first_part[:2])
        except ValueError:
            continue
        chunks.append((idx, first_part[2:]))

    if not chunks:
        raise ValueError(f"no domains with prefix: {prefix}")

    chunks.sort(key=lambda c: c[0])
    combined = "".join(chunk for _, chunk in chunks).upper()
    padding = "=" * ((8 - len(combined) % 8) % 8)
    try:
        return base64.b32decode(combined + padding)
    except Exception as e:
        raise ValueError(f"base32 decode error: {e}") from e
