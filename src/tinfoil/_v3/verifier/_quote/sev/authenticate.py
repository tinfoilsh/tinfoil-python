"""Authentication of an SEV-SNP report: the VCEK chain up to the embedded AMD root, revocation against the
document-carried CRL, and the report signature."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tinfoil._v3.verifier._measurement import SEVSNP
from tinfoil._v3.verifier._quote.sev.lib.abi import Report
from tinfoil._v3.verifier._quote.sev.lib.chain import CertificateChain
from tinfoil._v3.verifier._x509.certificate import Certificate
from tinfoil._v3.verifier._x509.crl import RevocationList

PRODUCT_GENOA = "Genoa"
PRODUCT_TURIN = "Turin"
SUPPORTED_PRODUCTS = (PRODUCT_GENOA, PRODUCT_TURIN)
REPORT_SIZE = 1184
MINIMUM_REPORT_VERSION = 3
"""The first report version that carries the CPUID family, model and stepping."""


class SevAuthenticationError(ValueError):
    """A report whose chain, revocation status or signature does not check out."""


@dataclass(frozen=True, slots=True)
class Options:
    """Per-authentication overrides; the default selects the embedded per-product anchor."""

    test_only_root_pem: bytes | None = None
    """A replacement AMD KDS ``cert_chain`` PEM (ASK then ARK) for the conformance harness."""


@dataclass(frozen=True, slots=True)
class Evidence:
    """An SEV-SNP attestation report with the collateral that authenticates it."""

    report: bytes
    vcek_der: bytes
    cert_chain_pem: str
    """The ASK then the ARK certificate, as the document carried them (untrusted transport)."""
    crl_der: bytes
    """The AMD KDS revocation list for the product line."""


@dataclass(frozen=True, slots=True)
class AmdRoots:
    """The pinned ASK and ARK for one product line."""

    product_line: str
    ask: Certificate
    ark: Certificate


@dataclass(frozen=True, slots=True)
class Quote:
    """A signature-verified SEV-SNP report, not yet compared against any expected value."""

    identity: str
    """The machines-map lookup key: CHIP_ID, lowercase hex."""
    measurement: SEVSNP
    """The authenticated launch measurement."""
    product_line: str
    report: Report
    chain: CertificateChain
    """The verified ARK, ASK and VCEK."""


def trusted_roots(product_line: str, root_pem: bytes | None) -> AmdRoots:
    """The pinned AMD anchors for ``product_line`` from the embedded material, or from ``root_pem`` when given.

    The PEM must carry exactly the ASK then the ARK; an unsupported
    product line is an error.
    """
    raise NotImplementedError


def decode_cert_chain(chain_pem: str) -> tuple[bytes, bytes]:
    """Decode the document-carried ASK and ARK DER from the KDS ``cert_chain`` PEM form.

    Exactly two non-empty CERTIFICATE blocks and no trailing data; any
    other block label is an error.
    """
    raise NotImplementedError


def product_from_report(report: Report) -> str:
    """The product line from the report's CPUID family, model and stepping (report version 3 and later).

    A report without the CPUID field, or one for a product other than
    Genoa or Turin, is an error.
    """
    raise NotImplementedError


def reject_masked_chip_id(report: Report) -> None:
    """Reject a report whose SIGNER_INFO masks CHIP_ID: masked platform identities are unsupported."""
    raise NotImplementedError


def parse_crl(crl_der: bytes, now: datetime) -> RevocationList:
    """Parse the AMD CRL and check that ``now`` lies within its validity window."""
    raise NotImplementedError


def verify_signature(
    evidence: Evidence, roots: AmdRoots, crl: RevocationList, now: datetime
) -> tuple[Report, CertificateChain]:
    """Verify the report signature under the AMD roots with the supplied VCEK and the document's ASK and ARK.

    The report must be exactly REPORT_SIZE bytes and parse; the ASK and
    ARK the document carries must equal the pinned ones; the VCEK must
    match its product's profile, be issued by the ASK, be valid at ``now``
    and not be listed in the CRL (which the ASK must have signed); the
    report's ECDSA P-384 signature must verify under the VCEK. No policy
    validation.
    """
    raise NotImplementedError


def authenticate(evidence: Evidence, now: datetime, options: Options | None = None) -> Quote:
    """Verify the report's chain up to the pinned AMD root and its VCEK against the supplied CRL.

    In order: ``now`` is timezone-aware; the VCEK and CRL are non-empty;
    the chain PEM decodes; the CRL parses and ``now`` is within its
    window; the product is read from the report and its roots selected;
    the signature chain verifies; CHIP_ID is not masked; the identity is
    derived; the measurement is 48 bytes.
    """
    raise NotImplementedError
