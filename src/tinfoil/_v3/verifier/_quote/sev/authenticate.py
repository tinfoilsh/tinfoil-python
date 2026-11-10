"""Authentication of an SEV-SNP report: the VCEK chain up to the embedded AMD root, revocation against the
document-carried CRL, and the report signature."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tinfoil._v3.verifier._measurement import REGISTER_SIZE, SEVSNP
from tinfoil._v3.verifier._quote.sev.identity import identity
from tinfoil._v3.verifier._quote.sev.lib.abi import (
    PRODUCT_GENOA as PRODUCT_GENOA,
)
from tinfoil._v3.verifier._quote.sev.lib.abi import (
    PRODUCT_TURIN as PRODUCT_TURIN,
)
from tinfoil._v3.verifier._quote.sev.lib.abi import (
    REPORT_SIZE,
    AbiError,
    Report,
    ReportSigner,
    parse_report,
    parse_signer_info,
    sev_product_from_cpuid1_eax,
)
from tinfoil._v3.verifier._quote.sev.lib.chain import (
    CertificateChain,
    ChainError,
    check_ask_not_revoked,
    common_name,
    parse_vcek,
    validate_vcek_certificate,
    validate_vcek_issuer,
    verify_report_signature,
    verify_vcek_chain,
)
from tinfoil._v3.verifier._trust import AMD_GENOA_CERT_CHAIN_PEM, AMD_TURIN_CERT_CHAIN_PEM
from tinfoil._v3.verifier._x509 import der
from tinfoil._v3.verifier._x509.certificate import Certificate, X509Error, parse_certificate
from tinfoil._v3.verifier._x509.crl import CRLError, RevocationList, parse_revocation_list

SUPPORTED_PRODUCTS = (PRODUCT_GENOA, PRODUCT_TURIN)
MINIMUM_REPORT_VERSION = 3
"""The first report version that carries the CPUID family, model and stepping."""
_EMBEDDED_ROOTS = {PRODUCT_GENOA: AMD_GENOA_CERT_CHAIN_PEM, PRODUCT_TURIN: AMD_TURIN_CERT_CHAIN_PEM}
_VLEK_ISSUER_PREFIX = "SEV-VLEK"


class SevAuthenticationError(ValueError):
    """A report whose chain, revocation status or signature does not check out."""


@dataclass(frozen=True, slots=True)
class Options:
    """Per-authentication overrides; the default selects the embedded per-product anchor.

    This package is private and the public verifier builds these options
    itself, so the override is reachable only from the conformance adapter's
    internal factory, never from the public constructor.
    """

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
    product line is an error. An intermediate named as a VLEK signer
    cannot issue VCEKs and is an error.
    """
    if root_pem is None:
        root_pem = _EMBEDDED_ROOTS.get(product_line)
        if root_pem is None:
            raise SevAuthenticationError(f"unsupported SEV product line {product_line!r}")
    try:
        ask_der, ark_der = parse_product_cert_chain(root_pem)
        ask = parse_certificate(ask_der)
        ark = parse_certificate(ark_der)
    except (SevAuthenticationError, X509Error) as err:
        raise SevAuthenticationError(f"parsing embedded AMD {product_line} root certificates: {err}") from err
    if common_name(ask.subject).startswith(_VLEK_ISSUER_PREFIX):
        raise SevAuthenticationError(
            f"root of trust missing intermediate certificate authority certificate for {ReportSigner.VCEK}"
        )
    return AmdRoots(product_line=product_line, ask=ask, ark=ark)


def parse_product_cert_chain(pem: bytes) -> tuple[bytes, bytes]:
    """Decode the ASK and ARK DER from an AMD KDS ``cert_chain`` body: exactly two CERTIFICATE blocks and nothing
    else."""
    try:
        text = pem.decode("ascii")
    except UnicodeDecodeError as err:
        raise SevAuthenticationError("cert_chain is not ASCII") from err
    try:
        blocks = der.pem_blocks(text, "CERTIFICATE")
    except der.DerError as err:
        raise SevAuthenticationError(f"cert_chain: {err}") from err
    if len(blocks) != 2:
        raise SevAuthenticationError(f"cert_chain must carry the ASK then the ARK, got {len(blocks)} blocks")
    return blocks[0], blocks[1]


def decode_cert_chain(chain_pem: str) -> tuple[bytes, bytes]:
    """Decode the document-carried ASK and ARK DER from the KDS ``cert_chain`` PEM form.

    Exactly two non-empty CERTIFICATE blocks and no text outside them; any
    other block label is an error.
    """
    try:
        blocks = der.pem_blocks(chain_pem, "CERTIFICATE")
    except der.DerError as err:
        raise SevAuthenticationError(f"cert_chain_pem: {err}") from err
    if len(blocks) != 2:
        raise SevAuthenticationError(
            f"cert_chain_pem must carry exactly the ASK and ARK certificates, got {len(blocks)} blocks"
        )
    return blocks[0], blocks[1]


def product_from_report(report: Report) -> str:
    """The product line from the report's CPUID family, model and stepping (report version 3 and later).

    A report without the CPUID field, or one for a product other than
    Genoa or Turin, is an error.
    """
    fms = report.cpuid1_eax_fms
    if fms == 0:
        raise SevAuthenticationError(
            f"report carries no CPUID product identity (report version {report.version}, want "
            f"{MINIMUM_REPORT_VERSION}+)"
        )
    product = sev_product_from_cpuid1_eax(fms)
    if product.name not in SUPPORTED_PRODUCTS:
        raise SevAuthenticationError(f"unsupported SEV product in report CPUID 0x{fms:x}")
    return product.name


def reject_masked_chip_id(report: Report) -> None:
    """Reject a report whose SIGNER_INFO masks CHIP_ID: masked platform identities are unsupported.

    The identity is derived from CHIP_ID right after the signature check,
    so a masked report never produces a quote; validation applies the rule
    again as part of its signer check.
    """
    try:
        signer = parse_signer_info(report.signer_info)
    except AbiError as err:
        raise SevAuthenticationError(f"parsing report SIGNER_INFO: {err}") from err
    if signer.mask_chip_key:
        raise SevAuthenticationError("report masks CHIP_ID; masked platform identities are unsupported")


def reject_zero_chip_id(report: Report) -> None:
    """Reject a report whose CHIP_ID is all zero while SIGNER_INFO does not mask it.

    Firmware zeroes CHIP_ID only when the host masks it, which
    ``reject_masked_chip_id`` already rejects, so an unmasked zero CHIP_ID
    is not a platform identity. Accepting it would skip the binding of the
    report to the VCEK's hardware id, since an all-zero value never names a
    certified chip, and would turn 64 zero bytes into the machine identity.
    """
    if not any(report.chip_id):
        raise SevAuthenticationError("report CHIP_ID is all zero without the mask flag set")


def parse_crl(crl_der: bytes, now: datetime) -> RevocationList:
    """Parse the AMD CRL and check that ``now`` lies within its validity window (both ends inclusive)."""
    try:
        crl = parse_revocation_list(crl_der)
    except CRLError as err:
        raise SevAuthenticationError(f"parsing amd-crl collateral: {err}") from err
    if now < crl.this_update or now > crl.next_update:
        raise SevAuthenticationError(
            "amd-crl collateral is outside its validity window "
            f"(this_update {crl.this_update.isoformat()}, next_update {crl.next_update.isoformat()})"
        )
    return crl


def parse_report_bytes(data: bytes) -> Report:
    """Decode a report that must be exactly REPORT_SIZE bytes."""
    if len(data) != REPORT_SIZE:
        raise SevAuthenticationError(f"SEV-SNP report must be exactly {REPORT_SIZE} bytes, got {len(data)}")
    try:
        return parse_report(data)
    except AbiError as err:
        raise SevAuthenticationError(f"failed to parse report: {err}") from err


def verify_signature(
    report: Report, evidence: Evidence, roots: AmdRoots, crl: RevocationList, now: datetime
) -> CertificateChain:
    """Verify the report signature under the AMD roots with the supplied VCEK.

    The report must be VCEK-signed; the VCEK must match the product's
    profile and TCB layout, name the product's ASK as its issuer, chain to
    the pinned ARK at ``now``; the ASK must not be listed in the CRL, which
    the ARK must have signed; the report must have a supported version and
    its ECDSA P-384 signature must verify under the VCEK. No policy
    validation.
    """
    signer = parse_signer_info(report.signer_info)
    if signer.signing_key != ReportSigner.VCEK:
        raise SevAuthenticationError(f"missing {signer.signing_key} certificate")
    try:
        vcek = parse_vcek(evidence.vcek_der)
        validate_vcek_certificate(vcek, roots.product_line)
        validate_vcek_issuer(vcek, roots.product_line)
        verify_vcek_chain(vcek, roots.ask, roots.ark, now)
        check_ask_not_revoked(roots.ask, roots.ark, crl, now)
        verify_report_signature(report, vcek)
    except ChainError as err:
        raise SevAuthenticationError(str(err)) from err
    return CertificateChain(ark=roots.ark, ask=roots.ask, vcek=vcek)


def authenticate(evidence: Evidence, now: datetime, options: Options | None = None) -> Quote:
    """Verify the report's chain up to the pinned AMD root and its VCEK against the supplied CRL.

    In order: ``now`` is timezone-aware; the VCEK is non-empty; the chain
    PEM decodes; the CRL is non-empty, parses and ``now`` is within its
    window; the report has the exact size and parses; the product is read
    from the report and its roots selected; the signature chain verifies;
    CHIP_ID is neither masked nor all zero; the identity is derived; the
    measurement is 48 bytes.

    The ASK and ARK that the document carries are checked for shape only:
    trust comes from the pinned roots, so they are not used.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise SevAuthenticationError("verification time is required")
    if not evidence.vcek_der:
        raise SevAuthenticationError("amd-vcek collateral carries an empty VCEK")
    try:
        decode_cert_chain(evidence.cert_chain_pem)
    except SevAuthenticationError as err:
        raise SevAuthenticationError(f"amd-vcek collateral: {err}") from err
    if not evidence.crl_der:
        raise SevAuthenticationError("amd-crl collateral carries an empty CRL")
    crl = parse_crl(evidence.crl_der, now)
    report = parse_report_bytes(evidence.report)
    product_line = product_from_report(report)
    roots = trusted_roots(product_line, options.test_only_root_pem if options is not None else None)
    chain = verify_signature(report, evidence, roots, crl, now)
    reject_masked_chip_id(report)
    reject_zero_chip_id(report)
    try:
        machine = identity(report.chip_id)
    except ValueError as err:
        raise SevAuthenticationError(str(err)) from err
    if len(report.measurement) != REGISTER_SIZE:
        raise SevAuthenticationError(f"report measurement must be {REGISTER_SIZE} bytes, got {len(report.measurement)}")
    return Quote(
        identity=machine,
        measurement=SEVSNP(launch=report.measurement),
        product_line=product_line,
        report=report,
        chain=chain,
    )
