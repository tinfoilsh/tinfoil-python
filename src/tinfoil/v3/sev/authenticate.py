"""AMD SEV-SNP report authentication against the pinned per-product AMD
roots, a 1:1 port of Go verifier/quote/sev/authenticate.go plus the checks
the configured tinfoilsh/go-sev-guest verify.SnpAttestation options perform
(offline getter, revocations on, pinned Genoa/Turin roots, product from the
report's CPUID FMS, pinned clock). Every rejection raises
VerificationError("QUOTE_REJECTED", ...)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from cryptography import x509 as cx509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..bytesutil import decode_base64
from ..embedded_roots import GENOA_CERT_CHAIN_PEM, TURIN_CERT_CHAIN_PEM
from ..envelope import (
    COLLATERAL_AMD_CRL_V1_FORMAT,
    COLLATERAL_AMD_VCEK_V1_FORMAT,
    SUBJECT_CPU,
    Document,
    endorsement_collateral,
    parse_amd_crl_collateral,
    parse_amd_vcek_collateral,
)
from ..errors import QUOTE_REJECTED, VerificationError
from ..measurement import SEV_GUEST_V2, Measurement
from . import kds
from .abi import (
    REPORT_SIZE,
    SIGN_ECDSA_P384_SHA384,
    VCEK_REPORT_SIGNER,
    VLEK_REPORT_SIGNER,
    SevReport,
    check_masked_chip_id,
    parse_report,
    parse_signer_info,
    report_signature_rs,
    report_signer_string,
    sev_product_name_from_cpuid1_eax,
    signed_component,
    validate_report_format,
)
from .identity import identity
from . import x509 as sx509

# Supported AMD product lines with pinned per-product roots.
PRODUCT_GENOA = "Genoa"
PRODUCT_TURIN = "Turin"


def _quote_error(message: str) -> VerificationError:
    return VerificationError(QUOTE_REJECTED, message)


@dataclass
class SevQuote:
    """A signature-verified SEV-SNP report, not yet compared against any
    expected value (Go sev.Quote)."""

    # identity is the machines-map lookup key (CHIP_ID, lowercase hex).
    identity: str
    # measurement is the launch measurement register.
    measurement: Measurement
    report: SevReport
    # product_line selects the policy translation (Go Quote.ProductLine()).
    product_line: str
    # Retained for policy assembly/validation (Go: Quote.attestation).
    vcek: cx509.Certificate


@dataclass
class _AMDRoots:
    """The pinned AMD trust anchor: ASK (or ASVK) intermediate plus ARK root
    (Go trust.AMDRootCerts / ProductCerts)."""

    ark: cx509.Certificate
    ask: Optional[cx509.Certificate] = None
    asvk: Optional[cx509.Certificate] = None


def _trusted_roots(product_line: str, root_pem_override: Optional[str]) -> _AMDRoots:
    """Build the pinned AMD trust anchor from the repo-owned per-product
    chain, or the injected override. A fresh parse per authentication:
    document-supplied collateral must never affect other verifications (Go
    trustedRoots + kds.ParseProductCertChain + trust.ProductCerts.Decode)."""
    root_pem = root_pem_override
    if root_pem is None:
        if product_line == PRODUCT_GENOA:
            root_pem = GENOA_CERT_CHAIN_PEM
        elif product_line == PRODUCT_TURIN:
            root_pem = TURIN_CERT_CHAIN_PEM
        else:
            raise ValueError(f'unsupported SEV product line "{product_line}"')

    def wrap(msg: str) -> ValueError:
        return ValueError(f"parsing embedded AMD {product_line} root certificates: {msg}")

    try:
        blocks, rest = sx509.pem_decode_all(root_pem)
    except ValueError as e:
        raise wrap(str(e)) from None
    if len(blocks) < 1 or blocks[0].type != "CERTIFICATE":
        raise wrap("could not find ASK or ASVK PEM block")
    if len(blocks) < 2 or blocks[1].type != "CERTIFICATE":
        raise wrap("could not find ARK PEM block")
    if len(blocks) != 2 or rest.strip() != "":
        raise wrap("unexpected trailing bytes")
    try:
        ica = sx509.load_certificate(blocks[0].der)
    except ValueError as e:
        raise wrap(f"could not parse intermediate certificate: {e}") from None
    try:
        ark = sx509.load_certificate(blocks[1].der)
    except ValueError as e:
        raise wrap(f"could not parse ARK certificate: {e}") from None
    # trust.ProductCerts.Decode: an SEV-VLEK intermediate is the ASVK.
    if sx509.common_name(ica.subject).startswith("SEV-VLEK"):
        return _AMDRoots(ark=ark, asvk=ica)
    return _AMDRoots(ark=ark, ask=ica)


def decode_cert_chain(chain_pem: str) -> tuple[bytes, bytes]:
    """Decode the document-carried ASK+ARK PEM chain (the AMD KDS cert_chain
    format). The chain is untrusted transport: verification runs against the
    pinned AMD root certificates (Go decodeCertChain). ValueError."""
    blocks, rest = sx509.pem_decode_all(chain_pem)
    for block in blocks:
        if block.type != "CERTIFICATE":
            raise ValueError(
                f'cert_chain_pem carries a "{block.type}" block, want CERTIFICATE'
            )
        if len(block.der) == 0:
            raise ValueError("cert_chain_pem carries an empty CERTIFICATE block")
    if len(blocks) != 2:
        raise ValueError(
            f"cert_chain_pem must carry exactly the ASK and ARK certificates, got {len(blocks)} blocks"
        )
    if rest.strip() != "":
        raise ValueError("cert_chain_pem carries trailing data after the certificates")
    return blocks[0].der, blocks[1].der


def _product_line_from_report(report: SevReport) -> str:
    """Derive the SEV product line from the report's CPUID FMS field, present
    since report version 3 (Go productFromReport + kds.ProductLine)."""
    if report.cpuid1_eax_fms == 0:
        raise ValueError(
            f"report carries no CPUID product identity (report version {report.version}, want 3+)"
        )
    product = sev_product_name_from_cpuid1_eax(report.cpuid1_eax_fms)
    if product not in (PRODUCT_GENOA, PRODUCT_TURIN):
        raise ValueError(
            f"unsupported SEV product in report CPUID 0x{report.cpuid1_eax_fms:x}"
        )
    return product


# --- KDS certificate validation (verify.decodeCerts subset) ------------------


def _validate_amd_location(name: cx509.Name, role: str) -> None:
    """The exact AMD KDS subject/issuer location fields (Go
    verify.validateAmdLocation)."""
    checks = [
        (NameOID.COUNTRY_NAME, "country", "countries", "US"),
        (NameOID.LOCALITY_NAME, "locality", "localities", "Santa Clara"),
        (NameOID.STATE_OR_PROVINCE_NAME, "state", "states", "CA"),
        (NameOID.ORGANIZATION_NAME, "organization", "organizations", "Advanced Micro Devices"),
        (
            NameOID.ORGANIZATIONAL_UNIT_NAME,
            "organizational unit",
            "organizational units",
            "Engineering",
        ),
    ]
    for oid, field, fields, want in checks:
        values = sx509.attr_values(name, oid)
        if len(values) != 1:
            raise ValueError(f"{role} has {len(values)} {fields}, want 1")
        if values[0] != want:
            raise ValueError(
                f"{role} {field} '{values[0]}' not expected for AMD. Expected '{want}'"
            )


def _validate_kds_certificate_product_nonspecific(
    vcek: cx509.Certificate, product_line: str
) -> kds.KDSExtensions:
    """The documented qualities of a VCEK certificate per the KDS spec (Go
    verify.validateKDSCertificateProductNonspecific for the VCEK signer with
    a known product line)."""
    if vcek.version != cx509.Version.v3:
        raise ValueError(f"VCEK certificate version is {vcek.version.value + 1}, expected 3")
    if not sx509.is_pss_sha384(vcek):
        raise ValueError(
            "VCEK certificate signature algorithm is not SHA-384 with RSASSA-PSS"
        )
    pub = vcek.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("VCEK certificate public key type is not ECDSA")
    if not isinstance(pub.curve, ec.SECP384R1):
        raise ValueError(
            f"VCEK certificate public key curve is {pub.curve.name}, expected P-384"
        )
    _validate_amd_location(vcek.subject, "VCEK subject")
    cn = sx509.common_name(vcek.subject)
    if cn != "SEV-VCEK":
        raise ValueError(
            f"VCEK certificate subject common name {cn} not expected. Expected SEV-VCEK"
        )
    exts = kds.vcek_certificate_extensions(vcek)
    # With a known product line the product-name claim is disregarded; only
    # the TCB format must match (report-v3 manufacturing-error workaround).
    kds.validate_extensions(exts, product_line)
    return exts


def _validate_kds_cert_issuer(vcek: cx509.Certificate, product_line: str) -> None:
    """KDS-specified issuer metadata (Go verify.validateKDSCertIssuer)."""
    _validate_amd_location(vcek.issuer, "VCEK issuer")
    want = f"SEV-{product_line}"
    cn = sx509.common_name(vcek.issuer)
    if cn != want:
        raise ValueError(
            f"VCEK certificate issuer common name {cn} not expected. Expected {want}"
        )


def _verify_chain(vcek: cx509.Certificate, roots: _AMDRoots, now: datetime) -> None:
    """Mirror Go x509 Certificate.Verify with Roots={ARK}, Intermediates=
    {ASK}, CurrentTime=now: raw-DER name chaining, RSA-PSS SHA-384
    signatures, validity windows, and CA constraints. The ARK self-signature
    is additionally verified (the trust anchor is repo-pinned, not
    system-provided)."""
    ica = roots.ask
    if ica is None:
        raise ValueError(
            "root of trust missing intermediate certificate authority certificate for key VCEK"
        )
    ark = roots.ark
    sx509.check_validity(vcek, now, "VCEK")

    if sx509.name_raw(vcek.issuer) != sx509.name_raw(ica.subject):
        raise ValueError(
            "error verifying VCEK certificate: certificate signed by unknown authority"
        )
    sx509.check_validity(ica, now, "ASK")
    sx509.check_ca_signer_constraints(ica, sx509.KEY_USAGE_CERT_SIGN, "ASK")
    if not sx509.is_pss_sha384(vcek) or not sx509.verify_pss_sha384(
        ica, vcek.tbs_certificate_bytes, vcek.signature
    ):
        raise ValueError("error verifying VCEK certificate: not signed by the ASK")

    if sx509.name_raw(ica.issuer) != sx509.name_raw(ark.subject):
        raise ValueError(
            "error verifying ASK certificate: certificate signed by unknown authority"
        )
    sx509.check_validity(ark, now, "ARK")
    sx509.check_ca_signer_constraints(ark, sx509.KEY_USAGE_CERT_SIGN, "ARK")
    if not sx509.is_pss_sha384(ica) or not sx509.verify_pss_sha384(
        ark, ica.tbs_certificate_bytes, ica.signature
    ):
        raise ValueError("error verifying ASK certificate: not signed by the ARK")

    if sx509.name_raw(ark.issuer) != sx509.name_raw(ark.subject):
        raise ValueError("error verifying ARK certificate: not self-issued")
    if not sx509.is_pss_sha384(ark) or not sx509.verify_pss_sha384(
        ark, ark.tbs_certificate_bytes, ark.signature
    ):
        raise ValueError("error verifying ARK certificate: not properly self-signed")


def _check_revocation(
    roots: _AMDRoots, vcek: cx509.Certificate, crl: cx509.CertificateRevocationList
) -> None:
    """Mirror verify.GetCrlAndCheckRoot fed by the offline getter: the CRL
    must be reachable from the pinned ASK's distribution points, be signed by
    the pinned ARK, and revoke neither the ASK nor the VCEK. Fail-closed: any
    miss rejects (the VCEK-serial check is a fail-closed extension of the
    library's ASK-only check)."""
    ask = roots.ask
    if ask is None:
        raise ValueError("missing ASK x509 certificate to check intermediate key validity")
    # offlineGetter answers only URLs whose path ends in /crl.
    served = False
    for url in sx509.crl_distribution_point_uris(ask):
        try:
            if urlparse(url).path.endswith("/crl"):
                served = True
                break
        except ValueError:
            continue
    if not served:
        raise ValueError("could not fetch product CRL")
    # verifyCRL: signed by the ARK (Go CRL.CheckSignatureFrom: CA + cRLSign
    # constraints, issuer/subject name match, then the signature).
    sx509.check_ca_signer_constraints(roots.ark, sx509.KEY_USAGE_CRL_SIGN, "ARK")
    if sx509.name_raw(crl.issuer) != sx509.name_raw(roots.ark.subject):
        raise ValueError("CRL is not signed by ARK")
    if not sx509.is_pss_sha384(crl) or not sx509.verify_pss_sha384(
        roots.ark, crl.tbs_certlist_bytes, crl.signature
    ):
        raise ValueError("CRL is not signed by ARK")
    for bad in crl:
        if bad.serial_number == ask.serial_number:
            raise ValueError("ASK was revoked")
        if bad.serial_number == vcek.serial_number:
            raise ValueError("VCEK was revoked")


def _verify_signature(
    report_base64: str,
    vcek_der: bytes,
    crl: cx509.CertificateRevocationList,
    root_pem: Optional[str],
    now: datetime,
) -> tuple[SevReport, str, cx509.Certificate]:
    """Verify the report signature under the AMD roots with the provided VCEK,
    checking revocation against the provided CRL. No policy validation (Go
    verifySignature + verify.SnpAttestation with the options authenticate.go
    sets)."""
    try:
        report_bytes = decode_base64(report_base64)
    except ValueError as e:
        raise _quote_error(str(e)) from None
    if len(report_bytes) != REPORT_SIZE:
        raise _quote_error(
            f"SEV-SNP report must be exactly {REPORT_SIZE} bytes, got {len(report_bytes)}"
        )

    try:
        report = parse_report(report_bytes)
    except ValueError as e:
        raise _quote_error(f"failed to parse report: {e}") from None

    try:
        product_line = _product_line_from_report(report)
        roots = _trusted_roots(product_line, root_pem)
    except ValueError as e:
        raise _quote_error(str(e)) from None

    # fillInAttestation: the certificate chain is complete, so the only
    # reachable check is a non-VCEK signer with no matching certificate.
    try:
        info = parse_signer_info(report.signer_info)
    except ValueError as e:
        raise _quote_error(str(e)) from None
    if info.signing_key == VLEK_REPORT_SIGNER:
        raise _quote_error("report signed with VLEK, but VLEK certificate is missing")
    if info.signing_key != VCEK_REPORT_SIGNER:
        raise _quote_error(f"missing {report_signer_string(info.signing_key)} certificate")

    # decodeCerts: VCEK wellformedness, then verification against the pinned
    # per-product roots.
    try:
        vcek = sx509.parse_cert(vcek_der)
    except ValueError as e:
        raise _quote_error(f"could not interpret VCEK DER bytes: {e}") from None
    try:
        _validate_kds_certificate_product_nonspecific(vcek, product_line)
        _validate_kds_cert_issuer(vcek, product_line)
        _verify_chain(vcek, roots, now)
    except ValueError as e:
        raise _quote_error(str(e)) from None

    # CheckRevocations against the document-carried CRL, fail-closed.
    try:
        _check_revocation(roots, vcek, crl)
    except ValueError as e:
        raise _quote_error(str(e)) from None

    # SnpReportSignature: format check, then ECDSA-P384-SHA384 over the
    # signed component with little-endian r||s.
    try:
        validate_report_format(report_bytes)
    except ValueError as e:
        raise _quote_error(f"attestation report format error: {e}") from None
    if report.signature_algo != SIGN_ECDSA_P384_SHA384:
        raise _quote_error(f"unknown SignatureAlgo: {report.signature_algo}")
    try:
        r, s = report_signature_rs(report_bytes)
    except ValueError as e:
        raise _quote_error(f"could not interpret report signature: {e}") from None
    if not sx509.verify_ecdsa_p384_sha384(vcek, signed_component(report_bytes), r, s):
        raise _quote_error("report signature verification error")

    return report, product_line, vcek


def reject_masked_chip_id(report: SevReport) -> None:
    """QUOTE_REJECTED wrapper of the masked-CHIP_ID check."""
    try:
        check_masked_chip_id(report)
    except ValueError as e:
        raise _quote_error(str(e)) from None


def sev_authenticate(
    doc: Document,
    root_pem: Optional[str] = None,
    now: Optional[datetime] = None,
) -> SevQuote:
    """Verify the report's signature chain up to the pinned AMD root and its
    VCEK against the document-carried CRL — no network fetches. Callers must
    assemble a policy and validate before trusting the platform (Go
    sev.Authenticate). root_pem overrides the embedded per-product anchor;
    now pins the validity-window clock."""
    if now is None:
        now = datetime.now(timezone.utc)

    entry = endorsement_collateral(doc, COLLATERAL_AMD_VCEK_V1_FORMAT, SUBJECT_CPU)
    if entry is None:
        raise _quote_error("document carries no amd-vcek endorsement collateral for the cpu")
    data = parse_amd_vcek_collateral(entry.data)
    try:
        vcek_der = decode_base64(data.vcek_der_base64)
    except ValueError as e:
        raise _quote_error(f"decoding vcek_der_base64: {e}") from None
    # An empty VCEK would otherwise read as a fetch request.
    if len(vcek_der) == 0:
        raise _quote_error(f"amd-vcek collateral entry {entry.id!r} carries an empty VCEK")
    try:
        decode_cert_chain(data.cert_chain_pem)
    except ValueError as e:
        raise _quote_error(f"amd-vcek collateral entry {entry.id!r}: {e}") from None

    crl_entry = endorsement_collateral(doc, COLLATERAL_AMD_CRL_V1_FORMAT, SUBJECT_CPU)
    if crl_entry is None:
        raise _quote_error("document carries no amd-crl endorsement collateral for the cpu")
    crl_data = parse_amd_crl_collateral(crl_entry.data)
    try:
        crl_der = decode_base64(crl_data.crl_der_base64)
    except ValueError as e:
        raise _quote_error(f"decoding crl_der_base64: {e}") from None
    if len(crl_der) == 0:
        raise _quote_error(f"amd-crl collateral entry {crl_entry.id!r} carries an empty CRL")
    # The chain check verifies the CRL's signature but not its validity
    # window, so a stale pre-revocation CRL would otherwise pass.
    try:
        crl = sx509.load_crl(crl_der)
    except ValueError as e:
        raise _quote_error(f"parsing amd-crl collateral: {e}") from None
    this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    if next_update is None or now < this_update or now > next_update:
        raise _quote_error(
            "amd-crl collateral is outside its validity window "
            f"(this_update {this_update.isoformat()}, next_update "
            f"{next_update.isoformat() if next_update is not None else 'absent'})"
        )

    report, product_line, vcek = _verify_signature(
        doc.cpu_evidence.report_base64, vcek_der, crl, root_pem, now
    )
    reject_masked_chip_id(report)

    try:
        ident = identity(report.chip_id)
    except ValueError as e:
        raise _quote_error(str(e)) from None

    return SevQuote(
        identity=ident,
        measurement=Measurement(type=SEV_GUEST_V2, registers=[report.measurement.hex()]),
        report=report,
        product_line=product_line,
        vcek=vcek,
    )
