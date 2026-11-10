"""The AMD endorsement key chain: the VCEK certificate profile and its KDS extensions, chain verification up to the
pinned ARK, revocation of the ASK, and the report signature.

The ARK and ASK are trust material that the caller pins; the VCEK comes
from the attestation document.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tinfoil._v3.verifier._quote.sev.lib.abi import (
    Report,
    ReportSigner,
    report_signature_der,
    signed_component,
    validate_report_format,
)
from tinfoil._v3.verifier._quote.sev.lib.tcb import (
    HWID_SIZE_VERSION_0,
    HWID_SIZE_VERSION_1,
    TCB_STRUCT_VERSION_0,
    TCB_STRUCT_VERSION_1,
    TcbError,
    TCBParts,
    TCBVersionStruct,
    tcb_struct_version,
)
from tinfoil._v3.verifier._x509 import der
from tinfoil._v3.verifier._x509.certificate import (
    OID_ECDSA_SHA384,
    OID_RSA_PSS,
    Certificate,
    SignatureAlgorithm,
    X509Error,
    can_issue_certificates,
    certificate_public_key,
    crl_distribution_point_uris,
    extensions,
    parse_certificate,
    signature_algorithm,
    verify_chain,
    verify_signature,
)
from tinfoil._v3.verifier._x509.crl import (
    CRLError,
    RevocationList,
    VerifiedRevocationList,
    is_revoked,
    verify_revocation_list,
)

# The KDS extensions of a VCEK certificate.
OID_STRUCT_VERSION = "1.3.6.1.4.1.3704.1.1"
OID_PRODUCT_NAME_1 = "1.3.6.1.4.1.3704.1.2"
OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
OID_SPL4 = "1.3.6.1.4.1.3704.1.3.4"
OID_SPL5 = "1.3.6.1.4.1.3704.1.3.5"
OID_SPL6 = "1.3.6.1.4.1.3704.1.3.6"
OID_SPL7 = "1.3.6.1.4.1.3704.1.3.7"
OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
OID_FMC_SPL = "1.3.6.1.4.1.3704.1.3.9"
OID_HWID = "1.3.6.1.4.1.3704.1.4"
OID_CSP_ID = "1.3.6.1.4.1.3704.1.5"
OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
"""Imparted by the issuing ASK; the one non-KDS extension a VCEK may carry."""
_KDS_OIDS = frozenset(
    {
        OID_STRUCT_VERSION,
        OID_PRODUCT_NAME_1,
        OID_BL_SPL,
        OID_TEE_SPL,
        OID_SNP_SPL,
        OID_SPL4,
        OID_SPL5,
        OID_SPL6,
        OID_SPL7,
        OID_UCODE_SPL,
        OID_FMC_SPL,
        OID_HWID,
        OID_CSP_ID,
    }
)

# The subject and issuer attributes that every AMD certificate carries.
AMD_COUNTRY = "US"
AMD_LOCALITY = "Santa Clara"
AMD_STATE = "CA"
AMD_ORGANIZATION = "Advanced Micro Devices"
AMD_ORGANIZATIONAL_UNIT = "Engineering"
VCEK_COMMON_NAME = "SEV-VCEK"

_CRL_PATH_SUFFIX = "/crl"


class ChainError(ValueError):
    """A certificate that does not fit the AMD profile, does not chain to the pinned root, is revoked, or a report
    signature that does not verify."""


@dataclass(frozen=True, slots=True)
class VcekExtensions:
    """The KDS extensions of a VCEK certificate."""

    struct_version: int
    product_name: str
    hwid: bytes
    """64 bytes in layout version 0; 8 bytes (the PSN-based hardware id) in layout version 1."""
    tcb: TCBVersionStruct
    """The TCB that the certificate is certified for, in the layout that ``struct_version`` names."""


@dataclass(frozen=True, slots=True)
class CertificateChain:
    """The verified ARK, ASK and VCEK."""

    ark: Certificate
    ask: Certificate
    vcek: Certificate


def kds_extensions(certificate: Certificate) -> dict[str, bytes]:
    """The KDS extensions by OID; any extension other than those and the authority key identifier is an error."""
    found: dict[str, bytes] = {}
    for ext in extensions(certificate):
        if ext.oid == OID_AUTHORITY_KEY_IDENTIFIER:
            continue
        if ext.oid not in _KDS_OIDS:
            raise ChainError(f"not an AMD KDS OID: {ext.oid}")
        found[ext.oid] = ext.value
    return found


def vcek_certificate_extensions(certificate: Certificate) -> VcekExtensions:
    """Decode the KDS extensions of a VCEK: the struct version selects the layout, every level is required, the
    hardware id has the layout's size, and a CSP id (a VLEK marker) is an error."""
    exts = kds_extensions(certificate)
    struct_version = _u8(exts, OID_STRUCT_VERSION, "StructVersion")
    product_name = _ia5_string(exts, OID_PRODUCT_NAME_1, "ProductName1")
    if struct_version == TCB_STRUCT_VERSION_0:
        hwid_size = HWID_SIZE_VERSION_0
    elif struct_version == TCB_STRUCT_VERSION_1:
        hwid_size = HWID_SIZE_VERSION_1
    else:
        raise ChainError(f"unsupported TCB structVersion {struct_version}")
    hwid = _octet_string(exts, OID_HWID, "HWID", hwid_size) if OID_HWID in exts else b""
    if OID_CSP_ID in exts:
        csp_id = _ia5_string(exts, OID_CSP_ID, "CSP_ID")
        if OID_HWID in exts:
            raise ChainError(f"certificate has both HWID ({hwid.hex()}) and CSP_ID ({csp_id}) extensions")
        raise ChainError(f"unexpected CSP_ID in VCEK certificate: {csp_id}")
    bl_spl = _u8(exts, OID_BL_SPL, "BlSpl")
    tee_spl = _u8(exts, OID_TEE_SPL, "TeeSpl")
    snp_spl = _u8(exts, OID_SNP_SPL, "SnpSpl")
    spl5 = _u8(exts, OID_SPL5, "Spl5")
    spl6 = _u8(exts, OID_SPL6, "Spl6")
    spl7 = _u8(exts, OID_SPL7, "Spl7")
    ucode_spl = _u8(exts, OID_UCODE_SPL, "UcodeSpl")
    spl4 = fmc_spl = 0
    if struct_version == TCB_STRUCT_VERSION_0:
        if OID_FMC_SPL in exts:
            raise ChainError("FmcSpl extension is not valid for TCB struct version 0")
        spl4 = _u8(exts, OID_SPL4, "Spl4")
    else:
        if OID_SPL4 in exts:
            raise ChainError("Spl4 extension is not valid for TCB struct version 1")
        fmc_spl = _u8(exts, OID_FMC_SPL, "FmcSpl")
    parts = TCBParts(
        version=struct_version,
        bl_spl=bl_spl,
        tee_spl=tee_spl,
        spl4=spl4,
        spl5=spl5,
        spl6=spl6,
        spl7=spl7,
        snp_spl=snp_spl,
        ucode_spl=ucode_spl,
        fmc_spl=fmc_spl,
    )
    try:
        tcb = parts.to_version_struct()
    except TcbError as err:
        raise ChainError(str(err)) from err
    if len(hwid) not in (HWID_SIZE_VERSION_0, HWID_SIZE_VERSION_1):
        raise ChainError("missing HWID extension for VCEK certificate")
    return VcekExtensions(struct_version=struct_version, product_name=product_name, hwid=hwid, tcb=tcb)


def _u8(exts: dict[str, bytes], oid: str, field: str) -> int:
    value = exts.get(oid)
    if value is None:
        raise ChainError(f"no extension for field {field}")
    try:
        number = der.integer(der.decode(value))
    except der.DerError as err:
        raise ChainError(f"could not parse extension {field} as an integer: {err}") from err
    if not 0 <= number <= 255:
        raise ChainError(f"int value for field {field} isn't a uint8: {number}")
    return number


def _ia5_string(exts: dict[str, bytes], oid: str, field: str) -> str:
    value = exts.get(oid)
    if not value:
        raise ChainError(f"no extension for field {field}")
    if value[0] != der.TAG_IA5_STRING:
        raise ChainError(f"value is not tagged as an IA5String: {value[0]}")
    try:
        return der.ia5_string(der.decode(value))
    except der.DerError as err:
        raise ChainError(f"could not parse extension {field} as an IA5String: {err}") from err


def _octet_string(exts: dict[str, bytes], oid: str, field: str, size: int) -> bytes:
    """The extension's value, which the KDS writes either bare or wrapped in an OCTET STRING."""
    value = exts[oid]
    if len(value) == size:
        return value
    try:
        octets = der.octet_string(der.decode(value))
    except der.DerError as err:
        raise ChainError(f"could not parse extension {field} as an octet string: {err}") from err
    if len(octets) != size:
        raise ChainError(f"{field} size is {len(octets)}, expected {size}")
    return octets


def common_name(name: x509.Name) -> str:
    """The last commonName attribute of a name, or "" when it has none."""
    value = ""
    for attribute in name.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        if isinstance(attribute.value, str):
            value = attribute.value
    return value


def validate_amd_location(name: x509.Name, role: str) -> None:
    """Require exactly one of each of AMD's country, locality, state, organization and organizational unit."""
    for oid, label, plural, want in (
        (x509.NameOID.COUNTRY_NAME, "country", "countries", AMD_COUNTRY),
        (x509.NameOID.LOCALITY_NAME, "locality", "localities", AMD_LOCALITY),
        (x509.NameOID.STATE_OR_PROVINCE_NAME, "state", "states", AMD_STATE),
        (x509.NameOID.ORGANIZATION_NAME, "organization", "organizations", AMD_ORGANIZATION),
        (x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "organizational unit", "organizational units", AMD_ORGANIZATIONAL_UNIT),
    ):
        values = [a.value for a in name.get_attributes_for_oid(oid) if isinstance(a.value, str)]
        if len(values) != 1:
            raise ChainError(f"{role} has {len(values)} {plural}, want 1")
        if values[0] != want:
            raise ChainError(f"{role} {label} '{values[0]}' not expected for AMD. Expected '{want}'")


def intermediate_common_name(product_line: str) -> str:
    """The commonName of the ASK that issues VCEKs for a product line."""
    return f"SEV-{product_line}"


def validate_vcek_certificate(certificate: Certificate, product_line: str) -> VcekExtensions:
    """Check the VCEK against the KDS profile: X.509 v3, signed with RSA-PSS SHA-384, an ECDSA P-384 key, AMD's
    subject with the VCEK common name, well-formed KDS extensions, and a TCB layout that matches ``product_line``."""
    if certificate.version != x509.Version.v3:
        raise ChainError(f"VCEK certificate version is {certificate.version.value + 1}, expected 3")
    if _signature_algorithm_oid(certificate) != OID_RSA_PSS:
        raise ChainError("VCEK certificate signature algorithm is not SHA-384 with RSASSA-PSS")
    key = certificate_public_key(certificate)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ChainError("VCEK certificate public key type is not ECDSA")
    if not isinstance(key.curve, ec.SECP384R1):
        raise ChainError(f"VCEK certificate public key curve is {key.curve.name}, expected P-384")
    validate_amd_location(certificate.subject, "VCEK subject")
    cn = common_name(certificate.subject)
    if cn != VCEK_COMMON_NAME:
        raise ChainError(f"VCEK certificate subject common name {cn} not expected. Expected {VCEK_COMMON_NAME}")
    exts = vcek_certificate_extensions(certificate)
    try:
        expected = tcb_struct_version(product_line)
    except TcbError as err:
        raise ChainError(f"could not determine TCB format for product {product_line!r}: {err}") from err
    if expected != exts.tcb.version:
        raise ChainError(f"product {product_line!r} and VCEK certificate use different TCB formats")
    return exts


def validate_vcek_issuer(certificate: Certificate, product_line: str) -> None:
    """Require the VCEK's issuer to be AMD's ASK for ``product_line``, by name."""
    validate_amd_location(certificate.issuer, "VCEK issuer")
    want = intermediate_common_name(product_line)
    cn = common_name(certificate.issuer)
    if cn != want:
        raise ChainError(f"VCEK certificate issuer common name {cn} not expected. Expected {want}")


def _signature_algorithm_oid(certificate: Certificate) -> str | None:
    """The OID of a supported signature algorithm, or None for one that is not supported."""
    outer = der.children(der.decode(certificate.public_bytes(serialization.Encoding.DER)))
    try:
        return signature_algorithm(outer[1]).oid
    except (X509Error, der.DerError):
        return None


def verify_vcek_chain(vcek: Certificate, ask: Certificate, ark: Certificate, now: datetime) -> None:
    """Verify the path VCEK, ASK, ARK at ``now``: validity, issuing authority and every signature along it."""
    try:
        verify_chain(vcek, [ask], [ark], now)
    except X509Error as err:
        raise ChainError(f"error verifying VCEK certificate: {err}") from err


def crl_distribution_points(certificate: Certificate) -> tuple[str, ...]:
    """The URIs named by the certificate's CRL distribution points, in order; empty without the extension.

    The extension is read from the DER directly, so that a name form other
    than a URI is skipped rather than failing the read, and a malformed
    extension is a ChainError.
    """
    try:
        return crl_distribution_point_uris(certificate)
    except X509Error as err:
        raise ChainError(f"CRL distribution points: {err}") from err


def _names_product_crl(url: str) -> bool:
    """Whether ``url``'s path ends in the product revocation list suffix; a URL that does not split is no match."""
    try:
        return urlsplit(url).path.endswith(_CRL_PATH_SUFFIX)
    except ValueError:
        return False


def check_ask_not_revoked(
    ask: Certificate, ark: Certificate, crl: RevocationList, now: datetime
) -> VerifiedRevocationList:
    """Check the product revocation list: the ASK must name a distribution point for it, the ARK must have signed
    it, ``now`` must lie within its window, and the ASK must not be listed.

    The VCEK's own serial is not looked up: AMD supersedes VCEKs through
    the TCB rather than revoking them.
    """
    if not any(_names_product_crl(url) for url in crl_distribution_points(ask)):
        raise ChainError("ASK names no CRL distribution point for the product revocation list")
    if not can_issue_certificates(ark):
        raise ChainError("ARK is not a certificate authority")
    try:
        verified = verify_revocation_list(crl, ark, now)
    except CRLError as err:
        raise ChainError(f"CRL is not signed by ARK: {err}") from err
    if is_revoked(verified, ask.serial_number):
        raise ChainError("ASK was revoked")
    return verified


def verify_report_signature(report: Report, vcek: Certificate) -> None:
    """Verify the report's ECDSA P-384 signature over the signed component under the VCEK's key.

    The report must have a supported version and a well-formed policy,
    and its signature algorithm must be ECDSA P-384 with SHA-384.
    """
    try:
        validate_report_format(report.raw)
        signature = report_signature_der(report)
    except ValueError as err:
        raise ChainError(f"attestation report format error: {err}") from err
    try:
        verify_signature(
            SignatureAlgorithm(oid=OID_ECDSA_SHA384),
            certificate_public_key(vcek),
            signature,
            signed_component(report.raw),
        )
    except X509Error as err:
        raise ChainError(f"report signature verification error: {err}") from err


def parse_vcek(vcek_der: bytes) -> Certificate:
    """Parse the VCEK's DER; an empty value is an error naming the signer."""
    if not vcek_der:
        raise ChainError(f"missing {ReportSigner.VCEK} certificate")
    try:
        return parse_certificate(vcek_der)
    except X509Error as err:
        raise ChainError(f"could not interpret {ReportSigner.VCEK} DER bytes: {err}") from err
