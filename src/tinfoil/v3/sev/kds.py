"""AMD Key Distribution Service definitions ported 1:1 from the forked
tinfoilsh/go-sev-guest kds package: product-specific TCB_VERSION layouts
(struct version 0 for Milan/Genoa/Siena, 1 for Turin) and the V[CL]EK
certificate extensions. All errors are ValueError; the calling module assigns
the rejection layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.x509 import UnrecognizedExtension

from .abi import (
    NONE_REPORT_SIGNER,
    VCEK_REPORT_SIGNER,
    VLEK_REPORT_SIGNER,
    fms_from_cpuid1_eax,
    report_signer_string,
)

# TCB struct versions: 0 for Milan & Genoa, 1 for Turin.
TCB_STRUCT_VERSION_0 = 0
TCB_STRUCT_VERSION_1 = 1

# HWID extension lengths per TCB struct version.
HWID_LEN_VERSION_0 = 64
HWID_LEN_VERSION_1 = 8

# KDS x509v3 extension OIDs (dotted).
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

_AUTHORITY_KEY_OID = "2.5.29.35"

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


def product_line_to_tcb_version(product_line: str) -> int:
    """The TCB struct version a product line uses in V[CL]EK x509 extensions
    (Go kds.productLineToTCBVersion)."""
    if product_line in ("Milan", "Genoa", "Siena"):
        return TCB_STRUCT_VERSION_0
    if product_line == "Turin":
        return TCB_STRUCT_VERSION_1
    raise ValueError(f'invalid product line "{product_line}"')


@dataclass(frozen=True)
class TCBParts:
    """All TCB field values of an AMD TCB_VERSION, tagged with the layout
    version they belong to (Go kds.TCBParts)."""

    version: int
    bl_spl: int = 0
    tee_spl: int = 0
    spl4: int = 0
    spl5: int = 0
    spl6: int = 0
    spl7: int = 0
    snp_spl: int = 0
    ucode_spl: int = 0
    fmc_spl: int = 0


def new_tcb_parts(
    product_line: str,
    *,
    fmc_spl: int = 0,
    bl_spl: int = 0,
    tee_spl: int = 0,
    snp_spl: int = 0,
    ucode_spl: int = 0,
) -> TCBParts:
    """Validate and tag TCB component values with the layout used by
    product_line (Go kds.NewTCBParts)."""
    version = product_line_to_tcb_version(product_line)
    parts = TCBParts(
        version=version,
        fmc_spl=fmc_spl,
        bl_spl=bl_spl,
        tee_spl=tee_spl,
        snp_spl=snp_spl,
        ucode_spl=ucode_spl,
    )
    tcb_parts_to_version(parts)  # range/layout validation
    return parts


def tcb_parts_to_version(parts: TCBParts) -> tuple[int, int]:
    """Compose (struct version, 64-bit TCB) from parts (Go
    kds.TCBParts.ToTCBVersionStruct). Only UcodeSpl may be 0-255; all others
    must be 0-127."""

    def check127(name: str, value: int) -> None:
        if value > 127:
            raise ValueError(f"{name} TCB part is {value}. Expect 0-127")

    check127("SnpSpl", parts.snp_spl)
    check127("Spl7", parts.spl7)
    check127("Spl6", parts.spl6)
    check127("Spl5", parts.spl5)
    check127("Spl4", parts.spl4)
    check127("TeeSpl", parts.tee_spl)
    check127("BlSpl", parts.bl_spl)
    check127("FmcSpl", parts.fmc_spl)

    if parts.version == TCB_STRUCT_VERSION_0:
        if parts.fmc_spl != 0:
            raise ValueError("FmcSpl is not defined for TCB struct version 0")
        tcb = (
            (parts.ucode_spl << 56)
            | (parts.snp_spl << 48)
            | (parts.spl7 << 40)
            | (parts.spl6 << 32)
            | (parts.spl5 << 24)
            | (parts.spl4 << 16)
            | (parts.tee_spl << 8)
            | parts.bl_spl
        )
        return TCB_STRUCT_VERSION_0, tcb
    if parts.version == TCB_STRUCT_VERSION_1:
        if parts.spl4 != 0 or parts.spl5 != 0 or parts.spl6 != 0 or parts.spl7 != 0:
            raise ValueError("reserved Turin TCB components must be zero")
        tcb = (
            (parts.ucode_spl << 56)
            | (parts.snp_spl << 24)
            | (parts.tee_spl << 16)
            | (parts.bl_spl << 8)
            | parts.fmc_spl
        )
        return TCB_STRUCT_VERSION_1, tcb
    raise ValueError(f"unsupported TCB struct version: {parts.version}")


def decompose_tcb(version: int, tcb: int) -> TCBParts:
    """Decode the security patch levels from a 64-bit TCB under a layout
    version (Go kds.TCBVersionStruct.ToTCBParts)."""
    if version == TCB_STRUCT_VERSION_1:
        # Turin reserves bits 55:32; rejecting non-zero values keeps them from
        # disappearing when the structured representation is composed again.
        reserved = tcb & 0x00FFFFFF00000000
        if reserved != 0:
            raise ValueError(f"non-zero reserved bits in Turin TCB: 0x{reserved:x}")
        return TCBParts(
            version=version,
            ucode_spl=(tcb >> 56) & 0xFF,
            snp_spl=(tcb >> 24) & 0xFF,
            tee_spl=(tcb >> 16) & 0xFF,
            bl_spl=(tcb >> 8) & 0xFF,
            fmc_spl=tcb & 0xFF,
        )
    if version == TCB_STRUCT_VERSION_0:
        return TCBParts(
            version=version,
            ucode_spl=(tcb >> 56) & 0xFF,
            snp_spl=(tcb >> 48) & 0xFF,
            spl7=(tcb >> 40) & 0xFF,
            spl6=(tcb >> 32) & 0xFF,
            spl5=(tcb >> 24) & 0xFF,
            spl4=(tcb >> 16) & 0xFF,
            tee_spl=(tcb >> 8) & 0xFF,
            bl_spl=tcb & 0xFF,
        )
    raise ValueError(f"unknown TCB version: {version}")


def tcb_parts_le(tcb0: TCBParts, tcb1: TCBParts) -> bool:
    """True iff both use the same layout and all components of tcb0 are <=
    tcb1's (Go kds.TCBPartsLE)."""
    return (
        tcb0.version == tcb1.version
        and tcb0.ucode_spl <= tcb1.ucode_spl
        and tcb0.snp_spl <= tcb1.snp_spl
        and tcb0.spl7 <= tcb1.spl7
        and tcb0.spl6 <= tcb1.spl6
        and tcb0.spl5 <= tcb1.spl5
        and tcb0.spl4 <= tcb1.spl4
        and tcb0.tee_spl <= tcb1.tee_spl
        and tcb0.bl_spl <= tcb1.bl_spl
        and tcb0.fmc_spl <= tcb1.fmc_spl
    )


def product_line_from_fms(fms: int) -> str:
    """The KDS product line for a CPUID_1_EAX value (Go kds.ProductLineFromFms)."""
    family, model, _ = fms_from_cpuid1_eax(fms)
    if family == 0x19:
        extended_model = model >> 4
        if extended_model == 0:
            return "Milan"
        if extended_model == 1:
            return "Genoa"
        if extended_model == 0xA:
            return "Siena"
    elif family == 0x1A:
        # The KDS specification assigns extended models 0h and 1h to Turin.
        extended_model = model >> 4
        if extended_model in (0, 1):
            return "Turin"
    return "Unknown"


# --- strict-DER value readers for KDS extension payloads ----------------------


def _read_tlv(data: bytes, offset: int = 0) -> tuple[int, int, bytes, int]:
    """Read one DER TLV: (class, tag, content, end). Strict lengths only."""
    # Sibling: tdx/der.py read_tlv. Kept separate on purpose — this reader
    # rejects non-minimal long-form lengths (Go asn1 strictness for KDS
    # extension values); der.py's tolerates them but caps length bytes at 4.
    if offset + 2 > len(data):
        raise ValueError("truncated DER element")
    b0 = data[offset]
    cls = b0 >> 6
    if b0 & 0x1F == 0x1F:
        raise ValueError("high-tag-number DER forms are not supported")
    tag = b0 & 0x1F
    lb = data[offset + 1]
    idx = offset + 2
    if lb < 0x80:
        length = lb
    elif lb == 0x80:
        raise ValueError("indefinite DER length")
    else:
        n = lb & 0x7F
        if idx + n > len(data):
            raise ValueError("truncated DER length")
        length = int.from_bytes(data[idx : idx + n], "big")
        if n > 1 and data[idx] == 0 or length < 0x80:
            raise ValueError("non-minimal DER length")
        idx += n
    end = idx + length
    if end > len(data):
        raise ValueError("truncated DER content")
    return cls, tag, data[idx:end], end


def asn1_u8(value: Optional[bytes], field: str) -> int:
    """Parse an extension value as a DER INTEGER in 0-255 (Go kds.asn1U8)."""
    if value is None:
        raise ValueError(f"no extension for field {field}")
    try:
        cls, tag, content, end = _read_tlv(value)
    except ValueError:
        raise ValueError(f"could not parse extension as an integer: field {field}") from None
    if cls != 0 or tag != 0x02 or len(content) == 0:
        raise ValueError(f"could not parse extension as an integer: field {field}")
    if len(content) > 1 and (
        (content[0] == 0 and content[1] < 0x80)
        or (content[0] == 0xFF and content[1] >= 0x80)
    ):
        raise ValueError(f"could not parse extension as an integer: field {field}")
    if end != len(value):
        raise ValueError(f"unexpected leftover bytes for U8 field {field}")
    i = int.from_bytes(content, "big", signed=True)
    if i < 0 or i > 255:
        raise ValueError(f"int value for field {field} isn't a uint8: {i}")
    return i


def asn1_ia5_string(value: Optional[bytes], field: str) -> str:
    """Parse an extension value as an IA5String (Go kds.asn1IA5String)."""
    if value is None or len(value) == 0:
        raise ValueError(f"no extension for field {field}")
    if value[0] != 0x16:
        raise ValueError(f"value is not tagged as an IA5String: {value[0]}")
    try:
        _, _, content, end = _read_tlv(value)
    except ValueError:
        raise ValueError(
            f"could not parse extension as an IA5String: field {field}"
        ) from None
    if any(b >= 0x80 for b in content):
        raise ValueError(f"could not parse extension as an IA5String: field {field}")
    if end != len(value):
        raise ValueError(f"unexpected leftover bytes for IA5String field {field}")
    return content.decode("ascii")


def asn1_octet_string(value: Optional[bytes], field: str, size: int) -> bytes:
    """Accept the KDS HWID both raw (the KDS omits the type tag) and as a
    proper OCTET STRING (Go kds.asn1OctetString)."""
    if value is None:
        raise ValueError(f"no extension for field {field}")
    if len(value) == size:
        return value
    try:
        cls, tag, content, end = _read_tlv(value)
    except ValueError:
        raise ValueError(
            f"could not parse extension as an octet string: field {field}"
        ) from None
    if cls != 0 or tag != 0x04:
        raise ValueError(f"could not parse extension as an octet string: field {field}")
    if end != len(value):
        raise ValueError(f"expected leftover bytes in extension value for field {field}")
    if size >= 0 and len(content) != size:
        raise ValueError(f"size is {len(content)}, expected {size}")
    return content


# --- V[CL]EK certificate extensions -------------------------------------------


@dataclass(frozen=True)
class KDSExtensions:
    """The KDS-specified x509 extensions of a V[CL]EK certificate (Go
    kds.Extensions). tcb_struct_version tags the tcb_version layout; HWID is
    64 bytes for struct version 0, 8 bytes for version 1."""

    struct_version: int
    product_name: str
    hwid: Optional[bytes]
    tcb_struct_version: int
    tcb_version: int
    csp_id: str


def _kds_oid_map(cert: x509.Certificate) -> dict[str, bytes]:
    """Index the certificate's extensions by KDS OID, rejecting non-KDS
    extensions (the authority key id, imparted by signing, is skipped) and
    duplicates (Go kds.kdsOidMap)."""
    result: dict[str, bytes] = {}
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if oid == _AUTHORITY_KEY_OID:
            continue
        if oid not in _KDS_OIDS:
            raise ValueError(f"not an AMD KDS OID: {oid}")
        if oid in result:
            raise ValueError(f"duplicate AMD KDS extension: {oid}")
        if not isinstance(ext.value, UnrecognizedExtension):
            raise ValueError(f"unexpected parsed AMD KDS extension: {oid}")
        result[oid] = ext.value.value
    return result


def _kds_oid_map_to_extensions(exts: dict[str, bytes]) -> KDSExtensions:
    struct_version = asn1_u8(exts.get(OID_STRUCT_VERSION), "StructVersion")
    product_name = asn1_ia5_string(exts.get(OID_PRODUCT_NAME_1), "ProductName1")
    if struct_version == TCB_STRUCT_VERSION_0:
        hwid_len = HWID_LEN_VERSION_0
    elif struct_version == TCB_STRUCT_VERSION_1:
        hwid_len = HWID_LEN_VERSION_1
    else:
        raise ValueError(f"unsupported TCB structVersion {struct_version}")

    hwid: Optional[bytes] = None
    if OID_HWID in exts:
        hwid = asn1_octet_string(exts[OID_HWID], "HWID", hwid_len)
    csp_id = ""
    if OID_CSP_ID in exts:
        csp_id = asn1_ia5_string(exts[OID_CSP_ID], "CSP_ID")
        if hwid is not None:
            raise ValueError(
                f"certificate has both HWID ({hwid.hex()}) and CSP_ID ({csp_id}) extensions"
            )

    bl_spl = asn1_u8(exts.get(OID_BL_SPL), "BlSpl")
    tee_spl = asn1_u8(exts.get(OID_TEE_SPL), "TeeSpl")
    snp_spl = asn1_u8(exts.get(OID_SNP_SPL), "SnpSpl")
    spl5 = asn1_u8(exts.get(OID_SPL5), "Spl5")
    spl6 = asn1_u8(exts.get(OID_SPL6), "Spl6")
    spl7 = asn1_u8(exts.get(OID_SPL7), "Spl7")
    ucode_spl = asn1_u8(exts.get(OID_UCODE_SPL), "UcodeSpl")

    spl4 = 0
    fmc_spl = 0
    if struct_version == TCB_STRUCT_VERSION_0:
        if OID_FMC_SPL in exts:
            raise ValueError("FmcSpl extension is not valid for TCB struct version 0")
        spl4 = asn1_u8(exts.get(OID_SPL4), "Spl4")
    else:
        if OID_SPL4 in exts:
            raise ValueError("Spl4 extension is not valid for TCB struct version 1")
        fmc_spl = asn1_u8(exts.get(OID_FMC_SPL), "FmcSpl")

    tcb_struct_version, tcb = tcb_parts_to_version(
        TCBParts(
            version=struct_version,
            bl_spl=bl_spl,
            snp_spl=snp_spl,
            tee_spl=tee_spl,
            spl4=spl4,
            spl5=spl5,
            spl6=spl6,
            spl7=spl7,
            ucode_spl=ucode_spl,
            fmc_spl=fmc_spl,
        )
    )
    return KDSExtensions(
        struct_version=struct_version,
        product_name=product_name,
        hwid=hwid,
        tcb_struct_version=tcb_struct_version,
        tcb_version=tcb,
        csp_id=csp_id,
    )


def vcek_certificate_extensions(cert: x509.Certificate) -> KDSExtensions:
    """The KDS extensions of a VCEK certificate (Go kds.VcekCertificateExtensions)."""
    exts = _kds_oid_map_to_extensions(_kds_oid_map(cert))
    if exts.csp_id != "":
        raise ValueError(f"unexpected CSP_ID in VCEK certificate: {exts.csp_id}")
    if exts.hwid is None or len(exts.hwid) not in (HWID_LEN_VERSION_0, HWID_LEN_VERSION_1):
        raise ValueError("missing HWID extension for VCEK certificate")
    return exts


def vlek_certificate_extensions(cert: x509.Certificate) -> KDSExtensions:
    """The KDS extensions of a VLEK certificate (Go kds.VlekCertificateExtensions)."""
    exts = _kds_oid_map_to_extensions(_kds_oid_map(cert))
    if exts.csp_id == "":
        raise ValueError("missing CSP_ID in VLEK certificate")
    if exts.hwid is not None:
        raise ValueError(f"unexpected HWID in VLEK certificate: {exts.hwid.hex()}")
    return exts


def certificate_extensions(cert: x509.Certificate, key: int) -> KDSExtensions:
    """Dispatch on the report signer kind (Go kds.CertificateExtensions)."""
    if key == VCEK_REPORT_SIGNER:
        return vcek_certificate_extensions(cert)
    if key == VLEK_REPORT_SIGNER:
        return vlek_certificate_extensions(cert)
    if key == NONE_REPORT_SIGNER:
        return KDSExtensions(0, "", None, TCB_STRUCT_VERSION_0, 0, "")
    raise ValueError(f"unexpected endorsement key kind {report_signer_string(key)}")


def validate_extensions(exts: KDSExtensions, product_line: str) -> None:
    """With a known product line, require the certificate's TCB format to
    match the product's; the product-name claim itself is disregarded (Go
    verify.validateExtensions for knownProductLine != "")."""
    try:
        expected = product_line_to_tcb_version(product_line)
    except ValueError:
        raise ValueError(
            f'could not determine TCB format for product "{product_line}"'
        ) from None
    if expected != exts.tcb_struct_version:
        raise ValueError(
            f'product "{product_line}" and V[CL]EK certificate use different TCB formats'
        )
