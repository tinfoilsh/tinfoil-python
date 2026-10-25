"""Synthetic AMD SEV-SNP stack for the v3 SEV unit tests: mints an
ARK -> ASK -> VCEK chain, a signed report, and a CRL for either product line
(Genoa: TCB struct version 0, 64-byte HWID; Turin: struct version 1, 8-byte
HWID, fmc_spl). Adapted from tinfoil-conformance fixturegen/v3/sev_synth.py,
extended with Turin (#115) and mutation hooks. RSA-2048 keeps tests fast;
nothing in verification checks key sizes."""

from __future__ import annotations

import base64
import datetime
import json
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

from docbuilder import build_doc

REPORT_SIZE = 0x4A0
SIGNATURE_OFFSET = 0x2A0
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.DIGEST_LENGTH)

OID_STRUCT_VERSION = ObjectIdentifier("1.3.6.1.4.1.3704.1.1")
OID_PRODUCT_NAME = ObjectIdentifier("1.3.6.1.4.1.3704.1.2")
OID_HWID = ObjectIdentifier("1.3.6.1.4.1.3704.1.4")
OID_SPL = {
    "bl": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.1"),
    "tee": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.2"),
    "snp": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.3"),
    "spl4": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.4"),
    "spl5": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.5"),
    "spl6": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.6"),
    "spl7": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.7"),
    "ucode": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.8"),
    "fmc": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.9"),
}

BASE_TIME = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
NOT_BEFORE = BASE_TIME - datetime.timedelta(days=1)
NOT_AFTER = BASE_TIME + datetime.timedelta(days=3650)
NOW = BASE_TIME + datetime.timedelta(days=30)  # pinned verification clock

# Per-product identity: (family, model, stepping), product-name extension,
# TCB struct version, HWID length, default TCB parts, default platform_info.
PRODUCTS = {
    "Genoa": {
        "fms": (0x19, 0x11, 0x00),
        "product_name": "Genoa-B0",
        "struct_version": 0,
        "hwid_len": 64,
        "tcb": {"bl": 7, "tee": 0, "snp": 20, "ucode": 72},
        "platform_info": 0x0,
    },
    "Turin": {
        "fms": (0x1A, 0x02, 0x00),
        "product_name": "Turin-B0",
        "struct_version": 1,
        "hwid_len": 8,
        "tcb": {"fmc": 1, "bl": 7, "tee": 0, "snp": 20, "ucode": 72},
        # PLATFORM_INFO bit 6 (IOMMU_WRITE_SAFE) is required for Turin.
        "platform_info": 0x40,
    },
}

_LEAF_SCALAR = 0x6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A
_keys: dict[str, rsa.RSAPrivateKey] = {}


def _rsa_key(name: str) -> rsa.RSAPrivateKey:
    if name not in _keys:
        _keys[name] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _keys[name]


def compose_tcb(struct_version: int, parts: dict) -> int:
    p = {k: parts.get(k, 0) for k in ("fmc", "bl", "tee", "spl4", "spl5", "spl6", "spl7", "snp", "ucode")}
    if struct_version == 1:
        return (p["ucode"] << 56) | (p["snp"] << 24) | (p["tee"] << 16) | (p["bl"] << 8) | p["fmc"]
    return (
        (p["ucode"] << 56) | (p["snp"] << 48) | (p["spl7"] << 40) | (p["spl6"] << 32)
        | (p["spl5"] << 24) | (p["spl4"] << 16) | (p["tee"] << 8) | p["bl"]
    )


_AMD_LOCATION = [
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Santa Clara"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
]


def _name(cn: str) -> x509.Name:
    return x509.Name(_AMD_LOCATION + [x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _crl_dp(product: str) -> x509.CRLDistributionPoints:
    url = f"https://kdsintf.amd.com/vcek/v1/{product}/crl"
    return x509.CRLDistributionPoints(
        [x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(url)],
                                relative_name=None, reasons=None, crl_issuer=None)]
    )


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(val)) + val


def der_integer(n: int) -> bytes:
    content = b"\x00" if n == 0 else n.to_bytes(n.bit_length() // 8 + 1, "big")
    return _der_tlv(0x02, content)


def der_ia5(s: str) -> bytes:
    return _der_tlv(0x16, s.encode())


def der_octet_string(b: bytes) -> bytes:
    return _der_tlv(0x04, b)


def _ca_certs(product: str, ark_key, ask_key):
    ark_name, ask_name = _name(f"ARK-{product}"), _name(f"SEV-{product}")
    ark = (
        x509.CertificateBuilder()
        .subject_name(ark_name).issuer_name(ark_name)
        .public_key(ark_key.public_key()).serial_number(1)
        .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_crl_dp(product), critical=False)
        .sign(ark_key, hashes.SHA384(), rsa_padding=PSS)
    )
    ask = (
        x509.CertificateBuilder()
        .subject_name(ask_name).issuer_name(ark_name)
        .public_key(ask_key.public_key()).serial_number(2)
        .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_crl_dp(product), critical=False)
        .sign(ark_key, hashes.SHA384(), rsa_padding=PSS)
    )
    return ark, ask


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def rogue_anchor(product: str = "Genoa") -> tuple[str, str]:
    """An unrelated ARK+ASK chain for the wrong-root case."""
    ark, ask = _ca_certs(product, _rsa_key("rogue-ark"), _rsa_key("rogue-ask"))
    return _pem(ark), _pem(ask)


def _vcek_extensions(product: str, struct_version: int, tcb_parts: dict, hwid: bytes,
                     extra_exts=()):
    exts = [
        x509.UnrecognizedExtension(OID_STRUCT_VERSION, der_integer(struct_version)),
        x509.UnrecognizedExtension(OID_PRODUCT_NAME, der_ia5(PRODUCTS[product]["product_name"])),
        x509.UnrecognizedExtension(OID_HWID, der_octet_string(hwid)),
    ]
    if struct_version == 1:
        spl_keys = ["bl", "tee", "snp", "spl5", "spl6", "spl7", "ucode", "fmc"]
    else:
        spl_keys = ["bl", "tee", "snp", "spl4", "spl5", "spl6", "spl7", "ucode"]
    for key in spl_keys:
        exts.append(x509.UnrecognizedExtension(OID_SPL[key], der_integer(tcb_parts.get(key, 0))))
    exts.extend(extra_exts)
    return exts


def _build_chain(product: str, vcek_key, struct_version: int, tcb_parts: dict,
                 hwid: bytes, extra_vcek_exts=()):
    ark_key, ask_key = _rsa_key("ark"), _rsa_key("ask")
    ark, ask = _ca_certs(product, ark_key, ask_key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("SEV-VCEK")).issuer_name(_name(f"SEV-{product}"))
        .public_key(vcek_key.public_key()).serial_number(3)
        .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
    )
    for e in _vcek_extensions(product, struct_version, tcb_parts, hwid, extra_vcek_exts):
        builder = builder.add_extension(e, critical=False)
    vcek = builder.sign(ask_key, hashes.SHA384(), rsa_padding=PSS)
    return ark, ask, vcek


def _build_crl(product: str, revoke_serials=(), expired=False, signer="ark"):
    key = _rsa_key(signer)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name(f"ARK-{product}"))
        .last_update(NOT_BEFORE)
        .next_update(NOT_BEFORE + datetime.timedelta(days=1) if expired else NOT_AFTER)
    )
    for serial in revoke_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial).revocation_date(NOT_BEFORE).build()
        )
    return builder.sign(key, hashes.SHA384(), rsa_padding=PSS)


def build_sev(
    product: str = "Genoa",
    *,
    report_data: bytes = b"\x00" * 64,
    measurement: bytes = b"\xaa" * 48,
    chip_id: bytes | None = None,
    tcb_parts: dict | None = None,
    vcek_tcb_parts: dict | None = None,
    current_tcb_parts: dict | None = None,
    committed_tcb_parts: dict | None = None,
    launch_tcb_parts: dict | None = None,
    reported_tcb_raw: int | None = None,
    policy: int = 0x30000,
    platform_info: int | None = None,
    host_data: bytes = b"\x00" * 32,
    tamper_report_sig: bool = False,
    version: int = 3,
    signer_info: int = 0,
    fms: tuple | None = None,
    vcek_hwid: bytes | None = None,
    cert_struct_version: int | None = None,
    extra_vcek_exts=(),
    revoke_serials=(),
    crl_expired: bool = False,
    crl_signer: str = "ark",
    guest_svn: int = 0,
    vmpl: int = 0,
    family_id: bytes = b"\x00" * 16,
    image_id: bytes = b"\x00" * 16,
    id_key_digest: bytes = b"\x00" * 48,
    author_key_digest: bytes = b"\x00" * 48,
    current_version: tuple = (21, 55, 1),   # build, minor, major
    committed_version: tuple = (21, 55, 1),
    launch_mit_vector: int = 0,
    current_mit_vector: int = 0,
    report_mut=None,
    use_rogue_anchor: bool = False,
) -> dict:
    """Return the pieces for a v3 SEV cpu_evidence + collateral + anchor."""
    prod = PRODUCTS[product]
    struct_version = prod["struct_version"] if cert_struct_version is None else cert_struct_version
    tcb_parts = dict(prod["tcb"]) if tcb_parts is None else tcb_parts
    vcek_tcb_parts = tcb_parts if vcek_tcb_parts is None else vcek_tcb_parts
    current_tcb_parts = tcb_parts if current_tcb_parts is None else current_tcb_parts
    committed_tcb_parts = tcb_parts if committed_tcb_parts is None else committed_tcb_parts
    launch_tcb_parts = tcb_parts if launch_tcb_parts is None else launch_tcb_parts
    if chip_id is None:
        if product == "Turin":
            chip_id = b"\x22" * 8 + b"\x00" * 56
        else:
            chip_id = b"\x11" * 64
    if vcek_hwid is None:
        vcek_hwid = chip_id[: prod["hwid_len"]]
    if platform_info is None:
        platform_info = prod["platform_info"]
    if fms is None:
        fms = prod["fms"]

    vcek_key = ec.derive_private_key(_LEAF_SCALAR, ec.SECP384R1())
    ark, ask, vcek = _build_chain(
        product, vcek_key, struct_version, vcek_tcb_parts, vcek_hwid, extra_vcek_exts
    )

    report_layout = prod["struct_version"]
    r = bytearray(REPORT_SIZE)
    struct.pack_into("<I", r, 0x00, version)
    struct.pack_into("<I", r, 0x04, guest_svn)
    struct.pack_into("<Q", r, 0x08, policy)
    r[0x10:0x20] = family_id
    r[0x20:0x30] = image_id
    struct.pack_into("<I", r, 0x30, vmpl)
    struct.pack_into("<I", r, 0x34, 1)  # ECDSA P-384
    struct.pack_into("<Q", r, 0x38, compose_tcb(report_layout, current_tcb_parts))
    struct.pack_into("<Q", r, 0x40, platform_info)
    struct.pack_into("<I", r, 0x48, signer_info)
    r[0x50:0x90] = report_data
    r[0x90:0xC0] = measurement
    r[0xC0:0xE0] = host_data
    r[0xE0:0x110] = id_key_digest
    r[0x110:0x140] = author_key_digest
    reported = compose_tcb(report_layout, tcb_parts) if reported_tcb_raw is None else reported_tcb_raw
    struct.pack_into("<Q", r, 0x180, reported)
    r[0x188], r[0x189], r[0x18A] = fms
    r[0x1A0:0x1E0] = chip_id
    struct.pack_into("<Q", r, 0x1E0, compose_tcb(report_layout, committed_tcb_parts))
    r[0x1E8], r[0x1E9], r[0x1EA] = current_version
    r[0x1EC], r[0x1ED], r[0x1EE] = committed_version
    struct.pack_into("<Q", r, 0x1F0, compose_tcb(report_layout, launch_tcb_parts))
    struct.pack_into("<Q", r, 0x1F8, launch_mit_vector)
    struct.pack_into("<Q", r, 0x200, current_mit_vector)
    if report_mut is not None:
        report_mut(r)

    sig = vcek_key.sign(bytes(r[:SIGNATURE_OFFSET]), ec.ECDSA(hashes.SHA384()))
    r_int, s_int = decode_dss_signature(sig)
    r[SIGNATURE_OFFSET : SIGNATURE_OFFSET + 48] = r_int.to_bytes(48, "little")
    r[SIGNATURE_OFFSET + 0x48 : SIGNATURE_OFFSET + 0x48 + 48] = s_int.to_bytes(48, "little")
    if tamper_report_sig:
        r[SIGNATURE_OFFSET] ^= 0xFF

    crl = _build_crl(product, revoke_serials=revoke_serials, expired=crl_expired,
                     signer=crl_signer)

    ark_pem, ask_pem = _pem(ark), _pem(ask)
    if use_rogue_anchor:
        ark_pem, ask_pem = rogue_anchor(product)
    return {
        "report": bytes(r),
        "vcek_der": vcek.public_bytes(serialization.Encoding.DER),
        "cert_chain_pem": _pem(ask) + _pem(ark),  # KDS order: ASK then ARK
        "crl_der": crl.public_bytes(serialization.Encoding.DER),
        "root_pem": ask_pem.strip() + "\n" + ark_pem.strip() + "\n",
        "chip_id": chip_id,
        "measurement": measurement,
    }


VCEK_FMT = "https://tinfoil.sh/collateral/amd-vcek/v1"
CRL_FMT = "https://tinfoil.sh/collateral/amd-crl/v1"


def sev_doc_bytes(art: dict, collateral_mut=None) -> bytes:
    """A v3 document carrying the synthetic report and its collateral."""
    b64 = lambda b: base64.b64encode(b).decode()
    collateral = [
        {"id": "vcek", "role": "endorsement", "format": VCEK_FMT, "subjects": ["cpu"],
         "data": {"vcek_der_base64": b64(art["vcek_der"]),
                  "cert_chain_pem": art["cert_chain_pem"]}},
        {"id": "crl", "role": "endorsement", "format": CRL_FMT, "subjects": ["cpu"],
         "data": {"crl_der_base64": b64(art["crl_der"])}},
    ]
    if collateral_mut is not None:
        collateral_mut(collateral)

    def mutate(doc):
        doc["cpu_evidence"]["report_base64"] = b64(art["report"])

    return build_doc(collateral=collateral, mutate=mutate)
