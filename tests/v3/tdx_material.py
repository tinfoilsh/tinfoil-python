"""Synthetic Intel-mimicking TDX material for unit tests: a root -> platform
CA -> PCK leaf chain with the Intel SGX OID extensions, a signed TDX quote v4,
and the PCS collateral (TCB Info, QE Identity, CRLs) the DCAP core replays.
Mirrors the conformance suite's fixture generator so unit tests exercise the
same real cryptography the fixtures do (no mocks)."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from docbuilder import build_doc

INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
SYNTH_FMSPC = "50806f000000"
PCE_SVN = 11

_OID_SGX_EXT = "1.2.840.113741.1.13.1"
_OID_PPID = "1.2.840.113741.1.13.1.1"
_OID_TCB = "1.2.840.113741.1.13.1.2"
_OID_PCEID = "1.2.840.113741.1.13.1.3"
_OID_FMSPC = "1.2.840.113741.1.13.1.4"

TCB_URL = f"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={SYNTH_FMSPC}"
QE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
PCKCRL_URL = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
ROOTCRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

TDX_QUOTE_V1_FORMAT = "https://tinfoil.sh/format/tdx-quote/v1"
INTEL_PCS_V1_FORMAT = "https://tinfoil.sh/collateral/intel-pcs/v1"


# --- Minimal DER helpers for the Intel SGX extension ---------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _der_seq(content: bytes) -> bytes:
    return bytes([0x30]) + _der_len(len(content)) + content


def _der_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunks = [p & 0x7F]
        p >>= 7
        while p:
            chunks.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunks))
    return bytes([0x06]) + _der_len(len(body)) + body


def _der_int(n: int) -> bytes:
    if n == 0:
        return bytes([0x02, 0x01, 0x00])
    body = b""
    x = n
    while x:
        body = bytes([x & 0xFF]) + body
        x >>= 8
    if body[0] & 0x80:
        body = b"\x00" + body
    return bytes([0x02]) + _der_len(len(body)) + body


def _der_octet(b: bytes) -> bytes:
    return bytes([0x04]) + _der_len(len(b)) + b


def build_sgx_extension(
    *,
    ppid: bytes = b"\x55" * 16,
    cpu_svn: bytes = bytes.fromhex("05050202030100030000000000000000"),
    pce_svn: int = PCE_SVN,
    tcb_components: Optional[list[int]] = None,
    pceid: bytes = b"\x00\x00",
    fmspc: bytes = bytes.fromhex(SYNTH_FMSPC),
) -> bytes:
    if tcb_components is None:
        tcb_components = list(cpu_svn)
    ppid_entry = _der_seq(_der_oid(_OID_PPID) + _der_octet(ppid))
    tcb_inner = b""
    for i, comp in enumerate(tcb_components, start=1):
        tcb_inner += _der_seq(_der_oid(f"{_OID_TCB}.{i}") + _der_int(comp))
    tcb_inner += _der_seq(_der_oid(f"{_OID_TCB}.17") + _der_int(pce_svn))
    tcb_inner += _der_seq(_der_oid(f"{_OID_TCB}.18") + _der_octet(cpu_svn))
    tcb_entry = _der_seq(_der_oid(_OID_TCB) + _der_seq(tcb_inner))
    pceid_entry = _der_seq(_der_oid(_OID_PCEID) + _der_octet(pceid))
    fmspc_entry = _der_seq(_der_oid(_OID_FMSPC) + _der_octet(fmspc))
    return _der_seq(ppid_entry + tcb_entry + pceid_entry + fmspc_entry)


# --- Synthetic chain ------------------------------------------------------------


@dataclass
class SynthCert:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)


@dataclass
class SynthChain:
    root_ca: SynthCert
    platform_ca: SynthCert
    tcb_signer: SynthCert
    pck_leaf: SynthCert
    ak_key: ec.EllipticCurvePrivateKey


_NAME_TAIL = [
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Santa Clara"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
]

NOT_BEFORE = datetime(2023, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2030, 1, 1, tzinfo=timezone.utc)


def _spki(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _build_root(common_name: str) -> SynthCert:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)] + _NAME_TAIL)
    ski = hashlib.sha1(_spki(key)).digest()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.AuthorityKeyIdentifier(ski, None, None), critical=False
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(ROOTCRL_URL)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier(ski), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return SynthCert(cert=cert, key=key)


def _build_under(
    issuer: SynthCert,
    common_name: str,
    *,
    is_ca: bool,
    sgx_extension: Optional[bytes] = None,
) -> SynthCert:
    key = ec.generate_private_key(ec.SECP256R1())
    ski = hashlib.sha1(_spki(key)).digest()
    aki = hashlib.sha1(
        issuer.cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).digest()
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)] + _NAME_TAIL)
        )
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(hashlib.sha256(common_name.encode()).digest()[:8], "big"))
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.AuthorityKeyIdentifier(aki, None, None), critical=False)
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "https://certificates.trustedservices.intel.com/IntelSGXPCKPlatform.crl"
                            )
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier(ski), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not is_ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if sgx_extension is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(_OID_SGX_EXT), sgx_extension),
            critical=False,
        )
    cert = builder.sign(issuer.key, hashes.SHA256())
    return SynthCert(cert=cert, key=key)


def build_synth_chain(
    *,
    ppid: bytes = b"\x55" * 16,
    pce_svn: int = PCE_SVN,
    sgx_extension: Optional[bytes] = None,
) -> SynthChain:
    root = _build_root("Intel SGX Root CA")
    platform_ca = _build_under(root, "Intel SGX PCK Platform CA", is_ca=True)
    tcb_signer = _build_under(root, "Intel SGX TCB Signing", is_ca=False)
    if sgx_extension is None:
        sgx_extension = build_sgx_extension(ppid=ppid, pce_svn=pce_svn)
    pck_leaf = _build_under(
        platform_ca, "Intel SGX PCK Certificate", is_ca=False, sgx_extension=sgx_extension
    )
    return SynthChain(
        root_ca=root,
        platform_ca=platform_ca,
        tcb_signer=tcb_signer,
        pck_leaf=pck_leaf,
        ak_key=ec.generate_private_key(ec.SECP256R1()),
    )


# --- TDX quote v4 ---------------------------------------------------------------


def _raw_pubkey_xy(key: ec.EllipticCurvePrivateKey) -> bytes:
    raw = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return raw[1:]


def _ecdsa_sign_raw(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    der = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


@dataclass
class TdBodyFields:
    """Controllable TD Quote Body fields; defaults match the conformance
    fixture generator's 'clean' TD."""

    tee_tcb_svn: bytes = b"\x00\x03\x05\x00" + b"\x00" * 12
    mr_seam: bytes = b"\xaa" * 48
    mr_signer_seam: bytes = b"\x00" * 48
    seam_attributes: bytes = b"\x00" * 8
    td_attributes: bytes = b"\x00\x00\x00\x40\x00\x00\x00\x00"
    xfam: bytes = b"\xe7\x1a\x06\x00\x00\x00\x00\x00"
    mr_td: bytes = b"\x11" * 48
    mr_config_id: bytes = b"\x00" * 48
    mr_owner: bytes = b"\x00" * 48
    mr_owner_config: bytes = b"\x00" * 48
    rtmr0: bytes = b"\x22" * 48
    rtmr1: bytes = b"\x33" * 48
    rtmr2: bytes = b"\x44" * 48
    rtmr3: bytes = b"\x00" * 48
    report_data: bytes = b"\x66" * 64

    def to_bytes(self) -> bytes:
        out = (
            self.tee_tcb_svn
            + self.mr_seam
            + self.mr_signer_seam
            + self.seam_attributes
            + self.td_attributes
            + self.xfam
            + self.mr_td
            + self.mr_config_id
            + self.mr_owner
            + self.mr_owner_config
            + self.rtmr0
            + self.rtmr1
            + self.rtmr2
            + self.rtmr3
            + self.report_data
        )
        assert len(out) == 584
        return out


def _build_qe_report(
    *,
    mrsigner: bytes,
    isv_prod_id: int,
    isv_svn: int,
    misc_select: int,
    attributes: bytes,
    ak_pubkey_raw: bytes,
    report_data: Optional[bytes] = None,
) -> bytes:
    if report_data is None:
        report_data = hashlib.sha256(ak_pubkey_raw).digest() + b"\x00" * 32
    body = (
        b"\x00" * 16  # cpu_svn
        + struct.pack("<I", misc_select)
        + b"\x00" * 28  # reserved1
        + attributes
        + b"\x77" * 32  # mr_enclave
        + b"\x00" * 32  # reserved2
        + mrsigner
        + b"\x00" * 96  # reserved3
        + struct.pack("<H", isv_prod_id)
        + struct.pack("<H", isv_svn)
        + b"\x00" * 60  # reserved4
        + report_data
    )
    assert len(body) == 384
    return body


def build_tdx_quote_v4(
    chain: SynthChain,
    *,
    body: Optional[TdBodyFields] = None,
    quote_signing_key: Optional[ec.EllipticCurvePrivateKey] = None,
    qe_mrsigner: bytes = b"\xdc" * 32,
    qe_isv_prod_id: int = 2,
    qe_isv_svn: int = 8,
    qe_misc_select: int = 0,
    qe_attributes: bytes = b"\x11" + b"\x00" * 15,
    qe_report_data: Optional[bytes] = None,
) -> bytes:
    """Pack a complete synthetic v4 TDX quote signed by chain.ak_key with the
    PCK chain leaf || platform CA || root."""
    if body is None:
        body = TdBodyFields()
    header = (
        struct.pack("<H", 4)
        + struct.pack("<H", 2)
        + struct.pack("<I", 0x81)
        + b"\x00\x00"  # RESERVED1
        + b"\x00\x00"  # RESERVED2
        + INTEL_QE_VENDOR_ID
        + b"\x00" * 20
    )
    body_bytes = body.to_bytes()
    signed_region = header + body_bytes

    signing_key = quote_signing_key or chain.ak_key
    quote_sig_raw = _ecdsa_sign_raw(signing_key, signed_region)
    ak_pubkey_raw = _raw_pubkey_xy(chain.ak_key)

    qe_report = _build_qe_report(
        mrsigner=qe_mrsigner,
        isv_prod_id=qe_isv_prod_id,
        isv_svn=qe_isv_svn,
        misc_select=qe_misc_select,
        attributes=qe_attributes,
        ak_pubkey_raw=ak_pubkey_raw,
        report_data=qe_report_data,
    )
    qe_report_sig_raw = _ecdsa_sign_raw(chain.pck_leaf.key, qe_report)
    qe_auth_data_section = struct.pack("<H", 0)

    pck_chain_pem = (
        chain.pck_leaf.pem.encode() + chain.platform_ca.pem.encode() + chain.root_ca.pem.encode()
    )
    qe_inner_cert_section = struct.pack("<H", 5) + struct.pack("<I", len(pck_chain_pem)) + pck_chain_pem
    qe_report_cert_data = qe_report + qe_report_sig_raw + qe_auth_data_section + qe_inner_cert_section
    qe_cert_data_section = struct.pack("<H", 6) + struct.pack("<I", len(qe_report_cert_data)) + qe_report_cert_data
    quote_sig_data = quote_sig_raw + ak_pubkey_raw + qe_cert_data_section
    return header + body_bytes + struct.pack("<I", len(quote_sig_data)) + quote_sig_data


# --- PCS collateral -------------------------------------------------------------


def _sign_intel_pcs_response(inner: dict[str, Any], outer_key: str, signer: SynthCert) -> str:
    inner_bytes = json.dumps(inner, separators=(",", ":")).encode()
    sig_raw = _ecdsa_sign_raw(signer.key, inner_bytes)
    return '{"' + outer_key + '":' + inner_bytes.decode() + ',"signature":"' + sig_raw.hex() + '"}'


def default_tcb_levels(status: str = "UpToDate") -> list[dict[str, Any]]:
    return [
        {
            "tcb": {
                "sgxtcbcomponents": [
                    {"svn": b} for b in [5, 5, 2, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]
                ],
                "pcesvn": PCE_SVN,
                "tdxtcbcomponents": [
                    {"svn": b} for b in [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                ],
            },
            "tcbDate": "2023-02-15T00:00:00Z",
            "tcbStatus": status,
        }
    ]


def build_tcb_info_response(
    chain: SynthChain,
    *,
    tcb_levels: Optional[list[dict[str, Any]]] = None,
    fmspc: str = SYNTH_FMSPC,
    next_update: str = "2030-07-18T08:42:58Z",
    tcb_evaluation_data_number: int = 18,
    module_status: str = "UpToDate",
) -> str:
    tcb_info = {
        "id": "TDX",
        "version": 3,
        "issueDate": "2023-06-18T08:42:58Z",
        "nextUpdate": next_update,
        "fmspc": fmspc,
        "pceId": "0000",
        "tcbType": 0,
        "tcbEvaluationDataNumber": tcb_evaluation_data_number,
        "tdxModule": {
            "mrsigner": "00" * 48,
            "attributes": "0000000000000000",
            "attributesMask": "FFFFFFFFFFFFFFFF",
        },
        "tdxModuleIdentities": [
            {
                "id": "TDX_03",
                "mrsigner": "00" * 48,
                "attributes": "0000000000000000",
                "attributesMask": "FFFFFFFFFFFFFFFF",
                "tcbLevels": [
                    {
                        "tcb": {"isvsvn": 0},
                        "tcbDate": "2023-06-18T08:42:58Z",
                        "tcbStatus": module_status,
                    }
                ],
            }
        ],
        "tcbLevels": tcb_levels if tcb_levels is not None else default_tcb_levels(),
    }
    return _sign_intel_pcs_response(tcb_info, "tcbInfo", chain.tcb_signer)


def build_qe_identity_response(
    chain: SynthChain,
    *,
    mrsigner_hex: str = "DC" * 32,
    isv_prod_id: int = 2,
    isv_svn: int = 8,
    tcb_evaluation_data_number: int = 18,
    tcb_status: str = "UpToDate",
) -> str:
    qe_identity = {
        "id": "TD_QE",
        "version": 2,
        "issueDate": "2023-06-08T07:24:59Z",
        "nextUpdate": "2030-07-08T07:24:59Z",
        "tcbEvaluationDataNumber": tcb_evaluation_data_number,
        "miscselect": "00000000",
        "miscselectMask": "FFFFFFFF",
        "attributes": "11000000000000000000000000000000",
        "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
        "mrsigner": mrsigner_hex.upper(),
        "isvprodid": isv_prod_id,
        "tcbLevels": [
            {"tcb": {"isvsvn": isv_svn}, "tcbDate": "2023-06-08T07:24:59Z", "tcbStatus": tcb_status}
        ],
    }
    return _sign_intel_pcs_response(qe_identity, "enclaveIdentity", chain.tcb_signer)


def build_crl(
    issuer: SynthCert,
    *,
    this_update: datetime = NOT_BEFORE,
    next_update: datetime = NOT_AFTER,
    revoked_serials: Optional[list[int]] = None,
) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.cert.subject)
        .last_update(this_update)
        .next_update(next_update)
    )
    for serial in revoked_serials or []:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(this_update)
            .build()
        )
    crl = builder.sign(issuer.key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)


def url_encoded_pem_chain(*certs: SynthCert) -> str:
    return urllib.parse.quote("".join(c.pem for c in certs))


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def pcs_response(url: str, header_name: Optional[str], header_val: Optional[str], body) -> dict:
    r = {
        "url": url,
        "body_base64": b64(body if isinstance(body, bytes) else body.encode()),
        "headers": {header_name: [header_val]} if header_name else {},
    }
    return r


def default_responses(
    chain: SynthChain,
    *,
    tcb: Optional[str] = None,
    qe: Optional[str] = None,
    pck_crl: Optional[bytes] = None,
    root_crl: Optional[bytes] = None,
) -> list[dict]:
    tcb_chain = url_encoded_pem_chain(chain.tcb_signer, chain.root_ca)
    pck_chain = url_encoded_pem_chain(chain.platform_ca, chain.root_ca)
    return [
        pcs_response(TCB_URL, "Tcb-Info-Issuer-Chain", tcb_chain, tcb or build_tcb_info_response(chain)),
        pcs_response(QE_URL, "Sgx-Enclave-Identity-Issuer-Chain", tcb_chain, qe or build_qe_identity_response(chain)),
        pcs_response(PCKCRL_URL, "Sgx-Pck-Crl-Issuer-Chain", pck_chain, pck_crl if pck_crl is not None else build_crl(chain.platform_ca)),
        pcs_response(ROOTCRL_URL, None, None, root_crl if root_crl is not None else build_crl(chain.root_ca)),
    ]


def tdx_document(quote: bytes, responses: list[dict]) -> bytes:
    """A structurally valid v3 document carrying the quote and PCS collateral."""

    def mutate(doc: dict) -> None:
        doc["cpu_evidence"]["format"] = TDX_QUOTE_V1_FORMAT
        doc["cpu_evidence"]["report_base64"] = b64(quote)

    collateral = [
        {
            "id": "pcs",
            "role": "endorsement",
            "format": INTEL_PCS_V1_FORMAT,
            "subjects": ["cpu"],
            "data": {"responses": responses},
        }
    ]
    return build_doc(collateral=collateral, mutate=mutate)
