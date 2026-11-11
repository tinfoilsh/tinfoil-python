"""A synthetic Intel TDX world for the verifier tests: a root, a PCK Platform CA, a TCB signing certificate, a PCK
certificate with the SGX extension, a signed quote, and the PCS responses that vouch for it.

Everything is generated at test time with ``cryptography``. ``Scenario``
holds every knob; each test changes one and builds the evidence.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from tests import pki
from tinfoil.verifier._document.collateral.tdx import PCSResponse
from tinfoil.verifier._quote.tdx.authenticate import Evidence
from tinfoil.verifier._quote.tdx.lib.abi import (
    CERT_DATA_TYPE_PCK_CERT_CHAIN,
    CERT_DATA_TYPE_QE_REPORT,
    HEADER_SIZE,
    INTEL_QE_VENDOR_ID,
    QE_REPORT_SIZE,
    TD_QUOTE_BODY_SIZE,
)
from tinfoil.verifier._x509 import der

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)

# The PCS URLs as the verifier requests them.
INTEL_SGX_ROOT_CA_CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
_TDX_BASE = "https://api.trustedservices.intel.com/tdx/certification/v4"
_SGX_BASE = "https://api.trustedservices.intel.com/sgx/certification/v4"


def tcb_info_url(fmspc: str) -> str:
    return f"{_TDX_BASE}/tcb?fmspc={fmspc}"


def qe_identity_url() -> str:
    return f"{_TDX_BASE}/qe/identity"


def pck_crl_url(ca: str) -> str:
    return f"{_SGX_BASE}/pckcrl?ca={ca}&encoding=der"


ROOT_CN = "Intel SGX Root CA"
PLATFORM_CA_CN = "Intel SGX PCK Platform CA"
PROCESSOR_CA_CN = "Intel SGX PCK Processor CA"
PCK_CN = "Intel SGX PCK Certificate"
TCB_SIGNING_CN = "Intel SGX TCB Signing"

PPID = bytes([0x55]) * 16
FMSPC = "50806f000000"
PCEID = "0000"
PCE_SVN = 11
CPU_SVN_COMPONENTS = bytes([5, 5, 2, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0])
TDX_COMPONENTS = [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
TEE_TCB_SVN = bytes([0, 3, 5] + [0] * 13)
QE_MRSIGNER = bytes([0xDC]) * 32
QE_ATTRIBUTES = bytes([0x11]) + bytes(15)
QE_ISV_PROD_ID = 2
QE_ISV_SVN = 8
MR_TD = bytes([0x11]) * 48
RTMRS = (bytes([0x22]) * 48, bytes([0x33]) * 48, bytes([0x44]) * 48, bytes(48))
REPORT_DATA = bytes([0xAB]) * 32 + bytes([0xCD]) * 32
TD_ATTRIBUTES = bytes.fromhex("0000001000000000")
XFAM = bytes.fromhex("e702060000000000")
MR_SEAM = bytes([0xAA]) * 48

_SGX_OID = "1.2.840.113741.1.13.1"

ENCIPHERMENT_USAGE = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=True,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)
"""A keyUsage that allows no signatures, for a PCK leaf that must not authenticate a QE report."""


# --- DER helpers -------------------------------------------------------------------


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der.encode_length(len(content)) + content


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        body.extend(reversed(chunk))
    return tlv(0x06, bytes(body))


def integer(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    content = value.to_bytes(length, "big")
    if content[0] & 0x80:
        content = b"\x00" + content
    return tlv(0x02, content)


def sequence(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def octet_string(value: bytes) -> bytes:
    return tlv(0x04, value)


def attribute(dotted: str, value: bytes) -> bytes:
    return sequence(oid(dotted), value)


def tcb_attribute(
    components: bytes = CPU_SVN_COMPONENTS, pce_svn: int = PCE_SVN, cpu_svn: bytes | None = None
) -> bytes:
    entries = [attribute(f"{_SGX_OID}.2.{i + 1}", integer(components[i])) for i in range(16)]
    entries.append(attribute(f"{_SGX_OID}.2.17", integer(pce_svn)))
    entries.append(attribute(f"{_SGX_OID}.2.18", octet_string(cpu_svn if cpu_svn is not None else components)))
    return attribute(f"{_SGX_OID}.2", sequence(*entries))


def sgx_extension(
    ppid: bytes = PPID,
    fmspc: str = FMSPC,
    pceid: str = PCEID,
    tcb: bytes | None = None,
    extra: tuple[bytes, ...] = (),
) -> bytes:
    """The DER value of the SGX extension: PPID, TCB, PCEID and FMSPC attributes, plus ``extra`` pairs."""
    items = [
        attribute(f"{_SGX_OID}.1", octet_string(ppid)),
        tcb if tcb is not None else tcb_attribute(),
        attribute(f"{_SGX_OID}.3", octet_string(bytes.fromhex(pceid))),
        attribute(f"{_SGX_OID}.4", octet_string(bytes.fromhex(fmspc))),
        *extra,
    ]
    return sequence(*items)


# --- the PKI -------------------------------------------------------------------------


@dataclass(frozen=True)
class IntelPKI:
    root: pki.Issued
    platform_ca: pki.Issued
    tcb_signing: pki.Issued

    def pem(self, issued: pki.Issued) -> bytes:
        return pki.load(issued.der).public_bytes(serialization.Encoding.PEM)


def _cdp(url: str) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(url)], None, None, None)])


def intel_pki(
    now: datetime = NOW,
    *,
    root_crl_url: str | None = INTEL_SGX_ROOT_CA_CRL_URL,
    platform_ca_cn: str = PLATFORM_CA_CN,
) -> IntelPKI:
    not_before = now - timedelta(days=365)
    not_after = now + timedelta(days=365)
    extra: list[tuple[x509.ExtensionType, bool]] = [] if root_crl_url is None else [(_cdp(root_crl_url), False)]
    root = pki.certificate(
        ROOT_CN,
        pki.p256(),
        ca=True,
        key_usage=pki.CA_USAGE,
        serial=1,
        not_before=not_before,
        not_after=not_after,
        extra=extra,
    )
    platform_ca = pki.certificate(
        platform_ca_cn,
        pki.p256(),
        root,
        ca=True,
        path_length=0,
        key_usage=pki.CA_USAGE,
        serial=2,
        not_before=not_before,
        not_after=not_after,
    )
    tcb_signing = pki.certificate(
        TCB_SIGNING_CN,
        pki.p256(),
        root,
        key_usage=pki.SIGNING_USAGE,
        serial=3,
        not_before=not_before,
        not_after=not_after,
    )
    return IntelPKI(root=root, platform_ca=platform_ca, tcb_signing=tcb_signing)


def pck_certificate(
    issuer: pki.Issued,
    key: ec.EllipticCurvePrivateKey | None = None,
    *,
    extension_value: bytes | None = None,
    now: datetime = NOW,
    serial: int = 4,
    cn: str = PCK_CN,
    extra_extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    key_usage: x509.KeyUsage | None = pki.SIGNING_USAGE,
) -> pki.Issued:
    """A PCK leaf with the six extensions of the profile: AKI, CDP, SKI, keyUsage, basicConstraints and the SGX
    extension. ``key_usage`` None leaves the keyUsage extension out."""
    key = key or pki.p256()
    issuer_cert = pki.load(issuer.der)
    value = extension_value if extension_value is not None else sgx_extension()
    extra: list[tuple[x509.ExtensionType, bool]] = [
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), False),  # type: ignore[arg-type]
        (_cdp("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"), False),
        (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
        (x509.UnrecognizedExtension(x509.ObjectIdentifier(_SGX_OID), value), False),
        *extra_extensions,
    ]
    return pki.certificate(
        cn,
        key,
        issuer,
        key_usage=key_usage,
        serial=serial,
        extra=extra,
        not_before=now - timedelta(days=365),
        not_after=now + timedelta(days=365),
    )


# --- quote ------------------------------------------------------------------------------


def raw_signature(key: ec.EllipticCurvePrivateKey, message: bytes, *, prehashed: bool = False) -> bytes:
    algorithm = ec.ECDSA(Prehashed(hashes.SHA256())) if prehashed else ec.ECDSA(hashes.SHA256())
    r, s = decode_dss_signature(key.sign(message, algorithm))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_public_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]


def header_bytes(*, reserved: bytes = bytes(4), version: int = 4, qe_vendor_id: bytes = INTEL_QE_VENDOR_ID) -> bytes:
    header = struct.pack("<HHI", version, 2, 0x81) + reserved + qe_vendor_id + bytes(20)
    assert len(header) == HEADER_SIZE
    return header


def body_bytes(
    *,
    tee_tcb_svn: bytes = TEE_TCB_SVN,
    mr_seam: bytes = MR_SEAM,
    mr_signer_seam: bytes = bytes(48),
    seam_attributes: bytes = bytes(8),
    td_attributes: bytes = TD_ATTRIBUTES,
    xfam: bytes = XFAM,
    mr_td: bytes = MR_TD,
    mr_config_id: bytes = bytes(48),
    mr_owner: bytes = bytes(48),
    mr_owner_config: bytes = bytes(48),
    rtmrs: tuple[bytes, bytes, bytes, bytes] = RTMRS,
    report_data: bytes = REPORT_DATA,
) -> bytes:
    body = (
        tee_tcb_svn
        + mr_seam
        + mr_signer_seam
        + seam_attributes
        + td_attributes
        + xfam
        + mr_td
        + mr_config_id
        + mr_owner
        + mr_owner_config
        + b"".join(rtmrs)
        + report_data
    )
    assert len(body) == TD_QUOTE_BODY_SIZE
    return body


def qe_report_bytes(
    report_data: bytes,
    *,
    mr_signer: bytes = QE_MRSIGNER,
    attributes: bytes = QE_ATTRIBUTES,
    misc_select: int = 0,
    isv_prod_id: int = QE_ISV_PROD_ID,
    isv_svn: int = QE_ISV_SVN,
) -> bytes:
    report = (
        bytes(16)
        + struct.pack("<I", misc_select)
        + bytes(28)
        + attributes
        + bytes([0xEE]) * 32
        + bytes(32)
        + mr_signer
        + bytes(96)
        + struct.pack("<HH", isv_prod_id, isv_svn)
        + bytes(60)
        + report_data
    )
    assert len(report) == QE_REPORT_SIZE
    return report


def quote_bytes(
    pck_key: ec.EllipticCurvePrivateKey,
    chain_pem: bytes,
    *,
    header: bytes | None = None,
    body: bytes | None = None,
    qe_report: bytes | None = None,
    qe_auth_data: bytes = b"",
    extra_bytes: bytes = b"",
    attestation_key: ec.EllipticCurvePrivateKey | None = None,
    qe_report_kwargs: dict[str, Any] | None = None,
    quote_signature: bytes | None = None,
) -> bytes:
    """A v4 quote signed by a fresh attestation key, whose QE report (signed by ``pck_key``) binds that key."""
    attestation_key = attestation_key or pki.p256()
    header = header if header is not None else header_bytes()
    body = body if body is not None else body_bytes()
    digest = hashlib.sha256(header + body).digest()
    signature = (
        quote_signature if quote_signature is not None else raw_signature(attestation_key, digest, prehashed=True)
    )
    ak = raw_public_key(attestation_key)
    if qe_report is None:
        bound = hashlib.sha256(ak + qe_auth_data).digest() + bytes(32)
        qe_report = qe_report_bytes(bound, **(qe_report_kwargs or {}))
    qe_signature = raw_signature(pck_key, qe_report)
    pck_chain = struct.pack("<HI", CERT_DATA_TYPE_PCK_CERT_CHAIN, len(chain_pem)) + chain_pem
    qe_data = qe_report + qe_signature + struct.pack("<H", len(qe_auth_data)) + qe_auth_data + pck_chain
    cert_data = struct.pack("<HI", CERT_DATA_TYPE_QE_REPORT, len(qe_data)) + qe_data
    signed = signature + ak + cert_data
    return header + body + struct.pack("<I", len(signed)) + signed + extra_bytes


# --- PCS responses ----------------------------------------------------------------------


def rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def tcb_level(components: list[int], pce_svn: int, tdx: list[int], status: str = "UpToDate") -> dict[str, Any]:
    return {
        "tcb": {
            "sgxtcbcomponents": [{"svn": s} for s in components],
            "pcesvn": pce_svn,
            "tdxtcbcomponents": [{"svn": s} for s in tdx],
        },
        "tcbDate": "2023-02-15T00:00:00Z",
        "tcbStatus": status,
    }


def tcb_info_object(
    *,
    now: datetime = NOW,
    fmspc: str = FMSPC,
    pceid: str = PCEID,
    issue_date: datetime | None = None,
    next_update: datetime | None = None,
    evaluation_number: int | None = 18,
    status: str = "UpToDate",
    module_status: str = "UpToDate",
    module_id: str = "TDX_03",
    module_isv_svn: int = 0,
    mrsigner: bytes = bytes(48),
    attributes: bytes = bytes(8),
    attributes_mask: bytes = bytes([0xFF]) * 8,
    levels: list[dict[str, Any]] | None = None,
    identities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    info: dict[str, Any] = {
        "id": "TDX",
        "version": 3,
        "issueDate": rfc3339(issue_date or now - timedelta(days=1)),
        "nextUpdate": rfc3339(next_update or now + timedelta(days=365)),
        "fmspc": fmspc,
        "pceId": pceid,
        "tcbType": 0,
        "tcbEvaluationDataNumber": evaluation_number,
        "tdxModule": {
            "mrsigner": mrsigner.hex(),
            "attributes": attributes.hex(),
            "attributesMask": attributes_mask.hex().upper(),
        },
        "tdxModuleIdentities": identities
        if identities is not None
        else [
            {
                "id": module_id,
                "mrsigner": mrsigner.hex(),
                "attributes": attributes.hex(),
                "attributesMask": attributes_mask.hex().upper(),
                "tcbLevels": [
                    {"tcb": {"isvsvn": module_isv_svn}, "tcbDate": "2023-06-18T08:42:58Z", "tcbStatus": module_status}
                ],
            }
        ],
        "tcbLevels": levels
        if levels is not None
        else [tcb_level(list(CPU_SVN_COMPONENTS), PCE_SVN, TDX_COMPONENTS, status)],
    }
    if evaluation_number is None:
        del info["tcbEvaluationDataNumber"]
    return info


def qe_identity_object(
    *,
    now: datetime = NOW,
    issue_date: datetime | None = None,
    next_update: datetime | None = None,
    evaluation_number: int | None = 18,
    status: str = "UpToDate",
    isv_svn: int = QE_ISV_SVN,
    mrsigner: bytes = QE_MRSIGNER,
    attributes: bytes = QE_ATTRIBUTES,
    attributes_mask: bytes = bytes.fromhex("FBFFFFFFFFFFFFFF0000000000000000"),
    miscselect: bytes = bytes(4),
    miscselect_mask: bytes = bytes([0xFF]) * 4,
    isv_prod_id: int = QE_ISV_PROD_ID,
    levels: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "id": "TD_QE",
        "version": 2,
        "issueDate": rfc3339(issue_date or now - timedelta(days=1)),
        "nextUpdate": rfc3339(next_update or now + timedelta(days=365)),
        "tcbEvaluationDataNumber": evaluation_number,
        "miscselect": miscselect.hex().upper(),
        "miscselectMask": miscselect_mask.hex().upper(),
        "attributes": attributes.hex().upper(),
        "attributesMask": attributes_mask.hex().upper(),
        "mrsigner": mrsigner.hex().upper(),
        "isvprodid": isv_prod_id,
        "tcbLevels": levels
        if levels is not None
        else [{"tcb": {"isvsvn": isv_svn}, "tcbDate": "2023-06-08T07:24:59Z", "tcbStatus": status}],
    }
    if evaluation_number is None:
        del identity["tcbEvaluationDataNumber"]
    return identity


def signed_response(member: str, obj: dict[str, Any], signer: ec.EllipticCurvePrivateKey) -> bytes:
    """``{"<member>":<obj>,"signature":"<hex>"}`` with the signature over the member's exact bytes."""
    inner = json.dumps(obj, separators=(",", ":")).encode()
    signature = raw_signature(signer, inner).hex()
    return b'{"' + member.encode() + b'":' + inner + b',"signature":"' + signature.encode() + b'"}'


def issuer_chain_header(*pems: bytes) -> str:
    return quote(b"".join(pems), safe="")


def response(url: str, body: bytes, headers: dict[str, tuple[str, ...]] | None = None) -> PCSResponse:
    return PCSResponse(url=url, headers=MappingProxyType(dict(headers or {})), body=body)


# --- scenario --------------------------------------------------------------------------

_DERIVED: Any = None
"""The default of a ``Scenario`` field that is derived from the scenario's ``now`` rather than given."""


def _is_derived(value: object) -> bool:
    return value is None


@dataclass(frozen=True)
class Scenario:
    """Every knob of a synthetic TDX attestation; the defaults verify.

    ``now`` anchors every default time: the PKI's validity, the PCK's
    validity, the two responses' issue dates and next updates, and the CRL
    windows. A field left at its default is derived from ``now`` when the
    scenario is built, and derived again by ``with_`` when ``now`` changes,
    so that one scenario is coherent at one time; a field given explicitly
    is kept as given.
    """

    now: datetime = NOW
    intel: IntelPKI = _DERIVED
    pck_key: ec.EllipticCurvePrivateKey = field(default_factory=pki.p256)
    extension_value: bytes | None = None
    pck_cn: str = PCK_CN
    pck_serial: int = 4
    chain_suffix: bytes = b""
    """Bytes appended to the PEM chain inside the quote."""
    header: bytes | None = None
    body: bytes | None = None
    qe_report_kwargs: dict[str, Any] = field(default_factory=dict)
    qe_auth_data: bytes = b""
    extra_bytes: bytes = b""
    quote_signature: bytes | None = None
    tcb_info: dict[str, Any] = _DERIVED
    qe_identity: dict[str, Any] = _DERIVED
    tcb_info_url: str | None = None
    pck_crl_revoked: tuple[int, ...] = ()
    root_crl_revoked: tuple[int, ...] = ()
    pck_crl_window: tuple[timedelta, timedelta] = (timedelta(days=-1), timedelta(days=30))
    root_crl_window: tuple[timedelta, timedelta] = (timedelta(days=-1), timedelta(days=30))
    include_root_crl: bool = True
    pck_crl_ca: str = "platform"
    """The CA name in the captured PCK CRL URL."""
    tcb_info_header: str | None = None
    qe_identity_header: str | None = None
    pck_crl_header: str | None = None
    derived: frozenset[str] = field(init=False, default=frozenset())
    """The fields that were derived from ``now`` rather than given."""

    def __post_init__(self) -> None:
        derived: set[str] = set()
        if _is_derived(self.intel):
            object.__setattr__(self, "intel", intel_pki(self.now))
            derived.add("intel")
        if _is_derived(self.tcb_info):
            object.__setattr__(self, "tcb_info", tcb_info_object(now=self.now))
            derived.add("tcb_info")
        if _is_derived(self.qe_identity):
            object.__setattr__(self, "qe_identity", qe_identity_object(now=self.now))
            derived.add("qe_identity")
        object.__setattr__(self, "derived", frozenset(derived))

    def pck(self) -> pki.Issued:
        return pck_certificate(
            self.intel.platform_ca,
            self.pck_key,
            extension_value=self.extension_value,
            now=self.now,
            serial=self.pck_serial,
            cn=self.pck_cn,
        )

    def chain_pem(self) -> bytes:
        return (
            self.intel.pem(self.pck())
            + self.intel.pem(self.intel.platform_ca)
            + self.intel.pem(self.intel.root)
            + self.chain_suffix
        )

    def quote(self) -> bytes:
        return quote_bytes(
            self.pck_key,
            self.chain_pem(),
            header=self.header,
            body=self.body,
            qe_auth_data=self.qe_auth_data,
            extra_bytes=self.extra_bytes,
            qe_report_kwargs=self.qe_report_kwargs,
            quote_signature=self.quote_signature,
        )

    def responses(self) -> tuple[PCSResponse, ...]:
        intel = self.intel
        signing_chain = issuer_chain_header(intel.pem(intel.tcb_signing), intel.pem(intel.root))
        crl_chain = issuer_chain_header(intel.pem(intel.platform_ca), intel.pem(intel.root))
        pck_crl = pki.crl(
            intel.platform_ca,
            this_update=self.now + self.pck_crl_window[0],
            next_update=self.now + self.pck_crl_window[1],
            revoked=list(self.pck_crl_revoked),
        )
        root_crl = pki.crl(
            intel.root,
            this_update=self.now + self.root_crl_window[0],
            next_update=self.now + self.root_crl_window[1],
            revoked=list(self.root_crl_revoked),
        )
        out = [
            response(
                self.tcb_info_url or tcb_info_url(FMSPC),
                signed_response("tcbInfo", self.tcb_info, intel.tcb_signing.key),  # type: ignore[arg-type]
                {"Tcb-Info-Issuer-Chain": (self.tcb_info_header or signing_chain,)},
            ),
            response(
                qe_identity_url(),
                signed_response("enclaveIdentity", self.qe_identity, intel.tcb_signing.key),  # type: ignore[arg-type]
                {"Sgx-Enclave-Identity-Issuer-Chain": (self.qe_identity_header or signing_chain,)},
            ),
            response(
                pck_crl_url(self.pck_crl_ca), pck_crl, {"Sgx-Pck-Crl-Issuer-Chain": (self.pck_crl_header or crl_chain,)}
            ),
        ]
        if self.include_root_crl:
            out.append(response(INTEL_SGX_ROOT_CA_CRL_URL, root_crl))
        return tuple(out)

    def evidence(self) -> Evidence:
        return Evidence(quote=self.quote(), pcs=self.responses())

    def root_pem(self) -> bytes:
        return self.intel.pem(self.intel.root)

    def with_(self, **changes: Any) -> Scenario:
        """A copy with ``changes``; when ``now`` changes, the fields derived from it are derived again."""
        if "now" in changes:
            for name in self.derived:
                changes.setdefault(name, _DERIVED)
        return replace(self, **changes)
