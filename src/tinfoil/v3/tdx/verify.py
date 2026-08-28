"""DCAP TDX quote-v4 verification, a 1:1 port of go-tdx-guest/verify for the
exact configuration tinfoil-go uses: Getter (collateral replay), TrustedRoots
(single pinned Intel SGX root), GetCollateral=true, CheckRevocations=true,
Now pinned. All errors are ValueError; the authenticate wrapper assigns
QUOTE_REJECTED."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol

from cryptography.hazmat.primitives.asymmetric import ec

from ..bytesutil import decode_hex
from .der import (
    CRL,
    Certificate,
    basic_constraints,
    bytes_to_latin1,
    crl_distribution_point_uris,
    ecdsa_p256_public_key,
    key_usage,
    parse_certificate,
    parse_crl,
    pem_decode,
    verify_der_signature,
    verify_raw_signature,
)
from .pcs import (
    TCB_COMPONENT_STATUS_UP_TO_DATE,
    EnclaveIdentity,
    PckExtensions,
    QeIdentity,
    TcbComponent,
    TcbInfo,
    TcbLevel,
    TdxModuleIdentity,
    TdxTcbInfo,
    parse_qe_identity,
    parse_tdx_tcb_info,
    pck_certificate_extensions,
    pck_crl_url,
    qe_identity_url,
    raw_top_level_member,
    tcb_info_url,
)
from .quote import EnclaveReport, QuoteV4, TDQuoteBody

_TCB_INFO_VERSION = 3
_QE_IDENTITY_VERSION = 2

_ROOT_CERT_PHRASE = "Intel SGX Root CA"
_INTERMEDIATE_CERT_PHRASE = "Intel SGX PCK Platform CA"
_PCK_CERT_PHRASE = "Intel SGX PCK Certificate"
_PROCESSOR_ISSUER = "Intel SGX PCK Processor CA"
_PROCESSOR_ISSUER_ID = "processor"
_PLATFORM_ISSUER = "Intel SGX PCK Platform CA"
_PLATFORM_ISSUER_ID = "platform"
_SGX_PCK_CRL_ISSUER_CHAIN_PHRASE = "Sgx-Pck-Crl-Issuer-Chain"
_SGX_QE_IDENTITY_ISSUER_CHAIN_PHRASE = "Sgx-Enclave-Identity-Issuer-Chain"
_TCB_INFO_ISSUER_CHAIN_PHRASE = "Tcb-Info-Issuer-Chain"
_TCB_SIGNING_PHRASE = "Intel SGX TCB Signing"
_TCB_INFO_ID = "TDX"
_QE_IDENTITY_ID = "TD_QE"
_TCB_INFO_TDX_MODULE_ID_PREFIX = "TDX_"

_OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"


class HTTPSGetter(Protocol):
    """Mirrors trust.HTTPSGetter: URL in, response headers + body out."""

    def get(self, url: str) -> tuple[dict[str, list[str]], bytes]: ...


@dataclass
class VerifyOptions:
    getter: HTTPSGetter
    trusted_root: Certificate  # single pinned Intel SGX root
    now: datetime


@dataclass
class PCKCertificateChain:
    pck_certificate: Certificate
    root_certificate: Certificate
    intermediate_certificate: Certificate


@dataclass
class Collateral:
    pck_crl_issuer_intermediate_certificate: Optional[Certificate] = None
    pck_crl_issuer_root_certificate: Optional[Certificate] = None
    pck_crl: Optional[CRL] = None
    tcb_info_issuer_intermediate_certificate: Optional[Certificate] = None
    tcb_info_issuer_root_certificate: Optional[Certificate] = None
    tdx_tcb_info: Optional[TdxTcbInfo] = None
    tcb_info_body: Optional[bytes] = None
    qe_identity_issuer_intermediate_certificate: Optional[Certificate] = None
    qe_identity_issuer_root_certificate: Optional[Certificate] = None
    qe_identity: Optional[QeIdentity] = None
    enclave_identity_body: Optional[bytes] = None
    root_ca_crl: Optional[CRL] = None


def _apply_mask(a: bytes, b: bytes) -> bytes:
    return bytes(x & y for x, y in zip(a, b))


def _extract_ca_from_pck_cert(pck_cert: Certificate) -> str:
    pck_issuer = pck_cert.issuer_cn
    if pck_issuer == _PLATFORM_ISSUER:
        return _PLATFORM_ISSUER_ID
    if pck_issuer == _PROCESSOR_ISSUER:
        return _PROCESSOR_ISSUER_ID
    raise ValueError("could not find CA from PCK certificate")


def extract_chain_from_quote_v4(quote: QuoteV4) -> PCKCertificateChain:
    """Split the concatenated PEM PCK chain (leaf || intermediate || root,
    optionally null-terminated)."""
    chain_bytes = (
        quote.signed_data.certification_data.qe_report_certification_data.pck_certificate_chain_data.pck_cert_chain
    )
    if len(chain_bytes) == 0:
        raise ValueError("PCK certificate chain is empty")
    invalid = ValueError(
        "incomplete PCK Certificate chain found, should contain 3 concatenated "
        "PEM-formatted 'CERTIFICATE'-type block (PCK Leaf Cert||Intermediate CA "
        "Cert||Root CA Cert)"
    )
    text = bytes_to_latin1(chain_bytes)
    pck = pem_decode(text)
    if pck is None or len(pck.rest) == 0 or pck.type != "CERTIFICATE":
        raise invalid
    pck_cert = parse_certificate(pck.der)

    intermediate = pem_decode(pck.rest)
    if intermediate is None or len(intermediate.rest) == 0 or intermediate.type != "CERTIFICATE":
        raise invalid
    intermediate_cert = parse_certificate(intermediate.der)

    root = pem_decode(intermediate.rest)
    if root is None or root.type != "CERTIFICATE":
        raise invalid
    # The final byte of the certificate chain can be a null byte.
    if len(root.rest) != 0 and root.rest != "\x00":
        raise ValueError(
            "unexpected trailing bytes were found in PCK Certificate Chain: "
            f"{len(root.rest)} byte(s)"
        )
    root_cert = parse_certificate(root.der)

    return PCKCertificateChain(
        pck_certificate=pck_cert,
        root_certificate=root_cert,
        intermediate_certificate=intermediate_cert,
    )


def _validate_x509_cert(cert: Certificate) -> None:
    if cert.version != 3:
        raise ValueError(f"certificate's version found {cert.version}. Expected 3")
    if cert.signature_algorithm_oid != _OID_ECDSA_WITH_SHA256:
        raise ValueError("certificate's signature algorithm is not ECDSA-SHA256")
    pub = cert.obj.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("certificate's public Key algorithm is not ECDSA")
    if not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError('certificate\'s public key curve is not "P-256"')


def _check_signature_from_cert(
    parent: Certificate, for_crl: bool, tbs: bytes, signature: bytes
) -> None:
    """Mirror x509.Certificate.CheckSignatureFrom's parent-constraint and
    signature checks."""
    bc_present, bc_ca = basic_constraints(parent)
    if (parent.version == 3 and not bc_present) or (bc_present and not bc_ca):
        raise ValueError(
            "x509: invalid signature: parent certificate cannot sign this kind of certificate"
        )
    ku_present, cert_sign, crl_sign = key_usage(parent)
    if ku_present and not (crl_sign if for_crl else cert_sign):
        raise ValueError(
            "x509: invalid signature: parent certificate cannot sign this kind of certificate"
        )
    if not verify_der_signature(tbs, signature, parent):
        raise ValueError("crypto/ecdsa: verification error")


def _validate_certificate(cert: Certificate, parent: Certificate, phrase: str) -> None:
    _validate_x509_cert(cert)
    if cert.subject_cn != phrase:
        raise ValueError(
            f"{json.dumps(cert.subject_cn)} is not expected in certificate's "
            f"subject name. Expected {json.dumps(phrase)}"
        )
    if cert.issuer_der != parent.subject_der:
        raise ValueError(
            "certificate's issuer name does not match with parent certificate's subject name"
        )
    try:
        _check_signature_from_cert(parent, False, cert.tbs, cert.signature)
    except ValueError as e:
        raise ValueError(
            f"certificate signature verification using parent certificate failed: {e}"
        ) from None


def _validate_crl(crl: Optional[CRL], trusted_certificate: Certificate) -> None:
    if crl is None:
        raise ValueError("CRL is empty")
    if crl.issuer_der != trusted_certificate.subject_der:
        raise ValueError("CRL issuer's name does not match with expected name")
    bc_present, bc_ca = basic_constraints(trusted_certificate)
    if (trusted_certificate.version == 3 and not bc_present) or (bc_present and not bc_ca):
        raise ValueError(
            "CRL signature verification failed using trusted certificate: constraint violation"
        )
    ku_present, _, crl_sign = key_usage(trusted_certificate)
    if ku_present and not crl_sign:
        raise ValueError(
            "CRL signature verification failed using trusted certificate: constraint violation"
        )
    if not verify_der_signature(crl.tbs, crl.signature, trusted_certificate):
        raise ValueError("CRL signature verification failed using trusted certificate")


def _check_validity(cert: Certificate, now: datetime, what: str) -> None:
    if now < cert.not_before or now > cert.not_after:
        raise ValueError(f"x509: {what} has expired or is not yet valid")


def _verify_chain_to_trusted_root(
    leaf: Certificate,
    intermediate: Optional[Certificate],
    trusted_root: Certificate,
    now: datetime,
) -> None:
    """Mirror x509.Certificate.Verify for the pools this configuration builds:
    the quote's intermediate (or none) and the single pinned root. Every
    candidate chain link matches by raw subject bytes."""
    _check_validity(leaf, now, "leaf certificate")

    def try_parent(cert: Certificate, parent: Certificate, what: str) -> None:
        if cert.issuer_der != parent.subject_der:
            raise ValueError("x509: certificate signed by unknown authority")
        _check_validity(parent, now, what)
        bc_present, bc_ca = basic_constraints(parent)
        if not bc_present or not bc_ca:
            raise ValueError("x509: certificate is not authorized to sign other certificates")
        _check_signature_from_cert(parent, False, cert.tbs, cert.signature)

    # Chain 1: leaf directly under the trusted root.
    if leaf.issuer_der == trusted_root.subject_der:
        try:
            try_parent(leaf, trusted_root, "root certificate")
            return
        except ValueError:
            pass  # fall through to the intermediate chain
    if intermediate is None:
        raise ValueError("x509: certificate signed by unknown authority")
    try_parent(leaf, intermediate, "intermediate certificate")
    try_parent(intermediate, trusted_root, "root certificate")


# --- Collateral acquisition (obtainCollateral and friends) ---------------------


def _go_query_unescape(s: str) -> str:
    """Mirror url.QueryUnescape: '+' is a space, %XX strictly decoded."""
    out = bytearray()
    i = 0
    raw = s.encode("utf-8")
    while i < len(raw):
        c = raw[i]
        if c == 0x2B:  # +
            out.append(0x20)
            i += 1
        elif c == 0x25:  # %
            hexpart = raw[i + 1 : i + 3]
            if len(hexpart) != 2 or not re.fullmatch(rb"[0-9a-fA-F]{2}", hexpart):
                raise ValueError("invalid URL escape")
            out.append(int(hexpart, 16))
            i += 3
        else:
            out.append(c)
            i += 1
    return out.decode("utf-8", errors="replace")


def _header_to_issuer_chain(
    headers: dict[str, list[str]], phrase: str
) -> tuple[Certificate, Certificate]:
    issuer_chain = headers.get(phrase)
    if issuer_chain is None:
        raise ValueError(f"{json.dumps(phrase)} is empty")
    if len(issuer_chain) != 1:
        raise ValueError(f"issuer chain is expected to be of size 1, found {len(issuer_chain)}")
    if issuer_chain[0] == "":
        raise ValueError(f"issuer chain certificates missing in {json.dumps(phrase)}")
    try:
        cert_chain = _go_query_unescape(issuer_chain[0])
    except ValueError:
        raise ValueError(f"unable to decode issuer chain in {json.dumps(phrase)}") from None
    intermediate = pem_decode(cert_chain)
    if intermediate is None or len(intermediate.rest) == 0:
        raise ValueError(
            f"could not parse PEM formatted signing certificate in {json.dumps(phrase)}"
        )
    if intermediate.type != "CERTIFICATE":
        raise ValueError(
            f"the {json.dumps(phrase)} PEM block type is "
            f'{json.dumps(intermediate.type)}. Expect "CERTIFICATE"'
        )
    root = pem_decode(intermediate.rest)
    if root is None or len(root.rest) != 0:
        raise ValueError(
            f"could not parse PEM formatted root certificate in {json.dumps(phrase)}"
        )
    if root.type != "CERTIFICATE":
        raise ValueError(
            f"the {json.dumps(phrase)} PEM block type is "
            f'{json.dumps(root.type)}. Expect "CERTIFICATE"'
        )
    return parse_certificate(intermediate.der), parse_certificate(root.der)


def _body_to_crl(body: bytes) -> CRL:
    try:
        return parse_crl(body)
    except ValueError as e:
        raise ValueError(f"unable to parse DER bytes of CRL: {e}") from None


def _get_pck_crl(ca: str, getter: HTTPSGetter, collateral: Collateral) -> None:
    headers, body = getter.get(pck_crl_url(ca))
    intermediate, root = _header_to_issuer_chain(headers, _SGX_PCK_CRL_ISSUER_CHAIN_PHRASE)
    collateral.pck_crl_issuer_intermediate_certificate = intermediate
    collateral.pck_crl_issuer_root_certificate = root
    collateral.pck_crl = _body_to_crl(body)


def _get_tcb_info(fmspc: str, getter: HTTPSGetter, collateral: Collateral) -> None:
    headers, body = getter.get(tcb_info_url(fmspc))
    intermediate, root = _header_to_issuer_chain(headers, _TCB_INFO_ISSUER_CHAIN_PHRASE)
    collateral.tcb_info_issuer_intermediate_certificate = intermediate
    collateral.tcb_info_issuer_root_certificate = root
    collateral.tdx_tcb_info = parse_tdx_tcb_info(body)
    if len(body) == 0:
        raise ValueError('"tcbInfo" is empty')
    raw = raw_top_level_member(body, "tcbInfo")
    if raw is None:
        raise ValueError('"tcbInfo" field is missing in the response received')
    collateral.tcb_info_body = raw


def _get_qe_identity(getter: HTTPSGetter, collateral: Collateral) -> None:
    headers, body = getter.get(qe_identity_url())
    intermediate, root = _header_to_issuer_chain(
        headers, _SGX_QE_IDENTITY_ISSUER_CHAIN_PHRASE
    )
    collateral.qe_identity_issuer_intermediate_certificate = intermediate
    collateral.qe_identity_issuer_root_certificate = root
    collateral.qe_identity = parse_qe_identity(body)
    if len(body) == 0:
        raise ValueError('"enclaveIdentity" is empty')
    raw = raw_top_level_member(body, "enclaveIdentity")
    if raw is None:
        raise ValueError('"enclaveIdentity" field is missing in the response received')
    collateral.enclave_identity_body = raw


def _get_root_crl(getter: HTTPSGetter, collateral: Collateral) -> None:
    # The QE identity issuer chain's root certificate carries the Root CA CRL URL.
    root_crl_urls = crl_distribution_point_uris(
        collateral.qe_identity_issuer_root_certificate  # type: ignore[arg-type]
    )
    if len(root_crl_urls) == 0:
        raise ValueError(
            "empty url found in QeIdentity issuer's chain which is required to "
            "receive ROOT CA CRL"
        )
    errs: list[str] = []
    for url in root_crl_urls:
        try:
            _, body = getter.get(url)
            collateral.root_ca_crl = _body_to_crl(body)
            return
        except ValueError as e:
            errs.append(str(e))
    raise ValueError("; ".join(errs) + "; could not fetch root CRL")


def _obtain_collateral(fmspc: str, ca: str, getter: HTTPSGetter) -> Collateral:
    collateral = Collateral()
    try:
        _get_tcb_info(fmspc, getter, collateral)
    except ValueError as e:
        raise ValueError(f"unable to receive tcbInfo: {e}") from None
    try:
        _get_qe_identity(getter, collateral)
    except ValueError as e:
        raise ValueError(f"unable to receive QeIdentity: {e}") from None
    try:
        _get_pck_crl(ca, getter, collateral)
    except ValueError as e:
        raise ValueError(f"unable to receive PCK CRL: {e}") from None
    try:
        _get_root_crl(getter, collateral)
    except ValueError as e:
        raise ValueError(f"unable to receive Root CA CRL: {e}") from None
    return collateral


# --- Collateral presence and expiration (verifyCollateral) ---------------------


def _check_collateral_expiration(collateral: Collateral, now: datetime) -> None:
    tcb_info = collateral.tdx_tcb_info.tcb_info  # type: ignore[union-attr]
    qe_identity = collateral.qe_identity.enclave_identity  # type: ignore[union-attr]
    if now > tcb_info.next_update:
        raise ValueError("tcbInfo has expired")
    if now > qe_identity.next_update:
        raise ValueError("QeIdentity has expired")
    if now > collateral.tcb_info_issuer_intermediate_certificate.not_after:  # type: ignore[union-attr]
        raise ValueError("tcbInfo signing certificate has expired")
    if now > collateral.tcb_info_issuer_root_certificate.not_after:  # type: ignore[union-attr]
        raise ValueError("tcbInfo root certificate has expired")
    if now > collateral.qe_identity_issuer_root_certificate.not_after:  # type: ignore[union-attr]
        raise ValueError("QeIdentity root certificate has expired")
    if now > collateral.qe_identity_issuer_intermediate_certificate.not_after:  # type: ignore[union-attr]
        raise ValueError("QeIdentity signing certificate has expired")
    if now > collateral.root_ca_crl.next_update:  # type: ignore[union-attr]
        raise ValueError("root CA CRL has expired")
    if now > collateral.pck_crl.next_update:  # type: ignore[union-attr]
        raise ValueError("PCK CRL has expired")
    if now > collateral.pck_crl_issuer_intermediate_certificate.not_after:  # type: ignore[union-attr]
        raise ValueError("PCK CRL signing certificate has expired")
    if now > collateral.pck_crl_issuer_root_certificate.not_after:  # type: ignore[union-attr]
        raise ValueError("PCK CRL root certificate has expired")


def _verify_collateral(collateral: Collateral, now: datetime) -> None:
    if collateral.tcb_info_body is None:
        raise ValueError("missing tcbInfo body in the collaterals obtained")
    if collateral.enclave_identity_body is None:
        raise ValueError("missing enclaveIdentity body in the collaterals obtained")
    if collateral.tdx_tcb_info is None:
        raise ValueError("tcbInfo is empty in collaterals")
    if collateral.qe_identity is None:
        raise ValueError("QeIdentity is empty in collaterals")
    if collateral.tcb_info_issuer_intermediate_certificate is None:
        raise ValueError("missing signing certificate in the issuer chain of tcbInfo")
    if collateral.tcb_info_issuer_root_certificate is None:
        raise ValueError("missing root certificate in the issuer chain of tcbInfo")
    if collateral.qe_identity_issuer_intermediate_certificate is None:
        raise ValueError("missing signing certificate in the issuer chain of QeIdentity")
    if collateral.qe_identity_issuer_root_certificate is None:
        raise ValueError("missing root certificate in the issuer chain of QeIdentity")
    if collateral.pck_crl is None:
        raise ValueError("missing PCK CRL in the collaterals obtained")
    if collateral.root_ca_crl is None:
        raise ValueError("missing ROOT CA CRL in the collaterals obtained")
    if collateral.pck_crl_issuer_intermediate_certificate is None:
        raise ValueError("missing signing certificate in the issuer chain of PCK CRL")
    if collateral.pck_crl_issuer_root_certificate is None:
        raise ValueError("missing root certificate in the issuer chain of PCK CRL")
    _check_collateral_expiration(collateral, now)


# --- PCK certificate chain verification (verifyPCKCertificationChain) ----------


def _check_certificate_expiration(chain: PCKCertificateChain, now: datetime) -> None:
    if now > chain.root_certificate.not_after:
        raise ValueError("root CA certificate in PCK certificate chain has expired")
    if now > chain.intermediate_certificate.not_after:
        raise ValueError("intermediate CA certificate in PCK certificate chain has expired")
    if now > chain.pck_certificate.not_after:
        raise ValueError("PCK leaf certificate in PCK certificate chain has expired")


def _verify_pck_certification_chain(
    chain: PCKCertificateChain, collateral: Collateral, opts: VerifyOptions
) -> None:
    root_cert = chain.root_certificate
    intermediate_cert = chain.intermediate_certificate
    pck_cert = chain.pck_certificate

    # The root certificate must be self-signed.
    try:
        _validate_certificate(root_cert, root_cert, _ROOT_CERT_PHRASE)
    except ValueError as e:
        raise ValueError(f"unable to validate root cert: {e}") from None
    try:
        _validate_certificate(intermediate_cert, root_cert, _INTERMEDIATE_CERT_PHRASE)
    except ValueError as e:
        raise ValueError(f"unable to validate Intermediate CA certificate: {e}") from None
    try:
        _validate_certificate(pck_cert, intermediate_cert, _PCK_CERT_PHRASE)
    except ValueError as e:
        raise ValueError(f"unable to validate PCK leaf certificate: {e}") from None
    try:
        _verify_chain_to_trusted_root(pck_cert, intermediate_cert, opts.trusted_root, opts.now)
    except ValueError as e:
        raise ValueError(f"error verifying PCK Certificate: {e}") from None

    try:
        _validate_crl(collateral.root_ca_crl, root_cert)
    except ValueError as e:
        raise ValueError(
            "root CA CRL verification failed using root certificate in PCK "
            f"Certificate chain: {e}"
        ) from None
    try:
        _validate_crl(collateral.pck_crl, intermediate_cert)
    except ValueError as e:
        raise ValueError(
            "PCK CRL verification failed using intermediate certificate in PCK "
            f"Certificate chain: {e}"
        ) from None
    if collateral.pck_crl.issuer_der != pck_cert.issuer_der:  # type: ignore[union-attr]
        raise ValueError(
            "issuer's name in PCK CRL does not match with PCK Leaf Certificate's issuer name"
        )
    for bad in collateral.root_ca_crl.revoked_serials:  # type: ignore[union-attr]
        if bad == intermediate_cert.serial:
            raise ValueError("intermediate certificate in PCK certificate chain was revoked")
    for bad in collateral.pck_crl.revoked_serials:  # type: ignore[union-attr]
        if bad == pck_cert.serial:
            raise ValueError("PCK Leaf certificate in PCK certificate chain was revoked")

    _check_certificate_expiration(chain, opts.now)


# --- Signed PCS response verification (verifyResponse / verifyTCBinfo /
# verifyQeIdentity) --------------------------------------------------------------


def _verify_response(
    signing_phrase: str,
    root_certificate: Certificate,
    signing_certificate: Certificate,
    raw_body: bytes,
    raw_signature: str,
    crl: Optional[CRL],
    opts: VerifyOptions,
) -> None:
    # The header root must BE the trusted root (go-tdx-guest pins by byte
    # equality); otherwise the CRL below would be validated against a root the
    # chain check never saw.
    if root_certificate.raw != opts.trusted_root.raw:
        raise ValueError("root certificate in the issuer chain does not equal the trusted root")
    try:
        _validate_certificate(root_certificate, root_certificate, _ROOT_CERT_PHRASE)
    except ValueError as e:
        raise ValueError(
            f"unable to validate root certificate in the issuer chain: {e}"
        ) from None
    try:
        _validate_certificate(signing_certificate, root_certificate, signing_phrase)
    except ValueError as e:
        raise ValueError(
            f"unable to validate signing certificate in the issuer chain: {e}"
        ) from None
    try:
        _verify_chain_to_trusted_root(signing_certificate, None, opts.trusted_root, opts.now)
    except ValueError as e:
        raise ValueError(f"unable to verify signing certificate: {e}") from None

    try:
        signature = decode_hex(raw_signature)
    except ValueError as e:
        raise ValueError(f"unable to decode signature string in the response: {e}") from None
    if len(signature) != 0x40:
        raise ValueError(
            "unable to convert signature to DER format: signature size is "
            f"{len(signature)} bytes. Expected 64 bytes"
        )
    if not verify_raw_signature(raw_body, signature, signing_certificate.spki_der):
        raise ValueError("could not verify response body using the signing certificate")

    try:
        _validate_crl(crl, root_certificate)
    except ValueError as e:
        raise ValueError(
            "root CA CRL verification failed using root certificate in the "
            f"issuer's chain: {e}"
        ) from None
    for bad in crl.revoked_serials:  # type: ignore[union-attr]
        if bad == signing_certificate.serial:
            raise ValueError("signing certificate was revoked")


def _verify_tcb_info(collateral: Collateral, opts: VerifyOptions) -> None:
    tcb_info = collateral.tdx_tcb_info.tcb_info  # type: ignore[union-attr]
    if tcb_info.id != _TCB_INFO_ID:
        raise ValueError(
            f"tcbInfo ID {json.dumps(tcb_info.id)} does not match with expected "
            f"ID {json.dumps(_TCB_INFO_ID)}"
        )
    if tcb_info.version != _TCB_INFO_VERSION:
        raise ValueError(
            f"tcbInfo version {tcb_info.version} does not match with expected "
            f"version {_TCB_INFO_VERSION}"
        )
    if len(tcb_info.tcb_levels) == 0:
        raise ValueError("tcbInfo contains empty TcbLevels")
    try:
        _verify_response(
            _TCB_SIGNING_PHRASE,
            collateral.tcb_info_issuer_root_certificate,  # type: ignore[arg-type]
            collateral.tcb_info_issuer_intermediate_certificate,  # type: ignore[arg-type]
            collateral.tcb_info_body,  # type: ignore[arg-type]
            collateral.tdx_tcb_info.signature,  # type: ignore[union-attr]
            collateral.root_ca_crl,
            opts,
        )
    except ValueError as e:
        raise ValueError(f"tcbInfo response verification failed: {e}") from None


def _verify_qe_identity(collateral: Collateral, opts: VerifyOptions) -> None:
    qe_identity = collateral.qe_identity.enclave_identity  # type: ignore[union-attr]
    if qe_identity.id != _QE_IDENTITY_ID:
        raise ValueError(
            f"QeIdentity ID {json.dumps(qe_identity.id)} does not match with "
            f"expected ID {json.dumps(_QE_IDENTITY_ID)}"
        )
    if qe_identity.version != _QE_IDENTITY_VERSION:
        raise ValueError(
            f"QeIdentity version {qe_identity.version} does not match with "
            f"expected version {_QE_IDENTITY_VERSION}"
        )
    if len(qe_identity.tcb_levels) == 0:
        raise ValueError("QeIdentity contains empty TcbLevels")
    try:
        _verify_response(
            _TCB_SIGNING_PHRASE,
            collateral.qe_identity_issuer_root_certificate,  # type: ignore[arg-type]
            collateral.qe_identity_issuer_intermediate_certificate,  # type: ignore[arg-type]
            collateral.enclave_identity_body,  # type: ignore[arg-type]
            collateral.qe_identity.signature,  # type: ignore[union-attr]
            collateral.root_ca_crl,
            opts,
        )
    except ValueError as e:
        raise ValueError(f"QeIdentity response verification failed: {e}") from None


# --- TCB status evaluation against Intel's signed collateral --------------------


def _is_cpu_svn_higher_or_equal(
    pck_cert_cpu_svn_components: bytes, sgx_tcbcomponents: list[TcbComponent]
) -> bool:
    if len(pck_cert_cpu_svn_components) != len(sgx_tcbcomponents):
        return False
    for i in range(len(pck_cert_cpu_svn_components)):
        if pck_cert_cpu_svn_components[i] < sgx_tcbcomponents[i].svn:
            return False
    return True


def _is_tdx_tcb_svn_higher_or_equal(
    tee_tcb_svn: bytes, tdx_tcbcomponents: list[TcbComponent]
) -> bool:
    if len(tee_tcb_svn) != len(tdx_tcbcomponents):
        return False
    start = 2 if tee_tcb_svn[1] > 0 else 0
    for i in range(start, len(tee_tcb_svn)):
        if tee_tcb_svn[i] < tdx_tcbcomponents[i].svn:
            return False
    return True


def _get_matching_tdx_module_tcb_level(
    tdx_module_identities: list[TdxModuleIdentity], tee_tcb_svn: bytes
) -> TcbLevel:
    tdx_module_identity_id = _TCB_INFO_TDX_MODULE_ID_PREFIX + tee_tcb_svn[1:2].hex()
    tdx_module_isv_svn = tee_tcb_svn[0]
    for tdx_module_identity in tdx_module_identities:
        if tdx_module_identity_id == tdx_module_identity.id:
            for tcb_level in tdx_module_identity.tcb_levels:
                if tdx_module_isv_svn >= tcb_level.tcb.isvsvn:
                    return tcb_level
            raise ValueError(
                "could not find a TDX Module Identity TCB Level matching the "
                f"TDX Module's ISVSVN ({tdx_module_isv_svn})"
            )
    raise ValueError(
        f"could not find a TDX Module Identity ({json.dumps(tdx_module_identity_id)}) "
        "matching the given TEE TDX version"
    )


def _get_matching_tcb_level(
    tcb_levels: list[TcbLevel],
    td_report: TDQuoteBody,
    pck_cert_pce_svn: int,
    pck_cert_cpu_svn_components: bytes,
) -> TcbLevel:
    for tcb_level in tcb_levels:
        if (
            _is_cpu_svn_higher_or_equal(
                pck_cert_cpu_svn_components, tcb_level.tcb.sgx_tcbcomponents
            )
            and pck_cert_pce_svn >= tcb_level.tcb.pcesvn
            and _is_tdx_tcb_svn_higher_or_equal(
                td_report.tee_tcb_svn, tcb_level.tcb.tdx_tcbcomponents
            )
        ):
            return tcb_level
    raise ValueError("no matching TCB level found")


def _check_qe_tcb_status(tcb_levels: list[TcbLevel], isvsvn: int) -> None:
    for tcb_level in tcb_levels:
        if tcb_level.tcb.isvsvn <= isvsvn:
            if tcb_level.tcb_status != TCB_COMPONENT_STATUS_UP_TO_DATE:
                raise ValueError(
                    f'TCB Status is not "UpToDate", found {json.dumps(tcb_level.tcb_status)}'
                )
            return
    raise ValueError("unable to find latest status of TCB, it is now OutOfDate")


def _check_tcb_info_tcb_status(
    tcb_info: TcbInfo, td_quote_body: TDQuoteBody, pck_extensions: PckExtensions
) -> None:
    matching_tcb_level = _get_matching_tcb_level(
        tcb_info.tcb_levels,
        td_quote_body,
        pck_extensions.tcb.pce_svn,
        pck_extensions.tcb.cpu_svn_components,
    )
    if td_quote_body.tee_tcb_svn[1] > 0:
        matching_tdx_module_tcb_level = _get_matching_tdx_module_tcb_level(
            tcb_info.tdx_module_identities, td_quote_body.tee_tcb_svn
        )
        if matching_tdx_module_tcb_level.tcb_status != TCB_COMPONENT_STATUS_UP_TO_DATE:
            raise ValueError(
                'TDX Module TCB Status is not "UpToDate", found '
                f"{json.dumps(matching_tdx_module_tcb_level.tcb_status)}"
            )
    if matching_tcb_level.tcb_status != TCB_COMPONENT_STATUS_UP_TO_DATE:
        raise ValueError(
            f'TCB Status is not "UpToDate", found {json.dumps(matching_tcb_level.tcb_status)}'
        )


# --- Quote body checks against TCB Info and QE Identity ------------------------


def _verify_td_quote_body(
    td_quote_body: TDQuoteBody, tcb_info: TcbInfo, pck_extensions: PckExtensions
) -> None:
    if pck_extensions.fmspc != tcb_info.fmspc:
        raise ValueError(
            f"FMSPC from PCK Certificate({json.dumps(pck_extensions.fmspc)}) is not "
            "equal to FMSPC value from Intel PCS's reported TDX TCB "
            f"info({json.dumps(tcb_info.fmspc)})"
        )
    if pck_extensions.pceid != tcb_info.pce_id:
        raise ValueError(
            f"PCEID from PCK Certificate({json.dumps(pck_extensions.pceid)}) is not "
            "equal to PCEID value from Intel PCS's reported TDX TCB "
            f"info({json.dumps(tcb_info.pce_id)})"
        )
    if tcb_info.tdx_module.mrsigner != td_quote_body.mr_signer_seam:
        raise ValueError(
            "MRSIGNERSEAM value from TD Quote Body is not equal to "
            "TdxModule.Mrsigner field in Intel PCS's reported TDX TCB info"
        )
    if len(tcb_info.tdx_module.attributes_mask) != len(td_quote_body.seam_attributes):
        raise ValueError(
            "size of SeamAttributes from TD Quote Body is not equal to size of "
            "TdxModule.AttributesMask in Intel PCS's reported TDX TCB info"
        )
    attributes_mask = _apply_mask(
        tcb_info.tdx_module.attributes_mask, td_quote_body.seam_attributes
    )
    if tcb_info.tdx_module.attributes != attributes_mask:
        raise ValueError(
            "AttributesMask value is not equal to TdxModule.Attributes field in "
            "Intel PCS's reported TDX TCB info"
        )
    try:
        _check_tcb_info_tcb_status(tcb_info, td_quote_body, pck_extensions)
    except ValueError as e:
        raise ValueError(
            f"TDX TCB info reported by Intel PCS failed TCB status check: {e}"
        ) from None


def _verify_qe_report(qe_report: EnclaveReport, qe_identity: EnclaveIdentity) -> None:
    if len(qe_identity.miscselect_mask) != 4:
        raise ValueError(
            f"MISCSELECTMask field size({len(qe_identity.miscselect_mask)}) in Intel "
            "PCS's reported QE Identity is not equal to expected size(4)"
        )
    if len(qe_identity.miscselect) != 4:
        raise ValueError(
            f"MISCSELECT field size({len(qe_identity.miscselect)}) in Intel PCS's "
            "reported QE Identity is not equal to expected size(4)"
        )
    misc_select_mask_val = (
        int.from_bytes(qe_identity.miscselect_mask, "little") & qe_report.misc_select
    )
    misc_select = int.from_bytes(qe_identity.miscselect, "little")
    if misc_select_mask_val != misc_select:
        raise ValueError(
            f"MISCSELECT value({misc_select}) from Intel PCS's reported QE Identity "
            f"is not equal to MISCSELECTMask value({misc_select_mask_val})"
        )

    if len(qe_identity.attributes_mask) != len(qe_report.attributes):
        raise ValueError(
            "size of AttributesMask value in Intel PCS's reported QE Identity is "
            "not equal to size of Attributes value in QE Report"
        )
    qe_attributes_mask = _apply_mask(qe_identity.attributes_mask, qe_report.attributes)
    if qe_identity.attributes != qe_attributes_mask:
        raise ValueError(
            "AttributesMask value is not equal to Attributes value in Intel PCS's "
            "reported QE Identity"
        )

    if qe_identity.mrsigner != qe_report.mr_signer:
        raise ValueError(
            "MRSIGNER value in QE Report is not equal to MRSIGNER value in Intel "
            "PCS's reported QE Identity"
        )

    if qe_report.isv_prod_id != qe_identity.isv_prod_id:
        raise ValueError(
            f"ISV PRODID value({qe_report.isv_prod_id}) in QE Report is not equal "
            f"to ISV PRODID value({qe_identity.isv_prod_id}) in Intel PCS's "
            "reported QE Identity"
        )

    try:
        _check_qe_tcb_status(qe_identity.tcb_levels, qe_report.isv_svn)
    except ValueError as e:
        raise ValueError(
            f"QE Identity reported by Intel PCS failed TCB status check: {e}"
        ) from None


# --- Quote signature verification (verifyQuote) ---------------------------------


def _verify_hash256(quote: QuoteV4) -> None:
    qe_report_certification_data = (
        quote.signed_data.certification_data.qe_report_certification_data
    )
    qe_report_data = qe_report_certification_data.qe_report.report_data
    qe_auth_data = qe_report_certification_data.qe_auth_data.data
    attest_key = quote.signed_data.ecdsa_attestation_key

    hashed = hashlib.sha256(attest_key + qe_auth_data).digest()
    hashed_message = hashed + bytes(len(qe_report_data) - len(hashed))
    if hashed_message != qe_report_data:
        raise ValueError(
            "QE Report Data does not match with value of SHA 256 calculated over "
            "the concatenation of ECDSA Attestation Key and QE Authenticated Data"
        )


def _verify_quote(
    quote: QuoteV4,
    chain: PCKCertificateChain,
    collateral: Collateral,
    pck_extensions: PckExtensions,
) -> None:
    try:
        attest_public_key = ecdsa_p256_public_key(quote.signed_data.ecdsa_attestation_key)
    except ValueError as e:
        raise ValueError(f"attestation key in the quote is invalid: {e}") from None
    if not verify_raw_signature(
        quote.header_and_body, quote.signed_data.signature, attest_public_key
    ):
        raise ValueError(
            "unable to verify message digest using quote's signature and ecdsa "
            "attestation key"
        )

    qe_report_certification_data = (
        quote.signed_data.certification_data.qe_report_certification_data
    )
    if not verify_raw_signature(
        qe_report_certification_data.qe_report_raw,
        qe_report_certification_data.qe_report_signature,
        chain.pck_certificate.spki_der,
    ):
        raise ValueError(
            "error verifying QE report signature: QE report's signature "
            "verification using PCK Leaf Certificate failed"
        )

    try:
        _verify_hash256(quote)
    except ValueError as e:
        raise ValueError(f"error verifying QE report data: {e}") from None

    _verify_td_quote_body(
        quote.td_quote_body,
        collateral.tdx_tcb_info.tcb_info,  # type: ignore[union-attr]
        pck_extensions,
    )
    _verify_qe_report(
        qe_report_certification_data.qe_report,
        collateral.qe_identity.enclave_identity,  # type: ignore[union-attr]
    )


def tdx_verify_quote_v4(quote: QuoteV4, opts: VerifyOptions) -> None:
    """Mirror tdxverify.TdxQuote for a parsed quote v4 under this
    configuration: replayed collateral, pinned root, revocations checked,
    validity at opts.now."""
    chain = extract_chain_from_quote_v4(quote)
    try:
        exts = pck_certificate_extensions(chain.pck_certificate)
    except ValueError as e:
        raise ValueError(f"could not get PCK certificate extensions: {e}") from None
    ca = _extract_ca_from_pck_cert(chain.pck_certificate)
    collateral = _obtain_collateral(exts.fmspc, ca, opts.getter)

    _verify_pck_certification_chain(chain, collateral, opts)
    try:
        _verify_collateral(collateral, opts.now)
    except ValueError as e:
        raise ValueError(f"could not verify collaterals obtained: {e}") from None
    _verify_tcb_info(collateral, opts)
    _verify_qe_identity(collateral, opts)
    _verify_quote(quote, chain, collateral, exts)
