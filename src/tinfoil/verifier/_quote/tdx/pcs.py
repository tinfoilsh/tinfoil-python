"""Replay of captured Intel PCS responses: the document's collateral answers the requests that DCAP verification
makes, so nothing is fetched."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from tinfoil.verifier._document.collateral.tdx import PCSResponse
from tinfoil.verifier._quote.tdx.lib.collateral import (
    CollateralError,
    PckCrl,
    QeIdentity,
    RootCrl,
    TdxCollateral,
    TdxTcbInfo,
    parse_issuer_chain_header,
    parse_qe_identity_response,
    parse_tcb_info_response,
    top_level_member,
)
from tinfoil.verifier._x509.certificate import Certificate, X509Error, crl_distribution_point_uris
from tinfoil.verifier._x509.crl import CRLError, RevocationList, parse_revocation_list

INTEL_PCS_TDX_BASE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4"
INTEL_PCS_SGX_BASE_URL = "https://api.trustedservices.intel.com/sgx/certification/v4"
INTEL_SGX_ROOT_CA_CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

HEADER_PCK_CRL_ISSUER_CHAIN = "Sgx-Pck-Crl-Issuer-Chain"
HEADER_TCB_INFO_ISSUER_CHAIN = "Tcb-Info-Issuer-Chain"
HEADER_QE_IDENTITY_ISSUER_CHAIN = "Sgx-Enclave-Identity-Issuer-Chain"

CA_PLATFORM = "platform"
CA_PROCESSOR = "processor"

_TCB_EVALUATION_PARAMETER = "tcbEvaluationDataNumber"
_TCB_INFO_MEMBER = "tcbInfo"
_ENCLAVE_IDENTITY_MEMBER = "enclaveIdentity"


class PCSReplayError(ValueError):
    """Captured collateral that is missing, malformed or outside its validity window."""


def pcs_collateral_key(url: str) -> str:
    """Canonicalize a PCS URL for lookup: the ``tcbEvaluationDataNumber`` query parameter is dropped, the rest is
    re-encoded with its parameters sorted by name, and the result is lowercased, so that a capture made at a
    specific number answers the parameterless request."""
    try:
        parts = urlsplit(url)
    except ValueError as err:
        raise PCSReplayError(f"parsing PCS URL {url!r}: {err}") from err
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != _TCB_EVALUATION_PARAMETER]
    query.sort(key=lambda item: item[0])
    return urlunsplit(parts._replace(query=urlencode(query))).lower()


def pck_crl_url(ca: str) -> str:
    """``.../sgx/certification/v4/pckcrl?ca=<ca>&encoding=der``."""
    return f"{INTEL_PCS_SGX_BASE_URL}/pckcrl?ca={ca}&encoding=der"


def tcb_info_url(fmspc: str) -> str:
    """``.../tdx/certification/v4/tcb?fmspc=<fmspc>``."""
    return f"{INTEL_PCS_TDX_BASE_URL}/tcb?fmspc={fmspc}"


def qe_identity_url() -> str:
    """``.../tdx/certification/v4/qe/identity``."""
    return f"{INTEL_PCS_TDX_BASE_URL}/qe/identity"


def canonical_header_name(name: str) -> str:
    """The canonical MIME form of a header name: the first letter and every letter after a hyphen upper case, the
    rest lower case. A name with a character outside the token alphabet is returned unchanged."""
    if not name or any(not (c.isalnum() and c.isascii()) and c not in "!#$%&'*+-.^_`|~" for c in name):
        return name
    out: list[str] = []
    upper = True
    for c in name:
        out.append(c.upper() if upper else c.lower())
        upper = c == "-"
    return "".join(out)


@dataclass(frozen=True, slots=True)
class Captured:
    """One captured response with its headers in canonical MIME form."""

    url: str
    headers: Mapping[str, tuple[str, ...]]
    body: bytes

    def header(self, name: str) -> str:
        """The one value of ``name`` (case-insensitively); a missing, repeated or empty header is an error."""
        values = self.headers.get(canonical_header_name(name))
        if values is None:
            raise PCSReplayError(f"{name!r} is empty")
        if len(values) != 1:
            raise PCSReplayError(f"issuer chain is expected to be of size 1, found {len(values)}")
        if values[0] == "":
            raise PCSReplayError(f"issuer chain certificates missing in {name!r}")
        return values[0]


class PCSReplay:
    """The captured responses indexed by canonical URL, with the appraisal time for the CRL windows."""

    __slots__ = ("_now", "_parsed", "_responses")

    def __init__(self, responses: Sequence[PCSResponse], now: datetime) -> None:
        """Indexes the responses; a URL that fails to parse is an error, a repeated URL keeps the last."""
        self._responses: dict[str, PCSResponse] = {}
        for response in responses:
            self._responses[pcs_collateral_key(response.url)] = response
        self._now = now
        self._parsed: dict[str, RevocationList | CRLError] = {}
        """Each captured body's parse as a CRL, or the failure, by collateral key; a body is parsed at most once."""

    def get(self, url: str) -> Captured:
        """The captured response for ``url``, or an error naming the URL.

        A body that parses as a CRL must have ``now`` within its window;
        a body under a URL containing ``crl`` that does not parse as a CRL
        is an error. Two captured header names with the same canonical
        form are an error, so that one cannot silently stand in for the
        other.
        """
        key = pcs_collateral_key(url)
        response = self._responses.get(key)
        if response is None:
            raise PCSReplayError(f"intel-pcs collateral has no captured response for {url}")
        parsed = self._parse_crl(key, response.body)
        if isinstance(parsed, CRLError):
            if "crl" in key:
                raise PCSReplayError(f"parsing captured CRL for {url}: {parsed}") from parsed
        elif self._now < parsed.this_update or self._now > parsed.next_update:
            raise PCSReplayError(f"captured CRL for {url} is outside its validity window")
        headers: dict[str, tuple[str, ...]] = {}
        for name, values in response.headers.items():
            canonical = canonical_header_name(name)
            if canonical in headers:
                raise PCSReplayError(f"repeated header {canonical!r} in the captured response for {url}")
            headers[canonical] = tuple(values)
        return Captured(url=response.url, headers=headers, body=bytes(response.body))

    def _parse_crl(self, key: str, body: bytes) -> RevocationList | CRLError:
        """Parse ``body`` as a CRL the first time that ``key`` is asked for, and return the remembered result,
        success or failure, after that."""
        parsed = self._parsed.get(key)
        if parsed is None:
            try:
                parsed = parse_revocation_list(body)
            except CRLError as err:
                parsed = err
            self._parsed[key] = parsed
        return parsed

    def _crl(self, url: str) -> RevocationList:
        """The CRL that ``get`` parsed for ``url``; a body that is not a CRL is an error."""
        parsed = self._parsed[pcs_collateral_key(url)]
        if isinstance(parsed, CRLError):
            raise PCSReplayError(f"unable to parse DER bytes of CRL: {parsed}") from parsed
        return parsed

    def tcb_info(self, fmspc: str) -> tuple[TdxTcbInfo, bytes, tuple[Certificate, Certificate]]:
        """Load the TCB Info for ``fmspc``: the decoded response, the signed ``tcbInfo`` bytes, and the signing
        certificate and root from the issuer-chain header."""
        try:
            captured = self.get(tcb_info_url(fmspc))
        except PCSReplayError as err:
            raise PCSReplayError(f"could not receive tcbInfo response: {err}") from err
        try:
            chain = parse_issuer_chain_header(
                captured.header(HEADER_TCB_INFO_ISSUER_CHAIN), HEADER_TCB_INFO_ISSUER_CHAIN
            )
            tcb_info = parse_tcb_info_response(captured.body)
            body = top_level_member(captured.body, _TCB_INFO_MEMBER)
        except CollateralError as err:
            raise PCSReplayError(f"unable to receive tcbInfo: {err}") from err
        return tcb_info, body, chain

    def qe_identity(self) -> tuple[QeIdentity, bytes, tuple[Certificate, Certificate]]:
        """Load the QE Identity: the decoded response, the signed ``enclaveIdentity`` bytes, and the signing
        certificate and root from the issuer-chain header."""
        try:
            captured = self.get(qe_identity_url())
        except PCSReplayError as err:
            raise PCSReplayError(f"could not receive QeIdentity response: {err}") from err
        try:
            chain = parse_issuer_chain_header(
                captured.header(HEADER_QE_IDENTITY_ISSUER_CHAIN), HEADER_QE_IDENTITY_ISSUER_CHAIN
            )
            identity = parse_qe_identity_response(captured.body)
            body = top_level_member(captured.body, _ENCLAVE_IDENTITY_MEMBER)
        except CollateralError as err:
            raise PCSReplayError(f"unable to receive QeIdentity: {err}") from err
        return identity, body, chain

    def pck_crl(self, ca: str) -> PckCrl:
        """Load the DER PCK CRL for ``ca`` (platform or processor) with the issuer chain from its header."""
        try:
            captured = self.get(pck_crl_url(ca))
        except PCSReplayError as err:
            raise PCSReplayError(f"could not fetch PCK CRL: {err}") from err
        try:
            intermediate, root = parse_issuer_chain_header(
                captured.header(HEADER_PCK_CRL_ISSUER_CHAIN), HEADER_PCK_CRL_ISSUER_CHAIN
            )
        except CollateralError as err:
            raise PCSReplayError(f"unable to receive PCK CRL: {err}") from err
        return PckCrl(crl=self._crl(pck_crl_url(ca)), ca_type=ca, issuer_intermediate=intermediate, issuer_root=root)

    def root_crl(self, distribution_points: Sequence[str]) -> RootCrl:
        """Load the DER root CA CRL from the first distribution point with a captured CRL body.

        The points are tried in order, each distinct URL once: the
        certificate that lists them is not yet verified, so a list that
        repeats one URL costs one lookup.
        """
        if not distribution_points:
            raise PCSReplayError(
                "empty url found in QeIdentity issuer's chain which is required to receive ROOT CA CRL"
            )
        failures: list[str] = []
        for url in dict.fromkeys(distribution_points):
            try:
                self.get(url)
                return RootCrl(crl=self._crl(url))
            except PCSReplayError as err:
                failures.append(str(err))
        raise PCSReplayError(f"could not fetch root CRL: {'; '.join(failures)}")

    def collateral(self, fmspc: str, ca: str) -> TdxCollateral:
        """Load everything that appraisal needs for one quote: TCB Info, QE Identity, the PCK CRL and the root CRL
        named by the QE Identity issuer root's CRL distribution points."""
        tcb_info, tcb_info_body, (tcb_info_signing, tcb_info_root) = self.tcb_info(fmspc)
        qe_identity, enclave_identity_body, (qe_identity_signing, qe_identity_root) = self.qe_identity()
        pck_crl = self.pck_crl(ca)
        root_crl = self.root_crl(crl_distribution_points(qe_identity_root))
        return TdxCollateral(
            tcb_info=tcb_info,
            tcb_info_body=tcb_info_body,
            tcb_info_issuer_intermediate=tcb_info_signing,
            tcb_info_issuer_root=tcb_info_root,
            qe_identity=qe_identity,
            enclave_identity_body=enclave_identity_body,
            qe_identity_issuer_intermediate=qe_identity_signing,
            qe_identity_issuer_root=qe_identity_root,
            pck_crl=pck_crl,
            root_crl=root_crl,
        )


def crl_distribution_points(certificate: Certificate) -> tuple[str, ...]:
    """The URI distribution points of the certificate's CRL distribution points extension, in order.

    The certificate is the QE Identity issuer root as the document carried
    it, read before it is verified, so the extension is walked from the
    DER directly: a name form other than a URI is skipped, and a malformed
    extension is a PCSReplayError rather than a library exception.
    """
    try:
        return crl_distribution_point_uris(certificate)
    except X509Error as err:
        raise PCSReplayError(f"CRL distribution points: {err}") from err


def check_issue_dates(collateral: TdxCollateral, now: datetime) -> None:
    """Reject TCB Info or QE Identity without an issue date, or whose issue date is after ``now``."""
    tcb_issued = collateral.tcb_info.tcb_info.issue_date
    qe_issued = collateral.qe_identity.enclave_identity.issue_date
    if tcb_issued is None or qe_issued is None:
        raise PCSReplayError("collateral issueDate was not observed during quote verification")
    if now < tcb_issued:
        raise PCSReplayError("TCB Info is not yet valid")
    if now < qe_issued:
        raise PCSReplayError("QE Identity is not yet valid")


def minimum_tcb_evaluation_data_number(collateral: TdxCollateral) -> int:
    """The lower of the TCB Info and QE Identity evaluation numbers; both must be present."""
    tcb = collateral.tcb_info.tcb_info.tcb_evaluation_data_number
    qe = collateral.qe_identity.enclave_identity.tcb_evaluation_data_number
    if tcb is None or qe is None:
        raise PCSReplayError("collateral tcbEvaluationDataNumber was not observed during quote verification")
    return min(tcb, qe)
