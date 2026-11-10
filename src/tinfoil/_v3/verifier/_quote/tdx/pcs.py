"""Replay of captured Intel PCS responses: the document's collateral answers the requests that DCAP verification
makes, so nothing is fetched."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from tinfoil._v3.verifier._document.collateral.tdx import PCSResponse
from tinfoil._v3.verifier._quote.tdx.lib.collateral import PckCrl, QeIdentity, RootCrl, TdxCollateral, TdxTcbInfo
from tinfoil._v3.verifier._x509.certificate import Certificate

INTEL_PCS_TDX_BASE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4"
INTEL_PCS_SGX_BASE_URL = "https://api.trustedservices.intel.com/sgx/certification/v4"
INTEL_SGX_ROOT_CA_CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

HEADER_PCK_CRL_ISSUER_CHAIN = "Sgx-Pck-Crl-Issuer-Chain"
HEADER_TCB_INFO_ISSUER_CHAIN = "Tcb-Info-Issuer-Chain"
HEADER_QE_IDENTITY_ISSUER_CHAIN = "Sgx-Enclave-Identity-Issuer-Chain"

CA_PLATFORM = "platform"
CA_PROCESSOR = "processor"


class PCSReplayError(ValueError):
    """Captured collateral that is missing, malformed or outside its validity window."""


def pcs_collateral_key(url: str) -> str:
    """Canonicalize a PCS URL for lookup: the ``tcbEvaluationDataNumber`` query parameter is dropped, the rest is
    re-encoded and lowercased, so that a capture made at a specific number answers the parameterless request."""
    raise NotImplementedError


def pck_crl_url(ca: str) -> str:
    """``.../sgx/certification/v4/pckcrl?ca=<ca>``."""
    raise NotImplementedError


def tcb_info_url(fmspc: str) -> str:
    """``.../tdx/certification/v4/tcb?fmspc=<fmspc>``."""
    raise NotImplementedError


def qe_identity_url() -> str:
    """``.../tdx/certification/v4/qe/identity``."""
    raise NotImplementedError


@dataclass(frozen=True, slots=True)
class Captured:
    """One captured response with its headers in canonical MIME form."""

    url: str
    headers: Mapping[str, tuple[str, ...]]
    body: bytes

    def header(self, name: str) -> str:
        """The one value of ``name`` (case-insensitively); a missing or repeated header is an error."""
        raise NotImplementedError


class PCSReplay:
    """The captured responses indexed by canonical URL, with the appraisal time for the CRL windows."""

    __slots__ = ("_now", "_responses")

    def __init__(self, responses: Sequence[PCSResponse], now: datetime) -> None:
        """Indexes the responses; a URL that fails to parse is an error, a repeated URL keeps the first."""
        raise NotImplementedError

    def get(self, url: str) -> Captured:
        """The captured response for ``url``, or an error naming the URL.

        A body that parses as a CRL must have ``now`` within its window;
        a body under a URL containing ``crl`` that does not parse as a CRL
        is an error.
        """
        raise NotImplementedError

    def tcb_info(self, fmspc: str, root: Certificate) -> tuple[TdxTcbInfo, bytes, tuple[Certificate, ...]]:
        """Load and verify the TCB Info for ``fmspc`` with its issuer chain to ``root``."""
        raise NotImplementedError

    def qe_identity(self, root: Certificate) -> tuple[QeIdentity, bytes, tuple[Certificate, ...]]:
        """Load and verify the QE Identity with its issuer chain to ``root``."""
        raise NotImplementedError

    def pck_crl(self, ca: str, root: Certificate) -> PckCrl:
        """Load and verify the PCK CRL for ``ca`` (platform or processor) with its issuer chain to ``root``."""
        raise NotImplementedError

    def root_crl(self, distribution_points: Sequence[str], root: Certificate) -> RootCrl:
        """Load and verify the root CA CRL from the first captured distribution point of the PCK issuer."""
        raise NotImplementedError

    def collateral(self, fmspc: str, ca: str, distribution_points: Sequence[str], root: Certificate) -> TdxCollateral:
        """Load everything that appraisal needs for one quote."""
        raise NotImplementedError


def check_issue_dates(collateral: TdxCollateral, now: datetime) -> None:
    """Reject TCB Info or QE Identity whose issue date is after ``now``."""
    raise NotImplementedError


def minimum_tcb_evaluation_data_number(collateral: TdxCollateral) -> int:
    """The lower of the TCB Info and QE Identity evaluation numbers."""
    raise NotImplementedError
