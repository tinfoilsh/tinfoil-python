"""Intel TDX quote authentication against the pinned Intel SGX root,
replaying the document's own captured PCS collateral — a 1:1 port of Go
verifier/quote/tdx/authenticate.go. Every rejection raises
VerificationError(QUOTE_REJECTED)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..bytesutil import decode_base64
from ..embedded_roots import SGX_ROOT_CA_PEM
from ..envelope import (
    COLLATERAL_INTEL_PCS_V1_FORMAT,
    SUBJECT_CPU,
    Document,
    PCSResponse,
    endorsement_collateral,
    parse_intel_pcs_collateral,
)
from ..errors import QUOTE_REJECTED, VerificationError
from ..measurement import TDX_GUEST_V2, Measurement
from .der import Certificate, parse_certificate, parse_crl, pem_decode
from .identity import identity
from .quote import QuoteV4, TDQuoteBody, quote_to_proto_v4
from .verify import VerifyOptions, tdx_verify_quote_v4


@dataclass
class TdxQuote:
    """A signature-verified TDX quote, not yet compared against any expected
    value."""

    # identity is the machines-map lookup key (PPID, lowercase hex).
    identity: str
    # measurement carries MRTD followed by the four RTMRs.
    measurement: Measurement
    # tcb_evaluation_data_number is the minimum tcbEvaluationDataNumber
    # observed in the verified Intel collateral.
    tcb_evaluation_data_number: int
    body: TDQuoteBody

    # The parsed quote, retained for policy validation (Go: unexported).
    quote: QuoteV4 = dc_field(repr=False, default=None)  # type: ignore[assignment]


def _quote_error(message: str) -> VerificationError:
    return VerificationError(QUOTE_REJECTED, message)


def tdx_authenticate(
    doc: Document, root_pem: Optional[str] = None, now: Optional[datetime] = None
) -> TdxQuote:
    """Verify the quote's signature chain up to the pinned Intel SGX root,
    replaying the document's captured PCS collateral — no network fetches.
    Callers must assemble a policy and validate before trusting the platform."""
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        trusted_root = _root_from_pem(root_pem if root_pem else SGX_ROOT_CA_PEM)
    except ValueError as e:
        raise _quote_error(str(e)) from None

    try:
        raw_quote = decode_base64(doc.cpu_evidence.report_base64)
    except ValueError as e:
        raise _quote_error(f"decoding TDX quote: {e}") from None
    try:
        quote = quote_to_proto_v4(raw_quote)
    except ValueError as e:
        raise _quote_error(f"parsing TDX quote: {e}") from None
    # The library parses but never constrains these: header bytes 8-11 are
    # reserved in quote v4 (exposed as QeSvn/PceSvn), and bytes past the
    # signed data are kept as extra_bytes. Reserved bytes must be zero;
    # trailing bytes may only be the zero padding of the fixed-size buffer
    # the quote was read from — anything non-zero is unsigned content.
    header = quote.header
    if header.qe_svn != b"\x00\x00" or header.pce_svn != b"\x00\x00":
        raise _quote_error("TDX quote header carries non-zero reserved bytes")
    if any(b != 0 for b in quote.extra_bytes):
        raise _quote_error("TDX quote carries non-zero bytes after the signed data")

    # The recorder observes the tcbEvaluationDataNumber of the collateral
    # actually used, so the policy floor is enforced on verified bytes.
    entry = endorsement_collateral(doc, COLLATERAL_INTEL_PCS_V1_FORMAT, SUBJECT_CPU)
    if entry is None:
        raise _quote_error("document carries no intel-pcs endorsement collateral for the cpu")
    data = parse_intel_pcs_collateral(entry.data)  # raises QUOTE_REJECTED
    try:
        recorder = TcbEvaluationRecorder(PCSReplayGetter(data.responses or [], now))
    except ValueError as e:
        raise _quote_error(str(e)) from None

    # All options explicit: collateral replayed from the document, chain
    # pinned to the Intel root, revocation checking on, validity at now.
    try:
        tdx_verify_quote_v4(quote, VerifyOptions(getter=recorder, trusted_root=trusted_root, now=now))
    except ValueError as e:
        raise _quote_error(f"verifying TDX quote: {e}") from None

    try:
        ppid = identity(quote)
        tcb_evaluation_data_number = recorder.minimum()
    except ValueError as e:
        raise _quote_error(str(e)) from None

    body = quote.td_quote_body
    registers = [body.mr_td.hex()]
    for rtmr in body.rtmrs:
        registers.append(rtmr.hex())
    return TdxQuote(
        identity=ppid,
        measurement=Measurement(type=TDX_GUEST_V2, registers=registers),
        tcb_evaluation_data_number=tcb_evaluation_data_number,
        body=body,
        quote=quote,
    )


def _root_from_pem(root_pem: str) -> Certificate:
    """Parse a single trusted root certificate (Go: pool of one)."""
    block = pem_decode(root_pem)
    if block is None or block.type != "CERTIFICATE":
        raise ValueError("intel SGX root PEM carried no certificate")
    return parse_certificate(block.der)


def pcs_collateral_key(raw_url: str) -> str:
    """Canonicalize an Intel PCS URL for replay lookup: the
    tcbEvaluationDataNumber query parameter selects which collateral edition
    Intel serves, so a capture made at a specific number must still answer the
    library's parameterless request for the same resource."""
    try:
        u = urlsplit(raw_url)
    except ValueError as e:
        raise ValueError(f"parsing PCS URL {json.dumps(raw_url)}: {e}") from None
    params = [
        (k, v)
        for k, v in parse_qsl(u.query, keep_blank_values=True)
        if k != "tcbEvaluationDataNumber"
    ]
    params.sort(key=lambda kv: kv[0])  # Go url.Values.Encode sorts by key
    return urlunsplit((u.scheme, u.netloc, u.path, urlencode(params), u.fragment))


_MIME_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def canonical_mime_header_key(key: str) -> str:
    """Mirror textproto.CanonicalMIMEHeaderKey for the token header names PCS
    uses."""
    if _MIME_TOKEN_RE.fullmatch(key) is None:
        return key
    return "-".join(
        part[0].upper() + part[1:].lower() if part else "" for part in key.split("-")
    )


class PCSReplayGetter:
    """Replays the document's captured PCS responses, keyed by canonical URL
    (tcbEvaluationDataNumber stripped, lowercased). A missing capture is an
    error — never a network fetch."""

    def __init__(self, responses: list[PCSResponse], now: datetime):
        self._now = now
        self._responses: dict[str, PCSResponse] = {}
        for resp in responses:
            self._responses[pcs_collateral_key(resp.url).lower()] = resp

    def get(self, request_url: str) -> tuple[dict[str, list[str]], bytes]:
        key = pcs_collateral_key(request_url).lower()
        resp = self._responses.get(key)
        if resp is None:
            raise ValueError(f"intel-pcs collateral has no captured response for {request_url}")
        try:
            body = decode_base64(resp.body_base64)
        except ValueError as e:
            raise ValueError(
                f"decoding captured PCS response body for {request_url}: {e}"
            ) from None
        # The library checks CRL NextUpdate but not ThisUpdate, so a
        # future-dated capture would otherwise pass. Intel also serves a
        # root-CA CRL from a .der URL that does not identify the body as a CRL.
        try:
            crl = parse_crl(body)
        except ValueError as e:
            if "crl" in key:
                raise ValueError(f"parsing captured CRL for {request_url}: {e}") from None
        else:
            if self._now < crl.this_update or self._now > crl.next_update:
                raise ValueError(
                    f"captured CRL for {request_url} is outside its validity window"
                )
        # Header keys are matched verbatim by the verification core (canonical
        # MIME form), so normalize whatever casing the capture used.
        headers: dict[str, list[str]] = {}
        for k, v in (resp.headers or {}).items():
            headers[canonical_mime_header_key(k)] = v if v is not None else []
        return headers, body


class TcbEvaluationRecorder:
    """Observes the tcbEvaluationDataNumber carried by the TCB Info and QE
    Identity responses that quote verification consumes."""

    def __init__(self, inner):
        self._inner = inner
        self._tcb_info: Optional[int] = None
        self._qe_identity: Optional[int] = None

    def get(self, request_url: str) -> tuple[dict[str, list[str]], bytes]:
        headers, body = self._inner.get(request_url)

        # Parse failures below are ignored on purpose: these bytes are
        # authenticated and interpreted by the verification core, and this
        # wrapper only observes one field. A response that never parses leaves
        # its slot unset, which fails minimum() after verification.
        try:
            path = urlsplit(request_url).path
        except ValueError:
            return headers, body
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
        except ValueError:
            return headers, body
        if not isinstance(parsed, dict):
            return headers, body
        if path.endswith("/tcb"):
            inner = parsed.get("tcbInfo")
            if isinstance(inner, dict):
                n = inner.get("tcbEvaluationDataNumber")
                if isinstance(n, int) and not isinstance(n, bool):
                    self._tcb_info = n
        elif path.endswith("/qe/identity"):
            inner = parsed.get("enclaveIdentity")
            if isinstance(inner, dict):
                n = inner.get("tcbEvaluationDataNumber")
                if isinstance(n, int) and not isinstance(n, bool):
                    self._qe_identity = n
        return headers, body

    def minimum(self) -> int:
        """The lower of the two observed numbers; both responses must have
        been seen (quote verification always fetches both when it succeeds)."""
        if self._tcb_info is None or self._qe_identity is None:
            raise ValueError(
                "collateral tcbEvaluationDataNumber was not observed during quote verification"
            )
        return self._qe_identity if self._qe_identity < self._tcb_info else self._tcb_info
