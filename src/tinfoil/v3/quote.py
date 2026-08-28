"""v3 CPU-evidence verification in three phases (Go: verifier/quote/quote.go):

 1. Authenticate: verify the quote's signature chain up to the pinned
    vendor root, from document-carried collateral only.
 2. Assemble: resolve the complete policy — every value the quote must
    attest, as one object. Assembly fails if any entry cannot be resolved.
 3. Validate: one comparison of the quote against the assembled policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .bytesutil import decode_hex
from .envelope import Document, SEV_SNP_REPORT_V1_FORMAT, TDX_QUOTE_V1_FORMAT
from .errors import POLICY_REJECTED, QUOTE_REJECTED, VerificationError
from .measurement import (
    SEV_GUEST_V2,
    SNP_TDX_MULTI_PLATFORM_V1,
    TDX_GUEST_V2,
    Measurement,
)
from .policy import PLATFORM_SEV_SNP, PLATFORM_TDX, Artifact, Shape, policy_for
from .sev import SevExpectations, SevQuote, sev_assemble, sev_authenticate, sev_validate
from .tdx import (
    CodeRegisters,
    TdxExpectations,
    TdxQuote,
    tdx_assemble,
    tdx_authenticate,
    tdx_validate,
)

# register_size is the byte length of every measurement register.
REGISTER_SIZE = 48


def _quote_error(message: str) -> VerificationError:
    return VerificationError(QUOTE_REJECTED, message)


def _policy_error(message: str) -> VerificationError:
    return VerificationError(POLICY_REJECTED, message)


@dataclass
class Authenticated:
    """A signature-verified quote, not yet compared against any expected
    value (Go: quote.Authenticated)."""

    # platform is PLATFORM_SEV_SNP or PLATFORM_TDX.
    platform: str
    # identity is the machine identifier from authenticated bytes
    # (SEV CHIP_ID / TDX PPID), lowercase hex.
    identity: str
    # measurement is the launch measurement (SEV) or MRTD+RTMRs (TDX).
    measurement: Measurement

    sev: Optional[SevQuote] = None
    tdx: Optional[TdxQuote] = None


@dataclass
class AssembledPolicy:
    """The complete expected state of a quote, fully resolved before
    validation runs. It captures the quote it was assembled for, so it
    cannot be applied to any other quote (Go: quote.AssembledPolicy)."""

    # policy_name is the matched policy name.
    policy_name: str
    # platform_measurement_name is the resolved TDX platform configuration;
    # empty for SEV-SNP.
    platform_measurement_name: str

    quote: Authenticated
    sev: Optional[SevExpectations] = None
    tdx: Optional[TdxExpectations] = None


def quote_authenticate(
    doc: Document,
    amd_root_pem: Optional[str] = None,
    intel_root_pem: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Authenticated:
    """Verify the quote's signature chain up to the pinned vendor root, from
    the document's own endorsement collateral — no network fetches (Go:
    quote.Authenticate). Callers must assemble a policy and validate before
    trusting the platform."""
    fmt = doc.cpu_evidence.format
    if fmt == SEV_SNP_REPORT_V1_FORMAT:
        q = sev_authenticate(doc, root_pem=amd_root_pem, now=now)
        return Authenticated(
            platform=PLATFORM_SEV_SNP,
            identity=q.identity,
            measurement=q.measurement,
            sev=q,
        )
    if fmt == TDX_QUOTE_V1_FORMAT:
        tq = tdx_authenticate(doc, root_pem=intel_root_pem, now=now)
        return Authenticated(
            platform=PLATFORM_TDX,
            identity=tq.identity,
            measurement=tq.measurement,
            tdx=tq,
        )
    raise _quote_error(f"unsupported cpu_evidence format {fmt!r}")


def quote_assemble(
    endorsements: Artifact,
    code: Optional[Measurement],
    shape: Optional[Shape],
    report_data: bytes,
    q: Authenticated,
) -> AssembledPolicy:
    """Resolve the complete policy for an authenticated quote from its three
    verified sources: the policy artifact (machine lookup by authenticated
    identity; for TDX, the platform measurement resolved under the required
    VM shape), the code measurement, and the envelope's REPORT_DATA. A
    machine absent from the artifact is not endorsed (Go: quote.Assemble)."""
    if code is None:
        raise _policy_error("assembling policy: expected code measurement is required")
    if shape is None:
        raise _policy_error("assembling policy: the code artifact's VM shape is required")
    name, machine_policy = policy_for(endorsements, q.identity, q.platform)
    assembled = AssembledPolicy(policy_name=name, platform_measurement_name="", quote=q)
    if q.platform == PLATFORM_SEV_SNP:
        digest = _sev_launch_digest(code)
        if machine_policy.sev_snp is None or q.sev is None:
            raise _policy_error(
                f"policy {name!r} and quote do not both carry SEV-SNP data"
            )
        assembled.sev = sev_assemble(machine_policy.sev_snp, q.sev, digest, report_data)
    elif q.platform == PLATFORM_TDX:
        registers = _tdx_code_registers(code)
        if machine_policy.tdx is None or q.tdx is None:
            raise _policy_error(f"policy {name!r} and quote do not both carry TDX data")
        assembled.tdx, assembled.platform_measurement_name = tdx_assemble(
            endorsements, machine_policy.tdx, shape, q.tdx, registers, report_data
        )
    else:
        raise _policy_error(f"unsupported platform {q.platform!r}")
    return assembled


def assembled_validate(p: AssembledPolicy) -> None:
    """Compare the captured quote against the assembled policy in a single
    call: no lookups, no translation (Go: AssembledPolicy.Validate)."""
    if p.quote.platform == PLATFORM_SEV_SNP:
        if p.sev is None or p.quote.sev is None:
            raise _policy_error("assembled policy and quote do not both carry SEV-SNP data")
        sev_validate(p.sev, p.quote.sev)
    elif p.quote.platform == PLATFORM_TDX:
        if p.tdx is None or p.quote.tdx is None:
            raise _policy_error("assembled policy and quote do not both carry TDX data")
        tdx_validate(p.tdx, p.quote.tdx)
    else:
        raise _policy_error(f"unsupported platform {p.quote.platform!r}")


def assemble_and_validate(
    endorsements: Artifact,
    code: Optional[Measurement],
    shape: Optional[Shape],
    report_data: bytes,
    auth: Authenticated,
) -> AssembledPolicy:
    """Compose quote_assemble and assembled_validate; every rejection is
    POLICY_REJECTED (Go: quote.Verify's assemble+validate tail)."""
    assembled = quote_assemble(endorsements, code, shape, report_data, auth)
    assembled_validate(assembled)
    return assembled


def _sev_launch_digest(m: Measurement) -> bytes:
    """Map the expected code measurement onto the SEV launch digest register
    (Go: sevLaunchDigest)."""
    if m.type == SNP_TDX_MULTI_PLATFORM_V1:
        if len(m.registers) != 3:
            raise _policy_error(
                f"multiplatform code measurement carries {len(m.registers)} registers, want 3"
            )
        return _decode_register(m.registers[0])
    if m.type == SEV_GUEST_V2:
        if len(m.registers) != 1:
            raise _policy_error(
                f"SEV code measurement carries {len(m.registers)} registers, want 1"
            )
        return _decode_register(m.registers[0])
    raise _policy_error(f"unsupported code measurement type {m.type!r} for SEV-SNP")


def _tdx_code_registers(m: Measurement) -> CodeRegisters:
    """Map the expected code measurement onto the TDX workload registers
    (Go: tdxCodeRegisters)."""
    if m.type == SNP_TDX_MULTI_PLATFORM_V1:
        # Registers are [snp_measurement, rtmr1, rtmr2]; RTMR3 is never
        # measured and must be zero.
        if len(m.registers) != 3:
            raise _policy_error(
                f"multiplatform code measurement carries {len(m.registers)} registers, want 3"
            )
        return CodeRegisters(
            rtmr1=_decode_register(m.registers[1]),
            rtmr2=_decode_register(m.registers[2]),
            rtmr3=bytes(REGISTER_SIZE),
        )
    if m.type == TDX_GUEST_V2:
        # Registers are [mrtd, rtmr0, rtmr1, rtmr2, rtmr3].
        if len(m.registers) != 5:
            raise _policy_error(
                f"TDX code measurement carries {len(m.registers)} registers, want 5"
            )
        return CodeRegisters(
            rtmr1=_decode_register(m.registers[2]),
            rtmr2=_decode_register(m.registers[3]),
            rtmr3=_decode_register(m.registers[4]),
        )
    raise _policy_error(f"unsupported code measurement type {m.type!r} for TDX")


def _decode_register(hex_value: str) -> bytes:
    """Decode a 48-byte hex measurement register (Go: decodeRegister)."""
    try:
        b = decode_hex(hex_value)
    except ValueError as e:
        raise _policy_error(f"code measurement register is not hex: {e}") from None
    if len(b) != REGISTER_SIZE:
        raise _policy_error(
            f"code measurement register must be {REGISTER_SIZE} bytes, got {len(b)}"
        )
    return b
