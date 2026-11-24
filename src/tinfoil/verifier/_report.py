"""The verification report: what each step of a verification did, and what it established."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import Any, Final, Literal, TypeAlias

from tinfoil._sdkinfo import UNKNOWN_VERSION
from tinfoil.verifier._document.document import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    CryptoMaterialItem,
)
from tinfoil.verifier._errors import LAYER_ENVELOPE, LAYER_POLICY, LAYER_PROVENANCE, LAYER_QUOTE, Layer
from tinfoil.verifier._measurement import Expected, Measurement
from tinfoil.verifier._verification import (
    ArtifactVerification,
    ConfigVerification,
    VerificationMetadata,
    VerifiedFacts,
    artifact_dict,
    code_measurement_dict,
    config_dict,
    crypto_material_data,
    json_text,
    measurement_dict,
    time_str,
)

REPORT_SCHEMA_VERSION: Final = 1
"""The ``schema_version`` that the JSON form of a ``VerificationReport`` carries. Adding a member keeps the version;
removing or renaming one, or changing what one means, bumps it. A consumer ignores members that it does not know."""

StepStatus: TypeAlias = Literal["passed", "failed", "skipped", "not_run"]
"""The outcome of a ``Step``; the ``STEP_*`` constants are its values."""

STEP_PASSED: Final[StepStatus] = "passed"
"""Every check of the step's layer ran and accepted the document."""
STEP_FAILED: Final[StepStatus] = "failed"
"""The step's layer rejected the document."""
STEP_SKIPPED: Final[StepStatus] = "skipped"
"""The layer had nothing to check, as for provenance when the caller embeds every reference value."""
STEP_NOT_RUN: Final[StepStatus] = "not_run"
"""The step did not run in full, because a step failed."""

LAYERS: Final[tuple[Layer, ...]] = (LAYER_ENVELOPE, LAYER_PROVENANCE, LAYER_QUOTE, LAYER_POLICY)
"""The layers that a report has a step for, in the order that they run."""

PROVENANCE_EMBEDDED = "the verifier embeds every reference value, so there is no endorsement to authenticate"
"""The message of a skipped provenance step."""


@dataclass(frozen=True, slots=True)
class Step:
    """The outcome of one verification layer."""

    layer: Layer
    """The layer that the step covers: one of the ``LAYER_*`` constants, or a later layer."""
    status: StepStatus
    """Whether the layer passed, failed, was skipped or did not run."""
    message: str = ""
    """The ``VerificationError``'s message for a failed step, the reason for a skipped one, and empty otherwise.
    Messages are diagnostic; do not parse them."""


@dataclass(frozen=True, slots=True, kw_only=True)
class CPUEvidence:
    """What the CPU's authenticated quote proves."""

    measurement: Measurement
    """Every register that the hardware measured: an ``SEVSNP`` or ``TDX`` value."""


@dataclass(frozen=True, slots=True, kw_only=True)
class MeasuredFacts:
    """What the document and its hardware evidence claim."""

    cpu: CPUEvidence | None = None
    """Set only once the quote step passed, so that what it holds came from the hardware."""
    tls_public_key_fp: str | None = None
    """The SPKI SHA-256 fingerprint of the TLS key that the document endorses, as
    ``VerifiedFacts.tls_public_key_fp`` returns it, or None when it endorses none. Only the policy step binds it to
    the enclave, so in a rejected report it is unverified."""
    hpke_public_key_fp: str | None = None
    """The lowercase-hex SHA-256 of the bytes of the HPKE public key that the document endorses, never the key
    itself, or None when it endorses none. It is unverified in a rejected report, as ``tls_public_key_fp`` is."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpectedFacts:
    """The reference values that the provenance step accepted: what the enclave should be running."""

    config_repo: str
    """The selected code or runtime repository, without version pins."""
    artifact: ArtifactVerification
    """The code release, or the runtime for a config-based verification."""
    config: ConfigVerification | None = None
    """The config that a config-based verification accepted; None for a code release."""
    platform: ArtifactVerification | None = None
    """The platform endorsements that a config-based verification accepted; None for a code release."""
    code_measurement: Expected | None = None
    """The registers that the release fixes on the platform that the document's CPU evidence names, with None for
    a register that the release leaves to the platform; None if the release fixes nothing usable on that platform.
    The values are authenticated; the platform that selects their layout is authenticated only once the quote step
    passed."""
    measurement: Measurement | None = None
    """Every register that the quote must attest: the code measurement, the verifier's pinned registers and, for a
    code release on TDX, the platform registers (MRTD and RTMR0) that the platform endorsements supply for the
    quote's machine. It is set once the policy step resolved every register, even if a later check of that step
    failed, and None otherwise."""


@dataclass(frozen=True, slots=True, kw_only=True)
class PartialFacts:
    """What a rejected verification established before the step that failed. Every fact in them is authenticated,
    except the key fingerprints, which ``MeasuredFacts`` describes."""

    expected: ExpectedFacts | None = None
    """None unless the provenance step passed or was skipped."""
    measured: MeasuredFacts | None = None
    """None unless the envelope step passed."""


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationReport:
    """One verification of an attestation document, step by step, and what each step established.

    ``Verifier.verify_v3`` returns one for a document that it accepts, and
    a ``VerificationError`` carries one, as ``report``, for a document that
    it rejects, so that a caller can show what happened either way. A
    report authorizes nothing by itself: only the endorsed keys in
    ``verified_facts`` may bind a channel. Every field is immutable, so a
    report can be shared without copying.
    """

    steps: tuple[Step, ...]
    """One step for each layer, in layer order: envelope, provenance, quote and policy today."""
    verified_facts: VerifiedFacts | None = None
    """Set if and only if no step failed. It is the only part of a report that carries the keys that a channel
    binds to."""
    partial_facts: PartialFacts | None = None
    """Set if and only if a step failed. It holds what the steps before the failure established."""
    metadata: VerificationMetadata
    """The verifier's identity and the appraisal instant. The verifier supplies them; the document does not attest
    them."""

    @property
    def failed_step(self) -> Step | None:
        """The step that failed, or None when none did."""
        for step in self.steps:
            if step.status == STEP_FAILED:
                return step
        return None

    def to_dict(self) -> dict[str, Any]:
        """The report in the JSON form that every Tinfoil SDK writes, as a ``dict`` of JSON values, so that a report
        can be shown or passed on, for example to a browser or another process:

        .. code-block:: text

            {
              "schema_version": 1,
              "steps": [
                {"layer": "envelope", "status": "passed"},
                {"layer": "provenance", "status": "passed"},
                {"layer": "quote", "status": "failed", "message": "<detail>"},
                {"layer": "policy", "status": "not_run"}
              ],
              "verified_facts": { ...on success only, as VerifiedFacts.to_dict writes them... },
              "partial_facts": {
                "expected": {"config_repo", "artifact", "config", "platform", "code_measurement", "measurement"},
                "measured": {"cpu_measurement", "tls_public_key_fp", "hpke_public_key_fp"}
              },
              "metadata": {
                "verified_at": "<RFC 3339, UTC>",
                "verifier": {"name": "tinfoil-python", "version": "<version>"},
                "host": "<host[:port]>"
              }
            }

        Keys are snake_case, hex is lowercase and times are RFC 3339 in UTC, written with ``Z``. A fact that was not
        established is left out, but an established fact that is empty is kept, as in ``"measured": {}``; no member
        is None or ``""``. Exactly one of ``verified_facts`` and ``partial_facts`` is present, and ``partial_facts``
        is present only on a rejection. A step's message is present only for a failed or skipped step.
        ``metadata.verifier`` is present only when the installed package names its version. ``metadata.host`` is
        present only in a report that a client produced: it names the host that the client contacted, which is not
        attested, so it proves nothing about the enclave.

        The JSON is for display and transport only, and it authorizes nothing: nothing in this SDK parses it back
        into a report or into verified facts, and a holder of the JSON cannot tell whether a verifier produced it, so
        a channel binds only to the ``VerifiedFacts`` that a verification returned in process."""
        out: dict[str, Any] = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "steps": [_step_dict(step) for step in self.steps],
        }
        if self.verified_facts is not None:
            out["verified_facts"] = self.verified_facts.to_dict()
        if self.partial_facts is not None:
            out["partial_facts"] = _partial_dict(self.partial_facts)
        out["metadata"] = _metadata_dict(self.metadata)
        return out

    def to_json(self, *, indent: int | None = None) -> str:
        """``to_dict`` serialized as JSON: compact by default, or pretty-printed with ``indent`` spaces per level."""
        return json_text(self.to_dict(), indent)


def hpke_public_key_fp(key: str) -> str | None:
    """The fingerprint that ``MeasuredFacts.hpke_public_key_fp`` reports for ``key``, an HPKE public key in hex as
    the document endorses it: the lowercase-hex SHA-256 of the key's bytes. None when ``key`` is not hex or is
    empty."""
    try:
        raw = bytes.fromhex(key)
    except ValueError:
        return None
    if not raw:
        return None
    return hashlib.sha256(raw).hexdigest()


def measured_keys(items: tuple[CryptoMaterialItem, ...]) -> MeasuredFacts:
    """The key fingerprints that ``items`` endorse, unverified."""
    hpke = crypto_material_data(items, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT)
    return MeasuredFacts(
        tls_public_key_fp=crypto_material_data(items, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT),
        hpke_public_key_fp=None if hpke is None else hpke_public_key_fp(hpke),
    )


class ReportBuilder:
    """Records each step of a verification as the verifier runs it, and the facts that each step establishes."""

    __slots__ = ("_steps", "expected", "measured", "metadata")

    def __init__(self, metadata: VerificationMetadata) -> None:
        self._steps = {layer: Step(layer, STEP_NOT_RUN) for layer in LAYERS}
        self.metadata = metadata
        self.expected: ExpectedFacts | None = None
        self.measured: MeasuredFacts | None = None

    def set(self, layer: Layer, status: StepStatus, message: str = "") -> None:
        self._steps[layer] = Step(layer, status, message)

    def passed(self, layer: Layer) -> None:
        self.set(layer, STEP_PASSED)

    def resolved(self, measurement: Measurement) -> None:
        """Records the full expected measurement that the policy step resolved."""
        if self.expected is not None:
            self.expected = replace(self.expected, measurement=measurement)

    def passed_all(self, facts: VerifiedFacts) -> VerificationReport:
        """The report of a verification that every step accepted."""
        return VerificationReport(steps=tuple(self._steps.values()), verified_facts=facts, metadata=self.metadata)

    def failed(self, layer: Layer, message: str) -> VerificationReport:
        """The report of a verification that ``layer`` rejected with ``message``."""
        self.set(layer, STEP_FAILED, message)
        return VerificationReport(
            steps=tuple(self._steps.values()),
            partial_facts=PartialFacts(expected=self.expected, measured=self.measured),
            metadata=self.metadata,
        )


def _step_dict(step: Step) -> dict[str, Any]:
    out: dict[str, Any] = {"layer": step.layer, "status": step.status}
    if step.message:
        out["message"] = step.message
    return out


def _metadata_dict(metadata: VerificationMetadata) -> dict[str, Any]:
    """``metadata`` as ``{"verified_at", "verifier", "host"}``, with the verifier only when its name and version are
    known and the host only when a client set it."""
    out: dict[str, Any] = {"verified_at": time_str(metadata.verified_at)}
    verifier = metadata.verifier
    if verifier.name and verifier.version and verifier.version != UNKNOWN_VERSION:
        out["verifier"] = {"name": verifier.name, "version": verifier.version}
    if metadata.host:
        out["host"] = metadata.host
    return out


def _partial_dict(partial: PartialFacts) -> dict[str, Any]:
    out: dict[str, Any] = {}
    expected = partial.expected
    if expected is not None:
        expected_out: dict[str, Any] = {"config_repo": expected.config_repo} if expected.config_repo else {}
        expected_out["artifact"] = artifact_dict(expected.artifact)
        if expected.config is not None:
            expected_out["config"] = config_dict(expected.config)
        if expected.platform is not None:
            expected_out["platform"] = artifact_dict(expected.platform)
        code = code_measurement_dict(expected.code_measurement)
        if code is not None:
            expected_out["code_measurement"] = code
        if expected.measurement is not None:
            expected_out["measurement"] = measurement_dict(expected.measurement)
        out["expected"] = expected_out
    measured = partial.measured
    if measured is not None:
        measured_out: dict[str, Any] = {}
        if measured.cpu is not None:
            measured_out["cpu_measurement"] = measurement_dict(measured.cpu.measurement)
        if measured.tls_public_key_fp:
            measured_out["tls_public_key_fp"] = measured.tls_public_key_fp
        if measured.hpke_public_key_fp:
            measured_out["hpke_public_key_fp"] = measured.hpke_public_key_fp
        out["measured"] = measured_out
    return out


__all__ = [
    "LAYERS",
    "REPORT_SCHEMA_VERSION",
    "STEP_FAILED",
    "STEP_NOT_RUN",
    "STEP_PASSED",
    "STEP_SKIPPED",
    "CPUEvidence",
    "ExpectedFacts",
    "MeasuredFacts",
    "PartialFacts",
    "ReportBuilder",
    "Step",
    "StepStatus",
    "VerificationReport",
    "hpke_public_key_fp",
    "measured_keys",
]
