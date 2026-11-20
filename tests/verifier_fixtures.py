"""Shared material for the verifier tests: embedded references, v3 documents around a dummy quote, and verifiers
whose Sigstore trust is a synthetic world's."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from tests import document_builder
from tests.sigstore_world import World
from tinfoil.verifier._document import document
from tinfoil.verifier._document.collateral import entry
from tinfoil.verifier._options import (
    ConfigTrust,
    EmbeddedArtifacts,
    EmbeddedConfig,
    Policy,
)
from tinfoil.verifier._policy import ARTIFACT_FORMAT_V2
from tinfoil.verifier._runtime import MEASUREMENT_SIZE
from tinfoil.verifier._verifier import Overrides, Verifier, _build

EMBEDDED_CONFIG_NAME = "/org/project/v1"
ZERO = "00" * MEASUREMENT_SIZE
SNP_LAUNCH = "ab" * MEASUREMENT_SIZE
TDX_MRTD = "cd" * MEASUREMENT_SIZE


def manifest_bytes(version: str = "v0.15.0", snp_launch: str = SNP_LAUNCH, mrtd: str = TDX_MRTD) -> bytes:
    """A runtime manifest of format version 1."""
    return json.dumps(
        {
            "version": version,
            "igvm": {
                "format_version": 1,
                "snp_launch": {"measurement": snp_launch},
                "tdx_launch": {"mrtd": mrtd, "rtmr0": ZERO, "rtmr1": ZERO, "rtmr2": ZERO, "rtmr3": ZERO},
            },
        },
        separators=(",", ":"),
    ).encode()


def config_bytes(manifest: bytes, version: str = "0.15.0") -> bytes:
    """A config whose ``cvm-version`` pins ``manifest``."""
    return f"cvm-version: {version}@sha256:{hashlib.sha256(manifest).hexdigest()}\n".encode()


def platform_bytes() -> bytes:
    """An empty v2 platform policy artifact."""
    return json.dumps({"format": ARTIFACT_FORMAT_V2, "measurements": {}, "machines": {}, "policies": {}}).encode()


@dataclass(frozen=True, kw_only=True)
class EmbeddedInputs:
    """Caller-trusted values for a verifier: a config for its config trust, and a runtime manifest and a platform
    artifact for its ``EmbeddedArtifacts``. A None member is left to its endorsement."""

    config: ConfigTrust | None = None
    runtime: bytes | None = None
    platform: bytes | None = None

    def options(self, policy: Policy | None = None) -> tuple[ConfigTrust | None, Policy]:
        """The config trust and the policy that select these values, with ``policy``'s other fields."""
        policy = policy or Policy()
        if self.runtime is not None or self.platform is not None:
            policy = Policy(
                pinned_registers=policy.pinned_registers,
                freshness_max_age=policy.freshness_max_age,
                artifacts=EmbeddedArtifacts(
                    runtime=self.runtime,
                    platform=self.platform,
                    freshness_keys=getattr(policy.artifacts, "freshness_keys", None),
                ),
            )
        return self.config, policy


def embedded_verifier(inputs: EmbeddedInputs, policy: Policy | None = None) -> Verifier:
    """A verifier that trusts ``inputs``."""
    return Verifier(*inputs.options(policy))


def embedded_inputs() -> EmbeddedInputs:
    """A config, the manifest that it pins and an empty platform artifact."""
    manifest = manifest_bytes()
    return EmbeddedInputs(
        config=EmbeddedConfig(data=config_bytes(manifest), name=EMBEDDED_CONFIG_NAME),
        runtime=manifest,
        platform=platform_bytes(),
    )


def reference_entry(entry_id: str, format_: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"id": entry_id, "role": entry.ROLE_REFERENCE_VALUES, "format": format_, "subjects": [], "data": data}


def endorsement_entry(entry_id: str, format_: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": entry_id,
        "role": entry.ROLE_ENDORSEMENT,
        "format": format_,
        "subjects": [entry.SUBJECT_CPU],
        "data": data,
    }


def embedded_document(
    collateral_format: str | None, *entries: dict[str, Any], report: bytes | None = None
) -> tuple[bytes, bytes, document.Document]:
    """A well-formed v3 document around a dummy SEV-SNP report with the given collateral: its bytes, the nonce that
    binds it and its parsed form."""
    nonce = document_builder.test_nonce()
    raw = document_builder.build_raw(nonce, collateral_format=collateral_format, collateral_entries=list(entries))
    if report is not None:
        raw["cpu_evidence"]["report_base64"] = document_builder.b64(report)
    encoded = document_builder.encode(raw)
    return encoded, nonce, document.parse(encoded, nonce)


def world_verifier(world: World, config: ConfigTrust | None = None, policy: Policy | None = None) -> Verifier:
    """A verifier whose Sigstore trust is the world's root."""
    return _build(config, policy, overrides=Overrides(sigstore_root=world.trusted_root_json()))
