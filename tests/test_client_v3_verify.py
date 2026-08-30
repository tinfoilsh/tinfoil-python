"""
Unit tests for SecureClient's v3 verify flow (Go: SecureClient.verifyV3).

The v3 engine (fetch_attestation / verify_document_v3) is stubbed at the
client module seam; the tests pin the nonce/host/repo plumbing, the
both-keys-required binding rule, the rejection-layer → step attribution, and
the TDX hardware-measurement fingerprint rule.
"""

import hashlib
from unittest.mock import patch

import pytest

from tinfoil.attestation.types import AttestationError, PredicateType
from tinfoil.client import SecureClient
from tinfoil.v3.client import VerifiedDocumentV3
from tinfoil.v3.envelope import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    CryptoMaterialItem,
)
from tinfoil.v3.errors import (
    ENVELOPE_REJECTED,
    POLICY_REJECTED,
    PROVENANCE_REJECTED,
    QUOTE_REJECTED,
    VerificationError,
)
from tinfoil.v3.measurement import (
    RTMR3_ZERO,
    SEV_GUEST_V2,
    SNP_TDX_MULTI_PLATFORM_V1,
    TDX_GUEST_V2,
    Measurement as V3Measurement,
)

TLS_FP = "ab" * 32
HPKE_KEY = "cd" * 32
DIGEST = "12" * 32

SEV_REGISTER = "ee" * 48
TDX_REGISTERS = ["a0" * 48, "b1" * 48, "c2" * 48, "d3" * 48, RTMR3_ZERO]
MULTIPLATFORM_REGISTERS = [SEV_REGISTER, "c2" * 48, "d3" * 48]


def _crypto_material(*, tls: bool = True, hpke: bool = True) -> list:
    items = []
    if tls:
        items.append(
            CryptoMaterialItem(
                id=CRYPTO_MATERIAL_ID_TLS,
                format=KEY_SPKI_FP_SHA256_V1_FORMAT,
                data=TLS_FP,
            )
        )
    if hpke:
        items.append(
            CryptoMaterialItem(
                id=CRYPTO_MATERIAL_ID_HPKE,
                format=KEY_X25519_HPKE_V1_FORMAT,
                data=HPKE_KEY,
            )
        )
    return items


def _sev_verified(**overrides) -> VerifiedDocumentV3:
    fields = {
        "code_digest": DIGEST,
        "code_tag": "v9.9.9",
        "code_measurement": V3Measurement(
            type=SNP_TDX_MULTI_PLATFORM_V1, registers=list(MULTIPLATFORM_REGISTERS)
        ),
        "enclave_measurement": V3Measurement(
            type=SEV_GUEST_V2, registers=[SEV_REGISTER]
        ),
        "crypto_material": _crypto_material(),
    }
    fields.update(overrides)
    return VerifiedDocumentV3(**fields)


def _tdx_verified() -> VerifiedDocumentV3:
    return _sev_verified(
        enclave_measurement=V3Measurement(
            type=TDX_GUEST_V2, registers=list(TDX_REGISTERS)
        )
    )


def _client() -> SecureClient:
    return SecureClient(enclave="enclave.test", repo="org/repo")


def _verify(client: SecureClient, verified: VerifiedDocumentV3):
    """Run verify() with the v3 engine stubbed to accept, returning the calls."""
    nonce = b"\x01" * 32
    with (
        patch("tinfoil.client.random_nonce", return_value=nonce) as mock_nonce,
        patch("tinfoil.client.fetch_attestation", return_value=b"doc-bytes") as mock_fetch,
        patch("tinfoil.client.verify_document_v3", return_value=verified) as mock_verify,
    ):
        ground_truth = client.verify()
    return ground_truth, mock_nonce, mock_fetch, mock_verify


class TestPlumbing:
    def test_nonce_host_and_repo_reach_the_v3_engine(self):
        client = _client()
        _, _, mock_fetch, mock_verify = _verify(client, _sev_verified())

        mock_fetch.assert_called_once_with("enclave.test", b"\x01" * 32)
        mock_verify.assert_called_once_with(b"doc-bytes", b"\x01" * 32, "org/repo")

    def test_ground_truth_carries_the_endorsed_keys_and_digest(self):
        client = _client()
        ground_truth, *_ = _verify(client, _sev_verified())

        assert ground_truth.public_key == TLS_FP
        assert ground_truth.hpke_public_key == HPKE_KEY
        assert ground_truth.digest == DIGEST
        assert ground_truth.measurement.type == PredicateType.SEV_GUEST_V2
        assert ground_truth.measurement.registers == [SEV_REGISTER]

    def test_document_carries_the_v3_facts(self):
        client = _client()
        _verify(client, _sev_verified())
        doc = client.get_verification_document()

        assert doc.security_verified is True
        assert doc.config_repo == "org/repo"
        assert doc.enclave_host == "enclave.test"
        assert doc.selected_router_endpoint == "enclave.test"
        assert doc.release_digest == DIGEST
        assert doc.release_tag == "v9.9.9"
        assert doc.tls_public_key == TLS_FP
        assert doc.hpke_public_key == HPKE_KEY
        assert doc.code_measurement.type == PredicateType.SNP_TDX_MULTIPLATFORM_v1
        assert doc.enclave_measurement.measurement.registers == [SEV_REGISTER]
        assert doc.enclave_measurement.public_key_fp == TLS_FP
        assert doc.enclave_measurement.hpke_public_key == HPKE_KEY
        assert doc.verified_at is not None
        assert doc.verifier.name == "tinfoil"
        assert all(step.status == "success" for step in doc.steps.values())

    def test_deferred_router_discovery_uses_the_atc_service(self):
        client = SecureClient(attestation_bundle_url="https://atc.example")
        assert client.enclave == ""  # discovery is deferred to verify()

        with patch(
            "tinfoil.client.get_router_address", return_value="router.test"
        ) as mock_discover:
            _, _, mock_fetch, _ = _verify(client, _sev_verified())

        mock_discover.assert_called_once_with(atc_base_url="https://atc.example")
        assert client.enclave == "router.test"
        assert mock_fetch.call_args.args[0] == "router.test"
        assert client.get_verification_document().enclave_host == "router.test"

    def test_pinned_measurement_mode_is_rejected(self):
        client = SecureClient(
            enclave="enclave.test", measurement={"snp_measurement": "aa" * 48}
        )
        with pytest.raises(ValueError, match="not supported by the v3"):
            client.verify()


class TestBindingRequiresBothKeys:
    @pytest.mark.parametrize("missing", ["tls", "hpke"])
    def test_missing_key_fails_binding(self, missing):
        client = _client()
        verified = _sev_verified(
            crypto_material=_crypto_material(
                tls=missing != "tls", hpke=missing != "hpke"
            )
        )

        with pytest.raises(AttestationError, match="binding:") as exc_info:
            _verify(client, verified)

        # The cause is the accessor's rejection; the ground truth stays unset.
        assert isinstance(exc_info.value.__cause__, ValueError)
        assert missing in str(exc_info.value)
        assert client.ground_truth is None

        doc = client.get_verification_document()
        assert doc.security_verified is False
        assert doc.steps["other_error"].status == "failed"
        assert doc.steps["other_error"].error.startswith("binding:")
        attached = getattr(exc_info.value, "verification_document", None)
        assert attached is not None
        assert attached.to_dict() == doc.to_dict()


class TestLayerAttribution:
    @pytest.mark.parametrize(
        "layer,step",
        [
            (ENVELOPE_REJECTED, "verify_enclave"),
            (QUOTE_REJECTED, "verify_enclave"),
            (PROVENANCE_REJECTED, "verify_code"),
            (POLICY_REJECTED, "compare_measurements"),
        ],
    )
    def test_rejection_layer_maps_to_step(self, layer, step):
        client = _client()
        rejection = VerificationError(layer, "engine said no")

        with (
            patch("tinfoil.client.random_nonce", return_value=b"\x01" * 32),
            patch("tinfoil.client.fetch_attestation", return_value=b"doc-bytes"),
            patch("tinfoil.client.verify_document_v3", side_effect=rejection),
        ):
            with pytest.raises(AttestationError, match="engine said no") as exc_info:
                client.verify()

        assert exc_info.value.__cause__ is rejection
        assert client.ground_truth is None

        doc = client.get_verification_document()
        assert doc.steps["fetch_digest"].status == "success"
        assert doc.steps[step].status == "failed"
        assert doc.steps[step].error == "engine said no"
        untouched = {"verify_code", "verify_enclave", "compare_measurements"} - {step}
        assert all(doc.steps[name].status == "pending" for name in untouched)

    def test_fetch_failure_is_attributed_to_the_fetch_step(self):
        client = _client()
        with patch(
            "tinfoil.client.fetch_attestation", side_effect=RuntimeError("HTTP 503")
        ):
            with pytest.raises(RuntimeError, match="HTTP 503") as exc_info:
                client.verify()

        doc = client.get_verification_document()
        assert doc.steps["fetch_digest"].status == "failed"
        assert doc.steps["fetch_digest"].error == "HTTP 503"
        assert getattr(exc_info.value, "verification_document", None) is not None

    def test_unexpected_engine_error_propagates_untouched(self):
        client = _client()
        with (
            patch("tinfoil.client.random_nonce", return_value=b"\x01" * 32),
            patch("tinfoil.client.fetch_attestation", return_value=b"doc-bytes"),
            patch("tinfoil.client.verify_document_v3", side_effect=TypeError("bug")),
        ):
            with pytest.raises(TypeError, match="bug"):
                client.verify()

        doc = client.get_verification_document()
        assert doc.steps["other_error"].status == "failed"
        assert doc.to_dict()["steps"]["otherError"]["error"] == "bug"


class TestFingerprintRules:
    def test_tdx_hardware_measurement_comes_from_the_quote_registers(self):
        client = _client()
        _verify(client, _tdx_verified())
        doc = client.get_verification_document()

        # Go parity: HardwareMeasurement{MRTD: reg[0], RTMR0: reg[1]}.
        assert doc.hardware_measurement is not None
        assert doc.hardware_measurement.mrtd == TDX_REGISTERS[0]
        assert doc.hardware_measurement.rtmr0 == TDX_REGISTERS[1]

        # Multiplatform code measurement projected onto the TDX registers,
        # hashed under the source predicate type (Go: measurement.Fingerprint).
        projected = [
            TDX_REGISTERS[0],
            TDX_REGISTERS[1],
            MULTIPLATFORM_REGISTERS[1],
            MULTIPLATFORM_REGISTERS[2],
            RTMR3_ZERO,
        ]
        expected_code = hashlib.sha256(
            (SNP_TDX_MULTI_PLATFORM_V1 + "".join(projected)).encode()
        ).hexdigest()
        assert doc.code_fingerprint == expected_code

        expected_enclave = hashlib.sha256(
            (TDX_GUEST_V2 + "".join(TDX_REGISTERS)).encode()
        ).hexdigest()
        assert doc.enclave_fingerprint == expected_enclave

    def test_sev_fingerprints_are_the_single_registers(self):
        client = _client()
        _verify(client, _sev_verified())
        doc = client.get_verification_document()

        assert doc.hardware_measurement is None
        assert doc.code_fingerprint == SEV_REGISTER
        assert doc.enclave_fingerprint == SEV_REGISTER


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
