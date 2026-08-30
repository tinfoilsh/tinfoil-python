import json
from unittest.mock import MagicMock, patch

import pytest
from sigstore.errors import VerificationError

from tinfoil.attestation.bundle import fetch_bundle_from
from tinfoil.attestation.types import (
    HardwareMeasurement,
    Measurement,
    PredicateType,
    Verification,
)
from tinfoil.client import SecureClient, SoftwareIdentity, VerificationDocument
from tinfoil.sigstore import _verify_dsse_bundle
from tinfoil.v3.client import VerifiedDocumentV3
from tinfoil.v3.envelope import (
    CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS,
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    CryptoMaterialItem,
)
from tinfoil.v3.errors import PROVENANCE_REJECTED, QUOTE_REJECTED
from tinfoil.v3.errors import VerificationError as V3VerificationError
from tinfoil.v3.measurement import SEV_GUEST_V2, Measurement as V3Measurement


def _measurement() -> Measurement:
    return Measurement(type=PredicateType.SEV_GUEST_V2, registers=["measurement"])


def _verification() -> Verification:
    return Verification(
        measurement=_measurement(),
        public_key_fp="tls-fingerprint",
        hpke_public_key="hpke-key",
    )


def _verified_v3() -> VerifiedDocumentV3:
    return VerifiedDocumentV3(
        code_digest="digest",
        code_tag="v1.2.3",
        code_measurement=V3Measurement(type=SEV_GUEST_V2, registers=["measurement"]),
        enclave_measurement=V3Measurement(type=SEV_GUEST_V2, registers=["measurement"]),
        crypto_material=[
            CryptoMaterialItem(
                id=CRYPTO_MATERIAL_ID_TLS,
                format=KEY_SPKI_FP_SHA256_V1_FORMAT,
                data="tls-fingerprint",
            ),
            CryptoMaterialItem(
                id=CRYPTO_MATERIAL_ID_HPKE,
                format=KEY_X25519_HPKE_V1_FORMAT,
                data="hpke-key",
            ),
        ],
    )


def test_direct_verification_binds_and_reports_selected_release_tag():
    client = SecureClient(enclave="enclave.test", repo="org/repo")

    with (
        patch("tinfoil.client.random_nonce", return_value=b"\x02" * 32),
        patch("tinfoil.client.fetch_attestation", return_value=b"doc-bytes"),
        patch(
            "tinfoil.client.verify_document_v3", return_value=_verified_v3()
        ) as verify_v3,
    ):
        client.verify()

    verify_v3.assert_called_once_with(b"doc-bytes", b"\x02" * 32, "org/repo")
    assert client.get_verification_document().release_tag == "v1.2.3"


def test_release_tag_is_reported_only_after_verification_accepts():
    client = SecureClient(enclave="enclave.test", repo="org/repo")

    with (
        patch("tinfoil.client.random_nonce", return_value=b"\x02" * 32),
        patch("tinfoil.client.fetch_attestation", return_value=b"doc-bytes"),
        patch(
            "tinfoil.client.verify_document_v3",
            side_effect=V3VerificationError(PROVENANCE_REJECTED, "tag mismatch"),
        ),
    ):
        with pytest.raises(Exception, match="tag mismatch"):
            client.verify()

    document = client.get_verification_document()
    assert document.release_tag is None
    assert document.steps["verify_code"].status == "failed"


def test_fetched_bundle_preserves_optional_release_tag():
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "domain": "enclave.test",
        "enclaveAttestationReport": {
            "format": PredicateType.SEV_GUEST_V2.value,
            "body": "Zm9v",
        },
        "digest": "digest",
        "releaseTag": "v1.2.3",
        "sigstoreBundle": {},
    }

    with patch("tinfoil.attestation.bundle.requests.get", return_value=response):
        bundle = fetch_bundle_from("https://atc.test")

    assert bundle.release_tag == "v1.2.3"


def test_sigstore_rejects_a_different_exact_workflow_tag():
    certificate = MagicMock()
    certificate.extensions.get_extension_for_oid.return_value.value.value = (
        b"refs/tags/v1.2.4"
    )
    verifier = MagicMock()

    def verify_dsse(_bundle, policy):
        policy._children[-1].verify(certificate)

    verifier.verify_dsse.side_effect = verify_dsse

    with (
        patch("tinfoil.sigstore.Verifier.production", return_value=verifier),
        patch("tinfoil.sigstore.Bundle.from_json", return_value=MagicMock()),
        patch("tinfoil.sigstore.reject_duplicate_sct_logs"),
    ):
        with pytest.raises(VerificationError, match="does not match pattern"):
            _verify_dsse_bundle(b"{}", "digest", "org/repo", "v1.2.3")


def test_sigstore_rejects_a_workflow_tag_with_trailing_newline():
    certificate = MagicMock()
    certificate.extensions.get_extension_for_oid.return_value.value.value = (
        b"refs/tags/v1.2.3\n"
    )
    verifier = MagicMock()

    def verify_dsse(_bundle, policy):
        policy._children[-1].verify(certificate)

    verifier.verify_dsse.side_effect = verify_dsse

    with (
        patch("tinfoil.sigstore.Verifier.production", return_value=verifier),
        patch("tinfoil.sigstore.Bundle.from_json", return_value=MagicMock()),
        patch("tinfoil.sigstore.reject_duplicate_sct_logs"),
    ):
        with pytest.raises(VerificationError, match="does not match pattern"):
            _verify_dsse_bundle(b"{}", "digest", "org/repo", "v1.2.3")


def test_get_verification_document_returns_an_isolated_copy():
    client = SecureClient(enclave="enclave.test", repo="org/repo")
    client._verification_document = VerificationDocument(release_tag="v1.2.3")

    returned = client.get_verification_document()
    returned.release_tag = "forged"
    returned.steps["verify_code"].status = "failed"

    unchanged = client.get_verification_document()
    assert unchanged.release_tag == "v1.2.3"
    assert unchanged.steps["verify_code"].status == "pending"


def test_failure_exception_document_cannot_mutate_client_state():
    client = SecureClient(enclave="enclave.test", repo="org/repo")

    with (
        patch("tinfoil.client.fetch_attestation", return_value=b"doc-bytes"),
        patch(
            "tinfoil.client.verify_document_v3",
            side_effect=V3VerificationError(QUOTE_REJECTED, "verification failed"),
        ),
    ):
        with pytest.raises(Exception) as exc_info:
            client.verify()

    getattr(exc_info.value, "verification_document").steps[
        "verify_enclave"
    ].status = "success"

    assert client.get_verification_document().steps["verify_enclave"].status == "failed"


def test_verification_document_serializes_to_shared_camel_case_schema():
    measurement = _measurement()
    document = VerificationDocument(
        config_repo="org/repo",
        enclave_host="enclave.test",
        release_digest="digest",
        release_tag="v1.2.3",
        code_measurement=measurement,
        enclave_measurement=_verification(),
        tls_public_key="tls-fingerprint",
        hpke_public_key="hpke-key",
        hardware_measurement=HardwareMeasurement(
            id="platform@digest", mrtd="mrtd", rtmr0="rtmr0"
        ),
        code_fingerprint="code-fingerprint",
        enclave_fingerprint="enclave-fingerprint",
        selected_router_endpoint="router.test",
        security_verified=True,
        verifier=SoftwareIdentity(name="tinfoil", version="0.14.0"),
        verified_at="2026-08-04T12:00:00Z",
    )

    serialized = document.to_dict()

    assert serialized["schemaVersion"] == 1
    assert serialized["releaseTag"] == "v1.2.3"
    assert serialized["codeMeasurement"] == {
        "type": PredicateType.SEV_GUEST_V2.value,
        "registers": ["measurement"],
    }
    assert serialized["enclaveMeasurement"] == {
        "measurement": serialized["codeMeasurement"],
        "tlsPublicKeyFingerprint": "tls-fingerprint",
        "hpkePublicKey": "hpke-key",
    }
    assert serialized["hardwareMeasurement"] == {
        "ID": "platform@digest",
        "MRTD": "mrtd",
        "RTMR0": "rtmr0",
    }
    assert serialized["steps"]["compareMeasurements"] == {"status": "pending"}
    assert serialized["verifiedAt"] == "2026-08-04T12:00:00Z"
    assert json.loads(document.to_json()) == serialized


def test_verification_document_serialization_omits_none_values():
    serialized = VerificationDocument().to_dict()

    assert "releaseTag" not in serialized
    assert "codeMeasurement" not in serialized
    assert "hardwareMeasurement" not in serialized
    assert "verifiedAt" not in serialized
