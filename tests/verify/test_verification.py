from datetime import datetime, timedelta, timezone

from tinfoil.verify import SoftwareIdentity, Verification, VerificationMetadata, crypto_material_data
from tinfoil.verify.document import (
    KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_SPKI_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT,
    CryptoMaterialItem,
)
from tinfoil.verify.measurement import Measurement, PredicateType

TLS = CryptoMaterialItem("tls", KEY_SPKI_FP_SHA256_V1_FORMAT, "aa" * 32)
HPKE = CryptoMaterialItem("hpke", KEY_X25519_HPKE_V1_FORMAT, "bb" * 32)
SSH = CryptoMaterialItem("host-ssh", KEY_SPKI_V1_FORMAT, "cc" * 40)
VERIFIED_AT = datetime(2026, 10, 1, tzinfo=timezone.utc)


def verification(*items: CryptoMaterialItem) -> Verification:
    measurement = Measurement(PredicateType.SEV_GUEST_V2, ["dd" * 48])
    return Verification(
        config_repo="org/repo",
        code_digest="ee" * 32,
        code_tag="v1.0.0",
        code_measurement=measurement,
        enclave_measurement=measurement,
        crypto_material=items,
        freshness_expires_at=VERIFIED_AT + timedelta(days=7),
        metadata=VerificationMetadata(verifier=SoftwareIdentity("tinfoil-python", "devel"), verified_at=VERIFIED_AT),
    )


def test_channel_keys_are_looked_up_by_id_and_format():
    verified = verification(TLS, HPKE, SSH)
    assert verified.tls_public_key_fp == TLS.data
    assert verified.hpke_public_key == HPKE.data
    assert verified.crypto_material_data("host-ssh", KEY_SPKI_V1_FORMAT) == SSH.data


def test_absent_channel_keys_are_none():
    verified = verification(SSH)
    assert verified.tls_public_key_fp is None
    assert verified.hpke_public_key is None


def test_an_item_in_another_format_does_not_count():
    verified = verification(CryptoMaterialItem("tls", KEY_SPKI_V1_FORMAT, "aa" * 40))
    assert verified.tls_public_key_fp is None
    assert verified.crypto_material_data("tls", KEY_SPKI_FP_SHA256_V1_FORMAT) is None


def test_crypto_material_data_reads_a_callers_own_record():
    assert crypto_material_data([SSH, HPKE], "hpke", KEY_X25519_HPKE_V1_FORMAT) == HPKE.data
    assert crypto_material_data([], "hpke", KEY_X25519_HPKE_V1_FORMAT) is None
