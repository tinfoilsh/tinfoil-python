"""Offline verification keeps artifact, hardware, and key-binding checks."""

import base64
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import socket

import pytest

import tinfoil
from tinfoil.v3 import client, envelope as env
from tinfoil.v3.errors import VerificationError
from tinfoil.v3.provenance import MAX_FRESHNESS_AGE

from docbuilder import NONCE, build_doc
import sevsynth
import sigstore_builder as sb
import test_provenance as provenance_cases
from test_sev_expectations import make_policy


APPRAISAL_TIME = datetime.fromtimestamp(sb.INTEGRATED_TIME, timezone.utc) + timedelta(hours=1)
SIGNING_KEY_ID = "enclave-signing-key"
SPKI_FORMAT = "https://tinfoil.sh/key/spki/v1"
SIGNING_KEY = "302a300506032b6570032100" + "12" * 32


@pytest.fixture(scope="module")
def signed_document():
    crypto_material = {"format": env.CRYPTO_MATERIAL_V1_FORMAT, "items": [
        {"id": SIGNING_KEY_ID, "format": SPKI_FORMAT, "data": SIGNING_KEY},
    ]}
    doc = json.loads(build_doc(crypto_section=crypto_material))
    report_data = bytes.fromhex(doc["challenge"]["report_data"])
    hardware = sevsynth.build_sev(report_data=report_data)
    doc["cpu_evidence"]["report_base64"] = sb.b64(hardware["report"])
    doc["collateral"] = json.loads(sevsynth.sev_doc_bytes(hardware))["collateral"]
    policy_name = "sev-policy"
    artifact = {
        "format": provenance_cases.ARTIFACT_FMT,
        "measurements": {},
        "machines": {hardware["chip_id"].hex(): policy_name},
        "policies": {policy_name: {"platform": "sev-snp", "sev_snp": asdict(make_policy())}},
    }
    code_bundle, root = provenance_cases.code_bundle()
    platform_bundle, _ = provenance_cases.plat_bundle(artifact=artifact)
    for identifier, format_, repo, tag, digest, subject, bundle in (
        ("code", env.COLLATERAL_SIGSTORE_CODE_V1_FORMAT, provenance_cases.REPO,
         provenance_cases.TAG, provenance_cases.DIGEST, "cip", code_bundle),
        ("platform", env.COLLATERAL_SIGSTORE_PLATFORM_V1_FORMAT, provenance_cases.PLAT_REPO,
         provenance_cases.PLAT_TAG, provenance_cases.PLAT_DIGEST, "platform", platform_bundle),
    ):
        doc["collateral"].append({
            "id": identifier, "role": env.ROLE_REFERENCE_VALUES, "format": format_,
            "data": {"repo": repo, "tag": tag, "digest": digest, "sigstore_bundle": bundle},
        })
        witness, _ = sb.build_freshness_bundle(subject, digest, repo, tag, provenance_cases.COMMIT)
        doc["collateral"].append({
            "id": identifier + "-freshness", "role": env.ROLE_REFERENCE_VALUES,
            "format": env.COLLATERAL_SIGSTORE_FRESHNESS_V1_FORMAT,
            "data": {"sigstore_bundle": witness},
        })
    roots = {"sigstore_root_json": json.dumps(root).encode(), "amd_root_pem": hardware["root_pem"]}
    return doc, roots


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("document verification attempted a network connection")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)


def verify(doc, roots, *, now=APPRAISAL_TIME, nonce=NONCE, repo=provenance_cases.REPO, **options):
    return client._verify_document_v3(
        json.dumps(doc).encode(), nonce, repo, verification_time=now, **roots, **options,
    )


def test_default_and_offline_return_same_verified_facts(signed_document):
    doc, roots = signed_document
    online = verify(doc, roots)
    offline = verify(doc, roots, ignore_freshness=True)
    assert offline == online
    assert offline.code_tag == provenance_cases.TAG
    assert offline.code_digest == provenance_cases.DIGEST
    assert offline.enclave_measurement.registers == ["aa" * 48]
    assert [(item.id, item.format, item.data) for item in offline.crypto_material] == [
        (SIGNING_KEY_ID, SPKI_FORMAT, SIGNING_KEY),
    ]


@pytest.mark.parametrize("witness_state", ["expired", "missing", "invalid"])
def test_offline_skips_witnesses_but_default_requires_them(signed_document, witness_state):
    original, roots = signed_document
    doc = deepcopy(original)
    now = APPRAISAL_TIME
    if witness_state == "expired":
        now += MAX_FRESHNESS_AGE
    elif witness_state == "missing":
        doc["collateral"] = [item for item in doc["collateral"] if not item["id"].endswith("-freshness")]
    else:
        for item in doc["collateral"]:
            if item["id"].endswith("-freshness"):
                item["data"]["sigstore_bundle"] = {}
    with pytest.raises(VerificationError):
        verify(doc, roots, now=now)
    assert verify(doc, roots, now=now, ignore_freshness=True) == verify(original, roots)


@pytest.mark.parametrize("identifier", ["code", "platform", "code-freshness", "platform-freshness"])
def test_offline_rejects_missing_bundle_members(signed_document, identifier):
    original, roots = signed_document
    doc = deepcopy(original)
    del next(item for item in doc["collateral"] if item["id"] == identifier)["data"]["sigstore_bundle"]
    with pytest.raises(VerificationError, match="missing sigstore_bundle"):
        verify(doc, roots, ignore_freshness=True)


@pytest.mark.parametrize("identifier", ["code", "platform"])
def test_offline_authenticates_both_reference_artifacts(signed_document, identifier):
    original, roots = signed_document
    doc = deepcopy(original)
    bundle = next(item for item in doc["collateral"] if item["id"] == identifier)["data"]["sigstore_bundle"]
    signature = bytearray(base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"]))
    signature[0] ^= 1
    bundle["dsseEnvelope"]["signatures"][0]["sig"] = sb.b64(signature)
    with pytest.raises(VerificationError):
        verify(doc, roots, ignore_freshness=True)


@pytest.mark.parametrize("change", ["nonce", "repository", "key", "report", "crl", "policy", "report_data_tail", "expired_crl"])
def test_offline_preserves_other_checks(signed_document, change):
    original, roots = signed_document
    doc = deepcopy(original)
    options = {"ignore_freshness": True}
    if change == "nonce":
        options["nonce"] = bytes(env.NONCE_SIZE)
    elif change == "repository":
        options["repo"] = "untrusted/repository"
    elif change == "key":
        material = json.loads(base64.b64decode(doc["crypto_material"]))
        material["items"][0]["data"] = SIGNING_KEY[:-2] + "34"
        doc["crypto_material"] = sb.b64(json.dumps(material).encode())
    elif change == "report":
        report = bytearray(base64.b64decode(doc["cpu_evidence"]["report_base64"]))
        report[sevsynth.SIGNATURE_OFFSET] ^= 1
        doc["cpu_evidence"]["report_base64"] = sb.b64(report)
    elif change == "crl":
        data = next(item for item in doc["collateral"] if item["id"] == "crl")["data"]
        crl = bytearray(base64.b64decode(data["crl_der_base64"]))
        crl[-1] ^= 1
        data["crl_der_base64"] = sb.b64(crl)
    elif change == "expired_crl":
        hardware = sevsynth.build_sev(crl_expired=True)
        data = next(item for item in doc["collateral"] if item["id"] == "crl")["data"]
        data["crl_der_base64"] = sb.b64(hardware["crl_der"])
    else:
        report_data = bytes.fromhex(doc["challenge"]["report_data"])
        if change == "report_data_tail":
            report_data = report_data[:-1] + b"\x01"
        hardware = sevsynth.build_sev(report_data=report_data, vmpl=1 if change == "policy" else 0)
        doc["cpu_evidence"]["report_base64"] = sb.b64(hardware["report"])
    with pytest.raises(VerificationError):
        verify(doc, roots, **options)


def test_public_offline_option_uses_full_verifier(signed_document, monkeypatch):
    doc, roots = signed_document
    verifier = client._verify_document_v3

    def with_test_roots(*args, **kwargs):
        kwargs["verification_time"] = APPRAISAL_TIME + MAX_FRESHNESS_AGE
        return verifier(*args, **kwargs, **roots)

    monkeypatch.setattr(client, "_verify_document_v3", with_test_roots)
    raw = json.dumps(doc).encode()
    with pytest.raises(VerificationError, match="stale"):
        tinfoil.verify_document_v3(raw, NONCE, provenance_cases.REPO)
    verified = tinfoil.verify_document_v3(raw, NONCE, provenance_cases.REPO, ignore_freshness=True)
    assert verified.crypto_material[0].data == SIGNING_KEY
