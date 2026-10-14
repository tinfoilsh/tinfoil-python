"""Public historical appraisal with real signatures and test trust roots."""

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone, tzinfo
import json

import pytest

import tinfoil
from tinfoil.v3 import client, envelope as env
from tinfoil.v3.errors import QUOTE_REJECTED, VerificationError
from tinfoil.v3.provenance import MAX_FRESHNESS_AGE
from tinfoil.v3.tdx.authenticate import tdx_authenticate

from docbuilder import NONCE
import sevsynth
import tdx_material as tdx
import test_provenance as provenance_cases
from test_offline_verification import (
    APPRAISAL_TIME, SIGNING_KEY, no_network, signed_document,
)
from test_tdx_expectations import matching_policy


ONE_SECOND = timedelta(seconds=1)
LATER_TIME = sevsynth.NOT_AFTER + timedelta(days=365)


@pytest.fixture(params=["sev", "tdx"])
def historical_document(request, signed_document):
    doc, roots = deepcopy(signed_document)
    if request.param == "sev":
        return doc, roots, sevsynth.NOT_BEFORE, sevsynth.NOT_AFTER

    chain = tdx.build_synth_chain()
    body = tdx.TdBodyFields(
        report_data=bytes.fromhex(doc["challenge"]["report_data"]),
        rtmr1=bytes.fromhex(provenance_cases.base_predicate()["tdx_measurement"]["rtmr1"]),
        rtmr2=bytes.fromhex(provenance_cases.base_predicate()["tdx_measurement"]["rtmr2"]),
    )
    hardware = json.loads(tdx.tdx_document(
        tdx.build_tdx_quote_v4(chain, body=body), tdx.default_responses(chain),
    ))
    quote = tdx_authenticate(
        env.parse_document(json.dumps(hardware).encode()),
        root_pem=chain.root_ca.pem, now=APPRAISAL_TIME,
    )
    policy = matching_policy(quote)
    policy_name = "tdx-policy"
    artifact = {
        "format": provenance_cases.ARTIFACT_FMT,
        "machines": {quote.identity: policy_name},
        "policies": {policy_name: {"platform": "tdx", "tdx": asdict(policy)}},
        "measurements": {policy.platform_measurements[0]: {
            "mrtd": body.mr_td.hex(), "rtmr0": body.rtmr0.hex(),
            "shape": provenance_cases.base_predicate()["vm_shape"],
        }},
    }
    doc["cpu_evidence"]["format"] = hardware["cpu_evidence"]["format"]
    doc["cpu_evidence"]["report_base64"] = hardware["cpu_evidence"]["report_base64"]
    doc["collateral"] = hardware["collateral"] + [
        item for item in doc["collateral"] if item["role"] == env.ROLE_REFERENCE_VALUES
    ]
    platform = next(item for item in doc["collateral"] if item["id"] == "platform")
    platform["data"]["sigstore_bundle"], _ = provenance_cases.plat_bundle(artifact=artifact)
    roots["intel_root_pem"] = chain.root_ca.pem
    return doc, roots, tdx.NOT_BEFORE, tdx.NOT_AFTER


@pytest.fixture
def public_verify(historical_document, monkeypatch):
    original, roots, _, _ = historical_document
    verifier = client._verify_document_v3

    def with_test_roots(*args, **kwargs):
        return verifier(*args, **kwargs, **roots)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return LATER_TIME.astimezone(tz)

    monkeypatch.setattr(client, "_verify_document_v3", with_test_roots)
    monkeypatch.setattr(client, "datetime", Clock)

    def verify(doc=original, **options):
        return tinfoil.verify_document_v3(
            json.dumps(doc).encode(), NONCE, provenance_cases.REPO, **options,
        )

    return verify


@pytest.mark.parametrize("ignore_freshness", [False, True])
def test_historical_time_accepts_evidence_expired_today(public_verify, ignore_freshness):
    verified = public_verify(
        verification_time=APPRAISAL_TIME, ignore_freshness=ignore_freshness,
    )
    assert verified.code_digest == provenance_cases.DIGEST
    assert verified.code_tag == provenance_cases.TAG
    assert verified.crypto_material[0].data == SIGNING_KEY


def test_default_time_still_rejects_expired_evidence(public_verify):
    for options in ({}, {"verification_time": None}):
        with pytest.raises(VerificationError) as error:
            public_verify(ignore_freshness=True, **options)
        assert error.value.layer == QUOTE_REJECTED


@pytest.mark.parametrize("boundary", ["before", "after"])
def test_historical_time_preserves_validity_windows(public_verify, historical_document, boundary):
    _, _, not_before, not_after = historical_document
    appraisal = not_before - ONE_SECOND if boundary == "before" else not_after + ONE_SECOND
    with pytest.raises(VerificationError) as error:
        public_verify(verification_time=appraisal, ignore_freshness=True)
    assert error.value.layer == QUOTE_REJECTED


def test_historical_time_does_not_implicitly_ignore_freshness(public_verify):
    appraisal = APPRAISAL_TIME + MAX_FRESHNESS_AGE
    with pytest.raises(VerificationError, match="stale"):
        public_verify(verification_time=appraisal)
    verified = public_verify(verification_time=appraisal, ignore_freshness=True)
    assert verified.crypto_material[0].data == SIGNING_KEY


def test_equivalent_timezone_offsets_return_same_facts(public_verify):
    local_time = APPRAISAL_TIME.astimezone(timezone(timedelta(hours=-7)))
    assert public_verify(verification_time=local_time) == public_verify(verification_time=APPRAISAL_TIME)


class UnspecifiedOffset(tzinfo):
    def utcoffset(self, dt):
        return None


@pytest.mark.parametrize("tz", [None, UnspecifiedOffset()])
def test_historical_time_requires_timezone(public_verify, tz):
    with pytest.raises(ValueError, match="verification_time must be timezone-aware"):
        public_verify(verification_time=APPRAISAL_TIME.replace(tzinfo=tz))


def test_historical_time_preserves_key_binding(public_verify, historical_document):
    doc, _, _, _ = historical_document
    doc["challenge"]["report_data"] = "0" * len(doc["challenge"]["report_data"])
    with pytest.raises(VerificationError, match="report_data"):
        public_verify(doc, verification_time=APPRAISAL_TIME, ignore_freshness=True)
