import json
from importlib.metadata import PackageNotFoundError

import pytest
import requests

from tinfoil import _sdkinfo
from tinfoil.attestation import fetch_attestation, fetch_bundle_from
from tinfoil.attestation.types import PredicateType


@pytest.mark.parametrize("mode", ["direct", "bundle_get", "bundle_post"])
@pytest.mark.parametrize("installed_version", ["1.2.3", None])
def test_attestation_requests_report_sdk_version(mode, installed_version, monkeypatch):
    def package_version(package):
        assert package == "tinfoil"
        if installed_version is None:
            raise PackageNotFoundError(package)
        return installed_version

    monkeypatch.setattr(_sdkinfo, "version", package_version)
    report = {"format": PredicateType.SEV_GUEST_V2.value, "body": "Zm9v"}
    bundle = {
        "domain": "enclave.example",
        "enclaveAttestationReport": report,
        "digest": "digest",
        "sigstoreBundle": {},
    }
    sent = []

    def send(session, request, **kwargs):
        sent.append(request)
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(report if mode == "direct" else bundle).encode()
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    if mode == "direct":
        result = fetch_attestation("enclave.example")
        assert result.body == report["body"]
        expected_url = "https://enclave.example/.well-known/tinfoil-attestation"
    else:
        enclave = "enclave.example" if mode == "bundle_post" else ""
        result = fetch_bundle_from("https://atc.example", enclave=enclave)
        assert result.enclave_attestation_report.body == report["body"]
        expected_url = "https://atc.example/attestation"

    assert len(sent) == 1
    request = sent[0]
    assert request.url == expected_url
    assert request.method == ("POST" if mode == "bundle_post" else "GET")
    assert request.headers["Tinfoil-SDK"] == "tinfoil-python"
    assert request.headers["Tinfoil-SDK-Version"] == (installed_version or "unknown")
    assert "Authorization" not in request.headers
    if mode == "bundle_post":
        assert json.loads(request.body) == {"enclaveUrl": "https://enclave.example"}
