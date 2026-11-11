"""The document fetch: its URL, headers, bounds, per-request timeouts and redirect policy."""

from __future__ import annotations

import time
from collections.abc import Iterator

import httpx
import pytest

from tests.v3.client.helpers import Recorder, response
from tinfoil._sdkinfo import SDK_NAME, sdk_version
from tinfoil._v3 import _fetch
from tinfoil._v3._errors import ConfigurationError, NetworkError
from tinfoil._v3._fetch import (
    MAX_DOCUMENT_BYTES,
    MAX_REDIRECTS,
    document_url,
    fetch_document,
    fetch_document_async,
    is_authority,
)
from tinfoil._v3.verifier import NONCE_SIZE

NONCE = bytes(range(NONCE_SIZE))


@pytest.fixture
def mocked(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    recorder = Recorder()
    monkeypatch.setattr(_fetch, "_TRANSPORT", recorder.transport)
    monkeypatch.setattr(_fetch, "_ASYNC_TRANSPORT", recorder.async_transport)
    return recorder


def test_url_forms() -> None:
    nonce = NONCE.hex()
    assert document_url("enclave.example", "", NONCE) == (
        f"https://enclave.example/.well-known/tinfoil-attestation?nonce={nonce}"
    )
    assert document_url("enclave.example", "relay.example:8443", NONCE) == (
        f"https://relay.example:8443/.well-known/tinfoil-attestation?nonce={nonce}&enclave=enclave.example"
    )
    assert document_url("enclave.example:8443", "relay.example", NONCE).endswith("&enclave=enclave.example%3A8443")


@pytest.mark.parametrize(
    "bad",
    [
        "https://enclave.example",
        "enclave.example/path",
        "user@enclave.example",
        "enclave.example:port",
        "enclave.example?x=1",
    ],
)
def test_url_rejects_anything_but_a_host(bad: str) -> None:
    assert not is_authority(bad)
    with pytest.raises(ValueError, match="invalid host"):
        document_url(bad, "", NONCE)
    with pytest.raises(ValueError, match="invalid host"):
        document_url("enclave.example", bad, NONCE)


def test_url_requires_host_and_nonce() -> None:
    with pytest.raises(ValueError, match="host is required"):
        document_url("", "", NONCE)
    with pytest.raises(ValueError, match="nonce must be"):
        document_url("enclave.example", "", NONCE[1:])
    with pytest.raises(ConfigurationError):
        fetch_document("https://enclave.example", "", NONCE)


@pytest.mark.parametrize("relay", [False, True])
def test_fetch_reports_sdk_identity(mocked: Recorder, relay: bool) -> None:
    mocked.handler = lambda _: response(200, b"attestation response")
    if relay:
        body = fetch_document("enclave.example", "relay.example", NONCE)
    else:
        body = fetch_document("enclave.example", "", NONCE)
    assert body == b"attestation response"
    request = mocked.requests[-1]
    assert request.url.path == "/.well-known/tinfoil-attestation"
    assert request.url.params["nonce"] == NONCE.hex()
    assert request.headers["Tinfoil-SDK"] == SDK_NAME
    assert request.headers["Tinfoil-SDK-Version"] == sdk_version()
    assert request.url.host == ("relay.example" if relay else "enclave.example")
    assert request.url.params.get("enclave") == ("enclave.example" if relay else None)


@pytest.mark.asyncio
async def test_fetch_async_reports_sdk_identity(mocked: Recorder) -> None:
    mocked.handler = lambda _: response(200, b"doc")
    assert await fetch_document_async("enclave.example", "relay.example", NONCE) == b"doc"
    request = mocked.requests[-1]
    assert request.headers["Tinfoil-SDK"] == SDK_NAME
    assert request.url.params["enclave"] == "enclave.example"


@pytest.mark.parametrize("size", [MAX_DOCUMENT_BYTES, MAX_DOCUMENT_BYTES + 1])
def test_fetch_size_limit_and_redirects(mocked: Recorder, size: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/redirect":
            return response(302, headers={"Location": "/redirect"})
        return response(200, b"x" * size)

    mocked.handler = handler
    if size > MAX_DOCUMENT_BYTES:
        with pytest.raises(NetworkError, match="exceeds 33554432 bytes"):
            fetch_document("enclave.example", "", NONCE)
    else:
        assert len(fetch_document("enclave.example", "", NONCE)) == size
    assert [r.url.path for r in mocked.requests].count("/.well-known/tinfoil-attestation") == 1


def test_fetch_rejects_non_https_redirect(mocked: Recorder) -> None:
    schemes: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        schemes.append(request.url.scheme)
        if request.url.scheme != "https":
            return response(200, b"plaintext document")
        return response(302, headers={"Location": "http://user:pw@enclave.example/redirect"})

    mocked.handler = handler
    with pytest.raises(NetworkError, match="refusing redirect to non-HTTPS URL") as err:
        fetch_document("enclave.example", "", NONCE)
    assert "pw" not in str(err.value)
    assert schemes == ["https"]


def test_fetch_rejects_a_redirect_with_user_information(mocked: Recorder) -> None:
    hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        if request.url.host == "mirror.example":
            return response(200, b"document from the credentialed mirror")
        return response(302, headers={"Location": "https://user:hunter2@mirror.example/doc"})

    mocked.handler = handler
    with pytest.raises(NetworkError, match="refusing redirect to a URL with user information") as err:
        fetch_document("enclave.example", "", NONCE)
    assert "hunter2" not in str(err.value)
    assert "user" not in str(err.value).replace("user information", "")
    assert hosts == ["enclave.example"], "the redirect is refused before it is followed"


def test_fetch_recomputes_each_requests_timeouts_from_the_time_left(mocked: Recorder) -> None:
    reads: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        reads.append(request.extensions["timeout"]["read"])
        if len(reads) < 3:
            time.sleep(0.05)
            return response(302, headers={"Location": f"/hop{len(reads)}"})
        return response(200, b"doc")

    mocked.handler = handler
    assert fetch_document("enclave.example", "", NONCE, timeout=None, deadline=time.monotonic() + 1.0) == b"doc"
    assert len(reads) == 3
    assert reads[0] <= 1.0
    assert reads[0] > reads[1] > reads[2], "each redirect's request gets only the time that is left"


class Trickle(httpx.SyncByteStream):
    """A body whose chunks arrive slowly, so a deadline passes while it is read."""

    def __iter__(self) -> Iterator[bytes]:
        for _ in range(10):
            time.sleep(0.03)
            yield b"x"


def test_fetch_stops_a_trickling_body_at_the_deadline(mocked: Recorder) -> None:
    mocked.handler = lambda _: httpx.Response(200, stream=Trickle())
    start = time.monotonic()
    with pytest.raises(NetworkError, match="no complete response"):
        fetch_document("enclave.example", "", NONCE, timeout=None, deadline=start + 0.1)
    assert time.monotonic() - start < 0.25, "the read is abandoned at the deadline, not at the body's end"


def test_fetch_keeps_the_redirect_limit(mocked: Recorder) -> None:
    mocked.handler = lambda _: response(302, headers={"Location": "/loop"})
    with pytest.raises(NetworkError, match=f"stopped after {MAX_REDIRECTS} redirects"):
        fetch_document("enclave.example", "", NONCE)
    assert len(mocked.requests) == MAX_REDIRECTS


def test_fetch_reports_http_errors_as_network_errors(mocked: Recorder) -> None:
    mocked.handler = lambda _: response(503, b"down")
    with pytest.raises(NetworkError, match="503"):
        fetch_document("enclave.example", "", NONCE)
    mocked.handler = lambda _: (_ for _ in ()).throw(httpx.ConnectError("refused"))
    with pytest.raises(NetworkError, match="refused") as err:
        fetch_document("enclave.example", "", NONCE)
    assert isinstance(err.value.__cause__, httpx.ConnectError)


def test_fetch_honors_the_caller_deadline(mocked: Recorder) -> None:
    mocked.handler = lambda _: response(200, b"doc")
    with pytest.raises(NetworkError, match="no complete response"):
        fetch_document("enclave.example", "", NONCE, deadline=time.monotonic() - 1)
    assert mocked.requests == [], "a passed deadline sends nothing"


def test_fetch_caps_each_operation_at_the_time_left() -> None:
    bound = _fetch._Deadline(30.0, time.monotonic() + 2.0)
    capped = bound.timeout(httpx.Timeout(None))
    assert capped.connect is not None
    assert capped.connect <= 2.0
    capped = bound.timeout(1.0)
    assert capped.read == 1.0
