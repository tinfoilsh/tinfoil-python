"""
Tests for long-lived client support: automatic re-verification of enclave
attestation when the server's TLS certificate rotates (for example, after
a router restart).
"""

import ssl
import threading
from unittest.mock import MagicMock, patch

import httpx
import pytest

from tinfoil.client import (
    GroundTruth,
    SecureClient,
    _AsyncReVerifyingTransport,
    _PinMismatchError,
    _ReVerifyingTransport,
    _is_certificate_error,
)


class TestIsCertificateError:
    def test_detects_pin_mismatch_error(self):
        err = _PinMismatchError("Certificate fingerprint mismatch: expected abc, got def")
        assert _is_certificate_error(err)

    def test_detects_pin_mismatch_no_certificate(self):
        err = _PinMismatchError("No certificate found")
        assert _is_certificate_error(err)

    def test_detects_pin_mismatch_no_tls_connection(self):
        err = _PinMismatchError("No TLS connection")
        assert _is_certificate_error(err)

    def test_detects_ssl_cert_verification_error(self):
        err = ssl.SSLCertVerificationError("bad cert")
        assert _is_certificate_error(err)

    def test_detects_certificate_verify_failed_ssl_error(self):
        err = ssl.SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        assert _is_certificate_error(err)

    def test_detects_through_cause_chain(self):
        original = _PinMismatchError("Certificate fingerprint mismatch: ...")
        wrapper = httpx.ConnectError("connection error")
        wrapper.__cause__ = original
        assert _is_certificate_error(wrapper)

    def test_detects_through_context_chain(self):
        original = _PinMismatchError("Certificate fingerprint mismatch: ...")
        try:
            try:
                raise original
            except _PinMismatchError:
                raise httpx.ConnectError("wrapped")
        except httpx.ConnectError as wrapped:
            assert _is_certificate_error(wrapped)

    def test_ignores_plain_value_error_with_matching_text(self):
        # A plain ValueError with cert-looking text should NOT trigger
        # re-verification — detection is type-based, not string-based.
        err = ValueError("Certificate fingerprint mismatch: expected abc, got def")
        assert not _is_certificate_error(err)

    def test_ignores_unrelated_value_error(self):
        err = ValueError("Something completely different")
        assert not _is_certificate_error(err)

    def test_ignores_unrelated_exception(self):
        err = RuntimeError("Unrelated")
        assert not _is_certificate_error(err)

    def test_ignores_generic_ssl_error(self):
        err = ssl.SSLError("unexpected eof while reading")
        assert not _is_certificate_error(err)

    def test_ignores_ssl_want_read_error(self):
        err = ssl.SSLWantReadError()
        assert not _is_certificate_error(err)


def _make_request() -> httpx.Request:
    return httpx.Request("GET", "https://example.test/")


def _make_response() -> httpx.Response:
    return httpx.Response(200, content=b"ok")


class TestReVerifyingTransportSync:
    def test_passes_through_when_no_error(self):
        secure_client = MagicMock(spec=SecureClient)
        inner = MagicMock(spec=httpx.BaseTransport)
        response = _make_response()
        inner.handle_request.return_value = response

        transport = _ReVerifyingTransport(secure_client, inner)

        result = transport.handle_request(_make_request())
        assert result is response
        secure_client._rebuild_sync_transport.assert_not_called()

    def test_propagates_unrelated_errors(self):
        secure_client = MagicMock(spec=SecureClient)
        inner = MagicMock(spec=httpx.BaseTransport)
        inner.handle_request.side_effect = RuntimeError("boom")

        transport = _ReVerifyingTransport(secure_client, inner)

        with pytest.raises(RuntimeError, match="boom"):
            transport.handle_request(_make_request())
        secure_client._rebuild_sync_transport.assert_not_called()

    def test_propagates_generic_ssl_errors(self):
        secure_client = MagicMock(spec=SecureClient)
        inner = MagicMock(spec=httpx.BaseTransport)
        inner.handle_request.side_effect = ssl.SSLError("unexpected eof while reading")

        transport = _ReVerifyingTransport(secure_client, inner)

        with pytest.raises(ssl.SSLError, match="unexpected eof"):
            transport.handle_request(_make_request())
        secure_client._rebuild_sync_transport.assert_not_called()

    def test_reverifies_and_retries_on_fingerprint_mismatch(self):
        secure_client = MagicMock(spec=SecureClient)
        new_inner = MagicMock(spec=httpx.BaseTransport)
        retry_response = _make_response()
        new_inner.handle_request.return_value = retry_response
        secure_client._rebuild_sync_transport.return_value = new_inner

        inner = MagicMock(spec=httpx.BaseTransport)
        inner.handle_request.side_effect = _PinMismatchError(
            "Certificate fingerprint mismatch: expected abc, got def"
        )

        transport = _ReVerifyingTransport(secure_client, inner)

        result = transport.handle_request(_make_request())
        assert result is retry_response
        secure_client._rebuild_sync_transport.assert_called_once()
        new_inner.handle_request.assert_called_once()
        inner.close.assert_called_once()

    def test_reverifies_through_httpx_connect_error_chain(self):
        secure_client = MagicMock(spec=SecureClient)
        new_inner = MagicMock(spec=httpx.BaseTransport)
        new_inner.handle_request.return_value = _make_response()
        secure_client._rebuild_sync_transport.return_value = new_inner

        inner = MagicMock(spec=httpx.BaseTransport)

        def raise_wrapped(_req):
            try:
                raise _PinMismatchError("Certificate fingerprint mismatch: ...")
            except _PinMismatchError:
                raise httpx.ConnectError("connect error")

        inner.handle_request.side_effect = raise_wrapped

        transport = _ReVerifyingTransport(secure_client, inner)
        transport.handle_request(_make_request())
        secure_client._rebuild_sync_transport.assert_called_once()

    def test_raises_original_error_when_reverification_fails(self):
        secure_client = MagicMock(spec=SecureClient)
        secure_client._rebuild_sync_transport.side_effect = RuntimeError(
            "verify failed"
        )

        original_err = _PinMismatchError("Certificate fingerprint mismatch: ...")
        inner = MagicMock(spec=httpx.BaseTransport)
        inner.handle_request.side_effect = original_err

        transport = _ReVerifyingTransport(secure_client, inner)

        with pytest.raises(_PinMismatchError, match="Certificate fingerprint mismatch"):
            transport.handle_request(_make_request())
        inner.close.assert_not_called()

    def test_retries_exactly_once_when_rebuilt_transport_also_fails(self):
        # If re-verification succeeds but the new transport also raises a cert
        # error (e.g. the server didn't actually rotate, or rotated to a key
        # the verifier doesn't yet see), the second error must propagate —
        # no infinite retry loop.
        secure_client = MagicMock(spec=SecureClient)
        new_inner = MagicMock(spec=httpx.BaseTransport)
        new_inner.handle_request.side_effect = _PinMismatchError(
            "Certificate fingerprint mismatch: still wrong"
        )
        secure_client._rebuild_sync_transport.return_value = new_inner

        inner = MagicMock(spec=httpx.BaseTransport)
        inner.handle_request.side_effect = _PinMismatchError(
            "Certificate fingerprint mismatch: initial"
        )

        transport = _ReVerifyingTransport(secure_client, inner)

        with pytest.raises(_PinMismatchError, match="still wrong"):
            transport.handle_request(_make_request())

        secure_client._rebuild_sync_transport.assert_called_once()
        inner.handle_request.assert_called_once()
        new_inner.handle_request.assert_called_once()


class TestReVerifyingTransportAsync:
    @pytest.mark.asyncio
    async def test_passes_through_when_no_error(self):
        secure_client = MagicMock(spec=SecureClient)
        inner = MagicMock(spec=httpx.AsyncBaseTransport)
        response = _make_response()

        async def ok(_req):
            return response

        inner.handle_async_request.side_effect = ok

        transport = _AsyncReVerifyingTransport(secure_client, inner)

        result = await transport.handle_async_request(_make_request())
        assert result is response

    @pytest.mark.asyncio
    async def test_reverifies_and_retries_on_fingerprint_mismatch(self):
        secure_client = MagicMock(spec=SecureClient)
        new_inner = MagicMock(spec=httpx.AsyncBaseTransport)
        retry_response = _make_response()

        async def retry_ok(_req):
            return retry_response

        new_inner.handle_async_request.side_effect = retry_ok
        secure_client._rebuild_async_transport.return_value = new_inner

        inner = MagicMock(spec=httpx.AsyncBaseTransport)

        async def fail(_req):
            raise _PinMismatchError("Certificate fingerprint mismatch: expected abc, got def")

        inner.handle_async_request.side_effect = fail

        transport = _AsyncReVerifyingTransport(secure_client, inner)
        result = await transport.handle_async_request(_make_request())
        assert result is retry_response
        secure_client._rebuild_async_transport.assert_awaited_once()
        inner.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_raises_original_error_when_reverification_fails(self):
        secure_client = MagicMock(spec=SecureClient)
        secure_client._rebuild_async_transport.side_effect = RuntimeError(
            "verify failed"
        )

        original_err = _PinMismatchError("Certificate fingerprint mismatch: ...")

        async def fail(_req):
            raise original_err

        inner = MagicMock(spec=httpx.AsyncBaseTransport)
        inner.handle_async_request.side_effect = fail

        transport = _AsyncReVerifyingTransport(secure_client, inner)

        with pytest.raises(_PinMismatchError, match="Certificate fingerprint mismatch"):
            await transport.handle_async_request(_make_request())
        inner.aclose.assert_not_called()


class TestSecureClientRebuildHooks:
    """Make sure the rebuild hooks actually re-run verify() with a fresh fingerprint."""

    @patch.object(SecureClient, "verify")
    def test_rebuild_sync_transport_calls_verify(self, mock_verify):
        mock_verify.return_value = GroundTruth(
            public_key="a" * 64, digest="d", measurement="m"
        )
        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")
        transport = client._rebuild_sync_transport()
        assert isinstance(transport, httpx.HTTPTransport)
        mock_verify.assert_called_once()

    @pytest.mark.asyncio
    @patch.object(SecureClient, "verify")
    async def test_rebuild_async_transport_offloads_verify(self, mock_verify):
        loop_thread_id = threading.get_ident()
        verify_thread_id = None

        def fake_verify():
            nonlocal verify_thread_id
            verify_thread_id = threading.get_ident()
            return GroundTruth(public_key="a" * 64, digest="d", measurement="m")

        mock_verify.side_effect = fake_verify
        client = SecureClient(enclave="test.enclave.sh", repo="test/repo")
        transport = await client._rebuild_async_transport()
        assert isinstance(transport, httpx.AsyncHTTPTransport)
        mock_verify.assert_called_once()
        assert verify_thread_id is not None
        assert verify_thread_id != loop_thread_id
