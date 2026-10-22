"""Seams for the conformance adapter. Never use them in production.

Each function here removes a guarantee verification relies on. An injected
root means evidence or reference values no longer have to chain to AMD,
Intel or Tinfoil's release workflows. Decoding without a nonce skips the
challenge binding that stops a replayed document. Go compiles its
equivalents only into its conformance build; Python has no build tags, so
they live in this private module, which nothing in the SDK imports.
"""

from __future__ import annotations

from typing import Any

from . import _provenance, _quote
from . import document as _document
from ._errors import as_usage_error
from ._verifier import Verifier


def verifier(
    *,
    sigstore_trusted_root: bytes | None = None,
    amd_root_pem: bytes | None = None,
    intel_root_pem: bytes | None = None,
    **options: Any,
) -> Verifier:
    """A Verifier that trusts the supplied roots in place of the embedded ones.

    ``amd_root_pem`` is the ASK then ARK, PEM-encoded. A None root keeps the
    embedded anchor. ``options`` are the Verifier's keyword arguments.
    """
    with as_usage_error():
        releases = (
            _provenance.ReleaseVerifier(sigstore_trusted_root)
            if sigstore_trusted_root is not None
            else _provenance.ReleaseVerifier.embedded()
        )
    instance = object.__new__(Verifier)
    instance._configure(releases, _quote.VendorRoots(amd=amd_root_pem, intel=intel_root_pem), **options)
    return instance


def decode_document(data: bytes) -> _document.Document:
    """Apply parse()'s structural rules without binding the challenge to a nonce.

    The result has no expected REPORT_DATA, so policy assembly rejects it.
    """
    return _document._decode(data)
