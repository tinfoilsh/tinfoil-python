#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["tuf>=6,<8", "cryptography>=43", "certifi>=2025.1.31"]
# ///
"""Regenerate the verifier's embedded trust material from its authoritative sources.

    uv run scripts/sync_trust.py [--allow-root-change]

Downloads the AMD Genoa and Turin certificate chains from the AMD KDS, the
Intel SGX Provisioning Certification Root CA from Intel, and the Sigstore
trusted root through a TUF client bootstrapped from a pinned root of the
Sigstore repository (SHA-256 below), then writes them as Python
constants under ``src/tinfoil/verifier/_trust/``. The Tinfoil release
signing key has no vendor download; it is a hand-maintained constant in this
script, pinned by its SHA-256.

Every source is fetched and checked before anything is written, the modules
are staged beside the committed ones, and each staged file is moved onto its
target only after every render succeeded; a move that fails restores the
targets already replaced, so the constants are replaced as a set or not at
all. Checks before writing:

- no socket operation of a download (the connection, or a wait for data)
  stalls longer than ``TIMEOUT_SECONDS``, for the direct downloads and for
  the TUF client's fetches alike, and every body is non-empty; a transfer
  that keeps delivering data is not bounded as a whole;
- the bootstrap TUF root has the pinned SHA-256, and the trusted root is JSON
  with the expected media type and every authority kind present, and the
  verifier's own strict parser accepts it, run in the project environment;
- each PEM holds exactly the expected certificates: the AMD chains the ASK
  then the ARK, with the ASK signed by the ARK and the ARK self-signed; the
  Intel file one self-signed root;
- the signing key has the pinned SHA-256 and loads as an ECDSA P-256 key;
- a self-signed root that differs from the committed one is refused unless
  ``--allow-root-change`` is passed, so a root never changes by accident.

Dev tooling, not part of the published package; the dependencies above are
resolved for this script alone and do not touch the project lockfile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from tuf.ngclient import Updater, Urllib3Fetcher

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUST_DIR = REPO_ROOT / "src" / "tinfoil" / "verifier" / "_trust"

TIMEOUT_SECONDS = 60
"""The bound on one socket operation, the connection or one wait for data, of every download: the direct ones and,
through its fetcher, the TUF client's. No transfer is bounded as a whole."""

PARSE_TRUSTED_ROOT = (
    "import sys\n"
    "from tinfoil.verifier._sigstore.trusted_root import parse_trusted_root\n"
    "parse_trusted_root(sys.stdin.buffer.read())\n"
)
"""Runs in the project environment, which holds the package and its dependencies; this script resolves only its
own."""

TRUSTED_ROOT_MEDIA_TYPE = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

AMD_GENOA_URL = "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
AMD_TURIN_URL = "https://kdsintf.amd.com/vcek/v1/Turin/cert_chain"
INTEL_SGX_ROOT_URL = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"

SIGSTORE_TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
SIGSTORE_TUF_INITIAL_ROOT_URL = f"{SIGSTORE_TUF_URL}/5.root.json"
SIGSTORE_TUF_INITIAL_ROOT_SHA256 = "e2a930b2d1d4053dd56e8faf66fd113658545d522e35d222ccf58fea87ccccf4"
"""The root the TUF client is bootstrapped from; a different hash is a loud failure, never accepted.

Roots 1 to 3 of the Sigstore public-good repository carry expiry times with fractional seconds or a UTC offset,
which the TUF client rejects, and root 4 names its keys by a legacy key-id scheme that the client cannot match
against the signatures on root 5, so version 5 (the earliest from which the update chain verifies) is the pinned
starting point; the client then verifies every later root and the target against it.
"""
SIGSTORE_TRUSTED_ROOT_TARGET = "trusted_root.json"

# The Tinfoil release signing key authenticates registry issuers, legacy public
# configs and artifact freshness approvals. It is published out of band, not
# downloadable, so it is maintained here by hand; rotating it means updating
# both the PEM and its SHA-256.
TINFOIL_SIGNING_KEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcadRPBdmNf1LPWYcY9AZ2Crrqxsy
nqzLE7k3kahjPxIM42bgZbze0GnT/EmGqe1w6So5AhmXci8By8Azt8gAhw==
-----END PUBLIC KEY-----
"""
TINFOIL_SIGNING_KEY_SHA256 = "7ff8acb6c54d0f969f53ba26ebef9200c3506bb9d45480b7d79be8170c1dbeb7"


class SyncError(Exception):
    """A source that cannot be used; nothing is written."""


@dataclass(frozen=True)
class Source:
    """Fetched bytes and their provenance, as recorded in the generated module header."""

    url: str
    content: bytes
    fetched_at: datetime

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


def fetch(url: str) -> Source:
    """Download ``url``; a socket operation that stalls past the timeout, an empty body or any transport error is
    a SyncError."""
    fetched_at = datetime.now(UTC)
    # The interpreter that runs this script may have no system trust store; the
    # Mozilla bundle that certifi ships verifies the vendors' TLS certificates.
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS, context=context) as response:  # noqa: S310
            content = response.read()
    except OSError as err:
        raise SyncError(f"{url}: {err}") from err
    if not content:
        raise SyncError(f"{url}: empty response")
    return Source(url, content, fetched_at)


def fetch_sigstore_trusted_root(workdir: Path) -> Source:
    """Fetch ``trusted_root.json`` through a TUF client bootstrapped from the pinned initial root."""
    initial_root = fetch(SIGSTORE_TUF_INITIAL_ROOT_URL)
    if initial_root.sha256 != SIGSTORE_TUF_INITIAL_ROOT_SHA256:
        raise SyncError(
            f"{SIGSTORE_TUF_INITIAL_ROOT_URL}: SHA-256 {initial_root.sha256} does not match the pinned "
            f"{SIGSTORE_TUF_INITIAL_ROOT_SHA256}"
        )
    metadata_dir = workdir / "tuf-metadata"
    targets_dir = workdir / "tuf-targets"
    metadata_dir.mkdir()
    targets_dir.mkdir()
    fetched_at = datetime.now(UTC)
    try:
        updater = Updater(
            metadata_dir=str(metadata_dir),
            metadata_base_url=SIGSTORE_TUF_URL,
            target_dir=str(targets_dir),
            target_base_url=f"{SIGSTORE_TUF_URL}/targets",
            fetcher=Urllib3Fetcher(socket_timeout=TIMEOUT_SECONDS),
            bootstrap=initial_root.content,
        )
        updater.refresh()
        info = updater.get_targetinfo(SIGSTORE_TRUSTED_ROOT_TARGET)
        if info is None:
            raise SyncError(f"TUF repository has no target {SIGSTORE_TRUSTED_ROOT_TARGET!r}")
        path = updater.download_target(info)
    except SyncError:
        raise
    except Exception as err:  # the TUF client raises its own hierarchy; every failure stops the sync
        raise SyncError(f"TUF update of {SIGSTORE_TRUSTED_ROOT_TARGET}: {err}") from err
    content = Path(path).read_bytes()
    if not content:
        raise SyncError(f"TUF target {SIGSTORE_TRUSTED_ROOT_TARGET} is empty")
    return Source(f"{SIGSTORE_TUF_URL} target {SIGSTORE_TRUSTED_ROOT_TARGET}", content, fetched_at)


def check_trusted_root(source: Source) -> None:
    """The quick shape checks, then the verifier's own strict parser, so that a root it would reject is never
    committed."""
    try:
        root = json.loads(source.content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise SyncError(f"{source.url}: not JSON: {err}") from err
    if not isinstance(root, dict) or root.get("mediaType") != TRUSTED_ROOT_MEDIA_TYPE:
        raise SyncError(f"{source.url}: not a Sigstore trusted root")
    for member in ("tlogs", "ctlogs", "certificateAuthorities", "timestampAuthorities"):
        if not root.get(member):
            raise SyncError(f"{source.url}: no {member}")
    uv = shutil.which("uv")
    if uv is None:
        raise SyncError(f"{source.url}: uv is needed to run the verifier's trusted-root parser and was not found")
    try:
        result = subprocess.run(
            [uv, "run", "--directory", str(REPO_ROOT), "python", "-c", PARSE_TRUSTED_ROOT],
            input=source.content,
            capture_output=True,
            check=False,
        )
    except OSError as err:
        raise SyncError(f"{source.url}: cannot run the verifier's trusted-root parser: {err}") from err
    if result.returncode != 0:
        lines = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        detail = lines[-1] if lines else f"exit status {result.returncode}"
        raise SyncError(f"{source.url}: the verifier rejects the trusted root: {detail}")


def load_certificates(source: Source, count: int) -> list[x509.Certificate]:
    try:
        certificates = x509.load_pem_x509_certificates(source.content)
    except ValueError as err:
        raise SyncError(f"{source.url}: {err}") from err
    if len(certificates) != count:
        raise SyncError(f"{source.url}: want {count} certificates, got {len(certificates)}")
    return certificates


def check_issued_by(subject: x509.Certificate, issuer: x509.Certificate, what: str) -> None:
    try:
        subject.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature) as err:
        raise SyncError(f"{what}: {err}") from err


def check_amd_chain(source: Source, product: str) -> None:
    ask, ark = load_certificates(source, 2)
    check_issued_by(ark, ark, f"{source.url}: ARK is not self-signed")
    check_issued_by(ask, ark, f"{source.url}: ASK is not signed by the ARK")
    for certificate, want in ((ask, f"SEV-{product}"), (ark, f"ARK-{product}")):
        cn = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if len(cn) != 1 or cn[0].value != want:
            raise SyncError(f"{source.url}: want common name {want!r}")


def check_intel_root(source: Source) -> None:
    (root,) = load_certificates(source, 1)
    check_issued_by(root, root, f"{source.url}: root is not self-signed")
    cn = root.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(cn) != 1 or cn[0].value != "Intel SGX Root CA":
        raise SyncError(f"{source.url}: unexpected common name")


def signing_key_source() -> Source:
    """The hand-maintained signing key, checked against its pin and loaded as an ECDSA P-256 key."""
    content = TINFOIL_SIGNING_KEY_PEM.encode("ascii")
    digest = hashlib.sha256(content).hexdigest()
    if digest != TINFOIL_SIGNING_KEY_SHA256:
        raise SyncError(f"signing key: SHA-256 {digest} does not match the pinned {TINFOIL_SIGNING_KEY_SHA256}")
    key = serialization.load_pem_public_key(content)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SyncError("signing key is not ECDSA P-256")
    return Source(
        "hand-maintained constant TINFOIL_SIGNING_KEY_PEM in scripts/sync_trust.py", content, datetime.now(UTC)
    )


def self_signed_spkis(pem: bytes) -> set[bytes]:
    """The SPKIs of the self-signed certificates in a PEM bundle."""
    roots: set[bytes] = set()
    for certificate in x509.load_pem_x509_certificates(pem):
        try:
            certificate.verify_directly_issued_by(certificate)
        except (ValueError, TypeError, InvalidSignature):
            continue
        roots.add(
            certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    return roots


def committed_roots(module: Path) -> set[bytes]:
    """The SPKIs of the self-signed roots in a committed PEM module, or none."""
    if not module.exists():
        return set()
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", module.read_text(), re.DOTALL)
    return self_signed_spkis("\n".join(blocks).encode("ascii")) if blocks else set()


def check_root_change(module: Path, source: Source, allow: bool) -> None:
    before = committed_roots(module)
    after = self_signed_spkis(source.content)
    if before and before != after and not allow:
        raise SyncError(f"{module.name}: the self-signed root changed; pass --allow-root-change to accept it")


def header(source: Source, *, long_lines: bool) -> str:
    lines = [
        '"""Generated by scripts/sync_trust.py. Do not edit.',
        "",
        f"Source: {source.url}",
        f"Fetched: {source.fetched_at.replace(microsecond=0).isoformat()}",
        f"SHA-256 of the fetched bytes: {source.sha256}",
        "CRLF line endings in the source are written as LF.",
        '"""',
        "",
    ]
    if long_lines:
        # Base64 lines in the source are longer than the project's line length.
        lines.insert(0, "# ruff: noqa: E501")
    lines.append("from __future__ import annotations")
    lines.append("")
    return "\n".join(lines)


def bytes_literal(name: str, content: bytes, doc: str) -> str:
    # The Intel root is distributed with CRLF line endings; the constant keeps
    # LF so that the module is stable under the formatter. PEM decoding
    # accepts either, and the header records the hash of the original bytes.
    text = content.decode("ascii").replace("\r\n", "\n")
    if '"""' in text or text.endswith('"') or "\\" in text:
        raise SyncError(f"{name}: content cannot be written as a triple-quoted literal")
    if not text.endswith("\n"):
        raise SyncError(f"{name}: content must end with a newline")
    return f'{name} = b"""\\\n{text}"""\n"""{doc}"""\n'


def render_bytes_module(source: Source, name: str, doc: str, *, long_lines: bool = False) -> str:
    return header(source, long_lines=long_lines) + "\n" + bytes_literal(name, source.content, doc)


def render_keys_module(source: Source) -> str:
    key = source.content.decode("ascii").rstrip("\n")
    body = f'PUBLIC_SIGNING_KEYS_PEM: tuple[str, ...] = (\n    """\\\n{key}\n""",\n)\n'
    body += (
        '"""The PEM public keys that authenticate registry issuers, legacy public configs and artifact approvals."""\n'
    )
    return header(source, long_lines=False) + "\n" + body


INIT_MODULE = '''"""The trust anchors that the verifier ships: generated constants, never fetched at run time.

Regenerate with ``uv run scripts/sync_trust.py``.
"""

from tinfoil.verifier._trust.amd_genoa import AMD_GENOA_CERT_CHAIN_PEM
from tinfoil.verifier._trust.amd_turin import AMD_TURIN_CERT_CHAIN_PEM
from tinfoil.verifier._trust.intel_sgx_root import INTEL_SGX_ROOT_CA_PEM
from tinfoil.verifier._trust.signing_keys import PUBLIC_SIGNING_KEYS_PEM
from tinfoil.verifier._trust.sigstore_root import SIGSTORE_TRUSTED_ROOT_JSON

__all__ = [
    "AMD_GENOA_CERT_CHAIN_PEM",
    "AMD_TURIN_CERT_CHAIN_PEM",
    "INTEL_SGX_ROOT_CA_PEM",
    "PUBLIC_SIGNING_KEYS_PEM",
    "SIGSTORE_TRUSTED_ROOT_JSON",
]
'''


def render_all(workdir: Path, allow_root_change: bool) -> dict[str, str]:
    """Fetch and check every source; return the module texts to write."""
    sigstore_root = fetch_sigstore_trusted_root(workdir)
    amd_genoa = fetch(AMD_GENOA_URL)
    amd_turin = fetch(AMD_TURIN_URL)
    intel_root = fetch(INTEL_SGX_ROOT_URL)
    signing_key = signing_key_source()

    check_trusted_root(sigstore_root)
    check_amd_chain(amd_genoa, "Genoa")
    check_amd_chain(amd_turin, "Turin")
    check_intel_root(intel_root)

    check_root_change(TRUST_DIR / "amd_genoa.py", amd_genoa, allow_root_change)
    check_root_change(TRUST_DIR / "amd_turin.py", amd_turin, allow_root_change)
    check_root_change(TRUST_DIR / "intel_sgx_root.py", intel_root, allow_root_change)

    return {
        "sigstore_root.py": render_bytes_module(
            sigstore_root,
            "SIGSTORE_TRUSTED_ROOT_JSON",
            "The Sigstore trusted root: Fulcio, Rekor, CT log and timestamp authority material.",
            long_lines=True,
        ),
        "amd_genoa.py": render_bytes_module(
            amd_genoa, "AMD_GENOA_CERT_CHAIN_PEM", "The AMD Genoa ASK then ARK certificates."
        ),
        "amd_turin.py": render_bytes_module(
            amd_turin, "AMD_TURIN_CERT_CHAIN_PEM", "The AMD Turin ASK then ARK certificates."
        ),
        "intel_sgx_root.py": render_bytes_module(
            intel_root, "INTEL_SGX_ROOT_CA_PEM", "The Intel SGX Provisioning Certification Root CA."
        ),
        "signing_keys.py": render_keys_module(signing_key),
        "__init__.py": INIT_MODULE,
    }


def commit_modules(outputs: dict[str, str], target: Path) -> None:
    """Replace the modules under ``target`` with ``outputs``, as a set or not at all.

    Every module is first written to a staged file beside its target, on
    the same filesystem, so that each swap is one ``os.replace``. The staged
    file takes the target's current permission bits, or 0644 for a new
    module, since ``mkstemp`` creates it readable by its owner only. The
    swaps run only once every file is staged; if one fails, the targets
    already swapped are restored from their original contents and the
    remaining staged files are removed.
    """
    target.mkdir(parents=True, exist_ok=True)
    staged: dict[str, Path] = {}
    originals: dict[str, bytes | None] = {}
    try:
        for name, text in outputs.items():
            final = target / name
            originals[name] = final.read_bytes() if final.is_file() else None
            mode = final.stat().st_mode & 0o777 if final.exists() else 0o644
            descriptor, path = tempfile.mkstemp(prefix=f".{name}.", suffix=".staged", dir=target)
            # Registered before the write so that a failed write still has its staged file removed.
            staged[name] = Path(path)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                os.fchmod(descriptor, mode)
                handle.write(text)
    except OSError as err:
        _discard(staged.values())
        raise SyncError(f"staging modules under {target}: {err}") from err
    swapped: list[str] = []
    try:
        for name, path in staged.items():
            os.replace(path, target / name)
            swapped.append(name)
    except OSError as err:
        for name in swapped:
            original = originals[name]
            if original is None:
                (target / name).unlink(missing_ok=True)
            else:
                (target / name).write_bytes(original)
        _discard(path for name, path in staged.items() if name not in swapped)
        raise SyncError(f"replacing modules under {target}: {err}; the originals were restored") from err


def _discard(paths: Iterable[Path]) -> None:
    for path in paths:
        path.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--allow-root-change", action="store_true", help="accept a self-signed root that differs")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="sync_trust-") as tmp:
        try:
            outputs = render_all(Path(tmp), args.allow_root_change)
            commit_modules(outputs, TRUST_DIR)
        except SyncError as err:
            print(f"sync_trust: {err}", file=sys.stderr)
            return 1
    for name in outputs:
        print(f"wrote {TRUST_DIR / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
