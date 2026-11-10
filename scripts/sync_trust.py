#!/usr/bin/env python3
"""Regenerate the verifier's embedded trust material from a tinfoil-go checkout.

    uv run python scripts/sync_trust.py <path-to-tinfoil-go-checkout> [--allow-root-change]

Reads the files that the Go verifier embeds (the Sigstore trusted root, the
AMD Genoa and Turin certificate chains, the Intel SGX root and the release
signing keys) and writes them as Python constants under
``src/tinfoil/_v3/verifier/_trust/``. Every source is read and checked before
anything is written, so a failure leaves the committed constants untouched.

Checks before writing:

- every source path exists, is a regular file or a symlink to one (a dangling
  symlink is an error, not an absence), and reads without error;
- the trusted root is JSON with the expected media type;
- each PEM file holds exactly the expected certificates: the AMD chains the
  ASK then the ARK, with the ASK signed by the ARK and the ARK self-signed;
  the Intel file one self-signed root;
- each signing key loads as an ECDSA P-256 public key;
- a self-signed root that differs from the committed one is refused unless
  ``--allow-root-change`` is passed, so a root never changes by accident.

Dev tooling, not part of the published package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUST_DIR = REPO_ROOT / "src" / "tinfoil" / "_v3" / "verifier" / "_trust"

TRUSTED_ROOT_MEDIA_TYPE = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

# Relative to the Go checkout.
SIGSTORE_ROOT_SOURCE = "verify/internal/endorsement/trusted_root.json"
AMD_GENOA_SOURCE = "verify/internal/quote/sev/genoa_cert_chain.pem"
AMD_TURIN_SOURCE = "verify/internal/quote/sev/turin_cert_chain.pem"
INTEL_SGX_ROOT_SOURCE = "verify/internal/quote/tdx/sgx_root_ca.pem"
SIGNING_KEYS_SOURCE = "verify/internal/endorsement/signing_keys.go"

_PEM_PUBLIC_KEY = re.compile(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+?-----END PUBLIC KEY-----", re.MULTILINE)


class SyncError(Exception):
    """A source that cannot be used; nothing is written."""


@dataclass(frozen=True)
class Source:
    relative_path: str
    content: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


def read_source(checkout: Path, relative_path: str) -> Source:
    path = checkout / relative_path
    if os.path.islink(path) and not path.exists():
        raise SyncError(f"{relative_path}: dangling symlink")
    if not path.is_file():
        raise SyncError(f"{relative_path}: not a regular file")
    try:
        content = path.read_bytes()
    except OSError as err:
        raise SyncError(f"{relative_path}: {err}") from err
    if not content:
        raise SyncError(f"{relative_path}: empty")
    return Source(relative_path, content)


def go_commit(checkout: Path) -> str:
    git = shutil.which("git")
    if git is None:
        raise SyncError("git is not on PATH")
    try:
        out = subprocess.run(
            [git, "-C", str(checkout), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as err:
        raise SyncError(f"cannot read the Go commit: {err}") from err
    commit = out.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SyncError(f"unexpected commit {commit!r}")
    return commit


def check_trusted_root(source: Source) -> None:
    try:
        root = json.loads(source.content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise SyncError(f"{source.relative_path}: not JSON: {err}") from err
    if not isinstance(root, dict) or root.get("mediaType") != TRUSTED_ROOT_MEDIA_TYPE:
        raise SyncError(f"{source.relative_path}: not a Sigstore trusted root")
    for member in ("tlogs", "certificateAuthorities", "timestampAuthorities"):
        if not root.get(member):
            raise SyncError(f"{source.relative_path}: no {member}")


def load_certificates(source: Source, count: int) -> list[x509.Certificate]:
    try:
        certificates = x509.load_pem_x509_certificates(source.content)
    except ValueError as err:
        raise SyncError(f"{source.relative_path}: {err}") from err
    if len(certificates) != count:
        raise SyncError(f"{source.relative_path}: want {count} certificates, got {len(certificates)}")
    return certificates


def check_issued_by(subject: x509.Certificate, issuer: x509.Certificate, what: str) -> None:
    try:
        subject.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature) as err:
        raise SyncError(f"{what}: {err}") from err


def check_amd_chain(source: Source, product: str) -> None:
    ask, ark = load_certificates(source, 2)
    check_issued_by(ark, ark, f"{source.relative_path}: ARK is not self-signed")
    check_issued_by(ask, ark, f"{source.relative_path}: ASK is not signed by the ARK")
    for certificate, want in ((ask, f"SEV-{product}"), (ark, f"ARK-{product}")):
        cn = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if len(cn) != 1 or cn[0].value != want:
            raise SyncError(f"{source.relative_path}: want common name {want!r}")


def check_intel_root(source: Source) -> None:
    (root,) = load_certificates(source, 1)
    check_issued_by(root, root, f"{source.relative_path}: root is not self-signed")
    cn = root.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(cn) != 1 or cn[0].value != "Intel SGX Root CA":
        raise SyncError(f"{source.relative_path}: unexpected common name")


def signing_keys(source: Source) -> list[str]:
    text = source.content.decode("utf-8")
    keys = _PEM_PUBLIC_KEY.findall(text)
    if not keys:
        raise SyncError(f"{source.relative_path}: no PEM public key found")
    for pem in keys:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise SyncError(f"{source.relative_path}: signing key is not ECDSA P-256")
    return keys


def committed_roots(module: Path) -> set[bytes]:
    """The SPKIs of the self-signed roots in a committed PEM module, or none."""
    if not module.exists():
        return set()
    text = module.read_text()
    roots: set[bytes] = set()
    for match in re.finditer(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.DOTALL):
        certificate = x509.load_pem_x509_certificate(match.group(0).encode("ascii"))
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


def new_roots(source: Source) -> set[bytes]:
    roots: set[bytes] = set()
    for certificate in x509.load_pem_x509_certificates(source.content):
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


def check_root_change(module: Path, source: Source, allow: bool) -> None:
    before = committed_roots(module)
    after = new_roots(source)
    if before and before != after and not allow:
        raise SyncError(f"{module.name}: the self-signed root changed; pass --allow-root-change to accept it")


def header(source: Source, commit: str, *, long_lines: bool) -> str:
    lines = [
        '"""Generated by scripts/sync_trust.py. Do not edit.',
        "",
        f"Source: tinfoil-go {source.relative_path} at commit {commit}",
        f"SHA-256 of the source: {source.sha256}",
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


def render_bytes_module(source: Source, commit: str, name: str, doc: str, *, long_lines: bool = False) -> str:
    return header(source, commit, long_lines=long_lines) + "\n" + bytes_literal(name, source.content, doc)


def render_keys_module(source: Source, commit: str, keys: list[str]) -> str:
    items = "".join(f'    """\\\n{key}\n""",\n' for key in keys)
    body = f"PUBLIC_SIGNING_KEYS_PEM: tuple[str, ...] = (\n{items})\n"
    body += (
        '"""The PEM public keys that authenticate registry issuers, legacy public configs and artifact approvals."""\n'
    )
    return header(source, commit, long_lines=False) + "\n" + body


INIT_MODULE = '''"""The trust anchors that the verifier ships: generated constants, never fetched at run time.

Regenerate with ``uv run python scripts/sync_trust.py <tinfoil-go checkout>``.
"""

from tinfoil._v3.verifier._trust.amd_genoa import AMD_GENOA_CERT_CHAIN_PEM
from tinfoil._v3.verifier._trust.amd_turin import AMD_TURIN_CERT_CHAIN_PEM
from tinfoil._v3.verifier._trust.intel_sgx_root import INTEL_SGX_ROOT_CA_PEM
from tinfoil._v3.verifier._trust.signing_keys import PUBLIC_SIGNING_KEYS_PEM
from tinfoil._v3.verifier._trust.sigstore_root import SIGSTORE_TRUSTED_ROOT_JSON

__all__ = [
    "AMD_GENOA_CERT_CHAIN_PEM",
    "AMD_TURIN_CERT_CHAIN_PEM",
    "INTEL_SGX_ROOT_CA_PEM",
    "PUBLIC_SIGNING_KEYS_PEM",
    "SIGSTORE_TRUSTED_ROOT_JSON",
]
'''


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("checkout", type=Path, help="path to a tinfoil-go checkout at the pinned commit")
    parser.add_argument("--allow-root-change", action="store_true", help="accept a self-signed root that differs")
    args = parser.parse_args(argv)
    checkout: Path = args.checkout.resolve()

    try:
        commit = go_commit(checkout)
        sigstore_root = read_source(checkout, SIGSTORE_ROOT_SOURCE)
        amd_genoa = read_source(checkout, AMD_GENOA_SOURCE)
        amd_turin = read_source(checkout, AMD_TURIN_SOURCE)
        intel_root = read_source(checkout, INTEL_SGX_ROOT_SOURCE)
        keys_source = read_source(checkout, SIGNING_KEYS_SOURCE)

        check_trusted_root(sigstore_root)
        check_amd_chain(amd_genoa, "Genoa")
        check_amd_chain(amd_turin, "Turin")
        check_intel_root(intel_root)
        keys = signing_keys(keys_source)

        check_root_change(TRUST_DIR / "amd_genoa.py", amd_genoa, args.allow_root_change)
        check_root_change(TRUST_DIR / "amd_turin.py", amd_turin, args.allow_root_change)
        check_root_change(TRUST_DIR / "intel_sgx_root.py", intel_root, args.allow_root_change)

        outputs = {
            "sigstore_root.py": render_bytes_module(
                sigstore_root,
                commit,
                "SIGSTORE_TRUSTED_ROOT_JSON",
                "The Sigstore trusted root: Fulcio, Rekor, CT log and timestamp authority material.",
                long_lines=True,
            ),
            "amd_genoa.py": render_bytes_module(
                amd_genoa, commit, "AMD_GENOA_CERT_CHAIN_PEM", "The AMD Genoa ASK then ARK certificates."
            ),
            "amd_turin.py": render_bytes_module(
                amd_turin, commit, "AMD_TURIN_CERT_CHAIN_PEM", "The AMD Turin ASK then ARK certificates."
            ),
            "intel_sgx_root.py": render_bytes_module(
                intel_root, commit, "INTEL_SGX_ROOT_CA_PEM", "The Intel SGX Provisioning Certification Root CA."
            ),
            "signing_keys.py": render_keys_module(keys_source, commit, keys),
            "__init__.py": INIT_MODULE,
        }
    except SyncError as err:
        print(f"sync_trust: {err}", file=sys.stderr)
        return 1

    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        (TRUST_DIR / name).write_text(text)
        print(f"wrote {TRUST_DIR / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
