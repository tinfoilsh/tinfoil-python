"""The trust anchors that the verifier ships: generated constants, never fetched at run time.

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
