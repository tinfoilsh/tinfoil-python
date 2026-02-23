"""
Integration test for all live enclaves from the config file.

Fetches config from GitHub, extracts all model enclaves, and verifies
attestation for each one.

Configure via environment variables:
    TINFOIL_CONFIG_URL - URL to config.yml (default: main branch)
    TINFOIL_API_KEY    - API key for model tests (optional)

Example:
    python -m pytest tests/test_all_enclaves.py -v -s
    python -m pytest tests/test_all_enclaves.py -v -s -k "llama"  # filter by model name
"""

import os
import pytest
import requests

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from tinfoil.client import SecureClient
from tinfoil.attestation import PredicateType

pytestmark = pytest.mark.integration

# Config URL
CONFIG_URL = os.environ.get(
    "TINFOIL_CONFIG_URL",
    "https://raw.githubusercontent.com/tinfoilsh/confidential-model-router/refs/heads/main/config.yml"
)

# Models to skip (not testable)
SKIP_MODELS = ["websearch"]


def fetch_config() -> dict:
    """Fetch and parse the config file."""
    if not HAS_YAML:
        raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
    response = requests.get(CONFIG_URL, timeout=30)
    response.raise_for_status()
    return yaml.safe_load(response.text)


def get_all_enclaves() -> list[tuple[str, str, str]]:
    """
    Get all enclaves from config.
    
    Returns:
        List of (model_name, repo, hostname) tuples

    Raises:
        ImportError: If PyYAML is not installed
        Exception: If the config cannot be fetched or parsed
    """
    if not HAS_YAML:
        raise ImportError("PyYAML not installed. Install with: pip install pyyaml")

    config = fetch_config()
    
    enclaves = []
    models = config.get("models", {})
    
    for model_name, model_config in models.items():
        if any(skip.lower() in model_name.lower() for skip in SKIP_MODELS):
            continue
        
        repo = model_config.get("repo", "")
        hostnames = model_config.get("enclaves", []) or model_config.get("hostnames", [])
        
        if not repo or not hostnames:
            continue
        
        for hostname in hostnames:
            enclaves.append((model_name, repo, hostname))
    
    return enclaves


def pytest_generate_tests(metafunc):
    """Defer network call to test generation time instead of module import."""
    if "enclave_config" in metafunc.fixturenames:
        try:
            enclaves = get_all_enclaves()
        except ImportError:
            enclaves = []
        except Exception:
            enclaves = []

        if not enclaves:
            enclaves = [("__skip__", "__skip__", "__skip__")]
            ids = ["no_enclaves"]
        else:
            ids = [f"{n}@{h}" for n, _, h in enclaves]

        metafunc.parametrize("enclave_config", enclaves, ids=ids)


def test_enclave_attestation(enclave_config):
    """
    Test attestation for a single enclave.
    
    Verifies:
    1. Can connect to enclave
    2. Attestation verification passes (crypto + policy)
    3. Sigstore verification passes
    4. Measurements match
    5. For TDX: hardware measurements verified
    """
    model_name, repo, hostname = enclave_config
    
    if model_name == "__skip__":
        if not HAS_YAML:
            pytest.skip("PyYAML not installed. Install with: pip install pyyaml")
        else:
            pytest.skip("No enclaves found in config")
    
    print(f"\n{'='*60}")
    print(f"Testing: {model_name}")
    print(f"  Enclave: {hostname}")
    print(f"  Repo: {repo}")
    print(f"{'='*60}")
    
    try:
        client = SecureClient(enclave=hostname, repo=repo)
        ground_truth = client.verify()
        
        # Print results
        measurement_type = ground_truth.measurement.type
        print(f"\n✓ Attestation verified!")
        print(f"  Architecture: {measurement_type.value}")
        print(f"  Fingerprint: {ground_truth.measurement.fingerprint()[:32]}...")
        print(f"  Public key: {ground_truth.public_key[:32]}...")
        print(f"  Digest: {ground_truth.digest[:32]}...")
        
        # Print architecture-specific info
        regs = ground_truth.measurement.registers
        if measurement_type == PredicateType.SEV_GUEST_V2:
            print(f"  SNP measurement: {regs[0][:32]}...")
        elif measurement_type == PredicateType.TDX_GUEST_V2:
            print(f"  MRTD: {regs[0][:32]}...")
            print(f"  RTMR0: {regs[1][:32]}...")
        
    except Exception as e:
        pytest.fail(f"Attestation failed for {model_name}@{hostname}: {e}")


def test_summary():
    """Print summary of all enclaves that will be tested."""
    if not HAS_YAML:
        pytest.skip("PyYAML not installed. Install with: pip install pyyaml")
    
    try:
        enclaves = get_all_enclaves()
    except Exception as e:
        pytest.fail(f"Failed to fetch enclave config: {e}")
    
    if not enclaves:
        pytest.skip("No enclaves found in config")
    
    print(f"\n{'='*60}")
    print(f"ENCLAVE SUMMARY")
    print(f"{'='*60}")
    print(f"Config: {CONFIG_URL}")
    print(f"Total enclaves: {len(enclaves)}")
    print(f"\nModels:")
    
    # Group by model
    models = {}
    for name, repo, host in enclaves:
        if name not in models:
            models[name] = {"repo": repo, "hosts": []}
        models[name]["hosts"].append(host)
    
    for name, info in sorted(models.items()):
        print(f"\n  {name}:")
        print(f"    Repo: {info['repo']}")
        print(f"    Enclaves: {len(info['hosts'])}")
        for host in info['hosts']:
            print(f"      - {host}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
