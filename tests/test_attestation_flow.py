"""
Integration test for attestation verification flow.

Tests the complete verification using the SecureClient API with a live router.
Works with any architecture (SNP or TDX) returned by the router service.
"""

import pytest

from tinfoil.client import SecureClient, get_router_address
from tinfoil.attestation import PredicateType

pytestmark = pytest.mark.integration  # allows pytest -m integration filtering

# Router always runs confidential-model-router
REPO = "tinfoilsh/confidential-model-router"


def test_full_verification_flow():
    """
    Tests the complete attestation verification flow using SecureClient.
    
    Gets a router from the ATC service and verifies it against the
    confidential-model-router repo. Works with any TEE type (SNP or TDX).

    SecureClient.verify() runs the v3 single-request flow:
    1. Fetch the attestation document (evidence + collateral) from the enclave
    2. Verify it offline against the embedded roots (envelope, code and
       platform provenance with freshness, quote, policy)
    3. Recover the endorsed channel keys (TLS fingerprint + HPKE key)
    """
    try:
        enclave = get_router_address()
    except Exception as e:
        pytest.skip(f"Could not fetch router address from ATC service: {e}")
    
    print(f"\nVerifying enclave: {enclave}")
    print(f"Against repo: {REPO}")
    
    client = SecureClient(enclave=enclave, repo=REPO)
    ground_truth = client.verify()
    
    # Print architecture-specific info
    measurement_type = ground_truth.measurement.type
    print(f"\n✓ Verification successful!")
    print(f"  Architecture: {measurement_type.value}")
    print(f"  Measurement fingerprint: {ground_truth.measurement.fingerprint()}")
    print(f"  Public key fingerprint: {ground_truth.public_key}")
    print(f"  Digest: {ground_truth.digest}")
    
    # Print registers based on type
    regs = ground_truth.measurement.registers
    if measurement_type == PredicateType.SEV_GUEST_V2:
        print(f"\n  SNP Measurement: {regs[0][:32]}...")
    elif measurement_type == PredicateType.TDX_GUEST_V2:
        print(f"\n  TDX Measurements:")
        print(f"    MRTD:  {regs[0][:32]}...")
        print(f"    RTMR0: {regs[1][:32]}...")
        print(f"    RTMR1: {regs[2][:32]}...")
        print(f"    RTMR2: {regs[3][:32]}...")
        print(f"    RTMR3: {regs[4][:32]}...")


def test_verification_document_carries_v3_facts():
    """
    After a live verify, the verification document must carry the v3 facts:
    the release digest, both measurement fingerprints, and both endorsed
    channel keys.
    """
    try:
        enclave = get_router_address()
    except Exception as e:
        pytest.skip(f"Could not fetch router address from ATC service: {e}")

    client = SecureClient(enclave=enclave, repo=REPO)
    ground_truth = client.verify()
    doc = client.get_verification_document()

    assert doc is not None and doc.security_verified
    # The code digest names the verified release artifact (sha256 hex).
    assert len(doc.release_digest) == 64
    assert all(c in "0123456789abcdef" for c in doc.release_digest)
    assert doc.release_tag, "release tag should come from the code provenance"
    # Fingerprints mirror the legacy display flow and must be populated.
    assert doc.code_fingerprint
    assert doc.enclave_fingerprint
    # Both endorsed channel keys are hard requirements in v3.
    assert doc.tls_public_key and len(doc.tls_public_key) == 64
    assert doc.hpke_public_key and len(doc.hpke_public_key) == 64
    assert ground_truth.public_key == doc.tls_public_key
    assert ground_truth.hpke_public_key == doc.hpke_public_key
    assert doc.verified_at is not None
    assert doc.verifier.name == "tinfoil"
    assert all(step.status == "success" for step in doc.steps.values())


def test_secure_http_client():
    """
    Tests that SecureClient creates a working pinned HTTP client
    and that TLS pinning is exercised by issuing an actual request.
    Works with any TEE type (SNP or TDX).
    """
    try:
        enclave = get_router_address()
    except Exception as e:
        pytest.skip(f"Could not fetch router address from ATC service: {e}")
    
    print(f"\nCreating secure HTTP client for: {enclave}")
    
    client = SecureClient(enclave=enclave, repo=REPO)
    http_client = client.make_secure_http_client()
    
    ground_truth = client.ground_truth
    assert ground_truth is not None
    
    try:
        response = http_client.get(f"https://{enclave}/.well-known/tinfoil-attestation")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        print(f"\n✓ TLS-pinned request succeeded (status {response.status_code})")
    finally:
        http_client.close()
    
    print(f"  Architecture: {ground_truth.measurement.type.value}")
    print(f"  TLS pinned to: {ground_truth.public_key}")


@pytest.mark.asyncio
async def test_secure_async_http_client():
    """
    Tests that the async pinned client can connect to the enclave.
    Mirrors test_secure_http_client for the async path.
    """
    try:
        enclave = get_router_address()
    except Exception as e:
        pytest.skip(f"Could not fetch router address from ATC service: {e}")

    client = SecureClient(enclave=enclave, repo=REPO)
    http_client = client.make_secure_async_http_client()

    ground_truth = client.ground_truth
    assert ground_truth is not None

    try:
        response = await http_client.get(f"https://{enclave}/.well-known/tinfoil-attestation")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    finally:
        await http_client.aclose()


def test_sync_pinned_client_rejects_wrong_host():
    """
    A client pinned to the enclave's cert must reject connections
    to a different host (whose cert won't match the pinned fingerprint).

    Certificate pinning is a property of the "tls" transport; the default
    "ehbp" transport is intentionally proxy-friendly and does not pin the host.
    """
    try:
        enclave = get_router_address()
    except Exception as e:
        pytest.skip(f"Could not fetch router address from ATC service: {e}")

    client = SecureClient(enclave=enclave, repo=REPO, transport="tls")
    http_client = client.make_secure_http_client()

    try:
        with pytest.raises(Exception):
            http_client.get("https://google.com")
    finally:
        http_client.close()


@pytest.mark.asyncio
async def test_async_pinned_client_rejects_wrong_host():
    """
    The async pinned client must reject connections to a host
    whose cert doesn't match the pinned fingerprint.

    Certificate pinning is a property of the "tls" transport; the default
    "ehbp" transport is intentionally proxy-friendly and does not pin the host.
    """
    try:
        enclave = get_router_address()
    except Exception as e:
        pytest.skip(f"Could not fetch router address from ATC service: {e}")

    client = SecureClient(enclave=enclave, repo=REPO, transport="tls")
    http_client = client.make_secure_async_http_client()

    try:
        with pytest.raises(Exception):
            await http_client.get("https://google.com")
    finally:
        await http_client.aclose()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
