import json
import re
import requests
from typing import Dict, Any

def fetch_latest_digest(repo: str) -> str:
    """
    Gets the latest release and attestation digest of a repo.
    
    Args:
        repo: The GitHub repository in format "owner/repo"
        
    Returns:
        The digest string
        
    Raises:
        Exception: If there's any error fetching or parsing the data
    """
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    release_response = requests.get(url)
    
    response_data = json.loads(release_response.content)
    tag_name = response_data["tag_name"]
    body = response_data["body"]
    
    # Backwards compatibility for old EIF releases
    eif_regex = re.compile(r'EIF hash: ([a-fA-F0-9]{64})')
    matches = eif_regex.search(body)
    if matches:
        return matches.group(1)
    
    # Fetch digest from release asset
    digest_url = f"https://github.com/{repo}/releases/download/{tag_name}/tinfoil.hash"
    response = requests.get(digest_url)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch attestation digest: {response.status_code} {response.reason}")
    
    return response.text.strip()

def fetch_attestation_bundle(repo: str, digest: str) -> bytes:
    """
    Fetches the sigstore bundle from a repo for a given repo and EIF hash.
    
    Args:
        repo: The GitHub repository in format "owner/repo"
        digest: The EIF hash/digest
        
    Returns:
        The attestation bundle as bytes
        
    Raises:
        Exception: If there's any error fetching or parsing the data
    """
    url = f"https://api.github.com/repos/{repo}/attestations/sha256:{digest}"
    bundle_response = requests.get(url)
    
    response_data = json.loads(bundle_response.content)
    
    try:
        # Extract the first attestation bundle
        return json.dumps(response_data["attestations"][0]["bundle"])
    except (KeyError, IndexError) as e:
        raise Exception(f"Invalid attestation response format: {e}")
