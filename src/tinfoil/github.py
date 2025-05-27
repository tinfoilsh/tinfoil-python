import json
import re
import requests
from typing import Dict, Any
import os
import platformdirs
import sys

# --- Cache Setup ---
_GITHUB_CACHE_DIR = platformdirs.user_cache_dir("tinfoil", "tinfoil")
# Create a subdirectory specific to GitHub attestations within the main cache
os.makedirs(_GITHUB_CACHE_DIR, exist_ok=True)

def _attestation_bundle_cache_path(repo: str, digest: str) -> str:
    """Generate a safe filepath for the attestation bundle cache."""
    # Replace '/' in repo name with '_' for safe filename
    safe_repo = repo.replace('/', '_')
    filename = f"bundle_{safe_repo}_{digest}.json"
    return os.path.join(_GITHUB_CACHE_DIR, filename)
# --- End Cache Setup ---

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
    url = f"https://api-github-proxy.tinfoil.sh/repos/{repo}/releases/latest"
    release_response = requests.get(url)
    release_response.raise_for_status()
    
    response_data = json.loads(release_response.content)
    tag_name = response_data["tag_name"]
    body = response_data["body"]
    
    # Backwards compatibility for old EIF releases
    eif_regex = re.compile(r'EIF hash: ([a-fA-F0-9]{64})')
    matches = eif_regex.search(body)
    if matches:
        return matches.group(1)
    
    # Other format to fetch Digest
    digest_regex = re.compile(r'Digest: `([a-fA-F0-9]{64})`')
    matches = digest_regex.search(body)
    if matches:
        return matches.group(1)
    
    # Fallback option: fetch digest from github special endpoint
    digest_url = f"https://github-proxy.tinfoil.sh/{repo}/releases/download/{tag_name}/tinfoil.hash"
    response = requests.get(digest_url)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch attestation digest: {response.status_code} {response.reason}")
    return response.text.strip()

def fetch_attestation_bundle(repo: str, digest: str) -> bytes:
    """
    Fetches the sigstore bundle from a repo for a given repo and EIF hash.
    Uses a local filesystem cache to avoid repeated downloads.

    Args:
        repo: The GitHub repository in format "owner/repo"
        digest: The EIF hash/digest

    Returns:
        The sigstore bundle JSON object, encoded as bytes.

    Raises:
        Exception: If there's any error fetching or parsing the data,
                   or reading/writing the cache.
    """
    cache_path = _attestation_bundle_cache_path(repo, digest)

    # 1. Try the cache first
    if os.path.isfile(cache_path):
        try:
            with open(cache_path, 'rb') as f:
                # Read directly as bytes, assuming it was stored correctly
                cached_bundle_bytes = f.read()
            # Attempt to parse to ensure it's valid JSON before returning
            json.loads(cached_bundle_bytes.decode('utf-8'))
            return cached_bundle_bytes
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"Cache read/decode error for {cache_path}: {e}. Attempting fetch.", file=sys.stderr)
            # If cache is corrupted, try removing it
            try:
                os.remove(cache_path)
            except OSError:
                pass
            # Proceed to fetch from network

    # 2. Cache miss or error - fetch from GitHub API
    url = f"https://api-github-proxy.tinfoil.sh/repos/{repo}/attestations/sha256:{digest}"
    try:
        bundle_response = requests.get(url, timeout=15)
        bundle_response.raise_for_status()
        response_data = json.loads(bundle_response.content)
    except requests.RequestException as e:
        raise Exception(f"Error fetching attestation from {url}: {e}") from e
    except json.JSONDecodeError as e:
        raise Exception(f"Error decoding JSON response from {url}: {e}") from e

    # 3. Extract bundle and write to cache
    try:
        # The bundle itself is typically a JSON object (dict)
        bundle_object = response_data["attestations"][0]["bundle"]
        # We need to store it as JSON text in the file
        bundle_json_string = json.dumps(bundle_object)
        # Encode the string to bytes for file writing and return value
        bundle_bytes_to_write = bundle_json_string.encode('utf-8')

        # Write to cache
        try:
            with open(cache_path, 'wb') as f:
                f.write(bundle_bytes_to_write)
        except OSError as e:
            # Don't fail the whole operation if cache write fails, just warn
            print(f"Warning: Failed to write cache file {cache_path}: {e}", file=sys.stderr)

        return bundle_json_string

    except (KeyError, IndexError, TypeError) as e:
        raise Exception(f"Invalid attestation response format from {url}: {e}. Response: {response_data}") from e
