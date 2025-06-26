#!/usr/bin/env python3
"""
Version bumping script for tinfoil-python
Usage: python scripts/bump_version.py --version 1.2.3
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import toml
except ImportError:
    print("Error: toml package not found. Install with: pip install toml")
    sys.exit(1)


def validate_version(version: str) -> bool:
    """Validate semantic version format"""
    pattern = r"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9-]+)*(?:\+[a-zA-Z0-9-]+)*$"
    return bool(re.match(pattern, version))


def bump_version(new_version: str, pyproject_path: Path = None) -> None:
    """Update version in pyproject.toml"""
    if pyproject_path is None:
        pyproject_path = Path("pyproject.toml")
    
    if not pyproject_path.exists():
        print(f"Error: {pyproject_path} not found")
        sys.exit(1)
    
    if not validate_version(new_version):
        print(f"Error: Invalid version format: {new_version}")
        print("Expected format: X.Y.Z or X.Y.Z-suffix")
        sys.exit(1)
    
    try:
        # Read current config
        with open(pyproject_path, 'r') as f:
            content = f.read()
        
        # Parse with toml to get current version for logging
        config = toml.loads(content)
        current_version = config.get('project', {}).get('version', 'unknown')
        print(f"Current version: {current_version}")
        
        # Use regex to replace only the version line, preserving formatting
        version_pattern = r'(version\s*=\s*")[^"]*(")'
        new_content = re.sub(version_pattern, rf'\g<1>{new_version}\g<2>', content)
        
        # Verify the change was made
        if new_content == content:
            print("Warning: No version line found or no change made")
            return
        
        # Write the modified content back
        with open(pyproject_path, 'w') as f:
            f.write(new_content)
        
        print(f"Version updated: {current_version} → {new_version}")
        
    except Exception as e:
        print(f"Error updating version: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Bump version in pyproject.toml")
    parser.add_argument("--version", required=True, help="New version number")
    parser.add_argument("--file", help="Path to pyproject.toml file")
    
    args = parser.parse_args()
    
    pyproject_path = Path(args.file) if args.file else None
    bump_version(args.version, pyproject_path)


if __name__ == "__main__":
    main() 