#!/usr/bin/env python3
"""
Validation script for debugging infrastructure.

This script validates that all debugging configurations are properly set up.
"""

import json
import re
import sys
import yaml
from pathlib import Path


def strip_json_comments(text: str) -> str:
    """Remove comments from JSON text."""
    text = re.sub(r'//.*?\n', '\n', text)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    return text


def validate_json_file(filepath: str, description: str) -> bool:
    """Validate a JSON file (with optional comments)."""
    try:
        with open(filepath, 'r') as f:
            content = strip_json_comments(f.read())
            data = json.loads(content)
        
        if 'configurations' in data:
            print(f'  ✅ {description} valid ({len(data["configurations"])} configurations)')
        elif 'recommendations' in data:
            print(f'  ✅ {description} valid ({len(data["recommendations"])} extensions)')
        else:
            print(f'  ✅ {description} valid')
        return True
    except Exception as e:
        print(f'  ❌ {description} invalid: {e}')
        return False


def validate_yaml_file(filepath: str, description: str) -> bool:
    """Validate a YAML file."""
    try:
        with open(filepath, 'r') as f:
            yaml.safe_load(f)
        print(f'  ✅ {description} valid')
        return True
    except Exception as e:
        print(f'  ❌ {description} invalid: {e}')
        return False


def validate_file_exists(filepath: str) -> bool:
    """Check if a file exists."""
    path = Path(filepath)
    if path.exists():
        print(f'  ✅ {filepath} exists')
        return True
    else:
        print(f'  ❌ {filepath} missing')
        return False


def test_secure_logger() -> bool:
    """Test secure logger functionality."""
    try:
        # Add parent directory to path for imports
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        from src.utils.secure_logger import get_secure_logger, mask_sensitive_data
        
        # Test import
        print('  ✅ secure_logger imports successfully')
        
        # Test masking
        data = {'password': 'secret', 'username': 'admin', 'api_key': 'sk-123456'}
        masked = mask_sensitive_data(data)
        
        assert masked['password'] == '***MASKED***', 'Password not masked!'
        assert masked['api_key'] == '***MASKED***', 'API key not masked!'
        assert masked['username'] == 'admin', 'Username should not be masked!'
        
        print('  ✅ Masking works correctly')
        return True
    except Exception as e:
        print(f'  ❌ Secure logger test failed: {e}')
        return False


def main():
    """Run all validations."""
    print("✓ Validating VS Code configurations...")
    
    all_valid = True
    
    # Validate JSON configs
    all_valid &= validate_json_file('.vscode/launch.json', 'launch.json')
    all_valid &= validate_json_file('.vscode/settings.json', 'settings.json')
    all_valid &= validate_json_file('.vscode/extensions.json', 'extensions.json')
    
    print()
    print("✓ Validating Docker Compose configuration...")
    all_valid &= validate_yaml_file('docker-compose.debug.yml', 'docker-compose.debug.yml')
    
    print()
    print("✓ Checking documentation files...")
    docs = [
        'docs/debugging-guide.md',
        'docs/troubleshooting.md',
        '.vscode/README.md'
    ]
    for doc in docs:
        all_valid &= validate_file_exists(doc)
    
    print()
    print("✓ Testing secure logger...")
    all_valid &= test_secure_logger()
    
    return 0 if all_valid else 1


if __name__ == '__main__':
    sys.exit(main())
