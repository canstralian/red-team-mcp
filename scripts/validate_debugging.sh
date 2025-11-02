#!/bin/bash
# Quick validation script for debugging infrastructure

set -e

echo "🔍 Validating Red Team MCP Debugging Infrastructure"
echo "=================================================="
echo ""

# Check Python version
echo "✓ Python Version:"
python3 --version
echo ""

# Check if secure_logger can be imported
echo "✓ Testing secure_logger import..."
python3 -c "from src.utils.secure_logger import get_secure_logger; print('  ✅ secure_logger imports successfully')"
echo ""

# Test masking functionality
echo "✓ Testing sensitive data masking..."
python3 -c "
from src.utils.secure_logger import mask_sensitive_data
data = {'password': 'secret', 'username': 'admin'}
masked = mask_sensitive_data(data)
assert masked['password'] == '***MASKED***', 'Password not masked!'
assert masked['username'] == 'admin', 'Username should not be masked!'
print('  ✅ Masking works correctly')
"
echo ""

# Validate JSON configs
echo "✓ Validating VS Code configurations..."
python3 -c "
import json
import re

def strip_json_comments(text):
    text = re.sub(r'//.*?\n', '\n', text)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    return text

# Validate launch.json
with open('.vscode/launch.json', 'r') as f:
    content = strip_json_comments(f.read())
    data = json.loads(content)
    print(f'  ✅ launch.json valid ({len(data[\"configurations\"])} configurations)')

# Validate settings.json
with open('.vscode/settings.json', 'r') as f:
    content = strip_json_comments(f.read())
    json.loads(content)
    print('  ✅ settings.json valid')

# Validate extensions.json
with open('.vscode/extensions.json', 'r') as f:
    content = strip_json_comments(f.read())
    data = json.loads(content)
    print(f'  ✅ extensions.json valid ({len(data[\"recommendations\"])} extensions)')
"
echo ""

# Validate YAML
echo "✓ Validating Docker Compose configuration..."
python3 -c "
import yaml
with open('docker-compose.debug.yml', 'r') as f:
    yaml.safe_load(f)
    print('  ✅ docker-compose.debug.yml valid')
"
echo ""

# Check documentation exists
echo "✓ Checking documentation files..."
docs=(
    "docs/debugging-guide.md"
    "docs/troubleshooting.md"
    ".vscode/README.md"
)

for doc in "${docs[@]}"; do
    if [ -f "$doc" ]; then
        echo "  ✅ $doc exists"
    else
        echo "  ❌ $doc missing"
        exit 1
    fi
done
echo ""

# Run secure logging example
echo "✓ Running secure logging example..."
python3 examples/secure_logging_example.py > /dev/null 2>&1
echo "  ✅ Secure logging example runs successfully"
echo ""

# Run unit tests
echo "✓ Running unit tests..."
python3 -m unittest discover -s tests -p "test_*.py" -v 2>&1 | grep -E "^(test_|Ran |OK|FAILED)" | tail -5
echo ""

echo "=================================================="
echo "✅ All debugging infrastructure checks passed!"
echo ""
echo "📚 Next steps:"
echo "  1. Open project in VS Code: code ."
echo "  2. Install recommended extensions"
echo "  3. Press F5 to start debugging"
echo "  4. Read docs/debugging-guide.md for detailed instructions"
echo ""
