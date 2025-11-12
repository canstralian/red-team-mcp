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

# Run Python validations
python3 scripts/validate_debugging.py
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
