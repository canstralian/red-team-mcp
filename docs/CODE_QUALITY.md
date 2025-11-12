# Code Quality Scanning

This project uses automated code quality scanning to enforce coding standards and detect potential issues.

## Overview

The code quality scanning system uses **flake8** for Python code to:
- Enforce PEP 8 coding standards
- Detect code smells and potential bugs
- Ensure consistent code style across the project
- Catch syntax errors and undefined names

## Tools Used

### flake8 (Python)
- **Purpose**: Lints Python code for style violations and errors
- **Configuration**: `.flake8` in repository root
- **Standards**: PEP 8 compliance with customizations

## Configuration

### .flake8
The flake8 configuration includes:
- **Max line length**: 100 characters (extended from PEP 8's 79 for modern displays)
- **Ignored codes**:
  - `W293`: Blank line contains whitespace (auto-fixable, not critical)
  - `W503`: Line break before binary operator (conflicts with newer PEP 8)
  - `E203`: Whitespace before ':' (conflicts with black formatter)
- **Complexity limit**: 15 (warns about overly complex functions)
- **Per-file ignores**: Allows star imports in `__init__.py` files

## CI/CD Integration

### GitHub Actions Workflow
The `.github/workflows/code-quality.yml` workflow:

1. **Triggers on**:
   - Push to `main`, `master`, `claude/**`, or `copilot/**` branches
   - Pull requests to `main` or `master` branches

2. **Steps**:
   - Checks out the repository
   - Sets up Python 3.11
   - Installs flake8
   - Runs flake8 on `src/` and `tests/` directories
   - Uploads report as artifact (retained for 30 days)
   - Comments on PR with results summary
   - **Blocks merge** if critical errors found (E9xx, F8xx codes)

3. **Success Criteria**:
   - **Pass**: No critical errors (E9xx, F8xx)
   - **Warning**: Non-critical issues present (logged but not blocking)
   - **Fail**: Critical errors that must be fixed before merge

## Running Locally

### Install Dependencies
```bash
pip install -e ".[dev]"
```

### Run flake8
```bash
# Check all Python code
flake8 src/ tests/

# Check specific files
flake8 src/main.py

# Generate report file
flake8 src/ tests/ --output-file=flake8-report.txt

# Show statistics
flake8 src/ tests/ --statistics
```

## Error Code Categories

### Critical Errors (Blocking)
- **E9xx**: Runtime errors (syntax errors, indentation errors)
- **F8xx**: Critical flake8 errors (undefined names, duplicate arguments)

These **must be fixed** before code can be merged.

### Common Non-Critical Issues
- **E501**: Line too long (>100 characters) - consider refactoring for readability
- **F401**: Imported but unused - remove unused imports
- **W291**: Trailing whitespace - clean up with editor
- **C901**: Function too complex - consider breaking into smaller functions

## Fixing Issues

### Automatic Fixes
Some issues can be auto-fixed with tools like:
```bash
# Remove trailing whitespace
find src/ -name "*.py" -exec sed -i 's/[[:space:]]*$//' {} +

# Auto-format with black (if adopted)
black src/ tests/
```

### Manual Fixes
For logic issues (F821, F841, C901):
1. Review the error message and location
2. Fix the underlying issue (add import, remove unused code, refactor)
3. Re-run flake8 to verify the fix

## Best Practices

1. **Run flake8 before committing**: Catch issues early
2. **Address critical errors immediately**: Don't let them accumulate
3. **Consider warnings seriously**: They often indicate code smells
4. **Keep functions simple**: Stay under complexity limit (15)
5. **Remove unused imports**: Keep code clean and dependencies minimal
6. **Follow PEP 8**: Use consistent style across the project

## Integration with Development Workflow

### Pre-commit Checks (Optional)
Consider adding a pre-commit hook:
```bash
# .git/hooks/pre-commit
#!/bin/bash
flake8 src/ tests/
if [ $? -ne 0 ]; then
    echo "flake8 checks failed. Please fix errors before committing."
    exit 1
fi
```

### IDE Integration
Most Python IDEs support flake8:
- **VS Code**: Python extension includes flake8 linting
- **PyCharm**: Settings → Tools → Python Integrated Tools → Flake8
- **Vim/Neovim**: Use ALE or syntastic plugins

## Continuous Improvement

The code quality configuration will evolve based on:
- Team feedback and consensus
- Project maturity and requirements
- Python version updates and PEP changes
- Security and performance considerations

To suggest changes, please open an issue or pull request with:
- Rationale for the change
- Impact on existing code
- Migration path if needed

## Current Status

As of the latest scan:
- ✅ **0 critical errors** (E9xx, F8xx)
- ⚠️ **~124 non-critical issues** (style, imports, complexity)
- ✅ All syntax errors resolved
- ✅ No undefined names or duplicate arguments

## Resources

- [flake8 Documentation](https://flake8.pycqa.org/)
- [PEP 8 Style Guide](https://pep8.org/)
- [Error Code Reference](https://flake8.pycqa.org/en/latest/user/error-codes.html)
- [PyCodeStyle Docs](https://pycodestyle.pycqa.org/)
