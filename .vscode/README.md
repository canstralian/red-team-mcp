# Debugging Workflow Setup Guide

## Overview

This directory contains debugging configurations and utilities for the Red Team MCP Server project. The debugging workflow covers Python development, Docker containers, distributed systems tracing, and secure logging practices.

## Quick Start

### 1. Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/canstralian/red-team-mcp.git
cd red-team-mcp

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .

# Install debugging tools
pip install debugpy ipdb memory-profiler line-profiler
```

### 2. Configure VS Code

The `.vscode/` directory contains pre-configured debugging setups:

- **launch.json**: Debug configurations for various scenarios
- **settings.json**: Recommended editor settings
- **extensions.json**: Recommended VS Code extensions

Open the project in VS Code and install recommended extensions when prompted.

### 3. Start Debugging

#### Debug Locally
1. Set breakpoints by clicking left of line numbers
2. Press `F5` or select "Run > Start Debugging"
3. Choose "Python: FastMCP Server" configuration
4. Use debug toolbar to step through code

#### Debug in Docker
```bash
# Build debug image
docker build -f Dockerfile.debug -t redteam-mcp:debug .

# Run with debugging enabled
docker-compose -f docker-compose.debug.yml up

# Attach VS Code debugger
# Use "Python: Remote Attach (Docker)" configuration
```

## Documentation

- **[docs/debugging-guide.md](../docs/debugging-guide.md)** - Complete debugging guide
  - Python/FastMCP debugging techniques
  - Docker debugging workflows
  - VS Code remote debugging setup
  - Secure logging practices
  - Distributed tracing methods
  - Performance profiling

- **[docs/troubleshooting.md](../docs/troubleshooting.md)** - Troubleshooting guide
  - Common issues and solutions
  - Diagnostic scripts
  - Debug checklist
  - Support resources

## Utilities

### Secure Logger (`src/utils/secure_logger.py`)

Prevents accidental logging of sensitive information:

```python
from src.utils.secure_logger import get_secure_logger, mask_sensitive_data

logger = get_secure_logger(__name__)

# Automatically masks sensitive data
logger.info("User login: password=secret")  # password is masked

# Mask data structures
config = {"api_key": "secret", "user": "admin"}
safe_config = mask_sensitive_data(config)
logger.info(f"Config: {safe_config}")  # api_key is masked
```

**Features:**
- Automatic masking of passwords, API keys, tokens
- Structured logging support
- Correlation ID tracking
- Log rotation and retention
- Production-safe defaults

### Examples

Run the secure logging examples:

```bash
python3 examples/secure_logging_example.py
```

This demonstrates:
- Basic secure logging
- Structured logging with context
- Correlation ID usage
- Error logging with stack traces
- Security-sensitive operations logging
- Configuration logging
- Performance logging

## Debugging Configurations

### VS Code Launch Configurations

| Configuration | Purpose |
|---------------|---------|
| Python: FastMCP Server | Debug the main MCP server |
| Python: Current File | Debug currently open file |
| Python: Run Tests | Debug unit tests |
| Python: Run Specific Test | Debug single test file |
| Python: Remote Attach | Attach to running debugpy |
| Python: Remote Attach (Docker) | Attach to debugger in Docker |
| Python: Verification Agent | Debug verification agent |
| Python: Profile with cProfile | Profile performance |

### Docker Configurations

| File | Purpose |
|------|---------|
| Dockerfile.debug | Debug-enabled Docker image |
| docker-compose.debug.yml | Docker Compose for debugging |

## Security Best Practices

### What to NEVER Log

❌ Passwords and credentials  
❌ API keys and tokens  
❌ Session cookies  
❌ Encryption keys  
❌ Credit card numbers, SSNs, PII  
❌ Full SQL queries with sensitive data  

### What to LOG

✅ Operation names and outcomes  
✅ Timestamps and durations  
✅ Error types (without sensitive details)  
✅ Request/correlation IDs  
✅ Performance metrics  
✅ Configuration (with sensitive fields masked)  

### Log Levels

Use appropriate log levels:

- **DEBUG**: Detailed diagnostic information (development only)
- **INFO**: General informational messages
- **WARNING**: Warning messages, degraded state
- **ERROR**: Error messages, operation failed
- **CRITICAL**: Critical issues, system failure

## Distributed Tracing

Use correlation IDs to trace requests across components:

```python
from src.utils.secure_logger import get_correlation_id_logger
import uuid

correlation_id = str(uuid.uuid4())
logger = get_correlation_id_logger(__name__, correlation_id)

logger.info("Request started")
# ... process request ...
logger.info("Request completed")
```

All logs will include the correlation ID for easy tracking.

## Performance Profiling

### CPU Profiling

```bash
python3 -m cProfile -o profile.stats src/main.py
python3 -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(20)"
```

### Memory Profiling

```bash
pip install memory-profiler
python3 -m memory_profiler src/main.py
```

### Line Profiling

```bash
pip install line_profiler
kernprof -l -v src/main.py
```

## Common Debugging Scenarios

### Scenario 1: Application Not Starting

```bash
# Check Python version
python3 --version

# Verify dependencies
pip list | grep -E "fastmcp|httpx|pydantic"

# Run with verbose logging
export PYTHONUNBUFFERED=1
export LOG_LEVEL=DEBUG
python3 -u src/main.py
```

### Scenario 2: Docker Container Issues

```bash
# Check container logs
docker logs <container_id>

# Run interactively
docker run -it --entrypoint /bin/bash redteam-mcp:latest

# Check resource usage
docker stats
```

### Scenario 3: Remote Debugging Not Connecting

```bash
# Verify debugpy is running
docker exec -it <container_id> netstat -tlnp | grep 5678

# Test connection
telnet localhost 5678

# Check port forwarding
docker ps  # Look for 0.0.0.0:5678->5678/tcp
```

## Testing

Run tests with debugging enabled:

```bash
# Run all tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Debug specific test in VS Code
# Use "Python: Run Specific Test" configuration
```

## Additional Resources

- [Main README](../README.md)
- [Security Documentation](../SECURITY.md)
- [Debugging Guide](../docs/debugging-guide.md)
- [Troubleshooting Guide](../docs/troubleshooting.md)
- [Python Debugging Documentation](https://docs.python.org/3/library/pdb.html)
- [VS Code Python Debugging](https://code.visualstudio.com/docs/python/debugging)
- [Docker Debugging Guide](https://docs.docker.com/config/containers/logging/)

## Support

If you encounter issues:

1. Check the [Troubleshooting Guide](../docs/troubleshooting.md)
2. Review logs with `LOG_LEVEL=DEBUG`
3. Search existing GitHub issues
4. Create a new issue with:
   - Error messages and stack traces
   - Steps to reproduce
   - Environment details (Python version, OS, Docker version)
   - What you've already tried

## Contributing

When contributing debugging improvements:

1. Test configurations on multiple platforms
2. Update documentation
3. Add examples for new debugging techniques
4. Ensure secure logging practices are followed
5. Include troubleshooting tips

---

**⚠️ Security Notice**: Never commit sensitive information (credentials, tokens, keys) to logs or version control. Always use the secure logger utilities provided in this project.
