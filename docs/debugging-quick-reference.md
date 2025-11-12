# Debugging Quick Reference

Quick reference guide for debugging the Red Team MCP Server. For detailed information, see [debugging-guide.md](debugging-guide.md).

## Quick Start

### Enable Debug Mode

```bash
export DEBUG=true
export LOG_LEVEL=DEBUG
export PYTHONUNBUFFERED=1
```

### Debug with VS Code

1. Open the project in VS Code
2. Set breakpoints (click left of line numbers)
3. Press F5 or select "Python: FastMCP Server" configuration
4. Code will pause at breakpoints

### Debug in Docker

```bash
# Build debug image
docker build -f Dockerfile.debug -t red-team-mcp:debug .

# Run with debugger attached
docker-compose -f docker-compose.debug.yml up

# Attach VS Code debugger
# Select "Python: Remote Attach (Docker)" configuration and press F5
```

## Common Commands

### Python Debugging

```python
# Set breakpoint
breakpoint()

# Or use ipdb for better experience
import ipdb; ipdb.set_trace()

# Common pdb commands
n     # Next line
s     # Step into
c     # Continue
p var # Print variable
l     # List code
w     # Where (stack trace)
q     # Quit
```

### Docker Debugging

```bash
# View logs
docker logs -f red-team-mcp-debug

# Execute shell in container
docker exec -it red-team-mcp-debug /bin/bash

# Check container status
docker inspect red-team-mcp-debug

# Monitor resources
docker stats red-team-mcp-debug
```

### Logging

```python
from src.utils.secure_logger import get_logger, CorrelationContext

# Get logger with correlation support
logger = get_logger(__name__)

# Set correlation ID
CorrelationContext.set_correlation_id("req-123")

# Log with structured data
logger.info(
    "Operation completed",
    extra={
        'extra_data': {
            'operation': 'generate_payload',
            'duration_ms': 150,
            'success': True
        }
    }
)
```

## Troubleshooting

### Import Errors

```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
pip3 install -e .
```

### Port Already in Use

```bash
# Find process using port
lsof -i :5678

# Kill process
kill -9 <PID>
```

### Breakpoints Not Hit

Check VS Code `launch.json` path mappings:
```json
"pathMappings": [
    {
        "localRoot": "${workspaceFolder}",
        "remoteRoot": "/app"
    }
]
```

### Logs Not Appearing

```python
import logging
logging.getLogger().setLevel(logging.DEBUG)
```

## Debug Workflows

### Workflow 1: Debug a Tool

```bash
# 1. Set environment
export DEBUG=true LOG_LEVEL=DEBUG

# 2. Run tool in isolation
python3 -c "
import asyncio
from src.main import reverse_shell
from src.models import ReverseShellInput

async def test():
    params = ReverseShellInput(
        shell_type='bash',
        lhost='127.0.0.1',
        lport=4444,
        encode=False
    )
    breakpoint()  # Add breakpoint
    result = await reverse_shell(params)
    print(result)

asyncio.run(test())
"
```

### Workflow 2: Debug Container Issues

```bash
# 1. Check logs
docker logs red-team-mcp-debug

# 2. Start shell in container
docker run -it --rm red-team-mcp:debug /bin/bash

# 3. Test manually
cd /app
python3 src/main.py
```

### Workflow 3: Trace Request Flow

```bash
# 1. Enable correlation IDs
export ENABLE_CORRELATION_IDS=true

# 2. Check logs with correlation ID
grep "correlation_id=abc-123" logs/*.log

# 3. Analyze flow
cat logs/app.log | jq 'select(.correlation_id=="abc-123")'
```

## Performance Debugging

```bash
# CPU profiling
python3 -m cProfile -s cumtime src/main.py

# Memory profiling
pip3 install memory_profiler
python3 -m memory_profiler src/main.py

# Async debugging
export PYTHONASYNCIODEBUG=1
```

## Security Reminders

⚠️ **NEVER LOG:**
- Passwords or credentials
- API keys or tokens
- Sensitive payload contents
- Personal identifiable information (PII)
- Encryption keys

✅ **DO LOG:**
- Authentication attempts (without credentials)
- Authorization decisions
- Tool usage metadata
- Error conditions
- Performance metrics

## Additional Resources

- **Full Guide**: [debugging-guide.md](debugging-guide.md)
- **Examples**: [../examples/secure_logging_demo.py](../examples/secure_logging_demo.py)
- **VS Code Debugging**: https://code.visualstudio.com/docs/python/debugging
- **Docker Debugging**: https://docs.docker.com/config/containers/debugging/
- **Python pdb**: https://docs.python.org/3/library/pdb.html

---

**Quick Tip**: Run `python3 examples/secure_logging_demo.py` to see working logging examples!
