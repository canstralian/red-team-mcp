# Red Team MCP Debugging Guide

## Table of Contents
- [Overview](#overview)
- [Python/FastMCP Debugging](#pythonfastmcp-debugging)
- [Docker Debugging](#docker-debugging)
- [VS Code Remote Debugging](#vs-code-remote-debugging)
- [Secure Logging Practices](#secure-logging-practices)
- [Distributed Component Tracing](#distributed-component-tracing)
- [Common Issues and Troubleshooting](#common-issues-and-troubleshooting)

## Overview

This guide provides a systematic debugging workflow for the Red Team MCP Server project. It covers debugging tools and techniques for Python applications, Docker containers, and distributed systems while ensuring security and operational safety.

### Quick Start Checklist
- [ ] Configure VS Code debugging (see `.vscode/launch.json`)
- [ ] Enable secure logging (see `src/utils/secure_logger.py`)
- [ ] Set appropriate log levels (`DEBUG` for development, `INFO` for production)
- [ ] Use structured logging for distributed tracing
- [ ] Never log sensitive data (credentials, tokens, PII)

## Python/FastMCP Debugging

### Local Development Debugging

#### Using Python Debugger (pdb)

Insert breakpoints in your code:
```python
import pdb; pdb.set_trace()
```

Or use the newer `breakpoint()` built-in (Python 3.7+):
```python
breakpoint()  # Automatically calls pdb.set_trace()
```

**Common pdb Commands:**
- `n` (next): Execute next line
- `s` (step): Step into function
- `c` (continue): Continue execution
- `l` (list): Show current code
- `p <var>` (print): Print variable value
- `pp <var>` (pretty print): Pretty print variable
- `w` (where): Show stack trace
- `q` (quit): Exit debugger

#### Using VS Code Debugger

1. Set breakpoints by clicking left of line numbers
2. Press `F5` or select "Run > Start Debugging"
3. Choose "Python: FastMCP Server" configuration
4. Use Debug toolbar to step through code

**VS Code Debug Features:**
- Variables panel: Inspect all variables in scope
- Watch expressions: Monitor specific expressions
- Call stack: Navigate execution context
- Debug console: Execute Python expressions in current context

### FastMCP Server Debugging

#### Enable Debug Mode

Set environment variable:
```bash
export MCP_DEBUG=1
export PYTHONUNBUFFERED=1
```

#### Run with Verbose Logging

```bash
python -u src/main.py --host localhost --port 3001
```

The `-u` flag disables output buffering for real-time log visibility.

#### Debug MCP Tools

To debug specific MCP tools:

```python
# In src/main.py or tool files
import logging
logger = logging.getLogger(__name__)

@mcp.tool(name="example_tool")
async def example_tool(params: ExampleInput) -> str:
    logger.debug(f"Tool called with params: {params}")
    try:
        result = process_data(params)
        logger.debug(f"Processing result: {result}")
        return result
    except Exception as e:
        logger.error(f"Error in tool: {e}", exc_info=True)
        raise
```

## Docker Debugging

### Build with Debug Flags

```dockerfile
# Add to Dockerfile for debugging
ENV PYTHONUNBUFFERED=1
ENV MCP_DEBUG=1

# Install debugging tools
RUN apt update && apt install -y \
    gdb \
    strace \
    tcpdump \
    net-tools \
    iputils-ping
```

### Run Container with Debug Options

```bash
# Run with interactive terminal
docker run -it --rm \
  -p 3001:3001 \
  -e PYTHONUNBUFFERED=1 \
  -e MCP_DEBUG=1 \
  redteam-mcp:latest

# Run with volume mount for live code changes
docker run -it --rm \
  -p 3001:3001 \
  -v $(pwd)/src:/app/src \
  -e PYTHONUNBUFFERED=1 \
  redteam-mcp:latest

# Run with shell access (override entrypoint)
docker run -it --rm \
  --entrypoint /bin/bash \
  redteam-mcp:latest
```

### Debug Running Container

```bash
# Get container ID
docker ps

# Access running container
docker exec -it <container_id> /bin/bash

# View logs
docker logs -f <container_id>

# View last 100 lines
docker logs --tail 100 <container_id>

# Inspect container
docker inspect <container_id>
```

### Network Debugging

```bash
# Inside container, test network connectivity
ping google.com
nslookup example.com
curl -v http://example.com

# Check listening ports
netstat -tlnp
ss -tlnp

# Capture network traffic
tcpdump -i any -w /tmp/capture.pcap
```

### Process Debugging

```bash
# Trace system calls
strace -p <pid>

# Attach GDB to running process (for C extensions)
gdb -p <pid>
```

## VS Code Remote Debugging

### Remote Debugging Setup

#### 1. Install debugpy in Container

Add to your Docker image:
```dockerfile
RUN pip install debugpy
```

#### 2. Configure Remote Debugging

Modify your application to listen for debugger:

```python
# src/main.py
import debugpy

def main():
    # Enable remote debugging
    if os.environ.get('ENABLE_REMOTE_DEBUG'):
        debugpy.listen(("0.0.0.0", 5678))
        print("⏳ Waiting for debugger to attach...")
        debugpy.wait_for_client()
        print("✅ Debugger attached!")
    
    # Start your application
    asyncio.run(mcp.run())
```

#### 3. Run Container with Debug Port

```bash
docker run -it --rm \
  -p 3001:3001 \
  -p 5678:5678 \
  -e ENABLE_REMOTE_DEBUG=1 \
  redteam-mcp:latest
```

#### 4. Attach VS Code Debugger

Use the "Python: Remote Attach" configuration in `.vscode/launch.json`.

### Docker Compose Debugging

```yaml
# docker-compose.debug.yml
version: '3.8'
services:
  redteam-mcp:
    build: .
    ports:
      - "3001:3001"
      - "5678:5678"  # Debug port
    environment:
      - PYTHONUNBUFFERED=1
      - MCP_DEBUG=1
      - ENABLE_REMOTE_DEBUG=1
    volumes:
      - ./src:/app/src
```

Run with: `docker-compose -f docker-compose.debug.yml up`

## Secure Logging Practices

### Critical Security Rules

**⚠️ NEVER LOG:**
- Passwords, API keys, tokens
- Credit card numbers, SSNs, PII
- Session cookies or authentication tokens
- Encryption keys or secrets
- Full SQL queries with sensitive data
- Stack traces in production (only in development)

### Secure Logger Usage

Use the provided secure logger utility:

```python
from src.utils.secure_logger import get_secure_logger, mask_sensitive_data

logger = get_secure_logger(__name__)

# Good: Log without sensitive data
logger.info("User authentication attempt", extra={
    "username": username,
    "ip_address": ip_address,
    "success": True
})

# Bad: Don't do this
logger.info(f"Login: {username}:{password}")  # ❌ Never log passwords!

# Good: Mask sensitive data
safe_config = mask_sensitive_data(config)
logger.debug(f"Configuration loaded: {safe_config}")
```

### Log Levels

Use appropriate log levels:

```python
logger.debug("Detailed diagnostic information")     # Development only
logger.info("General informational messages")       # Normal operation
logger.warning("Warning messages, degraded state")  # Potential issues
logger.error("Error messages, operation failed")    # Errors
logger.critical("Critical issues, system failure")  # Critical failures
```

### Structured Logging

Use structured logging for better parsing and analysis:

```python
logger.info(
    "MCP tool executed",
    extra={
        "tool_name": "redteam_reverse_shell",
        "duration_ms": elapsed_time * 1000,
        "status": "success",
        "user_id": user_id  # Only if not PII
    }
)
```

### Log Rotation and Retention

Configure log rotation to prevent disk filling:

```python
import logging.handlers

handler = logging.handlers.RotatingFileHandler(
    'redteam-mcp.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
```

Or use time-based rotation:

```python
handler = logging.handlers.TimedRotatingFileHandler(
    'redteam-mcp.log',
    when='midnight',
    interval=1,
    backupCount=7
)
```

## Distributed Component Tracing

### Correlation IDs

Use correlation IDs to trace requests across components:

```python
import uuid

def generate_correlation_id():
    return str(uuid.uuid4())

# In your handler
correlation_id = generate_correlation_id()
logger.info(
    "Request started",
    extra={"correlation_id": correlation_id}
)

# Pass correlation_id to downstream services
response = await downstream_service.call(
    data=payload,
    headers={"X-Correlation-ID": correlation_id}
)

logger.info(
    "Request completed",
    extra={"correlation_id": correlation_id}
)
```

### Request Context Logging

Use context managers for automatic context logging:

```python
from contextlib import contextmanager
import logging

@contextmanager
def request_context(correlation_id, operation):
    """Context manager for request logging."""
    logger = logging.getLogger(__name__)
    logger.info(
        f"Starting {operation}",
        extra={"correlation_id": correlation_id}
    )
    start_time = time.time()
    try:
        yield
    except Exception as e:
        logger.error(
            f"Failed {operation}",
            extra={
                "correlation_id": correlation_id,
                "error": str(e),
                "duration_ms": (time.time() - start_time) * 1000
            }
        )
        raise
    else:
        logger.info(
            f"Completed {operation}",
            extra={
                "correlation_id": correlation_id,
                "duration_ms": (time.time() - start_time) * 1000
            }
        )

# Usage
with request_context(correlation_id, "payload_generation"):
    result = generate_payload(params)
```

### Distributed Tracing with OpenTelemetry (Optional)

For advanced distributed tracing:

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

# Setup tracer
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

# Add spans to your operations
with tracer.start_as_current_span("generate_payload") as span:
    span.set_attribute("payload.type", payload_type)
    result = generate_payload(params)
    span.set_attribute("payload.size", len(result))
```

### Performance Profiling

#### Using cProfile

```bash
python -m cProfile -o profile.stats src/main.py
python -m pstats profile.stats
```

In pstats interactive mode:
```
sort cumulative
stats 20
```

#### Using line_profiler

```bash
pip install line_profiler

# Add @profile decorator to functions
@profile
def expensive_function():
    # Your code here
    pass

# Run profiler
kernprof -l -v src/main.py
```

#### Memory Profiling

```bash
pip install memory_profiler

# Profile memory usage
python -m memory_profiler src/main.py
```

### Async Debugging

#### Debug Async Code

```python
import asyncio

# Enable asyncio debug mode
asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
loop = asyncio.get_event_loop()
loop.set_debug(True)

# Detect slow coroutines
import warnings
warnings.simplefilter('always', ResourceWarning)
```

#### Debug Hanging Async Tasks

```python
# List all running tasks
import asyncio

async def debug_tasks():
    tasks = [t for t in asyncio.all_tasks() if not t.done()]
    for task in tasks:
        print(f"Task: {task.get_name()}, {task}")
        task.print_stack()
```

## Common Issues and Troubleshooting

### Issue: MCP Server Not Starting

**Symptoms:** Server fails to start or exits immediately

**Debug Steps:**
1. Check Python version: `python --version` (requires >=3.8)
2. Verify dependencies: `pip list | grep -E "fastmcp|httpx|pydantic"`
3. Run with verbose logging: `python -u src/main.py`
4. Check for port conflicts: `lsof -i :3001` or `netstat -an | grep 3001`

**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Use different port
python src/main.py --port 3002
```

### Issue: Docker Container Crashes

**Symptoms:** Container exits unexpectedly

**Debug Steps:**
1. Check container logs: `docker logs <container_id>`
2. Check exit code: `docker inspect <container_id> | grep ExitCode`
3. Run interactively: `docker run -it --entrypoint /bin/bash redteam-mcp`
4. Check resource limits: `docker stats`

**Common Exit Codes:**
- 0: Success (normal exit)
- 1: Application error
- 137: Out of memory (OOM killed)
- 139: Segmentation fault
- 143: SIGTERM (graceful shutdown)

### Issue: Remote Debugging Not Connecting

**Symptoms:** VS Code cannot attach to remote debugger

**Debug Steps:**
1. Verify debugpy is installed: `pip list | grep debugpy`
2. Check port is exposed: `docker ps` (verify 5678 is listed)
3. Check firewall rules: `telnet localhost 5678`
4. Verify debugpy is listening: Inside container, `netstat -tlnp | grep 5678`

**Solution:**
```python
# Add timeout to wait_for_client
import debugpy
debugpy.listen(("0.0.0.0", 5678))
debugpy.wait_for_client(timeout=30)  # Wait max 30 seconds
```

### Issue: Performance Degradation

**Symptoms:** Slow response times, high CPU/memory usage

**Debug Steps:**
1. Profile the application: `python -m cProfile src/main.py`
2. Monitor resources: `docker stats` or `htop`
3. Check for memory leaks: Use `memory_profiler`
4. Analyze slow queries/operations

**Solution:**
- Add caching for frequently accessed data
- Optimize database queries
- Use connection pooling
- Implement rate limiting

### Issue: Logs Not Appearing

**Symptoms:** No log output or missing log entries

**Debug Steps:**
1. Check log level: `echo $LOG_LEVEL`
2. Verify logger configuration
3. Check for buffering issues: Set `PYTHONUNBUFFERED=1`
4. Check log file permissions

**Solution:**
```bash
export PYTHONUNBUFFERED=1
export LOG_LEVEL=DEBUG
python src/main.py
```

### Issue: Import Errors in Docker

**Symptoms:** `ModuleNotFoundError` in Docker but works locally

**Debug Steps:**
1. Verify PYTHONPATH: `echo $PYTHONPATH`
2. Check working directory: `pwd`
3. List installed packages: `pip list`
4. Verify file structure matches imports

**Solution:**
```dockerfile
# In Dockerfile, ensure proper PYTHONPATH
ENV PYTHONPATH=/app/src:$PYTHONPATH
WORKDIR /app
```

## Best Practices Summary

### Development
- ✅ Use VS Code debugger instead of print statements
- ✅ Enable debug logging in development
- ✅ Test in Docker to match production environment
- ✅ Use virtual environments
- ✅ Keep dependencies updated

### Production
- ✅ Set log level to INFO or WARNING
- ✅ Enable log rotation
- ✅ Monitor system resources
- ✅ Use structured logging
- ✅ Implement health checks

### Security
- ✅ Never log sensitive data
- ✅ Use secure logger utilities
- ✅ Sanitize error messages
- ✅ Rotate logs regularly
- ✅ Restrict log access

### Performance
- ✅ Profile before optimizing
- ✅ Use async operations appropriately
- ✅ Implement caching strategically
- ✅ Monitor resource usage
- ✅ Load test critical paths

## Additional Resources

- [Python Debugging Documentation](https://docs.python.org/3/library/pdb.html)
- [VS Code Python Debugging](https://code.visualstudio.com/docs/python/debugging)
- [Docker Debugging Guide](https://docs.docker.com/config/containers/logging/)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
