# Debugging Guide for Red Team MCP Server

## Table of Contents
1. [Overview](#overview)
2. [Python/FastMCP Debugging](#pythonfastmcp-debugging)
3. [Docker Debugging](#docker-debugging)
4. [VS Code Remote Debugging](#vs-code-remote-debugging)
5. [Logging Best Practices](#logging-best-practices)
6. [Distributed Component Tracing](#distributed-component-tracing)
7. [Browser Development Tools](#browser-development-tools)
8. [Common Debugging Workflows](#common-debugging-workflows)
9. [Troubleshooting](#troubleshooting)

---

## Overview

This guide establishes a systematic debugging workflow for the Red Team MCP Server project. The project consists of:

- **Backend**: Python-based MCP server using the FastMCP framework
- **Infrastructure**: Docker containerization for consistent development and deployment
- **Security Focus**: Offensive security toolkit requiring careful handling of sensitive data

### Key Principles
- **Security First**: Never log sensitive information (credentials, tokens, payloads)
- **Structured Logging**: Use JSON-formatted logs with correlation IDs
- **Reproducibility**: Ensure debugging environments match production configurations
- **Isolation**: Debug in isolated environments to prevent security incidents

---

## Python/FastMCP Debugging

### Interactive Debugging with pdb

The Python debugger (pdb) provides command-line debugging capabilities:

```python
# Add breakpoint in code
import pdb; pdb.set_trace()

# Or use Python 3.7+ built-in breakpoint
breakpoint()
```

**Common pdb commands:**
```bash
n       # Next line
s       # Step into function
c       # Continue execution
p var   # Print variable
l       # List code around current line
w       # Show stack trace
q       # Quit debugger
```

### Enhanced Debugging with ipdb

For a better debugging experience, install and use ipdb:

```bash
pip install ipdb
```

```python
import ipdb; ipdb.set_trace()
```

### Debugging Async Code

FastMCP uses async/await patterns. Debug async functions carefully:

```python
import asyncio
import pdb

async def debug_async_function():
    # Set breakpoint in async function
    breakpoint()
    result = await some_async_operation()
    return result
```

**Tips for async debugging:**
- Use `await` properly when stepping through code
- Check event loop state with `asyncio.current_task()`
- Monitor pending tasks with `asyncio.all_tasks()`

### Debugging FastMCP Tools

To debug specific MCP tools:

```python
# In src/main.py or test file
async def test_tool():
    from src.main import reverse_shell
    from src.models import ReverseShellInput
    
    params = ReverseShellInput(
        shell_type="bash",
        lhost="127.0.0.1",
        lport=4444,
        encode=False
    )
    
    # Add breakpoint
    breakpoint()
    result = await reverse_shell(params)
    print(result)

# Run with asyncio
import asyncio
asyncio.run(test_tool())
```

### Python Logging for Debugging

Enable debug logging during development:

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.debug("Detailed debug information")
```

---

## Docker Debugging

### Building Debug Images

Create a debug-specific Dockerfile for enhanced debugging capabilities:

```dockerfile
# Dockerfile.debug
FROM kalilinux/kali-rolling

# Install debugging tools
RUN apt update && apt install -y \
    python3-flask \
    postgresql-client \
    python3-pip \
    python3-ipdb \
    strace \
    gdb \
    tcpdump \
    vim \
    net-tools

# Install Python debugging packages
RUN pip3 install --break-system-packages \
    ipdb \
    debugpy \
    httpx

COPY . /app
WORKDIR /app

# Expose debug port
EXPOSE 5678

# Run with debug configuration
CMD ["python3", "-m", "debugpy", "--listen", "0.0.0.0:5678", "--wait-for-client", "app.py"]
```

Build the debug image:

```bash
docker build -f Dockerfile.debug -t red-team-mcp:debug .
```

### Running Debug Containers

Run container with debugging enabled:

```bash
# Run with debug port exposed
docker run -it --rm \
  -p 3001:3001 \
  -p 5678:5678 \
  -v $(pwd):/app \
  --name red-team-mcp-debug \
  red-team-mcp:debug

# Run with interactive shell for manual debugging
docker run -it --rm \
  -v $(pwd):/app \
  --name red-team-mcp-debug \
  red-team-mcp:debug /bin/bash
```

### Docker Compose for Debugging

Create `docker-compose.debug.yml`:

```yaml
version: '3.8'

services:
  red-team-mcp:
    build:
      context: .
      dockerfile: Dockerfile.debug
    ports:
      - "3001:3001"
      - "5678:5678"  # Debug port
    volumes:
      - .:/app
      - ./logs:/app/logs
    environment:
      - DEBUG=true
      - LOG_LEVEL=DEBUG
      - PYTHONUNBUFFERED=1
    command: python3 -m debugpy --listen 0.0.0.0:5678 --wait-for-client src/main.py
```

Run with:

```bash
docker-compose -f docker-compose.debug.yml up
```

### Inspecting Running Containers

```bash
# View container logs
docker logs -f red-team-mcp-debug

# Execute commands in running container
docker exec -it red-team-mcp-debug /bin/bash

# Inspect container details
docker inspect red-team-mcp-debug

# Monitor container resource usage
docker stats red-team-mcp-debug
```

### Network Debugging

```bash
# Capture network traffic in container
docker exec red-team-mcp-debug tcpdump -i any -w /app/capture.pcap

# View container network settings
docker network inspect bridge
```

---

## VS Code Remote Debugging

### Setup for Local Python Debugging

Install the Python extension for VS Code, then create `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: FastMCP Server",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/src/main.py",
            "console": "integratedTerminal",
            "justMyCode": false,
            "env": {
                "PYTHONPATH": "${workspaceFolder}",
                "DEBUG": "true"
            }
        },
        {
            "name": "Python: Debug Current File",
            "type": "python",
            "request": "launch",
            "program": "${file}",
            "console": "integratedTerminal",
            "justMyCode": false
        },
        {
            "name": "Python: Debug Tests",
            "type": "python",
            "request": "launch",
            "module": "pytest",
            "args": [
                "-v",
                "-s",
                "${file}"
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        }
    ]
}
```

### Remote Debugging with Docker

1. **Install debugpy in container** (already in Dockerfile.debug)

2. **Configure VS Code** (`.vscode/launch.json`):

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Remote Attach (Docker)",
            "type": "python",
            "request": "attach",
            "connect": {
                "host": "localhost",
                "port": 5678
            },
            "pathMappings": [
                {
                    "localRoot": "${workspaceFolder}",
                    "remoteRoot": "/app"
                }
            ],
            "justMyCode": false
        }
    ]
}
```

3. **Start debugging**:
   - Start the Docker container with debug port exposed
   - Set breakpoints in VS Code
   - Run "Python: Remote Attach (Docker)" configuration
   - Execute code that triggers breakpoints

### Debugging with DevContainers

Create `.devcontainer/devcontainer.json`:

```json
{
    "name": "Red Team MCP Dev Container",
    "dockerFile": "../Dockerfile.debug",
    "customizations": {
        "vscode": {
            "extensions": [
                "ms-python.python",
                "ms-python.debugpy",
                "ms-azuretools.vscode-docker"
            ],
            "settings": {
                "python.defaultInterpreterPath": "/usr/bin/python3",
                "python.linting.enabled": true,
                "python.linting.pylintEnabled": false,
                "python.formatting.provider": "black"
            }
        }
    },
    "forwardPorts": [3001, 5678],
    "postCreateCommand": "pip3 install --break-system-packages -e .",
    "remoteUser": "root"
}
```

Open in DevContainer: `Cmd/Ctrl+Shift+P` → "Dev Containers: Reopen in Container"

---

## Logging Best Practices

### Structured Logging Implementation

Create a secure logging module (`src/utils/secure_logger.py`):

```python
import logging
import json
import re
from typing import Any, Dict
from datetime import datetime
import uuid

class SecureJSONFormatter(logging.Formatter):
    """JSON formatter that sanitizes sensitive data."""
    
    # Patterns for sensitive data
    SENSITIVE_PATTERNS = [
        r'password["\']?\s*[:=]\s*["\']?([^"\'}\s]+)',
        r'token["\']?\s*[:=]\s*["\']?([^"\'}\s]+)',
        r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'}\s]+)',
        r'secret["\']?\s*[:=]\s*["\']?([^"\'}\s]+)',
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # emails
    ]
    
    def sanitize_message(self, message: str) -> str:
        """Remove sensitive information from log messages."""
        for pattern in self.SENSITIVE_PATTERNS:
            message = re.sub(pattern, r'\1***REDACTED***', message, flags=re.IGNORECASE)
        return message
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with sanitization."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': self.sanitize_message(record.getMessage()),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add correlation ID if present
        if hasattr(record, 'correlation_id'):
            log_data['correlation_id'] = record.correlation_id
            
        # Add extra fields
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
            
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
            
        return json.dumps(log_data)

def setup_secure_logger(name: str, log_level: str = "INFO") -> logging.Logger:
    """Setup secure logger with JSON formatting."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(SecureJSONFormatter())
    logger.addHandler(console_handler)
    
    # File handler (for persistent logs)
    file_handler = logging.FileHandler('logs/app.log')
    file_handler.setFormatter(SecureJSONFormatter())
    logger.addHandler(file_handler)
    
    return logger

# Correlation ID context
class CorrelationContext:
    """Context manager for correlation IDs."""
    _correlation_id = None
    
    @classmethod
    def get_correlation_id(cls) -> str:
        """Get or create correlation ID."""
        if cls._correlation_id is None:
            cls._correlation_id = str(uuid.uuid4())
        return cls._correlation_id
    
    @classmethod
    def set_correlation_id(cls, correlation_id: str):
        """Set correlation ID."""
        cls._correlation_id = correlation_id
    
    @classmethod
    def clear(cls):
        """Clear correlation ID."""
        cls._correlation_id = None

# Logger adapter for correlation IDs
class CorrelationAdapter(logging.LoggerAdapter):
    """Logger adapter that adds correlation IDs."""
    
    def process(self, msg, kwargs):
        """Add correlation ID to log records."""
        correlation_id = CorrelationContext.get_correlation_id()
        if 'extra' not in kwargs:
            kwargs['extra'] = {}
        kwargs['extra']['correlation_id'] = correlation_id
        return msg, kwargs
```

### Usage Example

```python
from src.utils.secure_logger import setup_secure_logger, CorrelationAdapter, CorrelationContext

# Setup logger
logger = setup_secure_logger(__name__, log_level="DEBUG")
logger = CorrelationAdapter(logger, {})

# Use in code
CorrelationContext.set_correlation_id("req-123-456")
logger.info("Processing request", extra={"user_id": "user123", "action": "generate_payload"})
logger.debug("Payload parameters", extra={"shell_type": "bash", "port": 4444})

# Log without sensitive data
logger.info("Authentication successful")  # Good
# logger.info(f"User token: {token}")  # Bad - will be sanitized
```

### Log Levels and When to Use Them

```python
logger.debug("Detailed diagnostic information")     # Development only
logger.info("General informational messages")       # Normal operations
logger.warning("Warning messages")                  # Unexpected but handled
logger.error("Error messages")                      # Errors that need attention
logger.critical("Critical system failures")         # System-wide failures
```

### Security Considerations

**DO:**
- ✅ Log authentication attempts (success/failure) without credentials
- ✅ Log authorization decisions
- ✅ Log security-relevant events (payload generation, tool usage)
- ✅ Log error conditions and exceptions
- ✅ Use structured logging with correlation IDs
- ✅ Sanitize all log messages before writing

**DON'T:**
- ❌ Log passwords, tokens, or API keys
- ❌ Log sensitive payload contents
- ❌ Log personal identifiable information (PII)
- ❌ Log full request/response bodies with credentials
- ❌ Log encryption keys or secrets
- ❌ Log database connection strings with passwords

---

## Distributed Component Tracing

### OpenTelemetry Integration

Install OpenTelemetry:

```bash
pip install opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation
```

Create tracing configuration (`src/utils/tracing.py`):

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import Resource
import logging

def setup_tracing(service_name: str = "red-team-mcp"):
    """Setup OpenTelemetry tracing."""
    
    # Create resource
    resource = Resource.create({
        "service.name": service_name,
        "service.version": "1.0.0"
    })
    
    # Create tracer provider
    provider = TracerProvider(resource=resource)
    
    # Add span processor (Console exporter for debugging)
    processor = BatchSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)
    
    # Set as global tracer provider
    trace.set_tracer_provider(provider)
    
    return trace.get_tracer(__name__)

# Usage in code
tracer = setup_tracing()

@tracer.start_as_current_span("generate_payload")
async def generate_payload(params):
    """Generate payload with tracing."""
    span = trace.get_current_span()
    span.set_attribute("payload.type", params.shell_type)
    span.set_attribute("payload.port", params.lport)
    
    try:
        result = await _generate_payload_internal(params)
        span.set_attribute("result.success", True)
        return result
    except Exception as e:
        span.set_attribute("result.success", False)
        span.record_exception(e)
        raise
```

### Request Correlation

Track requests across components:

```python
from contextvars import ContextVar
import uuid

# Context variable for request ID
request_id_var: ContextVar[str] = ContextVar('request_id', default=None)

def get_request_id() -> str:
    """Get current request ID or generate new one."""
    request_id = request_id_var.get()
    if request_id is None:
        request_id = str(uuid.uuid4())
        request_id_var.set(request_id)
    return request_id

# Middleware to set request ID
async def request_id_middleware(request, call_next):
    """Middleware to add request ID to all requests."""
    request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    request_id_var.set(request_id)
    
    response = await call_next(request)
    response.headers['X-Request-ID'] = request_id
    return response
```

### Distributed Tracing Best Practices

1. **Always propagate context**: Pass correlation IDs between services
2. **Trace key operations**: Payload generation, tool execution, database queries
3. **Add meaningful attributes**: Operation type, parameters, results
4. **Record exceptions**: Always record exceptions in spans
5. **Sample wisely**: Use sampling to reduce overhead in production

---

## Browser Development Tools

### Preparing for Web Interface Debugging

While the current project doesn't have a React frontend, here's guidance for future web debugging:

#### Chrome/Firefox DevTools

**Console Debugging:**
```javascript
// Set breakpoints with debugger statement
debugger;

// Console logging with groups
console.group('API Request');
console.log('URL:', url);
console.log('Payload:', payload);
console.groupEnd();

// Table view for objects
console.table(data);

// Performance monitoring
console.time('API Call');
await fetchData();
console.timeEnd('API Call');
```

**Network Tab:**
- Monitor HTTP requests and responses
- Check request/response headers
- Inspect payload data
- Analyze timing and performance
- Filter by request type (XHR, Fetch, WS)

**React DevTools:**
```bash
# Install React DevTools browser extension
# Available for Chrome and Firefox
```

Features:
- Inspect component hierarchy
- View component props and state
- Profile component performance
- Track component updates

#### Security Testing in Browser

```javascript
// Check Content Security Policy
console.log(document.querySelector('meta[http-equiv="Content-Security-Policy"]'));

// Test for XSS vulnerabilities
// (Only in authorized testing environments)
console.log(document.cookie);
console.log(localStorage);

// Monitor WebSocket connections
// Use Network tab → WS filter
```

---

## Common Debugging Workflows

### Workflow 1: Debugging Tool Execution

**Scenario:** A MCP tool is not returning expected results

```bash
# Step 1: Enable debug logging
export DEBUG=true
export LOG_LEVEL=DEBUG

# Step 2: Run tool in isolation
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
    result = await reverse_shell(params)
    print(result)

asyncio.run(test())
"

# Step 3: Check logs
tail -f logs/app.log | jq .
```

### Workflow 2: Debugging Docker Container Issues

**Scenario:** Container crashes or doesn't start

```bash
# Step 1: Check container logs
docker logs red-team-mcp-debug

# Step 2: Inspect container
docker inspect red-team-mcp-debug | jq '.[0].State'

# Step 3: Start container with shell
docker run -it --rm red-team-mcp:debug /bin/bash

# Step 4: Test components manually
cd /app
python3 src/main.py

# Step 5: Check dependencies
pip3 list | grep fastmcp
```

### Workflow 3: Debugging Performance Issues

**Scenario:** Tool execution is slow

```bash
# Step 1: Profile with cProfile
python3 -m cProfile -o profile.stats src/main.py

# Step 2: Analyze with pstats
python3 -c "
import pstats
stats = pstats.Stats('profile.stats')
stats.sort_stats('cumulative')
stats.print_stats(20)
"

# Step 3: Use line_profiler for detailed analysis
pip3 install line_profiler
kernprof -l -v src/main.py

# Step 4: Memory profiling
pip3 install memory_profiler
python3 -m memory_profiler src/main.py
```

### Workflow 4: Debugging Async Issues

**Scenario:** Async operations hanging or not completing

```python
import asyncio
import logging

# Enable asyncio debug mode
logging.basicConfig(level=logging.DEBUG)

# Get event loop and enable debug
loop = asyncio.get_event_loop()
loop.set_debug(True)

# Check pending tasks
async def debug_tasks():
    tasks = asyncio.all_tasks()
    for task in tasks:
        print(f"Task: {task.get_name()}, Done: {task.done()}")
        if not task.done():
            print(f"  Stack: {task.get_stack()}")

# Run with timeout
try:
    await asyncio.wait_for(operation(), timeout=5.0)
except asyncio.TimeoutError:
    print("Operation timed out")
    await debug_tasks()
```

### Workflow 5: Debugging Integration Issues

**Scenario:** Multiple components not communicating correctly

```bash
# Step 1: Enable correlation IDs
export ENABLE_CORRELATION_IDS=true

# Step 2: Check each component
docker-compose logs -f service1
docker-compose logs -f service2

# Step 3: Trace request flow
grep "correlation_id=abc-123" logs/*.log

# Step 4: Network debugging
docker network inspect red-team-mcp_default
docker exec service1 ping service2
docker exec service1 curl http://service2:3001/health
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: Import Errors

```bash
# Problem: "ModuleNotFoundError: No module named 'fastmcp'"

# Solution 1: Install dependencies
pip3 install -e .
# or
pip3 install fastmcp httpx pydantic

# Solution 2: Check PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/app"
```

#### Issue: Async Event Loop Errors

```python
# Problem: "RuntimeError: Event loop is closed"

# Solution: Use asyncio.run() instead of loop.run_until_complete()
# Bad:
loop = asyncio.get_event_loop()
loop.run_until_complete(main())

# Good:
asyncio.run(main())
```

#### Issue: Docker Container Permission Errors

```bash
# Problem: Permission denied errors in container

# Solution 1: Run as root (for development only)
docker run --user root ...

# Solution 2: Fix volume permissions
sudo chown -R $(id -u):$(id -g) ./logs
```

#### Issue: Breakpoints Not Hit in VS Code

```json
// Problem: Breakpoints in Docker container not working

// Solution: Ensure path mappings are correct
{
    "pathMappings": [
        {
            "localRoot": "${workspaceFolder}",
            "remoteRoot": "/app"  // Must match container workdir
        }
    ]
}
```

#### Issue: Logs Not Appearing

```python
# Problem: Logger not producing output

# Solution 1: Check log level
import logging
logging.getLogger().setLevel(logging.DEBUG)

# Solution 2: Ensure handler is added
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
logger.addHandler(handler)

# Solution 3: Flush output
import sys
sys.stdout.flush()
```

### Debug Mode Environment Variables

Set these environment variables for enhanced debugging:

```bash
# General debugging
export DEBUG=true
export LOG_LEVEL=DEBUG
export PYTHONUNBUFFERED=1

# Asyncio debugging
export PYTHONASYNCIODEBUG=1

# Memory debugging
export PYTHONMALLOC=debug

# Show deprecation warnings
export PYTHONWARNINGS=all
```

### Performance Debugging

```bash
# CPU profiling
python3 -m cProfile -s cumtime src/main.py > profile.txt

# Memory profiling
python3 -m memory_profiler src/main.py

# Track memory leaks
python3 -m tracemalloc src/main.py
```

### Security Testing Tools

```bash
# Static analysis
pip3 install bandit
bandit -r src/

# Dependency vulnerabilities
pip3 install safety
safety check

# Code quality
pip3 install pylint
pylint src/
```

---

## Additional Resources

### Documentation Links
- [Python Debugging with pdb](https://docs.python.org/3/library/pdb.html)
- [VS Code Python Debugging](https://code.visualstudio.com/docs/python/debugging)
- [Docker Debugging Guide](https://docs.docker.com/config/containers/debugging/)
- [OpenTelemetry Python](https://opentelemetry.io/docs/instrumentation/python/)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)

### Recommended Tools
- **ipdb**: Enhanced Python debugger
- **debugpy**: Remote debugging for Python
- **httpx**: HTTP client with debugging support
- **OpenTelemetry**: Distributed tracing
- **Jaeger**: Trace visualization
- **Prometheus**: Metrics collection

### Debug Checklist

Before starting debugging:
- [ ] Review error messages and stack traces
- [ ] Check logs for correlation IDs
- [ ] Verify environment configuration
- [ ] Ensure dependencies are installed
- [ ] Test in isolated environment first
- [ ] Enable appropriate log levels
- [ ] Set up proper breakpoints
- [ ] Sanitize any sensitive data in logs

---

## Security Reminders

⚠️ **CRITICAL SECURITY CONSIDERATIONS**

1. **Never commit debug configurations to production**
2. **Always sanitize logs before sharing**
3. **Disable debug mode in production environments**
4. **Use isolated networks for debugging**
5. **Clear sensitive data from memory after debugging**
6. **Rotate any exposed credentials immediately**
7. **Review logs for accidental data exposure**
8. **Use debug containers only in secure environments**

---

## Maintenance

This debugging guide should be reviewed and updated:
- When new components are added to the project
- When debugging tools or practices change
- After security incidents involving logging
- Quarterly as part of documentation review

**Last Updated:** November 2025
**Maintainers:** Security Team
**Contact:** security@example.com
