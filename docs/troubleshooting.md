# Red Team MCP Troubleshooting Guide

## Quick Diagnostics Script

Run this script to quickly diagnose common issues:

```bash
#!/bin/bash
# diagnostics.sh - Quick diagnostics for Red Team MCP Server

echo "=== Red Team MCP Server Diagnostics ==="
echo ""

echo "1. Python Version:"
python3 --version
echo ""

echo "2. Python Path:"
which python3
echo ""

echo "3. Installed Python Packages:"
pip3 list | grep -E "fastmcp|httpx|pydantic|debugpy"
echo ""

echo "4. Environment Variables:"
echo "PYTHONUNBUFFERED: ${PYTHONUNBUFFERED:-not set}"
echo "MCP_DEBUG: ${MCP_DEBUG:-not set}"
echo "LOG_LEVEL: ${LOG_LEVEL:-not set}"
echo ""

echo "5. Port 3001 Status:"
lsof -i :3001 || echo "Port 3001 is available"
echo ""

echo "6. Docker Status:"
docker --version 2>/dev/null || echo "Docker not installed"
docker ps 2>/dev/null | grep redteam || echo "No redteam containers running"
echo ""

echo "7. Disk Space:"
df -h . | tail -1
echo ""

echo "8. Memory Usage:"
free -h 2>/dev/null || echo "free command not available"
echo ""

echo "=== End Diagnostics ==="
```

## Problem: Import Errors

### Symptom
```
ModuleNotFoundError: No module named 'mcp'
ModuleNotFoundError: No module named 'src.models'
```

### Solutions

#### Solution 1: Install Dependencies
```bash
pip3 install -e .
# OR
pip3 install fastmcp httpx pydantic
```

#### Solution 2: Fix PYTHONPATH
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python3 src/main.py
```

#### Solution 3: Use Module Syntax
```bash
python3 -m src.main
```

## Problem: MCP Server Not Responding

### Symptom
Server starts but doesn't respond to requests, or connection refused errors.

### Solutions

#### Solution 1: Check if Server is Running
```bash
ps aux | grep python
netstat -tlnp | grep 3001
# OR
lsof -i :3001
```

#### Solution 2: Check Firewall
```bash
# Allow port 3001
sudo ufw allow 3001
# OR
sudo iptables -A INPUT -p tcp --dport 3001 -j ACCEPT
```

#### Solution 3: Bind to Correct Interface
```bash
# Bind to all interfaces
python3 src/main.py --host 0.0.0.0 --port 3001
```

## Problem: Docker Container Exits Immediately

### Symptom
```bash
docker run redteam-mcp:latest
# Container exits immediately
```

### Solutions

#### Solution 1: Check Logs
```bash
docker logs $(docker ps -a | grep redteam-mcp | awk '{print $1}')
```

#### Solution 2: Run Interactively
```bash
docker run -it redteam-mcp:latest /bin/bash
# Then manually run the application
python3 src/main.py
```

#### Solution 3: Check Dockerfile CMD
Ensure your Dockerfile has a valid CMD or ENTRYPOINT:
```dockerfile
CMD ["python3", "src/main.py"]
```

## Problem: Remote Debugging Not Working

### Symptom
VS Code shows "Cannot connect to runtime process, timeout after 10000 ms"

### Solutions

#### Solution 1: Verify debugpy is Running
Inside container:
```bash
docker exec -it <container_id> /bin/bash
netstat -tlnp | grep 5678
# Should show debugpy listening on port 5678
```

#### Solution 2: Check Port Forwarding
```bash
# Ensure port 5678 is exposed
docker ps
# Should show 0.0.0.0:5678->5678/tcp

# Test connection
telnet localhost 5678
```

#### Solution 3: Increase Timeout
In `.vscode/launch.json`:
```json
{
  "name": "Python: Remote Attach",
  "type": "debugpy",
  "request": "attach",
  "connect": {
    "host": "localhost",
    "port": 5678
  },
  "timeout": 30000  // Increase to 30 seconds
}
```

#### Solution 4: Use debugpy CLI
Start debugpy manually:
```bash
python3 -m debugpy --listen 0.0.0.0:5678 --wait-for-client -m src.main
```

## Problem: Async Debugging Issues

### Symptom
Breakpoints not hitting in async functions, or debugger hanging.

### Solutions

#### Solution 1: Enable Async Debug Mode
```python
import asyncio
loop = asyncio.get_event_loop()
loop.set_debug(True)
```

#### Solution 2: Use asyncio-compatible Debugger
```python
import asyncio
import debugpy

async def main():
    # Your async code
    pass

if __name__ == "__main__":
    debugpy.listen(("0.0.0.0", 5678))
    debugpy.wait_for_client()
    asyncio.run(main())
```

#### Solution 3: Check for Event Loop Issues
```python
# Debug event loop tasks
import asyncio

async def debug_tasks():
    tasks = asyncio.all_tasks()
    for task in tasks:
        print(f"Task: {task.get_name()}")
        task.print_stack()
```

## Problem: No Log Output

### Symptom
Application runs but no logs appear in console or file.

### Solutions

#### Solution 1: Set Log Level
```bash
export LOG_LEVEL=DEBUG
python3 src/main.py
```

#### Solution 2: Disable Buffering
```bash
export PYTHONUNBUFFERED=1
python3 -u src/main.py
```

#### Solution 3: Check Logger Configuration
```python
from src.utils.secure_logger import get_secure_logger, setup_root_logger

# Setup root logger at application start
setup_root_logger(level='DEBUG', log_file='app.log')

# Get logger in your modules
logger = get_secure_logger(__name__)
logger.debug("This is a debug message")
```

## Problem: Performance Issues

### Symptom
Slow response times, high CPU or memory usage.

### Solutions

#### Solution 1: Profile the Application
```bash
# CPU profiling
python3 -m cProfile -o profile.stats src/main.py
python3 -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(20)"

# Memory profiling
pip3 install memory-profiler
python3 -m memory_profiler src/main.py
```

#### Solution 2: Monitor Resources
```bash
# Monitor Docker container resources
docker stats

# Monitor system resources
htop
# OR
top
```

#### Solution 3: Check for Memory Leaks
```python
import tracemalloc

tracemalloc.start()

# Your code here

current, peak = tracemalloc.get_traced_memory()
print(f"Current memory usage: {current / 10**6}MB")
print(f"Peak memory usage: {peak / 10**6}MB")
tracemalloc.stop()
```

## Problem: Test Failures

### Symptom
Tests fail when run via unittest or pytest.

### Solutions

#### Solution 1: Run Tests with Verbose Output
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

#### Solution 2: Run Specific Test
```bash
python3 -m unittest tests.verification.test_time_integrity.TestTimeIntegrityChecker.test_sdwdate_high_confidence
```

#### Solution 3: Check Test Dependencies
Ensure test fixtures and mocks are properly set up:
```python
# In test file
import unittest
from unittest.mock import patch, MagicMock

class TestExample(unittest.TestCase):
    def setUp(self):
        # Setup test fixtures
        pass
    
    def tearDown(self):
        # Cleanup after tests
        pass
```

## Problem: Docker Build Failures

### Symptom
```
ERROR: failed to solve: process "/bin/sh -c apt update" did not complete successfully
```

### Solutions

#### Solution 1: Clear Docker Cache
```bash
docker system prune -a
docker build --no-cache -t redteam-mcp:latest .
```

#### Solution 2: Fix APT Sources
Update Dockerfile:
```dockerfile
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
```

#### Solution 3: Use Specific Base Image
```dockerfile
FROM kalilinux/kali-rolling:latest
```

## Problem: Network Issues in Docker

### Symptom
Cannot connect to external services from inside Docker container.

### Solutions

#### Solution 1: Check DNS
```bash
docker exec -it <container_id> /bin/bash
cat /etc/resolv.conf
ping 8.8.8.8
ping google.com
```

#### Solution 2: Use Host Network
```bash
docker run --network host redteam-mcp:latest
```

#### Solution 3: Configure Docker DNS
In `/etc/docker/daemon.json`:
```json
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
```

Then restart Docker:
```bash
sudo systemctl restart docker
```

## Problem: Permission Denied Errors

### Symptom
```
PermissionError: [Errno 13] Permission denied: '/app/logs/app.log'
```

### Solutions

#### Solution 1: Fix File Permissions
```bash
# On host
chmod -R 755 logs/
chown -R $(id -u):$(id -g) logs/

# In Dockerfile
RUN mkdir -p /app/logs && chmod 777 /app/logs
```

#### Solution 2: Run as Non-root User
```dockerfile
# In Dockerfile
RUN useradd -m -u 1000 appuser
USER appuser
```

#### Solution 3: Use Docker Volumes
```bash
docker run -v $(pwd)/logs:/app/logs redteam-mcp:latest
```

## Debugging Checklist

When encountering issues, work through this checklist:

- [ ] Check error messages and stack traces
- [ ] Verify Python version (>=3.8)
- [ ] Confirm all dependencies are installed
- [ ] Check environment variables are set
- [ ] Verify ports are available (not in use)
- [ ] Check firewall rules
- [ ] Review logs (application and system)
- [ ] Test with minimal configuration
- [ ] Try in different environment (local vs Docker)
- [ ] Check for recent code changes
- [ ] Review Docker logs if using containers
- [ ] Verify network connectivity
- [ ] Check disk space and memory
- [ ] Review recent system updates
- [ ] Test with debug mode enabled

## Getting Help

If you still need help after trying these solutions:

1. **Gather Information**
   - Error messages and full stack traces
   - Output from diagnostics script
   - Version information (Python, Docker, OS)
   - Steps to reproduce the issue
   - Expected vs actual behavior

2. **Check Documentation**
   - README.md
   - docs/debugging-guide.md
   - Code comments and docstrings

3. **Search Issues**
   - Check GitHub issues for similar problems
   - Search Stack Overflow

4. **Create Minimal Reproduction**
   - Isolate the problem
   - Create smallest possible example
   - Remove unrelated code

5. **File an Issue**
   - Provide all gathered information
   - Include reproduction steps
   - Attach relevant logs
   - Mention what you've already tried

## Additional Resources

- [Python Debugging with pdb](https://docs.python.org/3/library/pdb.html)
- [VS Code Python Debugging](https://code.visualstudio.com/docs/python/debugging)
- [Docker Debugging Guide](https://docs.docker.com/config/containers/logging/)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [asyncio Debugging](https://docs.python.org/3/library/asyncio-dev.html)
