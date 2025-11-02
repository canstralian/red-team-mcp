# Red Team MCP Server Architecture

## Red Team MCP Server Requirements

The Red Team MCP Server must deliver comprehensive offensive security capabilities while maintaining operational security through advanced stealth, resilience, and attack methodologies:

### Core Requirements:
- **Stealth Operations**: Traffic obfuscation, domain fronting, encrypted C2 channels
- **Resilience**: Distributed architecture, automatic failover, data replication
- **Advanced Attacks**: Custom payload delivery, exploitation modules, post-exploitation tools
- **Operational Security**: Anti-forensics, log sanitization, secure communications
- **Scalability**: Multi-target campaign management, resource optimization
- **Legal Compliance**: Audit trails, authorization verification, scope enforcement

## Kali MCP Server Baseline

The existing MCP server provides a solid foundation with:

### Current Capabilities:
- **Payload Generation**: Reverse shells (Bash, Python, PowerShell, PHP, etc.)
- **Web Shell Creation**: Multi-language web shells with obfuscation
- **SQLi Payloads**: Database-specific injection vectors
- **XSS Generation**: Cross-site scripting with filter bypasses
- **Privilege Escalation**: Enumeration commands for Linux/Windows
- **Credential Spraying**: Service-specific brute force frameworks

### Architecture Strengths:
- Modular tool design with FastMCP framework
- Pydantic input validation for security
- Multi-format output support (Markdown/JSON)
- Comprehensive payload obfuscation methods

## Design Enhancement 1: Stealth and Obfuscation

### Traffic Shaping and Protocol Obfuscation
- **Domain Fronting**: Route C2 traffic through legitimate CDN endpoints
- **Protocol Mimicry**: Disguise malicious traffic as HTTPS, DNS, or other protocols
- **Traffic Randomization**: Variable timing, packet sizes, and communication patterns
- **Encrypted Channels**: End-to-end encryption with custom key exchange

### Implementation Details and Security Considerations for Enhancement 1

**Traffic Obfuscation Layer:**
- Implement domain fronting using major CDNs (CloudFlare, AWS CloudFront)
- Use DNS-over-HTTPS tunneling for covert channel establishment
- Deploy custom TLS fingerprinting to mimic legitimate applications
- Integrate jitter and sleep randomization to avoid pattern detection

**Security Considerations:**
- Regularly rotate domain fronts and infrastructure
- Implement certificate pinning bypass techniques
- Monitor for DNS sinkholing and traffic inspection
- Use ephemeral encryption keys with perfect forward secrecy

## Development and Debugging

### Debugging Workflow

The project includes comprehensive debugging support for Python, Docker, and distributed systems:

- **[Debugging Guide](docs/debugging-guide.md)** - Complete debugging workflow documentation
  - Python/FastMCP debugging with pdb and VS Code
  - Docker container debugging techniques
  - Remote debugging setup for containers
  - Secure logging practices to prevent sensitive data exposure
  - Distributed component tracing with correlation IDs
  - Performance profiling and optimization

- **[Troubleshooting Guide](docs/troubleshooting.md)** - Common issues and solutions
  - Quick diagnostic scripts
  - Step-by-step problem resolution
  - Docker debugging checklist
  - Network and permission issues

### VS Code Setup

Pre-configured debugging setups are available in `.vscode/`:

```bash
# Quick start
code .  # Open project in VS Code
# Install recommended extensions when prompted
# Press F5 to start debugging with default configuration
```

**Available debug configurations:**
- Python: FastMCP Server - Debug the main application
- Python: Run Tests - Debug unit tests
- Python: Remote Attach (Docker) - Attach to containerized app

### Secure Logging

The project includes secure logging utilities that automatically mask sensitive data:

```python
from src.utils.secure_logger import get_secure_logger, mask_sensitive_data

logger = get_secure_logger(__name__)
logger.info("User login: password=secret")  # Automatically masks password

# Example output
python3 examples/secure_logging_example.py
```

**Security Features:**
- Automatic masking of passwords, API keys, tokens, and PII
- Structured logging with correlation IDs for distributed tracing
- Log rotation and retention policies
- Production-safe defaults

### Docker Debugging

Debug-enabled Docker setup:

```bash
# Build debug image with debugging tools
docker build -f Dockerfile.debug -t redteam-mcp:debug .

# Run with remote debugging enabled
docker-compose -f docker-compose.debug.yml up

# Attach VS Code debugger (use "Python: Remote Attach (Docker)" configuration)
```

See the [Debugging Guide](docs/debugging-guide.md) for complete setup instructions.

## Documentation

- [README.md](README.md) - Project overview and architecture
- [SECURITY.md](SECURITY.md) - Security policies and reporting
- [docs/debugging-guide.md](docs/debugging-guide.md) - Debugging workflow
- [docs/troubleshooting.md](docs/troubleshooting.md) - Common issues
- [docs/verification-integrity.md](docs/verification-integrity.md) - Verification system
- [docs/copilot-codex-guide.md](docs/copilot-codex-guide.md) - Copilot integration
