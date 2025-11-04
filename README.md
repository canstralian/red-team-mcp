# Red Team MCP Server

A Model Context Protocol (MCP) server providing offensive security tools for authorized penetration testing and red team operations.

⚠️ **LEGAL WARNING**: These tools are for AUTHORIZED security testing ONLY. Unauthorized access to computer systems is illegal. Always obtain explicit written permission before using these tools.

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/canstralian/red-team-mcp.git
cd red-team-mcp

# Install dependencies
pip install -r requirements.txt

# Test the server
python -m src.main --help
```

### Using with MCP Clients

For detailed setup instructions with Claude Code, GitHub Copilot, and other MCP clients, see [SETUP.md](SETUP.md).

**Quick configuration for Claude Code:**

Add to `~/.config/claude-code/mcp_settings.json`:

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["-m", "src.main"],
      "cwd": "/path/to/red-team-mcp",
      "env": {
        "PYTHONPATH": "."
      }
    }
  }
}
```

### Available Tools

The server provides 8 security testing tools:

1. **redteam_reverse_shell** - Generate reverse shell payloads (Bash, Python, PHP, PowerShell, etc.)
2. **redteam_web_shell** - Create web shells for HTTP access
3. **redteam_sqli_payloads** - SQL injection vectors for various databases
4. **redteam_xss_payloads** - Cross-site scripting payloads with filter bypasses
5. **redteam_privesc_enum** - Privilege escalation enumeration for Linux/Windows
6. **redteam_obfuscate_payload** - Payload obfuscation (base64, hex, gzip, etc.)
7. **redteam_cred_spray** - Credential spray attack generation
8. **redteam_exploit_search** - Exploit database search

For complete documentation, see [SETUP.md](SETUP.md).

---

## Architecture

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
