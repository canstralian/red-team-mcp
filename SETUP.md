# Red Team MCP Server Setup Guide

This guide will help you set up and configure the Red Team MCP Server for use with code agents like Claude Code, GitHub Copilot, or other MCP-compatible clients.

## ⚠️ Legal Warning

**This server provides offensive security tools for AUTHORIZED penetration testing ONLY.**

- Only use on systems you have explicit written permission to test
- Unauthorized access to computer systems is illegal
- Always follow your organization's security policies and procedures
- Maintain proper authorization documentation

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Git

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/canstralian/red-team-mcp.git
cd red-team-mcp
```

### 2. Install Dependencies

```bash
pip install -e .
```

Or install dependencies directly:

```bash
pip install fastmcp>=0.2.0 httpx>=0.25.0 pydantic>=2.0.0
```

### 3. Verify Installation

Test that the server can start:

```bash
python -m src.main --help
```

## Configuration

### For Claude Code

1. Locate your Claude Code configuration directory:
   - **macOS/Linux**: `~/.config/claude-code/`
   - **Windows**: `%APPDATA%\claude-code\`

2. Create or edit the `mcp_settings.json` file:

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

Replace `/path/to/red-team-mcp` with the actual path to your installation.

### For GitHub Copilot

1. Configure in your IDE's settings or copilot configuration file
2. Add the MCP server endpoint configuration
3. Refer to the `mcp-config.json` file for the configuration template

### Standalone Server

You can also run the server standalone:

```bash
python -m src.main --host localhost --port 3001
```

## Available Tools

The Red Team MCP Server provides the following tools:

### 1. `redteam_reverse_shell`
Generate reverse shell payloads for various languages and platforms.

**Parameters:**
- `shell_type`: bash, python, php, powershell, perl, netcat, ruby, socat
- `lhost`: Attacker's IP address
- `lport`: Listening port (1-65535)
- `encode`: Base64 encode the payload (boolean)

### 2. `redteam_web_shell`
Generate web shells for maintaining access via HTTP.

**Parameters:**
- `shell_type`: php_simple, php_advanced, jsp, aspx, perl_cgi
- `password`: Optional password protection
- `obfuscate`: Apply obfuscation (boolean)

### 3. `redteam_sqli_payloads`
Generate SQL injection payloads for various attack scenarios.

**Parameters:**
- `injection_type`: auth_bypass, union_based, error_based, blind_boolean, blind_time, stacked_queries
- `columns`: Number of columns for UNION attacks (optional)
- `database`: mysql, mssql, postgres, oracle

### 4. `redteam_xss_payloads`
Generate Cross-Site Scripting (XSS) payloads.

**Parameters:**
- `xss_type`: reflected, stored, dom_based, cookie_stealer, keylogger, phishing
- `callback_url`: URL for exfiltration (optional)
- `bypass_filters`: Include filter bypass techniques (boolean)

### 5. `redteam_privesc_enum`
Generate privilege escalation enumeration commands.

**Parameters:**
- `target_os`: linux, windows
- `check_type`: all, quick, kernel, suid, sudo, cron, services

### 6. `redteam_obfuscate_payload`
Apply obfuscation techniques to payloads.

**Parameters:**
- `payload`: Payload to obfuscate
- `method`: base64, hex, gzip, rot13, unicode, mixed
- `language`: bash, powershell, python, php

### 7. `redteam_cred_spray`
Generate credential spray attack payloads and commands.

**Parameters:**
- `target_service`: smb, ssh, rdp, http, ldap, ftp, winrm
- `usernames`: List of usernames
- `passwords`: List of passwords
- `target`: Target IP or hostname (optional)

### 8. `redteam_exploit_search`
Search for exploits and vulnerabilities in public databases.

**Parameters:**
- `query`: Search query (software name, CVE, keyword)
- `limit`: Maximum results (1-50, default 10)
- `response_format`: markdown, json

## Usage Examples

### Using with Claude Code

Once configured, you can ask Claude Code to use the tools:

```
Claude, use the redteam_reverse_shell tool to generate a Python reverse shell
connecting to 192.168.1.100 on port 4444
```

### Using with Python

You can also use the tools programmatically:

```python
from src.main import mcp
from src.models import ReverseShellInput, ShellType

# Generate a reverse shell
input_data = ReverseShellInput(
    shell_type=ShellType.BASH,
    lhost="192.168.1.100",
    lport=4444,
    encode=False
)

result = await reverse_shell(input_data)
print(result)
```

## Testing

Run the test suite:

```bash
pytest tests/
```

## Troubleshooting

### Server Won't Start

1. Check Python version: `python --version` (should be 3.8+)
2. Verify dependencies: `pip list | grep fastmcp`
3. Check for port conflicts: `lsof -i :3001` (on macOS/Linux)

### Tools Not Available in Code Agent

1. Verify the server is running
2. Check the configuration file path
3. Restart your code agent
4. Check the code agent's logs for errors

### Import Errors

Make sure PYTHONPATH is set correctly:

```bash
export PYTHONPATH=/path/to/red-team-mcp:$PYTHONPATH
```

## Security Best Practices

1. **Authorization**: Always obtain written authorization before testing
2. **Scope**: Stay within the agreed-upon testing scope
3. **Documentation**: Keep detailed logs of all testing activities
4. **Data Handling**: Protect any sensitive data discovered during testing
5. **Reporting**: Report vulnerabilities responsibly to the system owner

## Development

### Project Structure

```
red-team-mcp/
├── src/
│   ├── __init__.py
│   ├── main.py              # MCP server and tool definitions
│   ├── models.py            # Pydantic input validation models
│   ├── payloads.py          # Payload generation logic
│   ├── utils.py             # Utility functions
│   ├── advanced_attacks/    # Advanced attack modules
│   ├── resilience/          # Resilience features
│   ├── stealth/             # Stealth and obfuscation
│   └── verification/        # Authorization verification
├── tests/                   # Test suite
├── docs/                    # Documentation
├── pyproject.toml           # Project configuration
├── mcp-config.json          # MCP configuration example
└── SETUP.md                 # This file
```

### Adding New Tools

1. Define input model in `src/models.py`
2. Add payload generation logic in `src/payloads.py`
3. Register tool in `src/main.py` using `@mcp.tool()` decorator
4. Add tests in `tests/`
5. Update documentation

## Support

- **Issues**: https://github.com/canstralian/red-team-mcp/issues
- **Documentation**: https://github.com/canstralian/red-team-mcp#readme
- **Security**: See SECURITY.md for security policy

## License

See LICENSE file for details.

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.
