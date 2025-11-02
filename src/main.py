#!/usr/bin/env python3
"""
RedTeam MCP Server

Offensive security toolkit for authorized penetration testing and red team operations.

⚠️  LEGAL WARNING ⚠️
These tools are for AUTHORIZED security testing only. Unauthorized access to computer
systems is illegal. Always obtain explicit written permission before using these tools.
"""

import asyncio
import sys

from mcp.server.fastmcp import FastMCP

from .models import (
    CredSprayInput,
    ExploitSearchInput,
    PayloadObfuscateInput,
    PrivescEnumInput,
    ResponseFormat,
    ReverseShellInput,
    SQLiPayloadInput,
    WebShellInput,
    XSSPayloadInput,
)
from .payloads import PayloadGenerator
from .utils import obfuscate_payload, truncate_response

# Initialize MCP server and payload generator
mcp = FastMCP("redteam_mcp")
payload_gen = PayloadGenerator()


@mcp.tool(
    name="redteam_reverse_shell",
    annotations={
        "title": "Reverse Shell Generator",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def reverse_shell(params: ReverseShellInput) -> str:
    """
    Generate reverse shell payloads for various languages and platforms.
    
    ⚠️  AUTHORIZATION REQUIRED: Use only on systems you have explicit permission to test.
    
    Creates reverse shell payloads in multiple languages (Bash, Python, PHP, PowerShell, etc.)
    that connect back to your listener. Essential for post-exploitation and maintaining access.
    """
    result = payload_gen.generate_reverse_shell(
        params.shell_type,
        params.lhost,
        params.lport,
        params.encode
    )
    return truncate_response(result, "Use --full flag for complete output")


@mcp.tool(
    name="redteam_web_shell",
    annotations={
        "title": "Web Shell Generator",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def web_shell(params: WebShellInput) -> str:
    """
    Generate web shells for maintaining access via HTTP.
    
    ⚠️  AUTHORIZATION REQUIRED: Use only on systems you have explicit permission to test.
    
    Creates web shells in various languages (PHP, JSP, ASPX) with optional password
    protection and obfuscation. Upload to compromised web servers for persistent access.
    """
    result = payload_gen.generate_web_shell(
        params.shell_type,
        params.password,
        params.obfuscate
    )
    return truncate_response(result, "Use --full flag for complete output")


@mcp.tool(
    name="redteam_sqli_payloads",
    annotations={
        "title": "SQL Injection Payloads",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def sqli_payloads(params: SQLiPayloadInput) -> str:
    """
    Generate SQL injection payloads for various attack scenarios.
    
    ⚠️  AUTHORIZATION REQUIRED: Use only on systems you have explicit permission to test.
    
    Creates SQLi payloads for authentication bypass, UNION-based extraction, error-based,
    blind boolean, blind time-based, and stacked queries. Database-specific payloads
    for MySQL, MSSQL, PostgreSQL, and Oracle.
    """
    result = payload_gen.generate_sqli_payloads(
        params.injection_type,
        params.columns,
        params.database
    )
    return truncate_response(result, "Use --full flag for complete output")


@mcp.tool(
    name="redteam_xss_payloads",
    annotations={
        "title": "XSS Payload Generator",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def xss_payloads(params: XSSPayloadInput) -> str:
    """
    Generate Cross-Site Scripting (XSS) payloads for various attack scenarios.
    
    ⚠️  AUTHORIZATION REQUIRED: Use only on systems you have explicit permission to test.
    
    Creates XSS payloads for reflected, stored, DOM-based, cookie stealing, keylogging,
    and phishing attacks. Includes filter bypass techniques and obfuscation.
    """
    result = payload_gen.generate_xss_payloads(
        params.xss_type,
        params.callback_url,
        params.bypass_filters
    )
    return truncate_response(result, "Use --full flag for complete output")


@mcp.tool(
    name="redteam_privesc_enum",
    annotations={
        "title": "Privilege Escalation Enumeration",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def privesc_enum(params: PrivescEnumInput) -> str:
    """
    Generate commands for privilege escalation enumeration on compromised systems.
    
    ⚠️  AUTHORIZATION REQUIRED: Use only on systems you have explicit permission to test.
    
    Provides comprehensive enumeration commands to identify privilege escalation
    vectors on Linux and Windows systems. Checks for SUID binaries, sudo misconfigs,
    kernel exploits, scheduled tasks, weak permissions, and more.
    """
    result = payload_gen.generate_privesc_enum(
        params.target_os,
        params.check_type
    )
    return truncate_response(result, "Use --full flag for complete output")


@mcp.tool(
    name="redteam_obfuscate_payload",
    annotations={
        "title": "Payload Obfuscation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def obfuscate_payload_tool(params: PayloadObfuscateInput) -> str:
    """
    Apply obfuscation techniques to payloads to evade detection.
    
    ⚠️  AUTHORIZATION REQUIRED: Use only on systems you have explicit permission to test.
    
    Obfuscates payloads using various methods like base64, hex, gzip, rot13, unicode,
    and mixed encoding. Useful for bypassing basic string-based detection systems.
    """
    obfuscated = obfuscate_payload(params.payload, params.method, params.language)
    
    output = f"""# Payload Obfuscation
**Method:** {params.method}
**Language:** {params.language}

## Original Payload
```{params.language}
{params.payload}
```

## Obfuscated Payload
```{params.language}
{obfuscated}
```

## Usage Notes
- Test obfuscated payload in safe environment first
- Some methods may require specific interpreters/decoders
- Combine multiple methods for enhanced evasion

⚠️  **LEGAL WARNING**: Use only on systems you have explicit written authorization to test.
"""
    
    return truncate_response(output, "Use --full flag for complete output")


@mcp.tool(
    name="redteam_cred_spray",
    annotations={
        "title": "Credential Spray Generator",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def cred_spray(params: CredSprayInput) -> str:
    """
    Generate credential spray attack payloads and commands.
    
    ⚠️  AUTHORIZATION REQUIRED: Use only on systems you have explicit permission to test.
    
    Creates credential spray attack scripts and commands for various services like SMB,
    SSH, RDP, HTTP, LDAP, and FTP. Helps test for weak/default credentials across
    multiple accounts without triggering account lockouts.
    """
    result = payload_gen.generate_cred_spray(
        params.target_service,
        params.usernames,
        params.passwords,
        params.target
    )
    return truncate_response(result, "Use --full flag for complete output")


@mcp.tool(
    name="redteam_exploit_search",
    annotations={
        "title": "Exploit Database Search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def exploit_search(params: ExploitSearchInput) -> str:
    """
    Search for exploits and vulnerabilities in public databases.
    
    ⚠️  AUTHORIZATION REQUIRED: Use only on systems you have explicit permission to test.
    
    Searches exploit databases for known vulnerabilities based on software names,
    CVE numbers, or keywords. Provides exploit details and potential attack vectors.
    """
    # Simulate exploit search (in real implementation, this would query actual databases)
    results = [
        {
            "title": f"Example Exploit for {params.query}",
            "cve": "CVE-2023-XXXX",
            "description": "Buffer overflow vulnerability",
            "platform": "Linux/Windows",
            "type": "Remote Code Execution"
        }
    ]
    
    if params.response_format == ResponseFormat.JSON:
        import json
        return json.dumps(results, indent=2)
    
    output = f"""# Exploit Search Results
**Query:** {params.query}
**Results Found:** {len(results)}

"""
    
    for i, result in enumerate(results, 1):
        output += f"""## {i}. {result['title']}
- **CVE:** {result['cve']}  
- **Platform:** {result['platform']}
- **Type:** {result['type']}
- **Description:** {result['description']}

"""
    
    output += """
## Next Steps
1. Verify target is vulnerable
2. Test in controlled environment
3. Develop proof of concept
4. Document findings

⚠️  **LEGAL WARNING**: Use only on systems you have explicit written authorization to test.
"""
    
    return truncate_response(output, "Use --full flag for complete output")


def main():
    """Main entry point for the MCP server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="RedTeam MCP Server")
    parser.add_argument("--port", type=int, default=3001, help="Port to run on")
    parser.add_argument("--host", default="localhost", help="Host to bind to")
    
    args = parser.parse_args()
    
    # In a real MCP server, this would start the server properly
    print(f"RedTeam MCP Server starting on {args.host}:{args.port}")
    print("⚠️  WARNING: For authorized security testing only!")
    
    try:
        asyncio.run(mcp.run())
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
