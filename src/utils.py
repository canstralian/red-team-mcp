"""
Utility functions for RedTeam MCP Server.

Helper functions for payload manipulation, output formatting, and obfuscation.
"""

import base64
import gzip
import codecs
from typing import Optional


CHARACTER_LIMIT = 25000
LEGAL_WARNING = "⚠️  **LEGAL WARNING**: Use only on systems you have explicit written authorization to test."


def truncate_response(content: str, truncation_message: str = "Output truncated") -> str:
    """
    Truncate response if it exceeds character limit.

    Args:
        content: The content to potentially truncate
        truncation_message: Message to append if truncated

    Returns:
        Original or truncated content
    """
    if len(content) <= CHARACTER_LIMIT:
        return content

    truncated = content[:CHARACTER_LIMIT]
    return f"{truncated}\n\n... [Output truncated - {len(content) - CHARACTER_LIMIT} characters hidden]\n{truncation_message}"


def obfuscate_payload(payload: str, method: str = "base64", language: str = "bash") -> str:
    """
    Obfuscate payload using various encoding methods.

    Args:
        payload: The payload to obfuscate
        method: Obfuscation method (base64, hex, gzip, rot13, unicode, mixed)
        language: Target language (bash, powershell, python, php)

    Returns:
        Obfuscated payload with appropriate wrapper for execution
    """
    method = method.lower()
    language = language.lower()

    if method == "base64":
        encoded = base64.b64encode(payload.encode()).decode()
        if language == "bash":
            return f"echo {encoded} | base64 -d | bash"
        elif language == "powershell":
            return f"powershell -EncodedCommand {encoded}"
        elif language == "python":
            return f"python -c \"import base64; exec(base64.b64decode('{encoded}'))\""
        elif language == "php":
            return f"<?php eval(base64_decode('{encoded}')); ?>"
        else:
            return encoded

    elif method == "hex":
        encoded = payload.encode().hex()
        if language == "bash":
            return f"echo {encoded} | xxd -r -p | bash"
        elif language == "python":
            return f"python -c \"exec(bytes.fromhex('{encoded}'))\""
        elif language == "php":
            return f"<?php eval(hex2bin('{encoded}')); ?>"
        else:
            return encoded

    elif method == "gzip":
        compressed = gzip.compress(payload.encode())
        encoded = base64.b64encode(compressed).decode()
        if language == "bash":
            return f"echo {encoded} | base64 -d | gunzip | bash"
        elif language == "python":
            return f"python -c \"import gzip,base64; exec(gzip.decompress(base64.b64decode('{encoded}')))\""
        else:
            return encoded

    elif method == "rot13":
        encoded = codecs.encode(payload, 'rot_13')
        if language == "bash":
            return f"echo '{encoded}' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash"
        elif language == "python":
            return f"python -c \"import codecs; exec(codecs.decode('{encoded}', 'rot_13'))\""
        else:
            return encoded

    elif method == "unicode":
        # Unicode escape encoding
        encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
        if language == "python":
            return f"python -c \"exec('{encoded}'.encode().decode('unicode-escape'))\""
        elif language == "javascript":
            return f"eval('{encoded}')"
        else:
            return encoded

    elif method == "mixed":
        # Combine base64 and hex
        b64 = base64.b64encode(payload.encode()).decode()
        hex_encoded = b64.encode().hex()
        if language == "bash":
            return f"echo {hex_encoded} | xxd -r -p | base64 -d | bash"
        elif language == "python":
            return f"python -c \"import base64; exec(base64.b64decode(bytes.fromhex('{hex_encoded}')))\""
        else:
            return hex_encoded

    else:
        # Default to base64
        return obfuscate_payload(payload, "base64", language)


def format_markdown_table(headers: list, rows: list) -> str:
    """
    Format data as a markdown table.

    Args:
        headers: List of header strings
        rows: List of lists containing row data

    Returns:
        Formatted markdown table
    """
    if not headers or not rows:
        return ""

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Build table
    header_row = "| " + " | ".join(h.ljust(w) for h, w in zip(headers, col_widths)) + " |"
    separator = "|" + "|".join("-" * (w + 2) for w in col_widths) + "|"
    data_rows = [
        "| " + " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths)) + " |"
        for row in rows
    ]

    return "\n".join([header_row, separator] + data_rows)


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format.

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IPv4 address, False otherwise
    """
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False

    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal.

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename
    """
    import re
    # Remove path separators and special characters
    sanitized = re.sub(r'[^\w\-\.]', '_', filename)
    # Remove leading/trailing dots and underscores
    sanitized = sanitized.strip('._')
    # Limit length
    return sanitized[:255]


def format_command_output(title: str, command: str, output: Optional[str] = None) -> str:
    """
    Format command and its output in markdown.

    Args:
        title: Title for the command section
        command: The command string
        output: Optional command output

    Returns:
        Formatted markdown string
    """
    result = f"## {title}\n\n"
    result += f"**Command:**\n```bash\n{command}\n```\n\n"

    if output:
        result += f"**Output:**\n```\n{output}\n```\n\n"

    return result
