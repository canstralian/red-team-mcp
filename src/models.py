"""Pydantic models for RedTeam MCP Server input validation."""

import re
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class ResponseFormat(str, Enum):
    """Output format for tool responses."""
    MARKDOWN = "markdown"
    JSON = "json"


class ShellType(str, Enum):
    """Reverse shell types."""
    BASH = "bash"
    PYTHON = "python"
    PERL = "perl"
    PHP = "php"
    NETCAT = "netcat"
    POWERSHELL = "powershell"
    RUBY = "ruby"
    SOCAT = "socat"


class ReverseShellInput(BaseModel):
    """Input model for reverse shell generation."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    shell_type: ShellType = Field(
        ...,
        description="Type of reverse shell to generate (bash, python, php, powershell, etc.)"
    )
    lhost: str = Field(
        ...,
        description="Attacker's IP address (e.g., '10.10.14.5', '192.168.1.100')",
        min_length=7,
        max_length=45
    )
    lport: int = Field(
        ...,
        description="Listening port on attacker machine (e.g., 4444, 9001)",
        ge=1,
        le=65535
    )
    encode: bool = Field(
        default=False,
        description="Base64 encode the payload (useful for bypassing filters)"
    )

    @field_validator('lhost')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Basic IP validation."""
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9\.\-]+$', v):
            raise ValueError("Invalid LHOST format")
        return v


class WebShellType(str, Enum):
    """Web shell types."""
    PHP_SIMPLE = "php_simple"
    PHP_ADVANCED = "php_advanced"
    JSP = "jsp"
    ASPX = "aspx"
    PERL_CGI = "perl_cgi"


class WebShellInput(BaseModel):
    """Input model for web shell generation."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    shell_type: WebShellType = Field(
        ...,
        description="Type of web shell (php_simple, php_advanced, jsp, aspx, perl_cgi)"
    )
    password: Optional[str] = Field(
        default=None,
        description="Optional password protection for the web shell",
        max_length=100
    )
    obfuscate: bool = Field(
        default=False,
        description="Apply basic obfuscation to evade static analysis"
    )


class SQLiType(str, Enum):
    """SQL injection payload types."""
    AUTH_BYPASS = "auth_bypass"
    UNION_BASED = "union_based"
    ERROR_BASED = "error_based"
    BLIND_BOOLEAN = "blind_boolean"
    BLIND_TIME = "blind_time"
    STACKED_QUERIES = "stacked_queries"


class SQLiPayloadInput(BaseModel):
    """Input model for SQLi payload generation."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    injection_type: SQLiType = Field(
        ...,
        description="Type of SQL injection (auth_bypass, union_based, error_based, etc.)"
    )
    columns: Optional[int] = Field(
        default=None,
        description="Number of columns for UNION-based injection",
        ge=1,
        le=20
    )
    database: str = Field(
        default="mysql",
        description="Target database type (mysql, mssql, postgres, oracle)"
    )


class XSSType(str, Enum):
    """XSS payload types."""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"
    COOKIE_STEALER = "cookie_stealer"
    KEYLOGGER = "keylogger"
    PHISHING = "phishing"


class XSSPayloadInput(BaseModel):
    """Input model for XSS payload generation."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    xss_type: XSSType = Field(
        ...,
        description="Type of XSS payload (reflected, stored, cookie_stealer, keylogger, etc.)"
    )
    callback_url: Optional[str] = Field(
        default=None,
        description="Callback URL for exfiltrated data (e.g., 'http://attacker.com/log.php')",
        max_length=500
    )
    bypass_filters: bool = Field(
        default=False,
        description="Generate payloads designed to bypass common XSS filters"
    )


class PrivescOS(str, Enum):
    """Target operating systems for privilege escalation."""
    LINUX = "linux"
    WINDOWS = "windows"


class PrivescEnumInput(BaseModel):
    """Input model for privilege escalation enumeration."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    target_os: PrivescOS = Field(
        ...,
        description="Target operating system (linux or windows)"
    )
    check_type: str = Field(
        default="all",
        description="Type of checks to perform: all, quick, kernel, suid, sudo, cron, services"
    )


class PayloadObfuscateInput(BaseModel):
    """Input model for payload obfuscation."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    payload: str = Field(
        ...,
        description="Payload to obfuscate",
        min_length=1,
        max_length=10000
    )
    method: str = Field(
        default="base64",
        description="Obfuscation method: base64, hex, gzip, rot13, unicode, mixed"
    )
    language: str = Field(
        default="bash",
        description="Target language: bash, powershell, python, php"
    )


class ExploitSearchInput(BaseModel):
    """Input model for exploit database search."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    query: str = Field(
        ...,
        description="Search query (software name, CVE, keyword)",
        min_length=3,
        max_length=200
    )
    limit: int = Field(
        default=10,
        description="Maximum number of results to return",
        ge=1,
        le=50
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'"
    )


class CredSprayInput(BaseModel):
    """Input model for credential spray payload generation."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    target_service: str = Field(
        ...,
        description="Target service (smb, ssh, rdp, http, ldap, ftp)"
    )
    usernames: List[str] = Field(
        ...,
        description="List of usernames to test",
        min_items=1,
        max_items=100
    )
    passwords: List[str] = Field(
        ...,
        description="List of passwords to test",
        min_items=1,
        max_items=20
    )
    target: Optional[str] = Field(
        default=None,
        description="Target IP or hostname (optional, for command generation)"
    )

    @field_validator('target_service')
    @classmethod
    def validate_service(cls, v: str) -> str:
        """Validate service type."""
        allowed = ['smb', 'ssh', 'rdp', 'http', 'ldap', 'ftp', 'winrm']
        if v.lower() not in allowed:
            raise ValueError(f"Service must be one of: {', '.join(allowed)}")
        return v.lower()