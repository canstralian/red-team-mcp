#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Defensive Control Database

Counter-controls mapped to MITRE ATT&CK techniques.
"""
from __future__ import annotations

from app.defense.models import (
    DefensiveControl,
    ControlEffectiveness,
    RiskLevel
)


# Defensive controls database
DEFENSIVE_CONTROLS = {
    "CTRL-001": DefensiveControl(
        control_id="CTRL-001",
        control_name="PowerShell Script Block Logging",
        control_type="detective",
        description="Enable PowerShell script block logging (Event ID 4104) to capture all executed commands",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1059.001"],
        detection_methods=[
            "Monitor Windows Event Log 4104",
            "Alert on encoded commands (FromBase64String)",
            "Alert on suspicious cmdlets (Invoke-Expression, Invoke-WebRequest)"
        ],
        response_actions=[
            "Isolate affected system",
            "Terminate PowerShell process",
            "Block C2 IP addresses"
        ]
    ),

    "CTRL-002": DefensiveControl(
        control_id="CTRL-002",
        control_name="PowerShell Constrained Language Mode",
        control_type="preventive",
        description="Enforce PowerShell Constrained Language Mode to restrict dangerous operations",
        implementation_cost=RiskLevel.MEDIUM,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1059.001"],
        detection_methods=[
            "Verify $ExecutionContext.SessionState.LanguageMode = ConstrainedLanguage"
        ],
        response_actions=[
            "Re-enforce language mode via GPO"
        ]
    ),

    "CTRL-003": DefensiveControl(
        control_id="CTRL-003",
        control_name="Bash History and Auditd Monitoring",
        control_type="detective",
        description="Enable comprehensive auditd rules for command execution",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.MODERATE,
        coverage=["T1059.004", "T1548"],
        detection_methods=[
            "Monitor /var/log/audit/audit.log for EXECVE records",
            "Alert on reverse shell patterns (bash -i, /dev/tcp)",
            "Monitor .bash_history modifications"
        ],
        response_actions=[
            "Kill suspicious shell processes",
            "Block outbound connections",
            "Preserve logs for forensics"
        ]
    ),

    "CTRL-004": DefensiveControl(
        control_id="CTRL-004",
        control_name="Egress Firewall Rules",
        control_type="preventive",
        description="Restrict outbound connections to known-good destinations",
        implementation_cost=RiskLevel.HIGH,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1059.001", "T1059.004", "T1059.006", "T1071.004", "T1090.004"],
        detection_methods=[
            "Monitor firewall denials",
            "Alert on unusual outbound ports"
        ],
        response_actions=[
            "Block destination IP/port",
            "Investigate source system"
        ]
    ),

    "CTRL-005": DefensiveControl(
        control_id="CTRL-005",
        control_name="Web Shell File Integrity Monitoring",
        control_type="detective",
        description="Monitor web directories for unauthorized file creation",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1505.003"],
        detection_methods=[
            "Monitor /var/www, C:\\inetpub for .php/.jsp/.aspx creation",
            "YARA rules for web shell signatures",
            "Checksums of legitimate files"
        ],
        response_actions=[
            "Quarantine suspicious files",
            "Restore from known-good backup",
            "Review web server access logs"
        ]
    ),

    "CTRL-006": DefensiveControl(
        control_id="CTRL-006",
        control_name="Web Application Firewall (WAF)",
        control_type="preventive",
        description="Deploy WAF with SQL injection and XSS rulesets",
        implementation_cost=RiskLevel.HIGH,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1190", "T1059.007"],
        detection_methods=[
            "Monitor WAF block events",
            "Analyze attack patterns"
        ],
        response_actions=[
            "Block attacking IP",
            "Rate limit requests",
            "Update WAF rules"
        ]
    ),

    "CTRL-007": DefensiveControl(
        control_id="CTRL-007",
        control_name="Parameterized SQL Queries",
        control_type="preventive",
        description="Enforce prepared statements and parameterized queries",
        implementation_cost=RiskLevel.MEDIUM,
        effectiveness=ControlEffectiveness.COMPLETE,
        coverage=["T1190"],
        detection_methods=[
            "Code review for dynamic SQL",
            "SAST scanning"
        ],
        response_actions=[
            "Refactor vulnerable code"
        ]
    ),

    "CTRL-008": DefensiveControl(
        control_id="CTRL-008",
        control_name="Content Security Policy (CSP)",
        control_type="preventive",
        description="Implement strict CSP headers to prevent XSS execution",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1059.007"],
        detection_methods=[
            "Monitor CSP violation reports"
        ],
        response_actions=[
            "Sanitize user input",
            "Update CSP policy"
        ]
    ),

    "CTRL-009": DefensiveControl(
        control_id="CTRL-009",
        control_name="Account Lockout Policy",
        control_type="preventive",
        description="Enforce account lockout after N failed login attempts",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1110.003"],
        detection_methods=[
            "Monitor Event ID 4740 (Windows) or auth.log (Linux)",
            "Alert on multiple lockouts"
        ],
        response_actions=[
            "Investigate locked accounts",
            "Block source IP"
        ]
    ),

    "CTRL-010": DefensiveControl(
        control_id="CTRL-010",
        control_name="Multi-Factor Authentication (MFA)",
        control_type="preventive",
        description="Require MFA for all authentication",
        implementation_cost=RiskLevel.MEDIUM,
        effectiveness=ControlEffectiveness.COMPLETE,
        coverage=["T1110.003"],
        detection_methods=[
            "Monitor MFA bypass attempts"
        ],
        response_actions=[
            "Enforce MFA policy",
            "Revoke compromised credentials"
        ]
    ),

    "CTRL-011": DefensiveControl(
        control_id="CTRL-011",
        control_name="File Hash Reputation Filtering",
        control_type="preventive",
        description="Block execution of known-malicious file hashes",
        implementation_cost=RiskLevel.MEDIUM,
        effectiveness=ControlEffectiveness.MODERATE,
        coverage=["T1027"],
        detection_methods=[
            "Submit hashes to VirusTotal",
            "Maintain internal blacklist"
        ],
        response_actions=[
            "Quarantine file",
            "Alert security team"
        ]
    ),

    "CTRL-012": DefensiveControl(
        control_id="CTRL-012",
        control_name="Behavioral Detection (YARA/Sigma)",
        control_type="detective",
        description="Deploy YARA/Sigma rules for obfuscated payloads",
        implementation_cost=RiskLevel.MEDIUM,
        effectiveness=ControlEffectiveness.MODERATE,
        coverage=["T1027", "T1059.001", "T1505.003"],
        detection_methods=[
            "YARA scans on file writes",
            "Sigma rules in SIEM"
        ],
        response_actions=[
            "Isolate system",
            "Memory dump for analysis"
        ]
    ),

    "CTRL-013": DefensiveControl(
        control_id="CTRL-013",
        control_name="SUID Binary Monitoring",
        control_type="detective",
        description="Monitor for new SUID binaries and suspicious executions",
        implementation_cost=RiskLevel.LOW,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1548"],
        detection_methods=[
            "find / -perm -4000 -ls | diff against baseline",
            "Monitor execve() of SUID binaries"
        ],
        response_actions=[
            "Remove unauthorized SUID bit",
            "Investigate privilege escalation"
        ]
    ),

    "CTRL-014": DefensiveControl(
        control_id="CTRL-014",
        control_name="Kernel Patch Management",
        control_type="preventive",
        description="Maintain up-to-date kernel patches",
        implementation_cost=RiskLevel.MEDIUM,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1068"],
        detection_methods=[
            "Vulnerability scanning",
            "Patch compliance monitoring"
        ],
        response_actions=[
            "Apply emergency patches",
            "Reboot systems"
        ]
    ),

    "CTRL-015": DefensiveControl(
        control_id="CTRL-015",
        control_name="TLS/SSL Inspection",
        control_type="detective",
        description="Decrypt and inspect TLS traffic for anomalies",
        implementation_cost=RiskLevel.HIGH,
        effectiveness=ControlEffectiveness.MODERATE,
        coverage=["T1090.004", "T1573", "T1071.004"],
        detection_methods=[
            "Analyze SNI mismatches",
            "Detect certificate pinning bypass",
            "Monitor encryption protocol anomalies"
        ],
        response_actions=[
            "Block suspicious domains",
            "Isolate affected hosts"
        ]
    ),

    "CTRL-016": DefensiveControl(
        control_id="CTRL-016",
        control_name="DNS Sinkholing and Query Analysis",
        control_type="detective",
        description="Analyze DNS queries for tunneling patterns",
        implementation_cost=RiskLevel.MEDIUM,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1071.004"],
        detection_methods=[
            "Alert on high query volumes to single domain",
            "Detect long subdomain labels (>63 chars)",
            "Analyze query entropy"
        ],
        response_actions=[
            "Sinkhole malicious domain",
            "Block DNS queries"
        ]
    ),

    "CTRL-017": DefensiveControl(
        control_id="CTRL-017",
        control_name="Network Traffic Baselining",
        control_type="detective",
        description="Establish traffic baselines and detect anomalies",
        implementation_cost=RiskLevel.HIGH,
        effectiveness=ControlEffectiveness.MODERATE,
        coverage=["T1001", "T1001.001", "T1071.004", "T1090.004"],
        detection_methods=[
            "Statistical analysis of packet sizes",
            "Detect beaconing patterns",
            "Analyze inter-packet timing"
        ],
        response_actions=[
            "Investigate anomalous flows",
            "Packet capture for analysis"
        ]
    ),

    "CTRL-018": DefensiveControl(
        control_id="CTRL-018",
        control_name="Network Segmentation",
        control_type="preventive",
        description="Segment networks to limit lateral movement",
        implementation_cost=RiskLevel.HIGH,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1046", "T1071.004", "T1090.004"],
        detection_methods=[
            "Monitor cross-segment traffic"
        ],
        response_actions=[
            "Enforce segmentation rules",
            "Investigate boundary violations"
        ]
    ),

    "CTRL-019": DefensiveControl(
        control_id="CTRL-019",
        control_name="Endpoint Detection and Response (EDR)",
        control_type="detective",
        description="Deploy EDR for real-time threat detection",
        implementation_cost=RiskLevel.HIGH,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=[
            "T1059.001", "T1059.004", "T1059.006",
            "T1027", "T1548", "T1068", "T1505.003"
        ],
        detection_methods=[
            "Behavioral analytics",
            "IOC matching",
            "Memory scanning"
        ],
        response_actions=[
            "Automated isolation",
            "Kill malicious processes",
            "Remediation scripts"
        ]
    ),

    "CTRL-020": DefensiveControl(
        control_id="CTRL-020",
        control_name="Application Allowlisting",
        control_type="preventive",
        description="Only allow execution of approved applications",
        implementation_cost=RiskLevel.HIGH,
        effectiveness=ControlEffectiveness.SUBSTANTIAL,
        coverage=["T1059.001", "T1059.004", "T1059.006", "T1027"],
        detection_methods=[
            "Monitor allowlist violations"
        ],
        response_actions=[
            "Block unauthorized execution",
            "Update allowlist"
        ]
    )
}


def get_control(control_id: str) -> DefensiveControl | None:
    """Retrieve control by ID."""
    return DEFENSIVE_CONTROLS.get(control_id)


def get_controls_for_technique(technique_id: str) -> list[DefensiveControl]:
    """Get all controls that cover a specific technique."""
    return [
        control for control in DEFENSIVE_CONTROLS.values()
        if technique_id in control.coverage
    ]


def get_controls_by_type(control_type: str) -> list[DefensiveControl]:
    """Get all controls of a specific type."""
    return [
        control for control in DEFENSIVE_CONTROLS.values()
        if control.control_type == control_type
    ]


def get_all_controls() -> dict[str, DefensiveControl]:
    """Get all controls in the database."""
    return DEFENSIVE_CONTROLS.copy()
