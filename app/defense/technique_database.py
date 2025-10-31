#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK Technique Database

Maps red-team-mcp attack capabilities to MITRE ATT&CK framework.
"""
from __future__ import annotations

from app.defense.models import (
    AttackTechnique,
    TechniqueCategory,
    RiskLevel
)


# Technique database mapping red-team-mcp capabilities to MITRE ATT&CK
ATTACK_TECHNIQUES = {
    "T1059.001": AttackTechnique(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic=TechniqueCategory.EXECUTION,
        description="PowerShell reverse shells and encoded commands",
        platform=["windows"],
        data_sources=["Process monitoring", "PowerShell logs", "Command history"],
        detection_difficulty=RiskLevel.MEDIUM
    ),

    "T1059.004": AttackTechnique(
        technique_id="T1059.004",
        technique_name="Command and Scripting Interpreter: Unix Shell",
        tactic=TechniqueCategory.EXECUTION,
        description="Bash/sh reverse shells and command execution",
        platform=["linux", "macos"],
        data_sources=["Process monitoring", "Command history", "Network connections"],
        detection_difficulty=RiskLevel.MEDIUM
    ),

    "T1059.006": AttackTechnique(
        technique_id="T1059.006",
        technique_name="Command and Scripting Interpreter: Python",
        tactic=TechniqueCategory.EXECUTION,
        description="Python-based reverse shells and payload execution",
        platform=["linux", "windows", "macos"],
        data_sources=["Process monitoring", "Network connections"],
        detection_difficulty=RiskLevel.MEDIUM
    ),

    "T1059.007": AttackTechnique(
        technique_id="T1059.007",
        technique_name="Command and Scripting Interpreter: JavaScript",
        tactic=TechniqueCategory.EXECUTION,
        description="Cross-site scripting (XSS) attacks",
        platform=["web"],
        data_sources=["Web application logs", "WAF logs", "Browser events"],
        detection_difficulty=RiskLevel.LOW
    ),

    "T1505.003": AttackTechnique(
        technique_id="T1505.003",
        technique_name="Server Software Component: Web Shell",
        tactic=TechniqueCategory.PERSISTENCE,
        description="PHP/JSP/ASPX web shells for persistent access",
        platform=["linux", "windows"],
        data_sources=["File monitoring", "Web server logs", "Process monitoring"],
        detection_difficulty=RiskLevel.MEDIUM
    ),

    "T1190": AttackTechnique(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic=TechniqueCategory.INITIAL_ACCESS,
        description="SQL injection attacks against web applications",
        platform=["web"],
        data_sources=["Web application logs", "Database logs", "WAF logs"],
        detection_difficulty=RiskLevel.LOW
    ),

    "T1110.003": AttackTechnique(
        technique_id="T1110.003",
        technique_name="Brute Force: Password Spraying",
        tactic=TechniqueCategory.CREDENTIAL_ACCESS,
        description="Credential spraying against SMB/SSH/RDP/HTTP services",
        platform=["linux", "windows"],
        data_sources=["Authentication logs", "Account logon", "Network traffic"],
        detection_difficulty=RiskLevel.LOW
    ),

    "T1027": AttackTechnique(
        technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        tactic=TechniqueCategory.DEFENSE_EVASION,
        description="Base64/hex/gzip payload obfuscation",
        platform=["linux", "windows", "macos"],
        data_sources=["File monitoring", "Process command-line"],
        detection_difficulty=RiskLevel.HIGH
    ),

    "T1548": AttackTechnique(
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        tactic=TechniqueCategory.PRIVILEGE_ESCALATION,
        description="SUID/sudo privilege escalation",
        platform=["linux", "macos"],
        data_sources=["File monitoring", "Process monitoring", "Command history"],
        detection_difficulty=RiskLevel.MEDIUM
    ),

    "T1068": AttackTechnique(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        tactic=TechniqueCategory.PRIVILEGE_ESCALATION,
        description="Kernel exploits and privilege escalation",
        platform=["linux", "windows"],
        data_sources=["Process monitoring", "Kernel logs"],
        detection_difficulty=RiskLevel.HIGH
    ),

    "T1090.004": AttackTechnique(
        technique_id="T1090.004",
        technique_name="Proxy: Domain Fronting",
        tactic=TechniqueCategory.COMMAND_AND_CONTROL,
        description="Domain fronting for C2 traffic obfuscation",
        platform=["linux", "windows", "macos"],
        data_sources=["Network traffic", "SSL/TLS inspection", "DNS"],
        detection_difficulty=RiskLevel.HIGH
    ),

    "T1071.004": AttackTechnique(
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        tactic=TechniqueCategory.COMMAND_AND_CONTROL,
        description="DNS tunneling for data exfiltration",
        platform=["linux", "windows", "macos"],
        data_sources=["DNS logs", "Network traffic", "Packet capture"],
        detection_difficulty=RiskLevel.MEDIUM
    ),

    "T1001": AttackTechnique(
        technique_id="T1001",
        technique_name="Data Obfuscation",
        tactic=TechniqueCategory.COMMAND_AND_CONTROL,
        description="Protocol mimicry and traffic disguise",
        platform=["linux", "windows", "macos"],
        data_sources=["Network traffic", "Packet inspection"],
        detection_difficulty=RiskLevel.HIGH
    ),

    "T1001.001": AttackTechnique(
        technique_id="T1001.001",
        technique_name="Data Obfuscation: Junk Data",
        tactic=TechniqueCategory.COMMAND_AND_CONTROL,
        description="Traffic randomization with jitter and padding",
        platform=["linux", "windows", "macos"],
        data_sources=["Network traffic analysis", "Statistical analysis"],
        detection_difficulty=RiskLevel.HIGH
    ),

    "T1573": AttackTechnique(
        technique_id="T1573",
        technique_name="Encrypted Channel",
        tactic=TechniqueCategory.COMMAND_AND_CONTROL,
        description="End-to-end encrypted C2 communications",
        platform=["linux", "windows", "macos"],
        data_sources=["Network traffic", "SSL/TLS inspection"],
        detection_difficulty=RiskLevel.HIGH
    ),

    "T1046": AttackTechnique(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic=TechniqueCategory.DISCOVERY,
        description="Service enumeration and port scanning",
        platform=["linux", "windows"],
        data_sources=["Network traffic", "Netflow/Enclave", "Packet capture"],
        detection_difficulty=RiskLevel.LOW
    )
}


def get_technique(technique_id: str) -> AttackTechnique | None:
    """Retrieve technique by ID."""
    return ATTACK_TECHNIQUES.get(technique_id)


def get_techniques_by_tactic(tactic: TechniqueCategory) -> list[AttackTechnique]:
    """Get all techniques for a specific tactic."""
    return [t for t in ATTACK_TECHNIQUES.values() if t.tactic == tactic]


def get_techniques_by_platform(platform: str) -> list[AttackTechnique]:
    """Get all techniques applicable to a platform."""
    return [t for t in ATTACK_TECHNIQUES.values() if platform in t.platform]


def get_all_techniques() -> dict[str, AttackTechnique]:
    """Get all techniques in the database."""
    return ATTACK_TECHNIQUES.copy()
