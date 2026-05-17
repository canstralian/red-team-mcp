#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SARIF Reporter - Convert verification findings to SARIF format

Converts verification_findings.json into SARIF 2.1.0 format using predefined rules.
Maps agent risk/controls to SARIF rule IDs and writes verification.sarif.

This enables integration with GitHub Code Scanning and other SARIF-compatible tools.

Usage:
    python tools/sarif_reporter.py [--findings FILE] [--rules FILE] [--output FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


SARIF_RULES_PATH = Path("tools/sarif_rules.json")
FINDINGS_PATH = Path("verification_findings.json")
OUTPUT_SARIF = Path("verification.sarif")


def load_sarif_skeleton(rules_path: Path) -> Dict[str, Any]:
    """
    Load SARIF skeleton with rule definitions.

    Args:
        rules_path: Path to sarif_rules.json

    Returns:
        SARIF skeleton dictionary
    """
    skel = json.loads(rules_path.read_text())
    # Ensure runs[0].results is empty before population
    skel["runs"][0]["results"] = []
    return skel


def level_for(rule_id: str, severity: str = "warning") -> str:
    """
    Determine SARIF level for a rule.

    Args:
        rule_id: Rule identifier
        severity: Control severity

    Returns:
        SARIF level ("error", "warning", "note")
    """
    # Critical rules are errors
    if rule_id in ("VIA001-freshness-missing", "VIA002-future-timestamp"):
        return "error"

    # Map severity to SARIF levels
    if severity == "critical":
        return "error"
    elif severity == "high":
        return "warning"
    else:
        return "note"


def rule_id_map(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Map an agent finding to a list of SARIF result entries.

    Args:
        finding: Finding dictionary from verification scan

    Returns:
        List of SARIF result objects
    """
    results: List[Dict[str, Any]] = []
    file_uri = "file:///" + Path(finding["file_path"]).as_posix()

    # Controls mapping
    controls = {c["control_name"]: c for c in finding["controls"]}

    # Risk flags
    risks = set(finding.get("risk_flags", []))

    # VIA001: freshness missing
    if "rollback" in controls and not controls["rollback"]["implemented"]:
        results.append(
            sarif_result(
                rule_id="VIA001-freshness-missing",
                message="Freshness checks (signed_on vs now + maximum age) missing.",
                file_uri=file_uri,
                line=controls["rollback"]["line_number"] or 1,
                severity=controls["rollback"]["severity"]
            )
        )

    # VIA002: future timestamp (from risk flags)
    if "future_signature" in risks or any("future" in rf for rf in risks):
        # Find relevant control line
        line = 1
        for control in finding["controls"]:
            if "time" in control["control_name"] or "fresh" in control["control_name"]:
                line = control.get("line_number", 1) or 1
                break

        results.append(
            sarif_result(
                rule_id="VIA002-future-timestamp",
                message="Signature timestamp appears newer than trusted host time.",
                file_uri=file_uri,
                line=line,
                severity="critical"
            )
        )

    # VIA003: notation missing
    if "tampering" in controls and not controls["tampering"]["implemented"]:
        results.append(
            sarif_result(
                rule_id="VIA003-notation-missing",
                message="Missing filename/hash binding notation (e.g., file@name).",
                file_uri=file_uri,
                line=controls["tampering"]["line_number"] or 1,
                severity=controls["tampering"]["severity"]
            )
        )

    # VIA004: apt not torified (heuristic via summary/risk flags)
    if "apt_not_torified" in risks or (
        "apt" in finding["summary"].lower() and "tor" not in finding["summary"].lower()
    ):
        results.append(
            sarif_result(
                rule_id="VIA004-apt-not-torified",
                message="APT usage not confirmed as torified/pinned.",
                file_uri=file_uri,
                line=1,
                severity="high"
            )
        )

    # VIA005: timeouts missing
    if "endless_data" in controls and not controls["endless_data"]["implemented"]:
        results.append(
            sarif_result(
                rule_id="VIA005-timeouts-missing",
                message="Verification timeouts/kill-after not found.",
                file_uri=file_uri,
                line=controls["endless_data"]["line_number"] or 1,
                severity=controls["endless_data"]["severity"]
            )
        )

    # Add confidence-based warnings if overall confidence is low/critical
    if finding["confidence"]["overall"] in ["critical", "low"]:
        critical_issues = finding["confidence"].get("critical_issues", [])
        if critical_issues:
            for issue in critical_issues:
                results.append(
                    sarif_result(
                        rule_id="VIA000-confidence-critical",
                        message=f"Critical confidence issue: {issue}",
                        file_uri=file_uri,
                        line=1,
                        severity="critical"
                    )
                )

    return results


def sarif_result(
    rule_id: str,
    message: str,
    file_uri: str,
    line: int,
    severity: str = "warning"
) -> Dict[str, Any]:
    """
    Create a SARIF result object.

    Args:
        rule_id: Rule identifier
        message: Result message
        file_uri: File URI
        line: Line number
        severity: Severity level

    Returns:
        SARIF result dictionary
    """
    return {
        "ruleId": rule_id,
        "level": level_for(rule_id, severity),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri},
                    "region": {"startLine": int(line)},
                }
            }
        ],
    }


def main() -> int:
    """
    Main entry point for SARIF reporter.

    Returns:
        Exit code (0 for success, 1 if blocking errors found)
    """
    parser = argparse.ArgumentParser(
        description="Convert verification findings to SARIF format"
    )
    parser.add_argument(
        "--findings",
        type=Path,
        default=FINDINGS_PATH,
        help="Input findings JSON file"
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=SARIF_RULES_PATH,
        help="SARIF rules JSON file"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_SARIF,
        help="Output SARIF file"
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        default=True,
        help="Exit with code 1 if any error-level results found"
    )

    args = parser.parse_args()

    # Load SARIF skeleton
    if not args.rules.exists():
        print(f"Error: SARIF rules file not found: {args.rules}", file=sys.stderr)
        return 1

    sarif = load_sarif_skeleton(args.rules)

    # Load findings
    if not args.findings.exists():
        print(f"Error: Findings file not found: {args.findings}", file=sys.stderr)
        return 1

    findings_data = json.loads(args.findings.read_text())
    findings = findings_data.get("findings", [])

    print(f"[*] Processing {len(findings)} findings...")

    # Convert findings to SARIF results
    all_results: List[Dict[str, Any]] = []
    for f in findings:
        all_results.extend(rule_id_map(f))

    sarif["runs"][0]["results"] = all_results

    # Write SARIF output
    args.output.write_text(json.dumps(sarif, indent=2))
    print(f"[+] Wrote {args.output} with {len(all_results)} results")

    # Check for blocking errors
    error_count = sum(1 for r in all_results if r.get("level") == "error")
    warning_count = sum(1 for r in all_results if r.get("level") == "warning")

    print(f"[*] Summary: {error_count} errors, {warning_count} warnings")

    # CI fail policy: fail on any 'error' level result
    if args.fail_on_error and error_count > 0:
        print(f"[!] Found {error_count} blocking errors - CI should fail")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
