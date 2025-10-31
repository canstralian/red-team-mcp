#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verification Integrity Scanner - CI/CD Integration Tool

Discover verification-related scripts and artifacts, run VerificationIntegrityAgent,
and emit JSON findings for SARIF conversion.

This is a read-only scanner - no execution of scanned files.
Follows PEP 8 and uses safe file operations only.

Usage:
    python tools/run_verification_scan.py [--root DIR] [--output FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, List, Dict, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.verification.verification_integrity_agent import VerificationIntegrityAgent

# File extensions to scan
SCAN_EXTS = {".sh", ".bash", ".py", ".txt", ".md", ".conf", ".yaml", ".yml", ".json"}


def iter_candidate_files(root: Path) -> Iterable[Path]:
    """
    Iterate over candidate files for verification scanning.

    Args:
        root: Root directory to scan

    Yields:
        Paths to candidate files
    """
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in SCAN_EXTS:
            yield p


def serialize_finding(finding: Any) -> Dict[str, Any]:
    """
    Serialize a VerificationFinding to JSON-compatible dict.

    Args:
        finding: VerificationFinding object

    Returns:
        Dictionary suitable for JSON serialization
    """
    return {
        "file_path": finding.file_path,
        "artifact_type": finding.artifact_type,
        "controls": [
            {
                "control_name": c.control_name,
                "implemented": c.implemented,
                "line_number": c.line_number,
                "details": c.details,
                "severity": c.severity
            }
            for c in finding.controls
        ],
        "confidence": {
            "overall": finding.confidence_score.overall_confidence,
            "weighted_score": finding.confidence_score.weighted_score,
            "factors_met": finding.confidence_score.factors_met,
            "factors_failed": finding.confidence_score.factors_failed,
            "critical_issues": finding.confidence_score.critical_issues
        },
        "summary": finding.summary,
        "risk_flags": finding.risk_flags,
        "recommendations": finding.recommendations,
        "metadata": finding.metadata
    }


def main() -> int:
    """
    Main entry point for verification scanner.

    Returns:
        Exit code (0 for success)
    """
    parser = argparse.ArgumentParser(
        description="Scan codebase for verification integrity issues"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="Root directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("verification_findings.json"),
        help="Output JSON file (default: verification_findings.json)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    root = args.root.resolve()
    if not root.exists():
        print(f"Error: Root directory does not exist: {root}", file=sys.stderr)
        return 1

    print(f"[*] Scanning {root} for verification integrity issues...")

    agent = VerificationIntegrityAgent()
    findings: List[Dict[str, Any]] = []
    scanned_count = 0

    for fp in iter_candidate_files(root):
        scanned_count += 1
        if args.verbose:
            print(f"[*] Scanning {fp.relative_to(root)}...")

        try:
            finding = agent.analyze_file(fp)
            if finding is None:
                continue

            findings.append(serialize_finding(finding))

            if args.verbose:
                print(f"    → {finding.summary}")

        except Exception as e:
            print(f"[!] Error scanning {fp}: {e}", file=sys.stderr)
            continue

    print(f"[+] Scanned {scanned_count} files, found {len(findings)} verification-related files")

    # Write output
    output_data = {
        "scan_metadata": {
            "root_directory": str(root),
            "scanned_files": scanned_count,
            "findings_count": len(findings)
        },
        "findings": findings
    }

    args.output.write_text(json.dumps(output_data, indent=2))
    print(f"[+] Wrote findings to {args.output}")

    # Summary statistics
    critical_count = sum(
        1 for f in findings
        if f["confidence"]["overall"] == "critical"
    )
    high_risk_count = sum(
        1 for f in findings
        if len(f["confidence"]["critical_issues"]) > 0
    )

    if critical_count > 0 or high_risk_count > 0:
        print(f"[!] Found {critical_count} critical confidence and {high_risk_count} high-risk findings")

    return 0


if __name__ == "__main__":
    sys.exit(main())
