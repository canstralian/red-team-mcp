# Verification Integrity Module

A Kicksecure-inspired security verification system for comprehensive artifact and script integrity validation.

## Quick Start

```python
from pathlib import Path
from src.verification import VerificationIntegrityAgent

# Initialize agent
agent = VerificationIntegrityAgent()

# Analyze a file
finding = agent.analyze_file(Path("script.sh"))

if finding:
    print(f"Confidence: {finding.confidence_score.overall_confidence}")
    print(f"Controls: {len(finding.controls)} detected")
    print(f"Recommendations: {finding.recommendations}")
```

## Key Features

- **Time Integrity**: sdwdate detection, freshness validation, future timestamp detection
- **Provenance**: GPG signature verification, notation binding, chain validation
- **APT Security**: Torified APT detection, source validation, transport security
- **Hardening**: AppArmor, kernel settings, service lockdown, filesystem hardening
- **Confidence Model**: Multi-factor scoring with actionable recommendations

## Components

- `time_integrity.py` - Trusted time source detection (sdwdate, NTP)
- `provenance_checker.py` - Signature verification with notation binding
- `apt_security.py` - APT source security validation
- `hardening_detector.py` - System hardening posture detection
- `confidence_model.py` - Multi-factor confidence scoring
- `verification_integrity_agent.py` - Main agent orchestration

## Documentation

See [docs/verification-integrity.md](../../docs/verification-integrity.md) for complete documentation.

## Testing

```bash
python -m pytest tests/verification/ -v
```

## Kicksecure Principles

This module implements:
- Time integrity via sdwdate
- Torified APT for secure updates
- Digital signature policy with notation
- Defense-in-depth hardening detection

## License

Part of Red Team MCP Server. See LICENSE for details.
