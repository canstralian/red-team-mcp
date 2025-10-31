# Verification Integrity Agent

## Overview

The Verification Integrity Agent is a Kicksecure-inspired security verification system that provides comprehensive artifact and script security analysis following defense-in-depth principles.

## Features

### 1. Trusted Time Source Detection

Detects and validates time sources for freshness checks:

- **sdwdate** (Kicksecure's Secure Distributed Web Date) - High confidence
- **NTP verified** - Medium confidence
- **System time** - Low confidence (requires operator review)

**Key protections:**
- Prevents rollback attacks through freshness validation
- Detects future timestamps (time manipulation attacks)
- Ensures signatures are validated against trusted time sources

### 2. Provenance and Signature Verification

Validates artifact provenance with notation binding:

- **GPG signature validation** - Verifies cryptographic signatures
- **Notation binding** - Ensures signatures bind to specific artifacts (file@name or hash@sha256)
- **Chain validation** - Checks key trust chains
- **Freshness enforcement** - Validates signature age against maximum_age

**Key protections:**
- Prevents substitution attacks via notation binding
- Detects unsigned or weakly-signed artifacts
- Enforces cryptographic chain of trust

### 3. APT Source Security

Validates package manager security configuration:

- **Torified APT detection** - Checks for apt-transport-tor usage
- **Transport security** - Validates HTTPS vs HTTP sources
- **Source analysis** - Parses /etc/apt/sources.list and sources.list.d
- **Script analysis** - Detects APT usage in shell scripts

**Key protections:**
- Prevents targeted update attacks via torified transport
- Detects insecure HTTP package sources
- Validates secure update channels

### 4. Environment Hardening Detection

Detects system hardening posture:

- **AppArmor** - Checks AppArmor status and profiles
- **Kernel hardening** - Validates sysctl security settings
- **Service lockdown** - Detects unnecessary services
- **Filesystem hardening** - Checks mount options (noexec, nosuid)
- **SSH hardening** - Validates SSH configuration

**Key protections:**
- Detects scripts that assume permissive defaults
- Validates defense-in-depth posture
- Identifies hardening gaps

### 5. Multi-Factor Confidence Model

Calculates holistic confidence scores:

- **Weighted scoring** - Combines time (20%), provenance (35%), APT (20%), hardening (25%)
- **Confidence levels** - High, Medium, Low, Critical
- **Operator review flagging** - Automatically flags low-confidence scenarios
- **Actionable recommendations** - Provides remediation guidance

## Architecture

```
src/verification/
├── __init__.py                          # Module exports
├── verification_integrity_agent.py      # Main agent
├── time_integrity.py                    # Time source validation
├── provenance_checker.py                # Signature verification
├── apt_security.py                      # APT security checking
├── hardening_detector.py                # System hardening detection
└── confidence_model.py                  # Multi-factor scoring
```

## Usage

### Command Line

```bash
# Scan entire codebase
python tools/run_verification_scan.py --root . --verbose

# Convert findings to SARIF
python tools/sarif_reporter.py

# Run tests
python -m pytest tests/verification/
```

### Python API

```python
from pathlib import Path
from src.verification import VerificationIntegrityAgent

agent = VerificationIntegrityAgent()

# Analyze a script
finding = agent.analyze_file(Path("install_script.sh"))

if finding:
    print(f"Confidence: {finding.confidence_score.overall_confidence}")
    print(f"Risk flags: {finding.risk_flags}")
    print(f"Recommendations:")
    for rec in finding.recommendations:
        print(f"  - {rec}")

# Analyze an artifact with signature
finding = agent.analyze_artifact(
    artifact_path=Path("package.tar.gz"),
    signature_path=Path("package.tar.gz.sig"),
    maximum_age=timedelta(days=7)
)

print(f"Provenance level: {finding.provenance_result.level}")
print(f"Notation binding: {finding.provenance_result.notation_binding_verified}")
```

### CI/CD Integration

The agent integrates with GitHub Actions via SARIF:

```yaml
- name: Run Verification Integrity Scan
  run: python tools/run_verification_scan.py

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: verification.sarif
```

See `.github/workflows/verification-integrity.yml` for full workflow.

## SARIF Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| VIA000-confidence-critical | Error | Critical confidence issues detected |
| VIA001-freshness-missing | Error | GPG freshness checks missing |
| VIA002-future-timestamp | Error | Signature timestamp in future |
| VIA003-notation-missing | Warning | Notation binding missing |
| VIA004-apt-not-torified | Warning | APT not using secure transport |
| VIA005-timeouts-missing | Warning | Verification timeouts missing |

## Security Controls

The agent detects the following controls in scripts/artifacts:

1. **Rollback Protection** - Freshness checks (signed_on vs now + maximum_age)
2. **Tampering Protection** - Notation binding (file@name or hash@sha256)
3. **Freeze Protection** - APT pinning or package freezing
4. **Endless Data Protection** - Timeouts for GPG operations

## Policy Configuration

Edit `.github/linters/.policy.ini` to configure policies:

```ini
[freshness]
require_maximum_age_seconds = 604800  # 7 days
require_trusted_time_source = true

[notation]
require_file_binding = true

[updates]
require_torified_apt = true
```

## Testing

### Unit Tests

```bash
# Run all tests
python -m pytest tests/verification/ -v

# Run specific test module
python -m pytest tests/verification/test_time_integrity.py -v
```

### Lab Tests (Safe Scenarios)

All tests use fixtures - no actual system modifications or untrusted code execution:

1. **Future timestamp test** - Benign fixture with future signed_on
2. **Missing notation test** - Signature without notation binding
3. **APT channel test** - Mock installer with clearnet vs torified APT
4. **Time fallback test** - Host without trusted time source

## Kicksecure Integration

This agent implements principles from Kicksecure:

- **sdwdate** for time integrity ([Kicksecure Time Attacks](https://www.kicksecure.com/wiki/Time_Attacks))
- **Torified APT** for secure updates ([Kicksecure Updates](https://www.kicksecure.com/wiki/Operating_System_Software_and_Updates))
- **Digital Signature Policy** ([Kicksecure Trust](https://www.kicksecure.com/wiki/Trust))
- **Defense-in-depth** hardening ([Kicksecure About](https://www.kicksecure.com/wiki/About))

## Roadmap

### Short term (days)
- ✅ sdwdate detection & freshness confidence
- ✅ Provenance with notation validation
- ✅ APT security checking
- ✅ CI integration via SARIF

### Medium term (weeks)
- [ ] RAG knowledge base with Kicksecure docs
- [ ] Policy enforcement engine
- [ ] Automated remediation suggestions
- [ ] SBOM integration

### Long term (months)
- [ ] Real-time monitoring agent
- [ ] Supply chain graph analysis
- [ ] Threat intelligence integration
- [ ] Automated incident response

## References

- [Kicksecure About](https://www.kicksecure.com/wiki/About)
- [Kicksecure Trust and Digital Signatures](https://www.kicksecure.com/wiki/Trust)
- [Kicksecure Time Attacks](https://www.kicksecure.com/wiki/Time_Attacks)
- [Kicksecure System Hardening](https://www.kicksecure.com/wiki/System_Hardening_Checklist)
- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

## License

This verification integrity agent is part of the Red Team MCP Server project.
See LICENSE file for details.
