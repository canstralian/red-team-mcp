# Trading Bot Swarm Copilot & Codex Configuration Guide

## Purpose and Scope
This guide standardizes the configuration of GitHub Copilot and Codex within the Trading Bot Swarm ecosystem so contributors share a consistent, secure, and high-quality development experience. Copilot acts as a disciplined pair programmer: it must respect project policies, prioritize safety, and never bypass required checks. Codex serves as the automation backbone for agentic workflows and CI verification. Together, they should reinforce reliability, performance, and safety across code, infrastructure-as-code, data pipelines, and automation scripts.

### Objectives
- Define behavioral guardrails for Copilot and Codex so generated code aligns with Trading Bot Swarm standards.
- Provide a reusable configuration blueprint covering linting, testing, async patterns, security controls, logging, observability, and CI/CD.
- Outline operational processes for quality automation, semantic release, dependency governance, and contributor workflows.
- Offer troubleshooting guidance and a maintenance cadence to keep the configuration current with platform evolution.

## Configuration Overview
### Core Principles
1. **Security First**: Default to least privilege, secure credentials, encrypted secrets, and proactive vulnerability scanning.
2. **Reliability & Observability**: Every service and agent must expose health signals, structured logs, and metrics compatible with the observability stack.
3. **Deterministic Quality**: All changes pass automated lint, test, and type checks before merging. Copilot/Codex proposals must cite required validations.
4. **Consistency**: Enforce standardized code style, naming, and async patterns across Python services, automation scripts, and infra definitions.

### Tooling Expectations
- **Testing**: Use `pytest` with coverage thresholds ≥90% for new modules. Async code must use `pytest-asyncio` fixtures. Snapshot tests require approval and versioning.
- **Linting & Formatting**: Adopt `ruff` for lint + format, `mypy` for static typing, and `black` for enforced formatting when needed. Copilot suggestions must align with lint rules to avoid churn.
- **Async Patterns**: Prefer `asyncio` with explicit context managers, cancellation handling, and timeouts. Disallow blocking calls in async paths; Codex must flag synchronous I/O in async contexts.
- **Security Defaults**: Mandatory secrets retrieval via the Secrets Manager client; forbid inline secrets. All HTTP clients require TLS verification, retry policies, and circuit breakers.
- **Logging & Observability**: Use the shared structured logging helper (`trading_swarm.logging.get_logger`) with JSON output. Ensure trace IDs propagate via contextvars and integrate with OpenTelemetry exporters.
- **CI/CD Integration**: Pull requests must trigger lint/test workflows. Protected branches enforce passing checks, review approvals, and signed commits. Copilot commits should reference issue IDs in their messages when available.
- **Version Control Hygiene**: Feature branches follow `feature/<scope>` naming. Squash merges only. Documentation-only changes skip heavy CI jobs but still require link-checkers if relevant.

## Custom Instruction Behavior
Tailor Copilot and Codex instructions so automated agents respect project policy, do not leak secrets, and always surface verification steps.

### Behavioral Rules Examples
- Copilot must prepend TODO comments with owner handles and context.
- Copilot suggestions cannot disable linters or tests without explicit approval and justification.
- Codex must request explicit confirmation before running destructive automation (e.g., database resets).
- Both agents must mention required lint/test commands in PR descriptions and flag when they have not been run.
- Agents must refuse to generate or execute trading strategies lacking risk controls (stop-loss, guardrails).

### Conceptual Custom Instructions (YAML)
```yaml
copilot:
  role: "Pair programmer with safety guardrails"
  always_include:
    - "Respect Trading Bot Swarm security baselines"
    - "Suggest tests, linters, and telemetry hooks for every change"
    - "Prefer dependency injection and typed interfaces"
  prohibited_actions:
    - "Bypass CI/CD checks"
    - "Insert hard-coded secrets or credentials"
    - "Recommend disabling security tooling"
  coding_guidelines:
    testing: "Default to pytest + coverage; highlight async fixtures for coroutine code"
    linting: "Align with ruff, mypy, black configured in pyproject.toml"
    observability: "Use get_logger(); attach trace/span context"
    async_patterns: "Use asyncio.create_task sparingly; always await and handle cancellation"

codex:
  role: "Automation orchestrator and CI enforcer"
  mandates:
    - "Run lint + test workflows on every non-doc change"
    - "Ignore documentation-only diffs for heavy compute jobs"
    - "Publish SARIF from static analysis to security dashboard"
  safeguards:
    - "Confirm before infrastructure mutations"
    - "Mask secrets in logs"
    - "Record provenance for generated artifacts"
  reporting:
    - "Summarize results with residual risk classification"
```

Emphasize to contributors that tests and linters must run for any code change. Documentation-only pull requests may skip compute-intensive jobs but must still ensure formatting and link validation.

## GitHub Workflow: Lint & Test Automation
The following workflow enforces linting and testing on relevant changes.

```yaml
name: quality-gate

on:
  pull_request:
    branches: [ main, release/* ]
    paths-ignore:
      - "docs/**"
      - "*.md"
  push:
    branches: [ main ]
    paths-ignore:
      - "docs/**"
      - "*.md"

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      - name: Lint
        run: |
          ruff check .
          mypy src
      - name: Format check
        run: black --check .
      - name: Test
        run: pytest --maxfail=1 --disable-warnings --cov=src
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
      - name: Publish SARIF
        if: always()
        run: ruff check . --output-format sarif > ruff.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ruff.sarif
```

## Semantic Release & Version Tagging Best Practices
Automate versioning to reflect meaningful changes and maintain release cadence.

```yaml
name: semantic-release

on:
  push:
    branches: [ main ]

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"
      - name: Install semantic-release
        run: npm install -g semantic-release @semantic-release/git @semantic-release/changelog
      - name: Run semantic-release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: semantic-release
```

Key practices:
- Use Conventional Commits to drive automatic versioning.
- Generate changelog entries and Git tags during release job.
- Publish release notes to stakeholders and trigger downstream deployment automation.

## Security & Dependency Scanning
Continuous scanning keeps the trading ecosystem resilient against supply-chain threats.

```yaml
name: security-scan

on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

jobs:
  dependency-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Python dependency scan
        uses: snyk/actions/python-setup-scan@v1
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      - name: Container scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: image
          image-ref: ghcr.io/trading-bot-swarm/app:latest

  codeql-analysis:
    uses: github/codeql-action/analyze@v3
    with:
      category: /language:python
```

Augment scanning with:
- Weekly secret scanning and license compliance checks.
- Automatic pull requests for outdated dependencies using Dependabot with security-only mode.

## Contributor Guidelines
1. **Proposing Changes**
   - Open an issue describing scope, risk, and test strategy.
   - Create a feature branch (`feature/<issue-id>-<summary>`).
   - Use Copilot responsibly: review suggestions, ensure they follow guardrails, and document deviations.
2. **Review Criteria**
   - All CI jobs pass (lint, test, security scans as applicable).
   - Code conforms to style, async, logging, and security policies.
   - Tests cover new behavior; high-risk code includes negative and resilience scenarios.
   - Documentation updates accompany feature or policy changes.
3. **Validation Process**
   - Submit PR with checklist confirming tests/linters ran locally unless change is documentation-only.
   - Include links to relevant pipeline runs and risk assessment.
   - Reviewers verify adherence to Copilot/Codex instructions, confirm coverage, and request additional telemetry if necessary.

## Troubleshooting & Optimization Tips
- **Lint Failures**: Run `ruff --fix` and `black .`; ensure type hints satisfy `mypy` strictness.
- **Flaky Async Tests**: Add timeouts, leverage `pytest.mark.asyncio`, and use deterministic fixtures.
- **Copilot Noise**: Refine prompts, anchor suggestions with TODO context, and disable inline completion for security-sensitive files.
- **CI Timeouts**: Cache dependencies via `actions/cache`, parallelize test suites, and leverage selective job triggers based on file globs.
- **Security Scan Alerts**: Prioritize CVEs with known exploits, document mitigations, and schedule patch windows.

## Maintenance Schedule
- **Quarterly**: Review Copilot/Codex instructions, update guardrails, validate supported language/runtime versions.
- **Monthly**: Audit workflows for dependency updates, check secrets rotation, refresh coverage thresholds, and ensure scanners use latest definitions.
- **Release Cycles**: Align guide updates with semantic release milestones; document changes in `docs/changelog.md`.

## Closing Note
Standardizing these practices ensures GitHub Copilot and Codex reinforce excellence across the Trading Bot Swarm. By upholding rigorous automation, security, and observability standards, we strengthen the reliability, performance, and safety of the trading ecosystem for every contributor and stakeholder.
