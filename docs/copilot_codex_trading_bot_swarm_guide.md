# Trading Bot Swarm Copilot & Codex Configuration Guide

## Purpose and Scope
- Establish a unified Copilot and Codex configuration for the Trading Bot Swarm ecosystem.
- Treat GitHub Copilot as a strictly governed pair programmer that complements human review.
- Guarantee consistency, code quality, and safe automation across swarm agents, shared libraries, and infrastructure.
- Provide reference automation, security, and maintenance practices that align with Trading Bot Swarm release standards.

## Configuration Overview
### Behavioral Principles
- Copilot acts as an advisory assistant; it **never** merges code, bypasses review, or suppresses tests.
- Enforce explicit prompts that require Copilot to propose tests, documentation updates, and security implications for any code change.
- Codex operates under the same behavioral discipline when run via CLI or MCP toolchains.

### Testing & Linting
- Every feature or bug fix must include automated tests (unit, integration, or simulation harness as appropriate).
- Execute `pytest` and `mypy` (or `pyright` for TypeScript adapters) before opening a PR.
- Enforce style checks with `ruff` for Python, `eslint` for JS/TS, and `prettier --check` for formatting.
- Coverage thresholds: Python ≥ 85%, JS/TS ≥ 80%; blockers for lower coverage unless explicitly waived.

### Code Style & Async Patterns
- Adopt PEP 8, Google-style docstrings, and type hints for all Python services.
- Prefer async-first patterns in network-bound workflows; use `asyncio` task groups with explicit timeouts.
- Require defensive cancellation handling and idempotent retriable code paths for distributed swarm agents.

### Security Defaults
- Default to least-privilege service accounts and secrets supplied via environment management (e.g., Doppler or AWS Secrets Manager).
- Mandate signature verification for downloaded models and datasets.
- Require dependency pinning with hash-checking (Poetry `hashes`, npm `package-lock.json`).
- Enable secret scanning hooks (GitHub Advanced Security or Gitleaks) for every commit.

### Logging & Observability
- Standardize structured logging (JSON) with correlation IDs derived from swarm task IDs.
- Push metrics to Prometheus-compatible endpoints; surface P99 latency, error rates, and retry counts.
- Integrate OpenTelemetry tracing with sampling policies tuned for high-frequency bot interactions.

### CI/CD Integration
- Pipeline stages: lint → unit tests → integration tests → security scans → deploy to staging.
- Require manual approval for production deploys; approvals must review Copilot suggestions and human commits.
- Use environment protection rules to ensure the swarm’s shared secrets are isolated per stage.

### Version Control Discipline
- Branch naming: `feature/<summary>`, `fix/<issue-id>`, `hotfix/<issue>`.
- Use signed commits (`git commit -S`).
- Rebase on main before opening PRs to keep history linear.

## Custom Instruction Behavior
### Codex Guardrails
- Require Codex prompts to specify testing commands and validation steps.
- Restrict Codex from writing secrets, credentials, or disabling security checks.
- Encourage Codex to propose threat modeling notes for high-risk changes.

### Copilot Guardrails
- Force Copilot to cite relevant files and remind developers to run tests.
- Reject Copilot completions that remove logging, authentication, or error handling without replacements.
- Copilot should flag when documentation updates are required but **should not** auto-generate release notes.

### Example Instruction Snippets (Conceptual YAML)
```yaml
copilot:
  role: "pair-programmer"
  defaults:
    enforce_tests: true
    enforce_lint: true
    require_security_review: true
  prompts:
    - "When suggesting code, include test updates and explain risk mitigations."
    - "Never suggest committing directly to main."
  forbidden_actions:
    - remove_security_controls
    - bypass_ci
    - introduce_hardcoded_secrets

codex:
  role: "cli-assistant"
  workflow:
    - step: "Analyze change scope"
      reminder: "List tests and linters to run; skip documentation-only changes."
    - step: "Propose implementation"
      reminder: "Highlight security impact and async considerations."
    - step: "Validation"
      reminder: "Run pytest, ruff, mypy; confirm git status clean."
  overrides:
    ignore_doc_only_changes: true
    require_change_log: false
```

## GitHub Workflow: Lint and Test Automation
Trigger: `pull_request` (opened, synchronize, reopened) and `workflow_dispatch`.

```yaml
name: quality-gate

on:
  pull_request:
    types: [opened, synchronize, reopened]
    paths-ignore:
      - "docs/**"
      - "*.md"
  workflow_dispatch:

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install Poetry
        run: pip install poetry
      - name: Install dependencies
        run: poetry install --with dev
      - name: Lint
        run: poetry run ruff check .
      - name: Type check
        run: poetry run mypy src tests
      - name: Unit tests
        run: poetry run pytest --maxfail=1 --disable-warnings -q
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
```

## Semantic Release & Version Tagging Best Practices
- Adopt conventional commits (`feat:`, `fix:`, `perf:`, `chore:`) to enable semantic release automation.
- Use `semantic-release` to auto-bump versions, generate changelogs, and create GitHub releases.

```yaml
name: semantic-release

on:
  push:
    branches: [main]

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npm ci
      - run: npx semantic-release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Version Tagging
- Ensure the CI pipeline tags releases in the format `v<major>.<minor>.<patch>`.
- Protect tags with required reviews before deletion.
- Mirror tags to container registries for swarm deployment rollbacks.

## Security & Dependency Scanning
- Schedule nightly scans plus on-demand `workflow_dispatch`.

```yaml
name: security-scan

on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

jobs:
  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python, javascript
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3

  dependency-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Python audit
        run: |
          pip install pip-audit
          pip-audit
      - name: Node audit
        run: |
          npm install --package-lock-only
          npm audit --audit-level=moderate
```

## Contributor Guidelines
- Open an issue describing scope, risks, and testing plan before submitting PRs.
- PR checklist must confirm tests, lint, threat model updates, and Copilot/Codex compliance.
- Reviewers examine:
  - Security impact (secrets, auth paths, data validation).
  - Observability completeness (logs, metrics, tracing).
  - Async robustness and resilience under load.
- Validation requires passing CI pipelines and manual verification of swarm simulations where applicable.

## Troubleshooting & Optimization Tips
- **Copilot stalls**: clear the IDE cache, refresh authentication, and verify network proxy settings.
- **CI flakiness**: rerun failed jobs with verbose logging; investigate timeouts and add retries around external APIs.
- **Coverage dips**: ensure new async workflows include deterministic unit tests and property-based checks.
- **Dependency conflicts**: leverage Poetry resolution hints (`poetry lock --no-update`) or npm overrides.
- **Security alerts**: prioritize remediation within 24 hours; if false positive, document the rationale in SECURITY.md.

## Maintenance Schedule
- Quarterly review to align with updated Trading Bot Swarm architecture and dependency baselines.
- Monthly sync with security engineering for new scanning tools or policy changes.
- Post-release audit to capture lessons learned and update guardrails.

---

**Goal:** Standardize excellence, fortify reliability, performance, and safety across the Trading Bot Swarm trading ecosystem.
