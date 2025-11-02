# Trading Bot Swarm Copilot & Codex Configuration Guide

## Purpose and Scope
This guide standardizes how GitHub Copilot and Codex operate within the Trading Bot Swarm ecosystem. It frames Copilot as a disciplined pair programmer that collaborates without overriding human intent, follows security-first defaults, and respects workflow guardrails. The scope covers local IDE setup, repository governance, automation pipelines, and contributor responsibilities that ensure consistent, high-quality, and safe automation across trading services.

## Configuration Overview
Establish these global expectations before enabling Copilot or Codex on a project:

### Testing & Linting
- Require every feature or bugfix branch to run unit, integration, and regression suites via `pytest`, with coverage thresholds defined per service.
- Enforce static analysis with `ruff` (Python), `mypy` (type checking), and service-specific linters (e.g., `eslint` for TypeScript dashboards).
- Block merges when automated checks fail or required coverage drops below targets.

### Code Style
- Adopt `ruff`'s PEP 8 profile plus project-specific rules (e.g., 100-character lines, explicit `async` naming).
- Mandate docstrings for exported classes/functions and type hints for all public interfaces.
- Require deterministic formatting with `black` or `ruff format`, and enforce import sorting.

### Async Patterns
- Prefer `asyncio` with explicit cancellation handling for trading loops.
- Use `anyio`-compatible primitives for cross-runtime libraries.
- Wrap long-lived tasks with timeouts, health checks, and structured exception propagation.

### Security Defaults
- Centralize secrets via Vault-backed environment injection; disallow plaintext secrets in configs.
- Use role-based access control for automation tokens and enforce least privilege for bots.
- Require signature verification, freshness checks, and sandboxing for third-party strategy bundles.

### Logging & Observability
- Emit structured JSON logs with correlation IDs and sensitive-field redaction.
- Instrument services with OpenTelemetry tracing and Prometheus metrics, surfacing circuit-breaker and latency data.
- Define SLIs/SLOs for trade execution success, latency, and risk-rule evaluation.

### CI/CD Integration
- Require pre-merge GitHub Actions for lint/test, security scanning, and policy conformance.
- Deploy via Argo CD or GitHub Environments with manual approval gates for production.
- Gate rollouts on canary metrics and automated rollback policies.

### Version Control Practices
- Use trunk-based development with short-lived feature branches, rebasing against `main`.
- Sign commits with GPG/SSH; require verified signatures for release branches.
- Tag semantic releases (`vMAJOR.MINOR.PATCH`) and document change logs in `CHANGELOG.md` via automation.

## Custom Instruction Behavior
Copilot and Codex must respect tailored instructions to maintain discipline. Configure IDE integrations (VS Code, JetBrains) to include the following behavior models.

### Example Rules
1. Never commit or push without passing tests and linters.
2. Default to secure patterns (parameterized queries, safe eval replacements, sanitized logging).
3. Escalate uncertain decisions to human reviewers instead of guessing.
4. Treat documentation-only changes as optional for automated testing, but never skip security or policy gates when code changes occur.

### Conceptual YAML Configuration
```yaml
copilot:
  role: "strict_pair_programmer"
  priorities:
    - "protect trading capital"
    - "preserve code quality"
    - "respect human intent"
  rules:
    - "run tests and linters before proposing commits"
    - "flag missing error handling, timeouts, or input validation"
    - "prefer existing utilities over creating duplicates"
    - "avoid altering documentation-only commits with automation"
  review_protocol:
    - step: "summarize change"
    - step: "list affected modules"
    - step: "recommend verification commands"

codex:
  role: "automation_author"
  safeguards:
    - "generate diffs only after lint/test commands succeed"
    - "adhere to repo-specific coding standards"
    - "refuse unsafe API usage (eval, exec, shell=True) unless explicitly justified"
  commit_policy:
    required_checks:
      - "pytest"
      - "ruff"
      - "mypy"
    skip_when:
      - condition: "docs_only"
        action: "allow lint/test skip"
  escalation:
    - trigger: "security_policy_violation"
      action: "notify maintainers"
```

## GitHub Workflow Example: Lint & Test Automation
Trigger the workflow on pull requests, pushes to protected branches, and manual dispatch for replayed checks.

```yaml
name: quality-gate

on:
  pull_request:
    branches: ["main", "release/*"]
  push:
    branches: ["main", "release/*"]
  workflow_dispatch:

jobs:
  lint-test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      checks: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      - name: Run linters
        run: |
          ruff check .
          mypy src
      - name: Run tests
        run: |
          pytest --maxfail=1 --disable-warnings --cov=src --cov-report=xml
      - name: Upload coverage to Codecov
        if: github.event_name != 'workflow_dispatch'
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          fail_ci_if_error: true
```

## Semantic Release & Version Tagging Best Practices
Automate semantic versioning to ensure predictable releases and change logs.

- Adopt Conventional Commits; lint commit messages in CI (`commitlint`).
- Use `semantic-release` or `python-semantic-release` for automated tagging, GitHub releases, and changelog generation.
- Gate release workflows to run only on `main` with successful quality checks.

```yaml
name: semantic-release

on:
  workflow_run:
    workflows: ["quality-gate"]
    types: ["completed"]

jobs:
  publish:
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install release tooling
        run: |
          pip install python-semantic-release
      - name: Run semantic release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          semantic-release publish
```

## Security & Dependency Scanning
Integrate continuous scanning to detect vulnerabilities and policy drift.

```yaml
name: security-scan

on:
  schedule:
    - cron: "0 3 * * 1"
  pull_request:
    branches: ["main", "release/*"]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run CodeQL analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "security"

  dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Dependency review
        uses: actions/dependency-review-action@v4
      - name: SCA scan
        uses: anchore/scan-action@v3
        with:
          path: .
```

## Contributor Guidelines
1. **Proposal**: Open an issue describing the change, impact on trading strategies, and verification plan.
2. **Design Review**: Seek feedback via architecture discussion threads; include threat modeling when touching risk engines or settlement paths.
3. **Implementation**: Create a feature branch, follow Copilot/Codex instructions, and document tests run.
4. **Validation**: Ensure automated checks pass, attach logs for manual sign-offs, and request review from domain owners.
5. **Approval Criteria**: Reviewers confirm security controls, performance benchmarks, and regression coverage before merging.

## Troubleshooting & Optimization Tips
- **Copilot drift**: Reset instructions and re-authenticate when suggestions ignore policies.
- **Flaky tests**: Quarantine via pytest markers and raise a reliability issue with reproduction steps.
- **Performance regressions**: Use profiling tooling (PySpy, cProfile) and compare metrics against baseline dashboards.
- **Dependency conflicts**: Regenerate lockfiles with `pip-compile` and run compatibility suites in staging environments.

## Maintenance Schedule
- Review this guide quarterly or when major tooling/policy changes occur.
- Sync with platform security reviews, release train retrospectives, and incident postmortems to capture lessons learned.
- Archive outdated instructions and link to superseded documents to maintain clarity.

## Closing Note
By aligning Copilot and Codex usage with these standards, the Trading Bot Swarm community standardizes excellence and strengthens the reliability, performance, and safety of the trading ecosystem.
