# Trading Bot Swarm Copilot & Codex Configuration Guide

> **Objective**: Deliver a single source of truth for configuring GitHub Copilot and Codex inside the Trading Bot Swarm so that every contributor, automation agent, and release pipeline operates with the same expectations for safety, speed, and quality.

## Purpose and Scope
This guide standardizes how GitHub Copilot and Codex operate within the Trading Bot Swarm ecosystem. Copilot must behave as a disciplined, policy-aware pair programmer that enhances human workflows without overriding intent. Codex-powered automations should follow the same guardrails, prioritizing capital protection, deterministic execution, and compliance with platform governance. The scope covers IDE setup, repository conventions, CI/CD practices, and contributor responsibilities to sustain consistent, high-quality, and secure automation across trading services and support tooling.

### Pair Programmer Expectations
- Treat Copilot as a junior engineer operating under explicit human direction. Require it to cite assumptions, alternatives, and validation steps before proposing code.
- Configure Copilot suggestions to default to read-only until reviewers approve significant logic or risk-model adjustments.
- Mandate that every automated suggestion includes references to the relevant tests, dashboards, or runbooks needed for validation.
- Escalate Copilot responses that contradict risk controls, compliance mandates, or resiliency patterns to human maintainers immediately.

## Configuration Overview
Establish these global expectations before enabling Copilot or Codex on a project. Treat the checklist as a baseline to be tightened for regulated or high-risk strategies.

### Testing & Linting
- Run unit, integration, property-based, and regression suites via `pytest` (or service-specific runners) on every feature or bugfix branch, with coverage thresholds negotiated per subsystem and enforced via `coverage.py`.
- Enforce static analysis with `ruff` (Python), `mypy` (type checking), and language-specific linters (`eslint`/`biome` for TypeScript dashboards, `golangci-lint` for Go microservices). Cache results in CI to reduce feedback latency.
- Block merges when automated checks fail, when required coverage drops below targets, or when flaky tests are detected without an owner-assigned remediation plan.

### Code Style
- Adopt `ruff`'s PEP 8 profile supplemented with project rules: 100-character lines, explicit `async` suffixes, and named return tuples for market-sensitive flows.
- Require docstrings (Google-style or NumPy-style) for exported classes/functions, type hints for all public interfaces, and inline rationale comments for risk or pricing algorithms.
- Enforce deterministic formatting with `black` or `ruff format`, maintain import sorting (`ruff check --select I`), and document any intentional deviations in `pyproject.toml`.

### Async Patterns
- Prefer `asyncio` with cooperative cancellation for trading loops; ensure graceful shutdown of market data feeds and order routers via `asyncio.TaskGroup` or `anyio.create_task_group`.
- Use `anyio`-compatible primitives and structured concurrency to simplify cross-runtime libraries and avoid orphaned coroutines.
- Wrap long-lived tasks with timeouts, health checks, and structured exception propagation. Surface anomalies via circuit-breaker metrics and escalate when latencies exceed service-level objectives.

### Security Defaults
- Centralize secrets via Vault-backed environment injection or cloud secret managers; prohibit plaintext secrets in configs, docs, or test fixtures.
- Use role-based access control for automation tokens, require hardware-backed MFA for maintainers, and enforce least privilege for bots via scoped PATs or GitHub App permissions.
- Require signature verification, freshness checks, and sandboxing for third-party strategy bundles. Capture dependency provenance with Software Bills of Materials (SBOMs).

### Logging & Observability
- Emit structured JSON logs with correlation IDs, tenant identifiers, and sensitive-field redaction. Default to INFO-level logging with environment overrides for noisy components.
- Instrument services with OpenTelemetry tracing, Prometheus metrics, and alerting on latency spikes, risk-rule rejections, and capital utilization drift. Include log exemplars for runbooks.
- Define SLIs/SLOs for trade execution success, decision latency, and risk evaluation turnaround; track error budgets and feed into release gating.

### CI/CD Integration
- Require pre-merge GitHub Actions (or equivalent) for lint/test, security scanning, and policy conformance. Deny approvals until all status checks succeed.
- Deploy via Argo CD, GitHub Environments, or Spinnaker with manual approval gates for production and automated smoke validation for staging.
- Gate rollouts on canary metrics, automated rollback policies, and post-deploy verification suites that exercise critical trading flows.

### Version Control Practices
- Use trunk-based development with short-lived branches rebased against `main`; prohibit long-lived forks without platform approval.
- Sign commits with GPG/SSH; require verified signatures for release branches and maintainers. Enforce protected branch rules with status checks and review gates.
- Tag semantic releases (`vMAJOR.MINOR.PATCH`) automatically and publish `CHANGELOG.md` updates via automation to maintain investor and auditor transparency.

## Custom Instruction Behavior
Copilot and Codex must respect tailored instructions to maintain discipline. Configure IDE integrations (VS Code, JetBrains, Neovim) and automation agents to load these expectations at startup.

### Example Rules
1. Never commit, push, or open a pull request without passing tests, linters, static analyzers, and policy checks relevant to the change set.
2. Default to secure patterns (parameterized queries, safe evaluation replacements, sanitized logging) and raise explicit warnings if constraints cannot be met.
3. Escalate uncertain decisions, ambiguous requirements, or conflicting instructions to human reviewers instead of guessing.
4. Treat documentation-only changes as optional for automated testing, but never skip security, policy, or dependency gates when code changes occur. Explicitly document when checks are skipped due to docs-only work.
5. Track all assumptions in change logs, including expected risk impacts, rollback strategies, and any outstanding follow-up tasks.

### Conceptual YAML Configuration
Provide custom instructions through IDE settings, repository onboarding scripts, or prompt templates using a consistent YAML schema:

```yaml
copilot:
  role: "strict_pair_programmer"
  priorities:
    - "protect trading capital"
    - "preserve code quality"
    - "respect human intent"
  engagement_model:
    request_review: true
    summarize_before_completion: true
  rules:
    - "run tests and linters before proposing commits"
    - "flag missing error handling, timeouts, or input validation"
    - "prefer existing utilities over creating duplicates"
    - "avoid altering documentation-only commits with automation"
    - "annotate security-sensitive suggestions with rationale"
  review_protocol:
    - step: "summarize change scope and risk classification"
    - step: "list affected modules and data contracts"
    - step: "recommend verification commands and dashboards"
  prohibited_actions:
    - "modify release tags without maintainer approval"

codex:
  role: "automation_author"
  safeguards:
    - "generate diffs only after lint/test commands succeed"
    - "adhere to repo-specific coding standards"
    - "refuse unsafe API usage (eval, exec, shell=True) unless explicitly justified"
    - "redact secrets, API keys, and account identifiers in logs"
  commit_policy:
    required_checks:
      - "pytest"
      - "ruff"
      - "mypy"
      - "bandit"
    skip_when:
      - condition: "docs_only"
        action: "allow lint/test skip but still run spellcheck"
  escalation:
    - trigger: "security_policy_violation"
      action: "notify maintainers and halt automation"
    - trigger: "market_safety_risk"
      action: "open incident and revert pending deployments"
```

Document how to load the YAML into VS Code (`settings.json`), JetBrains (`.ide/copilot-config.yml`), and CI onboarding scripts so new contributors inherit the behavior automatically.

## GitHub Workflow Example: Lint & Test Automation
Trigger the workflow on pull requests, pushes to protected branches, dependency updates, and manual dispatch for replayed checks. This job doubles as the quality gate and publishes artifacts for downstream jobs.

```yaml
name: quality-gate

on:
  pull_request:
    branches: ["main", "release/*"]
  push:
    branches: ["main", "release/*"]
  workflow_dispatch:
  schedule:
    - cron: "15 2 * * 1-5"  # weekday drift detection

jobs:
  lint-test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      checks: write
      security-events: write
    env:
      PIP_CACHE_DIR: .pip-cache
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Restore Python cache
        uses: actions/cache@v4
        with:
          path: |
            .pip-cache
            ~/.cache/pip
          key: python-${{ runner.os }}-${{ hashFiles('requirements*.txt') }}
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
          bandit -r src
      - name: Run tests
        run: |
          pytest --maxfail=1 --disable-warnings --cov=src --cov-report=xml --cov-report=term
      - name: Upload coverage to Codecov
        if: github.event_name != 'workflow_dispatch'
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          fail_ci_if_error: true
      - name: Archive pytest results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pytest-logs
          path: .pytest_cache
```

## Semantic Release & Version Tagging Best Practices
Automate semantic versioning to ensure predictable releases, regulatory traceability, and clear change logs for audit trails.

- Adopt Conventional Commits and lint messages in CI (`commitlint` or `conform`), rejecting pushes that violate the format.
- Use `semantic-release` or `python-semantic-release` for automated tagging, GitHub releases, changelog generation, and release notes distribution to trading desks.
- Gate release workflows to run only on `main` after successful quality-gate, security, and manual approval jobs. Capture release metadata for risk review dashboards.

```yaml
name: semantic-release

on:
  workflow_run:
    workflows: ["quality-gate"]
    types: ["completed"]

jobs:
  publish:
    if: >-
      ${{ github.event.workflow_run.conclusion == 'success' &&
          github.event.workflow_run.head_branch == 'main' }}
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
          PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
        run: |
          semantic-release publish
      - name: Broadcast release summary
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {"text": "Semantic release completed for ${{ github.repository }}"}
```

## Security & Dependency Scanning
Integrate continuous scanning to detect vulnerabilities, policy drift, and supply-chain exposure. Combine SAST, dependency reviews, secret scanning, and container analysis.

```yaml
name: security-scan

on:
  schedule:
    - cron: "0 3 * * 1"
  pull_request:
    branches: ["main", "release/*"]
  push:
    branches: ["main"]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python
      - name: Autobuild
        uses: github/codeql-action/autobuild@v3
      - name: Run CodeQL analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "security"

  dependency_review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Dependency review
        uses: actions/dependency-review-action@v4

  container_scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build OCI image
        run: docker build -t trading-bot:${{ github.sha }} .
      - name: Scan image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: trading-bot:${{ github.sha }}
          format: 'table'
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
```

## Contributor Guidelines
1. **Proposal**: Open an issue describing the change, expected impact on trading strategies, observability, and risk posture. Attach diagrams or runbooks when architecture shifts are involved.
2. **Design Review**: Seek feedback via architecture threads or design docs; include threat modeling when touching risk engines, settlement paths, or customer data boundaries.
3. **Implementation**: Create a feature branch, follow Copilot/Codex instructions, document command logs for tests/linters, and update configuration snapshots as needed.
4. **Validation**: Ensure automated checks pass, attach logs for manual sign-offs, link to dashboards verifying SLO adherence, and request review from domain owners plus security champions.
5. **Approval Criteria**: Reviewers confirm security controls, performance benchmarks, regression coverage, observability hooks, and rollback readiness before merging.
6. **Post-Merge Monitoring**: Observe canary environments, confirm alerting health, and close the issue with validation evidence.

## Troubleshooting & Optimization Tips
- **Copilot drift**: Reset instructions, clear local cache, and re-authenticate when suggestions ignore policies. Document deviations for governance review.
- **Flaky tests**: Quarantine via pytest markers, file a reliability issue with reproduction steps, and prioritize fixes within the next sprint.
- **Performance regressions**: Profile with PySpy/cProfile, compare metrics against baseline dashboards, and update load-test scenarios to mirror production order flow.
- **Dependency conflicts**: Regenerate lockfiles with `pip-compile`, run compatibility suites in staging, and document overrides in `DEPENDENCY_NOTES.md`.
- **CI bottlenecks**: Enable caching, parallelize test shards, and monitor pipeline durations in Grafana to maintain <10 minute feedback loops.

## Maintenance Schedule
- Review this guide quarterly or when major tooling/policy changes occur (e.g., new security mandates, exchange integrations, or compliance updates).
- Sync with platform security reviews, release train retrospectives, incident postmortems, and model governance boards to capture lessons learned.
- Archive outdated instructions, link to superseded documents, and notify contributors via Slack/Teams and repository release notes to maintain clarity.

## Closing Note
By aligning Copilot and Codex usage with these standards, the Trading Bot Swarm community reinforces excellence in reliability, performance, and safety across all automated trading capabilities, ensuring every contribution strengthens the ecosystem.
