# GitHub Copilot and Codex Configuration Guide for the Trading Bot Swarm Ecosystem

## Purpose and Scope
The purpose of this guide is to standardize how GitHub Copilot and Codex operate within the Trading Bot Swarm ecosystem. Both assistants act strictly as pair programmers who reinforce our engineering guardrails, never as autonomous committers. They:

- Provide inline suggestions that follow the project's architectural and security conventions.
- Surface potential defects, missing tests, or policy violations before code review.
- Respect human approval workflows—no automatic code merges or infrastructure changes.

This guide defines configuration requirements, behavioral rules, automation workflows, and maintenance practices that ensure consistency, code quality, and secure operations across every repository in the swarm.

## Configuration Overview
To align Copilot and Codex output with Trading Bot Swarm standards, every project must document and enforce the following baselines:

- **Testing Discipline** – All code changes must be accompanied by unit, integration, or simulation tests. Fast smoke suites should run locally before pushing. Long-running backtests remain optional but encouraged for high-risk strategies.
- **Linting and Static Analysis** – Enforce formatters (e.g., `black`, `ruff`, `prettier`) and static analyzers (`mypy`, `pyright`, `eslint`, `golangci-lint`) through pre-commit hooks and CI gates. Assistants should never suggest bypassing lint failures.
- **Code Style and Architecture** – Use repository-specific style guides, SOLID-inspired modularization, and domain-driven contexts. Copilot suggestions must align with our asynchronous message bus patterns and shared libraries.
- **Async and Concurrency Patterns** – Default to `asyncio`-based coordination with cancellation handling, bounded queues, and timeout enforcement. Avoid blocking calls in event loops and document fallback behavior for degraded infrastructure.
- **Security Defaults** – Enforce least privilege IAM roles, parameterized queries, key rotation helpers, and secrets isolation (Vault/SM). Generated code must never log secrets or disable security checks.
- **Logging and Observability** – Standardize structured logging (`json` or OpenTelemetry), correlation IDs, metric emission, and tracing instrumentation. Suggestions should include meaningful log levels and redaction helpers.
- **CI/CD Integration** – Require assistants to note when pipelines (build, test, deploy) must be updated. Deploy workflows must target immutable artifacts (container images, packages) with provenance metadata.
- **Version Control Hygiene** – Mandate small, reviewable pull requests, conventional commit messages, and branch protections (required reviews, passing checks). Copilot must encourage rebase over merge commits for feature branches.

## Custom Instruction Behavior
Configure Copilot and Codex with explicit rules that prioritize safety and quality.

### Behavioral Rules for Both Assistants
1. Always reference the repository's configuration files (pre-commit, linters, test matrix) before suggesting changes.
2. Generate code that includes unit tests or concrete validation steps.
3. Highlight potential security, compliance, or performance impacts and recommend mitigations.
4. Prefer refactoring existing components before introducing new services or dependencies.
5. Treat documentation-only pull requests as test-exempt while reminding contributors to update changelogs if needed.

### Copilot Custom Instructions (Conceptual YAML)
```yaml
assistant: copilot
role: "Pair Programmer with Guardrails"
rules:
  - Always propose tests, lint updates, and docstrings alongside code changes.
  - Decline to generate code that accesses live trading keys or bypasses risk controls.
  - Suggest async patterns compatible with Trading Bot Swarm message bus APIs.
  - Reference SECURITY.md and threat models when handling authentication or key management code.
  - Encourage running `make lint test` (or repo equivalent) before submitting PRs.
  - Ignore documentation-only edits when recommending test execution.
responses:
  format: "Concise bullet points with reasoning and follow-up verification steps"
```

### Codex Custom Instructions (Conceptual YAML)
```yaml
assistant: codex
role: "Secure Automation Partner"
rules:
  - Operate in dry-run mode unless explicitly approved by a maintainer.
  - Validate configuration changes against schema definitions and policy-as-code tests.
  - Require secrets to be sourced from pre-approved secret managers; never inline credentials.
  - Enforce semantic versioning and conventional commits when generating release notes.
  - Recommend re-running unit tests, integration tests, and linters after any code change.
  - Skip test reminders when only Markdown or comment files change.
outputs:
  include:
    - risk_assessment
    - test_and_lint_checklist
    - follow_up_actions
```

## Emphasizing Testing and Linting
- For any code modification, assistants must explicitly call out the need to run fast tests (`pytest -m "not slow"`, `npm test -- --watch=false`, etc.) and applicable linters.
- Documentation-only edits (`*.md`, `*.rst`, `*.txt`) are exempt from automated reminders, but changelog and diagram updates remain recommended.

## GitHub Workflow: Lint and Test Automation
The following workflow enforces linting and testing on every push to `main` and pull request targeting `main` or release branches, excluding documentation-only changes.

```yaml
name: quality-gate

on:
  push:
    branches: ["main", "release/**"]
    paths-ignore:
      - "**/*.md"
      - "docs/**"
  pull_request:
    branches: ["main", "release/**"]
    paths-ignore:
      - "**/*.md"
      - "docs/**"

jobs:
  quality-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout repository
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
        run: make lint
      - name: Run unit tests
        env:
          PYTHONWARNINGS: "error"
        run: make test
      - name: Publish coverage
        if: success()
        uses: codecov/codecov-action@v4
```

This job should block merges until both lint and test stages pass, acting as the minimum quality gate for all trading components.

## Semantic Release and Version Tagging Workflow
Automate releases with semantic versioning and changelog generation using the following pattern:

```yaml
name: semantic-release

on:
  push:
    branches: ["main"]

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
      - name: Install Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"
      - name: Install dependencies
        run: npm ci
      - name: Run semantic-release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: npx semantic-release
```

Semantic-release will interpret conventional commit messages, update changelogs, create GitHub releases, and tag versions automatically. Ensure generated artifacts (packages, container images) are attached to releases with integrity metadata.

## Security and Dependency Scanning
Layer automated security checks to catch vulnerabilities early:

```yaml
name: security-scan

on:
  schedule:
    - cron: "0 3 * * 1"  # Every Monday at 03:00 UTC
  workflow_dispatch:

jobs:
  dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run pip-audit
        run: pip install pip-audit && pip-audit
      - name: Run npm audit (if package.json exists)
        if: hashFiles('package.json') != ''
        run: npm audit --production
  codeql:
    uses: github/codeql-action/analyze@v3
    with:
      category: "code-scanning"
```

Augment these scans with Dependabot or Renovate for automated dependency updates and configure required reviewers for high-risk upgrades. Codex should propose mitigations (pinning versions, applying patches) when vulnerabilities surface.

## Contributor Workflow
1. **Proposal** – Open an issue describing the change, risks, and validation plan. For strategy updates, include expected performance impact and risk metrics.
2. **Implementation** – Work on a feature branch, ensuring commits follow the Conventional Commits spec (`feat:`, `fix:`, `chore:`). Keep diffs focused and well-tested.
3. **Validation** – Run `make lint test` (or repo equivalent) locally, capture results, and document any skipped checks with justification.
4. **Review** – Submit a pull request referencing the issue, attach test artifacts, and request review from domain maintainers. Reviewers verify architecture alignment, security controls, and performance safeguards.
5. **Approval & Merge** – Require at least two approvals for high-risk trading logic, one approval otherwise. Squash or rebase commits to maintain a linear history.

## Review Criteria
- Completeness of tests and coverage for core execution paths.
- Compliance with security policies, secret management, and infrastructure hardening.
- Performance considerations (latency, throughput, failure handling) for swarm coordination.
- Documentation updates where behavior changes affect operators or automated agents.
- Evidence that automated workflows (quality gate, release, security scans) were executed successfully.

## Troubleshooting and Optimization Tips
- **Copilot Suggestion Drift** – If suggestions ignore project patterns, regenerate context by selecting relevant files or restating constraints in the prompt.
- **Codex Dry-Run Failures** – Ensure configuration schemas are up to date and run Codex validation commands with verbose logs to identify mismatches.
- **Flaky Tests** – Use deterministic seed configuration and parallel-safe fixtures. Document any quarantined tests with remediation timelines.
- **CI Timeouts** – Cache dependencies (`actions/cache`) and shard long-running simulations across matrix jobs.
- **Security Scan Noise** – Triage alerts weekly, suppressing only with documented rationale and expiration dates.

## Maintenance Schedule
- **Monthly** – Review workflow YAML files for new action versions, update lint/test configurations, and refresh Copilot/Codex instruction templates.
- **Quarterly** – Audit security scanning coverage, validate semantic-release changelog accuracy, and ensure risk controls reflect production incidents.
- **After Major Releases** – Reassess async patterns, observability standards, and dependency baselines to match the current trading infrastructure.

## Conclusion
By standardizing Copilot and Codex behavior, enforcing automation guardrails, and maintaining vigilant review practices, the Trading Bot Swarm ecosystem strengthens its reliability, performance, and safety. This guide exists to institutionalize excellence so that every contribution advances a resilient, secure, and high-quality trading platform.
