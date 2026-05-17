# Trading Bot Swarm Copilot and Codex Configuration Guide

## Purpose and Scope
This guide standardizes how the Trading Bot Swarm ecosystem configures GitHub Copilot, Codex, and Copilot's coding agent extension via Model Context Protocol (MCP). It treats Copilot as a disciplined pair programmer that reinforces automation safety, code quality, and operational reliability. Teams must apply these instructions to any repository that participates in the swarm, including bots, shared libraries, infrastructure, and orchestration code. The guidance covers local developer workflows, CI/CD automation, and maintenance expectations so that every contribution adheres to the swarm's reliability and security bar.

## Configuration Overview
- **Testing**: Every change that affects executable code must include unit, integration, and scenario tests as appropriate. Favor deterministic tests with explicit fixtures. Use `pytest` and `coverage` for Python services, `jest` for Node utilities, and containerized smoke tests for deployment manifests. Never merge code without a green test suite.
- **Linting**: Enforce `ruff` plus `black` for Python, `eslint` for TypeScript, and `hadolint` for Dockerfiles. Linters must run locally (pre-commit) and in CI.
- **Code Style**: Follow PEP 8 with asynchronous patterns conforming to `asyncio` best practices. Prefer type hints everywhere and enforce via `mypy`. Keep functions short, pure where possible, and documented with doctrings describing preconditions, postconditions, and failure modes.
- **Async Patterns**: Use structured concurrency and cancellation-aware tasks. Wrap long-running coroutines in timeouts. Expose async APIs through `async` context managers and avoid mixing blocking IO with async loops.
- **Security Defaults**: Enable secrets scanning, require parameterized queries, and enforce least-privilege IAM roles. Default to TLS for intra-service calls. Review new dependencies for known CVEs before merging.
- **Logging & Observability**: Use structured JSON logging with correlation IDs. Emit metrics (latency, error rate, throughput) and traces to the shared OpenTelemetry collector. Add health checks for all microservices.
- **CI/CD Integration**: Require branch protection, status checks, and signed commits. CI pipelines must gate on linting, tests, security scans, and policy checks. CD pipelines deploy only tagged releases and include automated rollback hooks.
- **Version Control Practices**: Use trunk-based development with short-lived branches. Squash merge commits. Reference Jira tickets in branch names and commit messages. Sign commits using organization-issued GPG keys.

## Extending the Copilot Coding Agent with MCP
Follow GitHub's MCP extension flow to integrate the coding agent with project-specific tools, policies, and knowledge bases. Configure the agent with MCP servers that expose Trading Bot Swarm domain data (market adapters, risk policies, deployment manifests) while enforcing the least privilege principle. Key steps derived from GitHub's guidance include registering MCP tools, specifying schema contracts, and defining context providers so the agent can retrieve documentation, architecture manifests, and guardrail templates during pair-programming sessions. Ensure the agent's instruction set mirrors the rules in this guide and audit MCP server responses for sensitive data leakage before enabling organization-wide use.

## Custom Instruction Behavior
Codex and Copilot must receive explicit behavioral constraints. Configure organization-level custom instructions so the assistant always:
1. Treats tests, linting, and security scans as mandatory before declaring work done.
2. Rejects requests to bypass reviews, policy checks, or logging requirements.
3. Highlights asynchronous safety, error handling, and secure defaults in all generated code.
4. Avoids modifying documentation-only files unless explicitly asked.

### Conceptual YAML Template
```yaml
copilot:
  persona: "Disciplined trading bot engineer"
  goals:
    - "Write resilient, observable, and secure code"
    - "Ensure tests, linters, and scanners run on every change"
  prohibitions:
    - "Skip quality gates"
    - "Commit secrets or credentials"
  reminders:
    - "Summarize test evidence in PR descriptions"
    - "Flag missing async cancellations"

codex:
  response_policy:
    max_tokens: 800
    prefer_diff: true
    cite_sources: true
  code_quality:
    run_tests: required
    run_linters: required
    reject_on_failure: true
  documentation:
    modify_docs: only_when_requested
```
Provide these instructions via the organization's Copilot and Codex configuration portals, and store the canonical YAML in a secure repository to track updates.

## Automation Expectations for Code Changes
- Run unit tests, integration tests, and linters locally before pushing.
- Include coverage reports when modifying core trading logic.
- Skip automation only for documentation changes clearly tagged `[docs-only]` in commit messages.
- Attach PR checklists confirming tests, lint, and security scans succeeded.

## GitHub Workflow: Lint and Test Automation
```yaml
name: quality-gate

on:
  pull_request:
    branches: [ main ]
    paths-ignore:
      - "**/*.md"
      - "docs/**"
  push:
    branches: [ main ]

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: "3.11"
      - name: Install tooling
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      - name: Lint
        run: |
          ruff check .
          black --check .
      - name: Type Check
        run: mypy src
      - name: Unit Tests
        run: pytest --maxfail=1 --disable-warnings --cov=src
      - name: Upload Coverage
        uses: codecov/codecov-action@v3
```
This workflow skips documentation-only changes, ensuring high-signal automation without slowing doc updates.

## Semantic Release and Version Tagging
- Adopt `semantic-release` for repositories distributing packages or services.
- Enforce Conventional Commits to derive version bumps.
- Automate release notes and changelog updates through CI.

```yaml
name: semantic-release

on:
  push:
    branches: [ main ]

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npm ci
      - run: npx semantic-release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
Ensure tags follow `vMAJOR.MINOR.PATCH` and are signed. Reject direct pushes to tags; releases must flow through the pipeline.

## Security and Dependency Scanning
Integrate automated scanning into CI/CD:
- **Dependency Review**: `actions/dependency-review-action@v3` on PRs.
- **SAST**: `github/codeql-action/init` and `autobuild` for languages in scope.
- **Container Scanning**: `aquasecurity/trivy-action@master` for Docker images.

```yaml
name: security-scan

on:
  pull_request:
  schedule:
    - cron: "0 3 * * *"

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v3

  codeql:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python,javascript
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - run: docker build -t ghcr.io/org/trading-bot:${{ github.sha }} .
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: ghcr.io/org/trading-bot:${{ github.sha }}
          format: table
          exit-code: "1"
          vuln-type: "os,library"
```
Security jobs fail on critical findings, blocking merges until resolved.

## Contributor Guidelines
1. **Proposal**: Open an issue describing the change, risks, testing approach, and rollback plan. For major features, attach design docs reviewed by the architecture guild.
2. **Implementation**: Follow branch naming conventions, keep commits atomic, and reference the issue ID. Include updated tests, metrics dashboards, and runbooks where applicable.
3. **Review Criteria**: Reviewers verify adherence to this guide, test coverage sufficiency, performance impact, security posture, and observability hooks. Require at least two approvals for high-risk components.
4. **Validation**: Before merge, ensure CI passes, manual smoke tests complete (if required), and release notes are drafted for user-facing changes.

## Troubleshooting and Optimization
- **Flaky Tests**: Quarantine with `pytest -m "not flaky"` and open an issue to stabilize. Monitor pipeline history to identify recurrent offenders.
- **Lint Failures**: Run `ruff --fix` and `black` locally. Update configuration files if new rules are required, ensuring cross-repo consistency.
- **Performance Regressions**: Use profiling tools (`py-spy`, `perf`) to identify hot paths. Add benchmarks to CI for critical algorithms.
- **Copilot MCP Issues**: Validate MCP server health, review schema contracts, and ensure agent tokens retain necessary scopes. If the agent produces non-compliant suggestions, re-sync instructions and clear cached sessions.

## Maintenance Schedule
- **Quarterly**: Review Copilot/Codex instruction YAML, update MCP server schema references, and audit security scan coverage.
- **Monthly**: Refresh dependency baselines, rotate credentials, and verify that workflow versions match the latest LTS releases.
- **Release Cycle**: Before each quarterly release, rehearse disaster recovery runbooks and validate observability dashboards reflect new metrics.

## Closing Note
By enforcing these standards, the Trading Bot Swarm community codifies excellence across automation, security, and reliability. Our goal is to standardize excellence and strengthen the reliability, performance, and safety of the trading ecosystem. Consistent Copilot and Codex configurations amplify engineering productivity while safeguarding the swarm's trading operations.
