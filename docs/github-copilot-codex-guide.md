# Trading Bot Swarm GitHub Copilot & Codex Configuration Guide

## Purpose and Scope
This guide standardizes how the Trading Bot Swarm ecosystem configures GitHub Copilot and Codex so contributors receive the same high-assurance automation everywhere in the stack. Copilot acts as a pair programmer bound by strict behavior rules, while Codex automates scaffolding and bulk refactors. Together they must reinforce the security, reliability, and performance guarantees that keep the trading platform safe.

The document covers:
- Core configuration principles that ensure deterministic, high-quality output.
- Guardrails for asynchronous patterns, security defaults, logging, observability, CI/CD, and version control.
- Mandatory behavioral instructions for Copilot and Codex, expressed as conceptual YAML.
- Automated quality gates for linting, testing, semantic releases, version tagging, and security scanning.
- Contributor workflows, troubleshooting, and maintenance practices so the guide stays current.

## Configuration Overview
| Area | Expectations |
| --- | --- |
| **Runtime Baseline** | Python 3.11+ across services. All dependencies must support this baseline. |
| **Dependency Management** | Lock SQLAlchemy to the 2.x series and track the latest Alembic release. Use Renovate/Dependabot with security alerts enabled. |
| **Testing** | Unit tests use `pytest` with async fixtures via `pytest-asyncio`. Integration tests run in CI nightly with Dockerized infrastructure. Contributors must add or update tests alongside code changes. |
| **Linting & Formatting** | Enforce `ruff` for linting and `black` for formatting. Apply `mypy` in strict mode for type safety. |
| **Code Style** | Favor dependency injection, explicit interfaces, and `pydantic` models for validation. Use `async`/`await` with structured concurrency (`asyncio.TaskGroup`) and cancellation safety. |
| **Security Defaults** | Require secrets via environment variables managed by Vault. Enforce parameterized queries, ORM scoped sessions, and least-privilege IAM roles. |
| **Logging & Observability** | Standardize on `structlog` with JSON output. Emit OpenTelemetry traces and metrics via OTLP collectors. |
| **CI/CD Integration** | Pull requests must pass lint, type-check, and test jobs. Tagged releases trigger semantic versioning, changelog generation, and artifact publishing. |
| **Version Control** | Feature branches follow `feat/<area>-<summary>`. Use signed commits and linear history enforced by GitHub branch protection. |

## Custom Instruction Behavior
Both Copilot and Codex operate under explicit guardrails to preserve code quality and compliance.

### Copilot Role Definition
- Treat Copilot as a reviewer-level assistant that suggests diffs but never self-commits.
- Copilot suggestions must reference existing patterns before inventing new abstractions.
- Copilot is forbidden from bypassing security checks, editing secrets, or disabling quality gates.
- All Copilot-assisted changes require human verification, test execution, and linting before merge.

### Codex Role Definition
- Codex automates repetitive scaffolding tasks and migration boilerplate.
- Codex must generate idempotent scripts with clear rollback paths.
- Codex cannot run shell commands that mutate production data or infrastructure.
- Codex changes require peer review plus security sign-off when touching authentication, authorization, or fund movement code.

### Conceptual YAML Instructions
```yaml
copilot:
  persona: "Pair programmer focused on security-first trading automation"
  principles:
    - "Follow project style guides (Black, Ruff, mypy strict)."
    - "Never suggest changes that weaken authentication, logging, or monitoring."
    - "Reference existing services (security-audit, code-quality-enforcer, ctf-analyzer, embedded-flasher) before proposing new modules."
    - "Promote async best practices: TaskGroup, timeouts, cancellation scopes."
  required_actions:
    - "Prompt human to run tests and linters for any code modification."
    - "Reject requests to skip documentation for security-sensitive updates."
    - "Flag secrets or credentials for manual redaction."
  forbidden:
    - "Committing code."
    - "Disabling CI jobs or modifying branch protections."
    - "Suggesting plaintext storage of sensitive data."

codex:
  persona: "Automation engineer delivering production-grade scaffolds"
  principles:
    - "Prefer configuration-driven designs with typed interfaces."
    - "Generate SQLAlchemy 2.x models with Alembic migrations using async engines."
    - "Align file layout with security-audit, code-quality-enforcer, ctf-analyzer, embedded-flasher order."
    - "Include logging, observability hooks, and rollbacks in scaffolds."
  required_actions:
    - "Emit TODOs with owners when manual secret provisioning is needed."
    - "Recommend pytest suites and Ruff/Mypy invocations after code generation."
    - "Document assumptions and environment variables in README stubs."
  forbidden:
    - "Running destructive database migrations without confirmation prompts."
    - "Generating code without dependency or version constraints."
    - "Removing existing security controls."
```

## Quality Gate Workflow Example
The `lint-and-test.yml` workflow enforces the minimum bar for any pull request targeting `main`.

```yaml
name: Lint and Test

on:
  pull_request:
    branches: ["main"]
    paths-ignore:
      - "docs/**"
      - "**/*.md"
  push:
    branches: ["main"]

jobs:
  quality-gate:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Install tooling
        run: |
          pip install ruff mypy pytest pytest-asyncio
      - name: Lint
        run: ruff check .
      - name: Type check
        run: mypy --strict src
      - name: Run tests
        run: pytest --maxfail=1 --disable-warnings -q
```

## Semantic Release & Version Tagging
Adopt conventional commits and automated release notes using `semantic-release`.

```yaml
name: Semantic Release

on:
  push:
    branches: ["main"]

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - name: Install dependencies
        run: npm ci
      - name: Semantic release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: npx semantic-release
```

### Version Tagging Best Practices
- Annotated tags follow `v<MAJOR>.<MINOR>.<PATCH>`.
- Every release includes generated changelog entries and links to CI artifacts.
- Rollback instructions must be attached to release notes for critical services.

## Security & Dependency Scanning
Security automation runs nightly and on pull requests that touch dependency manifests.

```yaml
name: Security Scan

on:
  schedule:
    - cron: "0 3 * * *"
  pull_request:
    paths:
      - "pyproject.toml"
      - "requirements*.txt"
      - "Dockerfile"

jobs:
  dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install pip-audit
        run: |
          python -m pip install --upgrade pip
          pip install pip-audit safety
      - name: pip-audit
        run: pip-audit --strict
      - name: Safety check
        run: safety check --full-report

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: trufflesecurity/trufflehog@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

## Contributor Guidelines
1. **Proposal Stage**
   - Open a GitHub issue describing scope, risks, testing strategy, and rollback plan.
   - Tag the issue with the relevant domain label (`execution`, `exchange-integration`, `risk-controls`).
2. **Implementation Stage**
   - Create a feature branch and follow Copilot/Codex guardrails.
   - Update or add tests; documentation changes alone still require spelling and lint checks.
   - Run `ruff`, `mypy --strict`, and `pytest` locally before pushing.
3. **Review Criteria**
   - Reviewers verify security posture, dependency impact, observability coverage, and performance regressions.
   - Any change touching fund movement or risk checks needs dual approval (engineering + security).
4. **Validation Process**
   - Ensure CI passes all gates.
   - Stage migrations in a sandbox environment and attach evidence to the pull request.
   - Confirm monitoring dashboards and alerts for new services before merge.

## Troubleshooting & Optimization Tips
- **Copilot Overreach**: If suggestions conflict with guardrails, tighten prompts and remind Copilot of the YAML instructions.
- **Flaky Async Tests**: Use deterministic timeouts, `asyncio.TaskGroup`, and fake clocks via `freezegun` or `pytest-freezegun`.
- **Slow Lints**: Cache `ruff` and `mypy` results using GitHub Actions cache keyed by `pyproject.toml` and the Python version.
- **Dependency Conflicts**: Pin transitive dependencies in `requirements.txt` snapshots generated by `pip-compile`.
- **Semantic Release Failures**: Verify commit history matches conventional commit spec; rerun the workflow after fixing commit messages.
- **Security Alerts**: Rotate credentials immediately, patch vulnerable packages, and document mitigations in the security issue tracker.

## Maintenance Schedule
- **Monthly**: Review Copilot/Codex instructions, update dependency baselines, and rotate API tokens.
- **Quarterly**: Validate CI workflows, renew threat models, and refresh observability runbooks.
- **After Major Releases**: Reconfirm compatibility with new exchange APIs, update semantic-release configuration, and audit access controls.
- **Annually**: Run full incident response drills and evaluate third-party integrations for compliance.

## Closing Note
Standardizing these practices elevates every contributor, ensuring the Trading Bot Swarm ecosystem remains reliable, performant, and safe. By enforcing disciplined automation, we continuously raise the bar for excellence across trading strategies and infrastructure.
