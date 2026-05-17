---
# Front matter / metadata
# This YAML block is intended for documentation generators, bot registries, or CI integrations.
name: "Code Review"
description: "Automated static code analysis agent for pull-request review: detects bugs, security flaws, and deviations from project coding standards."
version: "0.1.0"
maintainer: "canstralian"
repo: "canstralian/red-team-mcp"
repo_id: 1085000049
path: ".github/agents/code-review-agent.md"
type: "agent/metadata"
consumer_targets:
  - "github-actions"
  - "copilot-bot"
  - "documentation-generator"
language_composition:
  - name: "Python"
    percent: 99.9
  - name: "Dockerfile"
    percent: 0.1
ci_integration:
  recommended_workflow: ".github/workflows/code-review.yml"
  sarif_upload: true
  pr_comments: true
tools:
  static_analysis:
    - bandit
    - flake8
    - pylint
    - mypy
  dockerfile_lint:
    - dockle
  secret_scanning:
    - detect-secrets
reporting:
  formats:
    - sarif
    - json
    - markdown
severities:
  fail_on: ["critical", "high"]
  warn_on: ["medium"]
  info_on: ["low"]
---
# Code Review Agent

Short description
- The Code Review agent runs automated, reproducible static-analysis checks on repository code and reports findings on pull requests. It targets maintainability, code quality, and security issues but does not perform dynamic execution or runtime fuzzing.

Purpose
- Automatically analyze changed files in pull requests and provide actionable feedback as PR comments and CI artifacts.
- Enforce repository-specific style and security rules to reduce human review load and surface high-risk changes earlier.
- Produce machine-readable reports (SARIF/JSON) for further processing and dashboards.

Capabilities
- Run Python static analysis tools: flake8, pylint, mypy (type checking).
- Run security-focused checks: bandit (common security issues), detect-secrets (prevent secrets in commits).
- Lint Dockerfiles with dockle or hadolint where Dockerfiles exist.
- Aggregate results into SARIF for GitHub Code Scanning and annotate PRs with contextual comments.
- Apply configured severity thresholds: optionally fail CI on high/critical findings while allowing lower severities to only warn.
- Output remediation guidance and suggested code diffs for simple fixes (style, formatting) but never auto-merge without human approval.

Scope & constraints
- Static analysis only by default. No dynamic tests, payload execution, or in-repo secret exfiltration.
- No automated code changes to production branches. Auto-fix patches may be suggested in a separate branch and require PR and human review.
- Tools and versions must be pinned in CI to ensure reproducible results.
- Must run only on changed files in PRs to reduce noise; full-repo scans can be scheduled separately.

Configuration guidelines (for this repo)
- Place this file at: .github/agents/code-review-agent.md
- Provide a GitHub Actions workflow at .github/workflows/code-review.yml (example below) that:
  - Runs on pull_request events.
  - Checks out the PR branch and the base branch.
  - Installs pinned versions of Python tools in an isolated virtual environment.
  - Runs detect-secrets against the diff and fails fast on secret leaks.
  - Runs flake8/mypy/bandit on changed Python files.
  - Produces SARIF and uploads it with actions/upload-sarif for GitHub Code Scanning.
  - Posts summarized comments to the PR for findings above configured thresholds.

Example recommended thresholds (customize per team)
- critical/high -> fail CI and add blocking PR comment
- medium -> add non-blocking PR comment
- low/info -> include in summary report and optional checklist item

Example CI snippet (conceptual)
- Use pre-built actions or a small reproducible job that:
  - uses python:3.11-slim
  - pip install -r .github/agents/requirements.txt (pin versions)
  - run detect-secrets scan --baseline .secrets.baseline --changed
  - run bandit -r src/ -f json -o bandit.json
  - run flake8 --output-file flake8.out
  - convert outputs to SARIF and upload

Reporting & triage
- Upload SARIF to GitHub Code Scanning so findings appear in the Security tab.
- Post inline PR comments for critical/high issues with:
  - concise description
  - file:line
  - reproduction steps or a minimal fix example
  - recommended remediation links (OWASP, PEP 8, language-specific docs)
- Maintain a suppression/acceptance policy: if an issue is a false positive, allow a documented annotation procedure (e.g., in-code ignore comments + rationales committed in the PR).

Security & privacy considerations
- Never send repository contents to a third-party service without explicit consent.
- Use local, pinned, open-source tools where possible.
- Sanitize outputs posted to PR comments to avoid exposing secrets or excessive context.

Onboarding & maintenance
- Add a small requirements file for the agent under .github/agents/requirements.txt with pinned versions.
- Document the agent in README or CONTRIBUTING with expected developer workflow (how to run locally, reproduce issues, create baselines).
- Schedule periodic (e.g., weekly) full-repo scans separately from PR checks to detect drift.

Notes for Copilot integration
- The metadata keys above (consumer_targets, ci_integration, recommended_workflow) are intentionally explicit so a bot or a workflow can discover and wire up this agent automatically.
- If Copilot or another automation consumes this file, ensure that the consumer is configured to parse the front matter and map:
  - recommended_workflow -> path to the workflow file that should be created or updated
  - tools -> list of tool names to install and run
  - reporting.formats -> which outputs to produce and upload