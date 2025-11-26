"""Assessment domain models for RedTeam MCP Server.

This module provides dataclasses for tracking targets, tool invocations,
findings, and assessment runs during penetration testing operations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _utc_now() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


@dataclass
class Target:
    """Represents a target system for assessment.

    Attributes:
        id: Unique identifier for the target.
        hostname: Optional hostname of the target.
        ip: Optional IP address of the target.
        scope_tags: List of scope/category tags for the target.
    """

    id: str
    hostname: Optional[str]
    ip: Optional[str]
    scope_tags: list[str] = field(default_factory=list)


@dataclass
class ToolInvocation:
    """Records a tool invocation during assessment.

    Attributes:
        tool_name: Name of the tool being invoked.
        args: Arguments passed to the tool.
        started_at: Timestamp when the tool started.
        finished_at: Optional timestamp when the tool finished.
        status: Current status of the invocation (pending, running, completed, failed).
        output_path: Optional path to tool output file.
    """

    tool_name: str
    args: dict[str, object]
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str = "pending"
    output_path: Optional[str] = None


@dataclass
class Finding:
    """Represents a security finding from an assessment.

    Attributes:
        id: Unique identifier for the finding.
        target: The target associated with this finding.
        severity: Severity level of the finding.
        description: Description of the finding.
        metadata: Additional metadata about the finding.
    """

    id: str
    target: Target
    severity: str
    description: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class AssessmentRun:
    """Represents a complete assessment run.

    Attributes:
        id: Unique identifier for the assessment run.
        targets: List of targets in this assessment.
        tool_runs: List of tool invocations during the assessment.
        findings: List of findings discovered during the assessment.
        created_at: Timestamp when the assessment was created.
    """

    id: str
    targets: list[Target]
    tool_runs: list[ToolInvocation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    created_at: datetime = field(default_factory=_utc_now)
