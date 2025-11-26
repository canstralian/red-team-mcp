"""Tests for assessment domain models."""

from datetime import datetime
from src.assessment import Target, ToolInvocation, Finding, AssessmentRun


class TestTarget:
    """Tests for the Target dataclass."""

    def test_target_minimal(self):
        """Test creating a target with required fields only."""
        target = Target(id="t1", hostname=None, ip=None)
        assert target.id == "t1"
        assert target.hostname is None
        assert target.ip is None
        assert target.scope_tags == []

    def test_target_with_all_fields(self):
        """Test creating a target with all fields."""
        target = Target(
            id="t2",
            hostname="example.com",
            ip="192.168.1.100",
            scope_tags=["internal", "production"]
        )
        assert target.id == "t2"
        assert target.hostname == "example.com"
        assert target.ip == "192.168.1.100"
        assert target.scope_tags == ["internal", "production"]

    def test_target_scope_tags_default_mutable(self):
        """Test that scope_tags default is properly isolated per instance."""
        target1 = Target(id="t1", hostname=None, ip=None)
        target2 = Target(id="t2", hostname=None, ip=None)
        target1.scope_tags.append("tag1")
        assert "tag1" in target1.scope_tags
        assert "tag1" not in target2.scope_tags


class TestToolInvocation:
    """Tests for the ToolInvocation dataclass."""

    def test_tool_invocation_minimal(self):
        """Test creating a tool invocation with required fields."""
        started = datetime(2024, 1, 15, 10, 30, 0)
        invocation = ToolInvocation(
            tool_name="nmap",
            args={"target": "192.168.1.0/24"},
            started_at=started
        )
        assert invocation.tool_name == "nmap"
        assert invocation.args == {"target": "192.168.1.0/24"}
        assert invocation.started_at == started
        assert invocation.finished_at is None
        assert invocation.status == "pending"
        assert invocation.output_path is None

    def test_tool_invocation_completed(self):
        """Test creating a completed tool invocation."""
        started = datetime(2024, 1, 15, 10, 30, 0)
        finished = datetime(2024, 1, 15, 10, 35, 0)
        invocation = ToolInvocation(
            tool_name="nikto",
            args={"host": "example.com", "port": 443},
            started_at=started,
            finished_at=finished,
            status="completed",
            output_path="/tmp/nikto_output.txt"
        )
        assert invocation.tool_name == "nikto"
        assert invocation.finished_at == finished
        assert invocation.status == "completed"
        assert invocation.output_path == "/tmp/nikto_output.txt"


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_minimal(self):
        """Test creating a finding with required fields."""
        target = Target(id="t1", hostname="example.com", ip=None)
        finding = Finding(
            id="f1",
            target=target,
            severity="high",
            description="SQL injection vulnerability found"
        )
        assert finding.id == "f1"
        assert finding.target == target
        assert finding.severity == "high"
        assert finding.description == "SQL injection vulnerability found"
        assert finding.metadata == {}

    def test_finding_with_metadata(self):
        """Test creating a finding with metadata."""
        target = Target(id="t1", hostname=None, ip="10.0.0.1")
        finding = Finding(
            id="f2",
            target=target,
            severity="critical",
            description="Remote code execution via deserialization",
            metadata={"cve": "CVE-2024-1234", "cvss": "9.8"}
        )
        assert finding.metadata == {"cve": "CVE-2024-1234", "cvss": "9.8"}

    def test_finding_metadata_default_mutable(self):
        """Test that metadata default is properly isolated per instance."""
        target = Target(id="t1", hostname=None, ip=None)
        finding1 = Finding(id="f1", target=target, severity="low", description="Test")
        finding2 = Finding(id="f2", target=target, severity="low", description="Test")
        finding1.metadata["key"] = "value"
        assert "key" in finding1.metadata
        assert "key" not in finding2.metadata


class TestAssessmentRun:
    """Tests for the AssessmentRun dataclass."""

    def test_assessment_run_minimal(self):
        """Test creating an assessment run with required fields."""
        targets = [Target(id="t1", hostname="example.com", ip=None)]
        run = AssessmentRun(id="run1", targets=targets)
        assert run.id == "run1"
        assert run.targets == targets
        assert run.tool_runs == []
        assert run.findings == []
        assert isinstance(run.created_at, datetime)

    def test_assessment_run_with_all_fields(self):
        """Test creating an assessment run with all fields."""
        target = Target(id="t1", hostname="example.com", ip="192.168.1.1")
        tool_run = ToolInvocation(
            tool_name="nmap",
            args={"-sV": True},
            started_at=datetime(2024, 1, 15, 10, 0, 0)
        )
        finding = Finding(
            id="f1",
            target=target,
            severity="medium",
            description="Open port 22"
        )
        created = datetime(2024, 1, 15, 9, 0, 0)
        
        run = AssessmentRun(
            id="run2",
            targets=[target],
            tool_runs=[tool_run],
            findings=[finding],
            created_at=created
        )
        
        assert run.id == "run2"
        assert len(run.targets) == 1
        assert len(run.tool_runs) == 1
        assert len(run.findings) == 1
        assert run.created_at == created

    def test_assessment_run_tool_runs_default_mutable(self):
        """Test that tool_runs default is properly isolated per instance."""
        targets = [Target(id="t1", hostname=None, ip=None)]
        run1 = AssessmentRun(id="r1", targets=targets)
        run2 = AssessmentRun(id="r2", targets=targets)
        run1.tool_runs.append(
            ToolInvocation(tool_name="test", args={}, started_at=datetime.now())
        )
        assert len(run1.tool_runs) == 1
        assert len(run2.tool_runs) == 0

    def test_assessment_run_findings_default_mutable(self):
        """Test that findings default is properly isolated per instance."""
        targets = [Target(id="t1", hostname=None, ip=None)]
        run1 = AssessmentRun(id="r1", targets=targets)
        run2 = AssessmentRun(id="r2", targets=targets)
        run1.findings.append(
            Finding(id="f1", target=targets[0], severity="low", description="Test")
        )
        assert len(run1.findings) == 1
        assert len(run2.findings) == 0
