"""Regression tests for VerificationIntegrityAgent file classification."""

from pathlib import Path
from unittest.mock import patch

from src.verification.verification_integrity_agent import VerificationIntegrityAgent


def test_markdown_setup_guide_is_excluded(tmp_path: Path) -> None:
    """Documentation must not be treated as an executable verification artifact."""
    setup = tmp_path / "SETUP.md"
    setup.write_text(
        "# Setup\n\n## Verify Installation\n\nRun `python -m src.main --help`.\n",
        encoding="utf-8",
    )

    agent = VerificationIntegrityAgent()

    assert agent.analyze_file(setup) is None


def test_verification_shell_script_remains_relevant(tmp_path: Path) -> None:
    """Executable verification content must survive the documentation exclusion."""
    script = tmp_path / "install.sh"
    script.write_text(
        """#!/bin/sh
curl -O package.tar.gz
curl -O package.tar.gz.sig
gpg --verify package.tar.gz.sig package.tar.gz
checksum verification
""",
        encoding="utf-8",
    )

    agent = VerificationIntegrityAgent(fixture_mode=True)
    finding = agent.analyze_file(script)

    assert finding is not None
    assert finding.artifact_type == "script"
    assert {control.control_name for control in finding.controls} == {
        "rollback",
        "tampering",
        "freeze",
        "endless_data",
    }

def test_file_read_error_is_reported_without_crashing(
    tmp_path: Path, capsys
) -> None:
    """Read failures should fail closed and report the file without raising."""
    script = tmp_path / "install.sh"
    script.write_text(
        "#!/bin/sh\ngpg --verify package.sig package.tar.gz\nchecksum verification\n",
        encoding="utf-8",
    )
    agent = VerificationIntegrityAgent(fixture_mode=True)

    with patch("builtins.open", side_effect=OSError("synthetic read failure")):
        finding = agent.analyze_file(script)

    captured = capsys.readouterr()
    assert finding is None
    assert "Error reading file" in captured.err
    assert "synthetic read failure" in captured.err

