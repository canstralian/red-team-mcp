"""Regression tests for VerificationIntegrityAgent file classification."""

from pathlib import Path

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


def test_verification_shell_script_remains_relevant() -> None:
    """The documentation exclusion must not hide actual verification scripts."""
    script = Path("install.sh")
    content = """#!/bin/sh
curl -O package.tar.gz
curl -O package.tar.gz.sig
gpg --verify package.tar.gz.sig package.tar.gz
checksum verification
"""

    agent = VerificationIntegrityAgent()

    assert agent._is_verification_relevant(script, content) is True
