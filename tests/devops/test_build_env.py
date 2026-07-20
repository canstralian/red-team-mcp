from __future__ import annotations

import sys
from pathlib import Path

import pytest

from src.devops import build_env


def write_pyproject(tmp_path: Path, requires: list[str] | None) -> Path:
    requires_lines = "\n".join(f'    "{pkg}",' for pkg in (requires or []))
    content = """
[build-system]
requires = [
{requires_lines}
]
build-backend = "example.backend"
""".strip().format(requires_lines=requires_lines)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(content, encoding="utf-8")
    return pyproject


def test_parse_build_requirements_returns_requires(tmp_path: Path) -> None:
    pyproject = write_pyproject(tmp_path, ["hatchling", "wheel>=0.40"])
    requirements = build_env.parse_build_requirements(pyproject)
    assert requirements == ["hatchling", "wheel>=0.40"]


def test_parse_build_requirements_handles_missing_requires(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'example'\n", encoding="utf-8")
    requirements = build_env.parse_build_requirements(pyproject)
    assert requirements == []


def test_install_build_requirements_invokes_pip(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], check: bool) -> None:
        calls.append(cmd)

    monkeypatch.setattr(build_env.subprocess, "run", fake_run)  # type: ignore[arg-type]

    installed = build_env.install_build_requirements(["hatchling"], quiet=True)

    assert installed == ["hatchling"]
    assert calls
    assert calls[0][:4] == [sys.executable, "-m", "pip", "install"]
    assert "--quiet" in calls[0]
    assert calls[0][-1] == "hatchling"


def test_cli_dry_run_lists_requirements(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pyproject = write_pyproject(tmp_path, ["hatchling"])
    exit_code = build_env.cli(["--pyproject", str(pyproject), "--dry-run"])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Would install build requirements: hatchling" in output


def test_cli_no_requirements(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pyproject = write_pyproject(tmp_path, [])
    exit_code = build_env.cli(["--pyproject", str(pyproject)])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "No build-system requirements" in output


def test_cli_missing_pyproject(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "pyproject.toml"
    exit_code = build_env.cli(["--pyproject", str(missing)])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "No pyproject.toml" in err


def test_cli_malformed_toml(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test that malformed TOML files are handled gracefully."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("this is not valid TOML [[[", encoding="utf-8")
    exit_code = build_env.cli(["--pyproject", str(pyproject)])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "Error parsing" in err
