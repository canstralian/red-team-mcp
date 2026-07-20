"""Utilities for installing build-system requirements prior to packaging.

This module detects build backends declared in ``pyproject.toml`` and ensures
that their requirements are available in the current interpreter environment.
It is primarily intended for CI systems that execute ``python -m build`` with
``--no-isolation`` and therefore must provision the backend explicitly.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for <3.11
    import tomli as tomllib  # type: ignore


def parse_build_requirements(pyproject_path: Path) -> List[str]:
    """Return the ``build-system.requires`` entries from ``pyproject.toml``.

    Parameters
    ----------
    pyproject_path:
        Path to the ``pyproject.toml`` file.

    Returns
    -------
    list[str]
        Normalized requirement strings declared for the build backend. If the
        file does not include a ``build-system`` table or ``requires`` key, an
        empty list is returned.
    """

    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    requires = data.get("build-system", {}).get("requires", [])
    return [str(req).strip() for req in requires if str(req).strip()]


def install_build_requirements(
    requirements: Sequence[str] | Path | str,
    *,
    quiet: bool = False,
) -> List[str]:
    """Install build backend requirements using ``pip``.

    Parameters
    ----------
    requirements:
        Either an iterable of requirement strings or a path to ``pyproject.toml``.
    quiet:
        When ``True`` the underlying ``pip`` command is invoked with ``--quiet``.

    Returns
    -------
    list[str]
        The list of requirement strings that were installed. If no requirements
        are discovered the function returns an empty list and performs no
        installation.

    Raises
    ------
    FileNotFoundError
        If a path is provided but the file does not exist.
    TOMLDecodeError
        If the pyproject.toml file contains invalid TOML syntax. The actual
        exception type is ``tomllib.TOMLDecodeError`` (Python 3.11+) or
        ``tomli.TOMLDecodeError`` (Python <3.11).
    subprocess.CalledProcessError
        If the pip installation command fails.
    """

    if isinstance(requirements, (str, Path)):
        requirements_path = Path(requirements)
        if not requirements_path.exists():
            raise FileNotFoundError(f"pyproject.toml not found: {requirements_path}")
        resolved = parse_build_requirements(requirements_path)
    else:
        resolved = [str(req).strip() for req in requirements if str(req).strip()]

    if not resolved:
        return []

    cmd = [sys.executable, "-m", "pip", "install"]
    if quiet:
        cmd.append("--quiet")
    cmd.extend(resolved)

    subprocess.run(cmd, check=True)
    return resolved


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Ensure build backends declared in pyproject.toml are available before "
            "running python -m build"
        )
    )
    parser.add_argument(
        "--pyproject",
        type=Path,
        default=Path("pyproject.toml"),
        help="Path to the pyproject.toml file (default: ./pyproject.toml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the backend requirements without installing them",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress pip output by adding --quiet to the installation command",
    )
    return parser


def cli(argv: Sequence[str] | None = None) -> int:
    """Entry point for command-line usage."""

    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    pyproject_path = args.pyproject
    if not pyproject_path.exists():
        print(f"⚠️  No pyproject.toml found at {pyproject_path}", file=sys.stderr)
        return 1

    try:
        requirements = parse_build_requirements(pyproject_path)
    except tomllib.TOMLDecodeError as e:
        print(f"❌ Error parsing {pyproject_path}: {e}", file=sys.stderr)
        return 1

    if not requirements:
        print("ℹ️  No build-system requirements declared; nothing to install.")
        return 0

    if args.dry_run:
        formatted = ", ".join(requirements)
        print(f"Would install build requirements: {formatted}")
        return 0

    installed = install_build_requirements(requirements, quiet=args.quiet)
    formatted = ", ".join(installed)
    print(f"✅ Installed build requirements: {formatted}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    raise SystemExit(cli())
