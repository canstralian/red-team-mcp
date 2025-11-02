"""Tests for the payload generation helpers."""

from pathlib import Path
import sys

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from payloads import PayloadGenerator  # type: ignore  # noqa: E402


def test_generate_reverse_shell_requires_valid_host():
    """Invalid hosts should raise ValueError."""

    generator = PayloadGenerator()
    with pytest.raises(ValueError):
        generator.generate_reverse_shell("bash", "invalid host", 4444, False)


def test_generate_reverse_shell_encoding():
    """Encoded reverse shell output should include Base64 section."""

    generator = PayloadGenerator()
    output = generator.generate_reverse_shell("bash", "10.0.0.1", 4444, True)
    assert "## Base64 Encoded" in output


def test_generate_cred_spray_normalizes_input():
    """Credential spray output should normalize usernames/passwords."""

    generator = PayloadGenerator()
    result = generator.generate_cred_spray("SSH", [" alice ", "bob"], ["pass1", "pass1"], None)
    assert "alice, bob" in result
    assert "pass1" in result
