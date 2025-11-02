"""Unit tests for RedTeam MCP utility helpers."""

from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

import utils  # type: ignore  # noqa: E402


def test_truncate_response_preserves_notice():
    """Ensure long responses are truncated and annotated."""

    text = "A" * (utils.CHARACTER_LIMIT + 10)
    notice = "See more"
    truncated = utils.truncate_response(text, notice)
    assert truncated.endswith(f"… {notice}")
    assert len(truncated) <= utils.CHARACTER_LIMIT


def test_obfuscate_payload_methods_round_trip():
    """ROT13 and Base64 obfuscation should be reversible."""

    payload = "echo test"
    assert utils.obfuscate_payload(payload, "base64") == "ZWNobyB0ZXN0"
    assert utils.obfuscate_payload(payload, "rot13") == "rpub grfg"
