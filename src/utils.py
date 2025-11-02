"""Utility helpers for the RedTeam MCP server."""

from __future__ import annotations

import base64
import codecs
import gzip
import io
import re
from typing import Final

CHARACTER_LIMIT: Final[int] = 25_000
"""Default character limit for responses returned to MCP clients."""

_CLEANUP_RE: Final[re.Pattern[str]] = re.compile(r"[ \t]+\n")
"""Regular expression that collapses trailing whitespace before newlines."""

_METHOD_SANITIZER: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9_]")
"""Sanitize user-supplied obfuscation method names."""


def truncate_response(text: str, notice: str, limit: int = CHARACTER_LIMIT) -> str:
    """Return ``text`` truncated to ``limit`` characters while preserving readability.

    The function first normalizes repeated trailing whitespace using a compiled
    regular expression so that generated Markdown renders consistently. If the
    cleaned text exceeds the limit, it is truncated and annotated with the
    supplied ``notice`` to guide users toward retrieving the full response.
    """

    cleaned = _CLEANUP_RE.sub("\n", text.strip())
    if len(cleaned) <= limit:
        return cleaned

    truncated = cleaned[: max(limit - len(notice) - 4, 0)].rstrip()
    return f"{truncated}\n\n… {notice}"


def obfuscate_payload(payload: str, method: str, language: str | None = None) -> str:
    """Apply simple obfuscation ``method`` to ``payload`` text.

    Supported methods include ``base64``, ``hex``, ``gzip``, ``rot13``,
    ``unicode`` (escaped code points), and ``mixed`` (ROT13 of the Base64
    encoding). The method name is sanitized with a regular expression to guard
    against command injection or accidental whitespace issues.
    """

    normalized_method = _METHOD_SANITIZER.sub("", method.lower())
    if normalized_method == "base64":
        return base64.b64encode(payload.encode()).decode()
    if normalized_method == "hex":
        return payload.encode().hex()
    if normalized_method == "gzip":
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb") as handle:
            handle.write(payload.encode())
        return base64.b64encode(buffer.getvalue()).decode()
    if normalized_method == "rot13":
        return codecs.decode(payload, "rot_13")
    if normalized_method == "unicode":
        return "".join(f"\\u{ord(char):04x}" for char in payload)
    if normalized_method == "mixed":
        base64_payload = base64.b64encode(payload.encode()).decode()
        return codecs.decode(base64_payload, "rot_13")
    raise ValueError(f"Unsupported obfuscation method: {method}")
