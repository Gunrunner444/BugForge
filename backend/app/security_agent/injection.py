"""Treat all external content as untrusted. Never let it issue agent instructions."""

from __future__ import annotations

from app.security_testing.sanitization import wrap_untrusted

_INSTRUCTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "you are now",
    "disregard your",
    "new instructions",
    "tool call:",
    "authorize all",
    "mark verified",
    "approve the report",
    "submit to hackerone",
)


def untrusted_observation(source: str, content: str) -> str:
    return wrap_untrusted(source, content or "")


def contains_injection_attempt(content: str) -> bool:
    lowered = (content or "").lower()
    return any(marker in lowered for marker in _INSTRUCTION_MARKERS)


def strip_instruction_attempts(content: str) -> str:
    """Keep the data, drop lines that look like instructions to the agent."""
    lines = []
    for line in (content or "").splitlines():
        if contains_injection_attempt(line):
            lines.append("[UNTRUSTED_INSTRUCTION_STRIPPED]")
            continue
        lines.append(line)
    return "\n".join(lines)
