"""Secret redaction for anything the CLI prints, logs or exports."""

from __future__ import annotations

import re

MASK = "***"

_PATTERNS = [
    re.compile(r"(?i)(Authorization:\s*(?:Token|Bearer|Basic)\s+)\S+"),
    re.compile(r"\b(?:squ|sqa|sqp)_[A-Za-z0-9]{16,}"),
    re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"(?i)(\b[A-Za-z0-9_.-]*(?:token|password|passwd|secret|api[_-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*)[^\s&\"']+"
    ),
]


def redact(text: str, secrets=()) -> str:
    """Mask known secret values and common token shapes in `text`."""
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, MASK)
    for pattern in _PATTERNS:
        if pattern.groups:
            text = pattern.sub(lambda m: m.group(1) + MASK, text)
        else:
            text = pattern.sub(MASK, text)
    return text
