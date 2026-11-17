"""Language detection by file extension, and project slugs."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

# Directories never analyzed or counted (dependencies and build output).
SKIP_DIRS = frozenset({".git", "node_modules", "bin", "obj", "dist", ".angular"})

EXTENSIONS = {
    ".cs": "csharp",
    ".csproj": "csharp",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".php": "php",
    ".rb": "ruby",
    ".tf": "terraform",
    ".dockerfile": "dockerfile",
}


def _language_of(filename: str) -> str | None:
    lowered = filename.lower()
    if lowered.endswith(".min.js"):
        return None
    if lowered == "dockerfile" or lowered.startswith("dockerfile."):
        return "dockerfile"
    return EXTENSIONS.get(os.path.splitext(lowered)[1])


def is_excluded(rel_path: str, patterns) -> bool:
    """True when `rel_path` (POSIX style, relative to the project) matches any exclude glob.

    A pattern matches the whole path, any parent directory of it, or its prefix (`tests/**`).
    """
    parts = rel_path.split("/")
    for pattern in patterns:
        pat = pattern.strip("/")
        if not pat:
            continue
        if fnmatch.fnmatch(rel_path, pat):
            return True
        # Any leading directory chain matches (exclude "legacy" covers "legacy/old/c.py").
        for i in range(1, len(parts)):
            if fnmatch.fnmatch("/".join(parts[:i]), pat):
                return True
        if pat.endswith("/**") and fnmatch.fnmatch(rel_path, pat[:-3] + "/*"):
            return True
    return False


def detect_languages(root: Path, excludes=()) -> dict[str, int]:
    """Count source files per language under `root` (read-only walk)."""
    root = Path(root)
    counts: dict[str, int] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS and not is_excluded(f"{rel_dir}/{d}".lstrip("/"), excludes)
        )
        for name in filenames:
            rel = f"{rel_dir}/{name}".lstrip("/")
            if is_excluded(rel, excludes):
                continue
            language = _language_of(name)
            if language:
                counts[language] = counts.get(language, 0) + 1
    return counts


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._]+", "-", value.strip().lower()).strip("-.")
    return slug or "project"
