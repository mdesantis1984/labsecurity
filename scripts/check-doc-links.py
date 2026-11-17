#!/usr/bin/env python3
"""Check that every relative link in the repository's Markdown documentation resolves.

Usage: scripts/check-doc-links.py [FILE ...]

Without arguments it checks the README pair, the root policy files, `docs/*.md` and `.github/**/*.md`.
A link passes when its target file or directory exists and, for `file#anchor` links to Markdown files, a heading
with that GitHub-style slug exists. External links (`http`, `https`, `mailto`) are not fetched.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GLOBS = ("README*.md", "CONTRIBUTING.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "docs/*.md", ".github/**/*.md")
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
EXTERNAL = ("http://", "https://", "mailto:")


def strip_code(text: str) -> str:
    """Remove fenced blocks and inline code so example links are not checked."""
    text = re.sub(r"^(```|~~~).*?^\1[ \t]*$", "", text, flags=re.MULTILINE | re.DOTALL)
    return re.sub(r"`[^`\n]*`", "", text)


def slug(heading: str) -> str:
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    for line in strip_code(path.read_text(encoding="utf-8")).splitlines():
        match = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if match:
            found.add(slug(match.group(1)))
    return found


def check_file(path: Path, root: Path = ROOT) -> list[str]:
    problems = []
    for target in LINK.findall(strip_code(path.read_text(encoding="utf-8"))):
        if target.startswith(EXTERNAL):
            continue
        name, _, fragment = target.partition("#")
        resolved = (path.parent / name).resolve() if name else path.resolve()
        shown = path.relative_to(root) if path.is_relative_to(root) else path
        if not resolved.exists():
            problems.append(f"{shown}: broken link {target}")
        elif fragment and resolved.suffix == ".md" and fragment not in anchors(resolved):
            problems.append(f"{shown}: missing anchor {target}")
    return problems


def default_files(root: Path = ROOT) -> list[Path]:
    return sorted({p for pattern in DEFAULT_GLOBS for p in root.glob(pattern) if p.is_file()})


def main(argv: list[str]) -> int:
    files = [Path(a).resolve() for a in argv] or default_files()
    problems = [problem for file in files for problem in check_file(file)]
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"checked {len(files)} files, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
