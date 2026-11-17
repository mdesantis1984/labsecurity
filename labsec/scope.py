"""Scan scope: which files of a project reach the scanners.

In a git repository the scope is exactly what git considers part of the project: tracked files plus untracked files that
are not ignored (`git ls-files -co --exclude-standard`). Whatever the repository's own `.gitignore` hides (linked
worktrees, local SDKs, package caches, build output) is never copied, and nested repositories or submodule checkouts are
skipped. Outside git, every file is a candidate except the built-in directories.

Three exclusion layers then apply, each counted under its own reason so a lap can say what was left out and why:
built-in directories, the default excludes (vendored agent skills, minified bundles, `node_modules`) and the
project's `.appsec.yml` `exclude:` list. Finally, source files with a line longer than `LONG_LINE_LIMIT` bytes are
treated as vendored or minified bundles and skipped (they are listed in the summary).
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from labsec.langs import EXTENSIONS, SKIP_DIRS, is_excluded

# Globs excluded from every scan unless a project re-includes them with `!<glob>` in `.appsec.yml` `exclude:`.
DEFAULT_EXCLUDES = (".agents/**", "**/*.min.js", "**/*.min.mjs", "**/node_modules/**")

# A source file with a line longer than this is a minified or vendored bundle, not code a person reviews.
LONG_LINE_LIMIT = 5000
_LONG_LINE_EXTENSIONS = frozenset(EXTENSIONS) | {".mts", ".cts"}

REASONS = {
    "gitignore": "ignored by the repository's .gitignore (never copied)",
    "nested-repo": "nested git repository or submodule checkout",
    "builtin-dir": "built-in directory (.git, node_modules, bin, obj, dist, .angular)",
    "default-exclude": "default exclude (vendored agent skills, minified bundles, node_modules)",
    "appsec-exclude": "excluded by .appsec.yml",
    "long-line": f"source file with a line longer than {LONG_LINE_LIMIT} bytes (vendored or minified bundle)",
}
MAX_LISTED_LONG_LINE = 20


@dataclass
class Scope:
    files: list[str]
    excluded: dict[str, int] = field(default_factory=dict)
    long_line_files: list[str] = field(default_factory=list)
    from_git: bool = False

    def to_summary(self) -> dict:
        """The part of the lap summary that says what was scanned and what was left out."""
        return {
            "files": len(self.files),
            "excluded": dict(sorted(self.excluded.items())),
            "long_line_files": self.long_line_files[:MAX_LISTED_LONG_LINE],
        }


def split_excludes(user: list[str]) -> tuple[list[str], list[str]]:
    """(active default patterns, project patterns). `!<default>` in the project list re-includes that default."""
    negated = {pattern[1:] for pattern in user if pattern.startswith("!")}
    defaults = [pattern for pattern in DEFAULT_EXCLUDES if pattern not in negated]
    return defaults, [pattern for pattern in user if not pattern.startswith("!")]


def effective_excludes(user: list[str]) -> list[str]:
    defaults, own = split_excludes(list(user))
    return defaults + own


def _git(project: Path, *args: str) -> bytes | None:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    proc = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(project), *args], capture_output=True, env=env, check=False
    )
    return proc.stdout if proc.returncode == 0 else None


def _split(raw: bytes) -> list[str]:
    return [os.fsdecode(part) for part in raw.split(b"\0") if part]


def _git_candidates(project: Path, excluded: dict[str, int]) -> list[str] | None:
    """Files git considers part of the project, or None when `project` is not a usable git repository."""
    if not (project / ".git").exists():
        return None
    listed = _git(project, "ls-files", "-co", "--exclude-standard", "-z")
    if listed is None:
        return None
    ignored = _git(project, "ls-files", "-o", "-i", "--exclude-standard", "--directory", "-z")
    if ignored:
        excluded["gitignore"] = len(_split(ignored))
    files: list[str] = []
    for rel in _split(listed):
        path = project / rel
        if rel.endswith("/") or (path.is_dir() and not path.is_symlink()):
            excluded["nested-repo"] = excluded.get("nested-repo", 0) + 1  # nested repository or submodule checkout
        elif os.path.lexists(path):  # tracked but deleted in the working tree: nothing to scan
            files.append(rel)
    return files


def _walk_candidates(project: Path, excluded: dict[str, int]) -> list[str]:
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(project):
        rel_dir = os.path.relpath(dirpath, project)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        kept = []
        for name in sorted(dirnames):
            if name in SKIP_DIRS:
                excluded["builtin-dir"] = excluded.get("builtin-dir", 0) + 1
            elif os.path.islink(os.path.join(dirpath, name)):
                files.append(f"{rel_dir}/{name}".lstrip("/"))  # a link to a directory is copied as a link
            else:
                kept.append(name)
        dirnames[:] = kept
        files.extend(f"{rel_dir}/{name}".lstrip("/") for name in filenames)
    return files


def has_long_line(path: Path, limit: int = LONG_LINE_LIMIT) -> bool:
    """True when a line of `path` is longer than `limit` bytes. Reads at most `limit + 2` bytes per step."""
    try:
        with open(path, "rb") as handle:
            if os.fstat(handle.fileno()).st_size <= limit:
                return False
            for chunk in iter(lambda: handle.readline(limit + 2), b""):
                if len(chunk.rstrip(b"\r\n")) > limit:
                    return True
    except OSError:
        return False
    return False


def _bump(excluded: dict[str, int], reason: str) -> None:
    excluded[reason] = excluded.get(reason, 0) + 1


def build_scope(project: Path, excludes=()) -> Scope:
    """The files of `project` that reach the scanners (read-only)."""
    project = Path(project)
    excluded: dict[str, int] = {}
    candidates = _git_candidates(project, excluded)
    from_git = candidates is not None
    if candidates is None:
        candidates = _walk_candidates(project, excluded)
    defaults, own = split_excludes(list(excludes))
    kept: list[str] = []
    long_line: list[str] = []
    for rel in sorted(candidates):
        if any(part in SKIP_DIRS for part in rel.split("/")[:-1]):
            _bump(excluded, "builtin-dir")
        elif is_excluded(rel, defaults):
            _bump(excluded, "default-exclude")
        elif is_excluded(rel, own):
            _bump(excluded, "appsec-exclude")
        elif os.path.splitext(rel)[1].lower() in _LONG_LINE_EXTENSIONS and not os.path.islink(project / rel) and has_long_line(project / rel):
            long_line.append(rel)
            _bump(excluded, "long-line")
        else:
            kept.append(rel)
    return Scope(files=kept, excluded=excluded, long_line_files=long_line, from_git=from_git)


# ----------------------------------------------------------------------------- work copy
def _prune(work: Path, wanted: set[str]) -> None:
    """Remove from `work` everything that is not in `wanted` (relative POSIX paths), then the directories left empty."""
    wanted_dirs = {""}
    for rel in wanted:
        parts = rel.split("/")[:-1]
        wanted_dirs.update("/".join(parts[: i + 1]) for i in range(len(parts)))
    for dirpath, dirnames, filenames in os.walk(work, topdown=False, followlinks=False):
        rel_dir = os.path.relpath(dirpath, work)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        links = [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
        for name in [*filenames, *links]:
            rel = f"{rel_dir}/{name}".lstrip("/")
            if rel not in wanted:
                os.chmod(dirpath, 0o700)
                os.unlink(os.path.join(dirpath, name))
        if rel_dir not in wanted_dirs:
            try:
                os.chmod(dirpath, 0o700)
                os.rmdir(dirpath)
            except OSError:
                pass


def sync_work_copy(project: Path, work: Path, scope: Scope) -> None:
    """Make `work` hold exactly `scope.files`, copied from `project` with rsync (the project is only read)."""
    work.mkdir(parents=True, exist_ok=True)
    _prune(work, set(scope.files))
    if not scope.files:
        return
    cmd = ["rsync", "-lpt", "--no-owner", "--no-group", "--from0", "--files-from=-", f"{project}/", f"{work}/"]
    payload = b"\0".join(os.fsencode(rel) for rel in scope.files) + b"\0"
    proc = subprocess.run(cmd, input=payload, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"rsync failed ({proc.returncode}): {proc.stderr.decode(errors='replace').strip()[:300]}")
