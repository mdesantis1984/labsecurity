"""Scan scope: the work copy holds exactly the files git considers (tracked + untracked-not-ignored) minus the excludes."""

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from labsec import scope
from labsec.appsec import AppSecConfig, AppSecError, load_appsec
from labsec.langs import detect_languages
from labsec.scope import DEFAULT_EXCLUDES, LONG_LINE_LIMIT, build_scope, effective_excludes
from labsec.summary import build_summary, render_json, render_text
from labsec.tools import prepare_work_copy, trivy_command

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]


def run(cwd, *args):
    subprocess.run([*GIT, *args], cwd=cwd, check=True, capture_output=True)


def write(root: Path, rel: str, content: str = "x\n") -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


@pytest.fixture(autouse=True)
def hermetic_git(monkeypatch):
    """No global or system git config: the host's own ignore rules must not change what a fixture repository holds."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    run(root, "init", "-q", "-b", "main")
    return root


def commit_all(root: Path) -> None:
    run(root, "add", "-A")
    run(root, "commit", "-q", "-m", "init")


# ----------------------------------------------------------------------------- git is the source of truth
def test_work_copy_is_tracked_plus_untracked_not_ignored(repo):
    write(repo, ".gitignore", ".toolchain/\n.worktrees/\nbackend/.cache/\n")
    write(repo, "src/App.cs")
    commit_all(repo)
    write(repo, "src/New.cs")  # untracked, not ignored: it belongs to the scan
    write(repo, ".toolchain/sdk/Microsoft.NETCore.App.deps.json", "{}")
    write(repo, "backend/.cache/packages/pkg/pkg.deps.json", "{}")
    write(repo, ".worktrees/wt1/src/App.cs")
    result = build_scope(repo)
    assert "src/App.cs" in result.files
    assert "src/New.cs" in result.files
    assert ".gitignore" in result.files
    assert not [f for f in result.files if f.startswith((".toolchain", ".worktrees", "backend/.cache"))]
    assert result.excluded["gitignore"] >= 3
    assert result.from_git is True


def test_linked_worktree_ignored_by_the_repo_is_never_scanned(repo):
    write(repo, ".gitignore", ".worktrees/\n")
    write(repo, "src/App.cs")
    commit_all(repo)
    run(repo, "worktree", "add", "-q", "-b", "feature", str(repo / ".worktrees" / "feature"))
    assert (repo / ".worktrees" / "feature" / "src" / "App.cs").is_file()
    files = build_scope(repo).files
    assert files == [".gitignore", "src/App.cs"]


def test_untracked_nested_repository_is_skipped_and_counted(repo):
    write(repo, "src/App.cs")
    commit_all(repo)
    nested = repo / "vendor-checkout"
    nested.mkdir()
    run(nested, "init", "-q", "-b", "main")
    write(nested, "lib/Other.cs")
    result = build_scope(repo)
    assert result.files == ["src/App.cs"]
    assert result.excluded["nested-repo"] == 1


def test_tracked_file_missing_on_disk_is_not_listed(repo):
    write(repo, "src/Gone.cs")
    write(repo, "src/Kept.cs")
    commit_all(repo)
    (repo / "src" / "Gone.cs").unlink()
    assert build_scope(repo).files == ["src/Kept.cs"]


def test_paths_with_spaces_and_unicode_survive(repo):
    write(repo, "src/My File ñ.cs")
    commit_all(repo)
    assert build_scope(repo).files == ["src/My File ñ.cs"]


def test_non_git_directory_keeps_the_previous_behaviour(tmp_path):
    root = tmp_path / "plain"
    write(root, "src/App.cs")
    write(root, "node_modules/p/index.js")
    write(root, "bin/Debug/App.dll")
    write(root, ".toolchain/x.json")  # no git: nothing says it is ignored
    result = build_scope(root)
    assert result.from_git is False
    assert result.files == [".toolchain/x.json", "src/App.cs"]
    assert result.excluded["builtin-dir"] == 2
    assert "gitignore" not in result.excluded


# ----------------------------------------------------------------------------- default excludes
def test_default_excludes_cover_vendored_content(repo):
    write(repo, ".agents/skills/s/run.js")
    write(repo, "public/vendor/app.min.js")
    write(repo, "public/vendor/app.min.mjs")
    write(repo, "app.min.js")
    write(repo, "web/node_modules/pkg/index.js")
    write(repo, "src/app.js")
    write(repo, "tests/fixtures/Sample.cs")  # fixtures stay in scope
    commit_all(repo)
    result = build_scope(repo)
    assert result.files == ["src/app.js", "tests/fixtures/Sample.cs"]
    assert result.excluded["default-exclude"] == 4
    assert result.excluded["builtin-dir"] == 1  # node_modules is also a built-in directory: it is counted there first
    assert set(DEFAULT_EXCLUDES) >= {".agents/**", "**/*.min.js", "**/*.min.mjs", "**/node_modules/**"}


def test_appsec_exclude_extends_the_defaults(repo):
    write(repo, "generated/Api.cs")
    write(repo, "src/App.cs")
    write(repo, ".agents/a.js")
    commit_all(repo)
    result = build_scope(repo, ["generated/**"])
    assert result.files == ["src/App.cs"]
    assert result.excluded["appsec-exclude"] == 1
    assert result.excluded["default-exclude"] == 1


def test_a_negated_default_is_scanned_again(repo):
    write(repo, ".agents/a.js")
    write(repo, "src/app.min.js")
    commit_all(repo)
    result = build_scope(repo, ["!.agents/**"])
    assert result.files == [".agents/a.js"]
    assert effective_excludes(["!.agents/**", "x/**"]) == [p for p in DEFAULT_EXCLUDES if p != ".agents/**"] + ["x/**"]


def test_appsec_rejects_a_negation_that_is_not_a_default(tmp_path):
    write(tmp_path, ".appsec.yml", "exclude: ['!docs/**']\n")
    with pytest.raises(AppSecError, match="not a default exclude"):
        load_appsec(tmp_path)
    write(tmp_path, ".appsec.yml", "exclude: ['!.agents/**', 'docs/**']\n")
    assert load_appsec(tmp_path).exclude == ["!.agents/**", "docs/**"]


# ----------------------------------------------------------------------------- long-line heuristic
def test_vendored_bundles_are_skipped_by_the_long_line_heuristic(repo):
    write(repo, "public/bundle.mjs", "import(a);" + "a" * (LONG_LINE_LIMIT + 1) + "\n")
    write(repo, "src/edge.js", "a" * LONG_LINE_LIMIT + "\n")  # exactly the limit stays
    write(repo, "src/many-short-lines.js", "var a = 1;\n" * 2000)
    write(repo, "data/big.json", "[" + "1," * 10000 + "1]\n")  # not source code: never inspected
    write(repo, "src/App.cs")
    commit_all(repo)
    result = build_scope(repo)
    assert result.long_line_files == ["public/bundle.mjs"]
    assert "public/bundle.mjs" not in result.files
    assert {"src/edge.js", "src/many-short-lines.js", "data/big.json", "src/App.cs"} <= set(result.files)
    assert result.excluded["long-line"] == 1


# ----------------------------------------------------------------------------- languages and summary
def test_languages_are_counted_from_the_scope_only(repo):
    write(repo, ".gitignore", ".worktrees/\n")
    write(repo, "src/App.cs")
    write(repo, ".worktrees/w/src/Other.cs")
    write(repo, ".worktrees/w/src/other.py")
    commit_all(repo)
    files = build_scope(repo).files
    assert detect_languages(repo, files=files) == {"csharp": 1}


def test_summary_reports_how_many_files_were_excluded_and_why():
    info = {"files": 120, "excluded": {"gitignore": 4, "default-exclude": 3, "long-line": 1}, "long_line_files": ["public/bundle.mjs"]}
    summary = build_summary(
        project="demo", branch="main", run_id="r1", engagement_url=None, tools=[],
        counts={"new": 0, "open": 0, "closed": 0, "blocking": {}}, blocking_findings=[], errors=[], scope=info,
    )
    assert summary["scope"] == info
    text = render_text(summary)
    assert "scope: 120 files scanned; excluded: default-exclude 3, gitignore 4, long-line 1" in text
    assert "public/bundle.mjs" in text
    assert '"scope"' in render_json(summary)


def test_summary_without_scope_is_unchanged():
    summary = build_summary(
        project="demo", branch="main", run_id="r1", engagement_url=None, tools=[],
        counts={"new": 0, "open": 0, "closed": 0, "blocking": {}}, blocking_findings=[], errors=[],
    )
    assert "scope" not in summary
    assert "scope:" not in render_text(summary)


# ----------------------------------------------------------------------------- work copy and Trivy
@pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync is not installed")
def test_prepare_work_copy_materializes_exactly_the_scope(repo, tmp_path):
    write(repo, ".gitignore", ".toolchain/\n")
    write(repo, "src/App.cs", "class A {}\n")
    write(repo, "src/My File.cs")
    write(repo, ".agents/a.js")
    commit_all(repo)
    write(repo, ".toolchain/sdk/x.deps.json", "{}")
    os.symlink("App.cs", repo / "src" / "link.cs")
    work = tmp_path / "work"
    (work / "stale" / "dir").mkdir(parents=True)
    (work / "stale" / "dir" / "old.cs").write_text("old")
    (work / ".toolchain").mkdir()
    (work / ".toolchain" / "x.deps.json").write_text("{}")
    ctx = SimpleNamespace(project=repo, work=work, appsec=AppSecConfig(), scope=None)
    prepare_work_copy(ctx)
    copied = sorted(str(p.relative_to(work)) for p in work.rglob("*") if p.is_file() or p.is_symlink())
    assert copied == [".gitignore", "src/App.cs", "src/My File.cs", "src/link.cs"]
    assert (work / "src" / "link.cs").is_symlink()
    assert not (work / "stale").exists()
    assert not (work / ".toolchain").exists()
    assert ctx.scope is not None and ctx.scope.excluded["default-exclude"] == 1
    assert not (repo / ".agents").exists() or (repo / ".agents" / "a.js").is_file()  # the project is never written


def test_trivy_never_scans_cache_or_toolchain_directories():
    command = trivy_command()
    skipped = [command[i + 1] for i, part in enumerate(command) if part == "--skip-dirs"]
    assert "**/.cache" in skipped and "**/.toolchain" in skipped
    assert command[:3] == ["fs", "--scanners", "vuln,misconfig"] and command[-1] == "/src"


def test_scope_module_exposes_the_documented_reasons():
    assert set(scope.REASONS) == {"gitignore", "nested-repo", "builtin-dir", "default-exclude", "appsec-exclude", "long-line"}
