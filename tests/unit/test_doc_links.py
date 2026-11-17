"""The documentation link checker (scripts/check-doc-links.py) and the repository's own links."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_doc_links", ROOT / "scripts" / "check-doc-links.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_links_and_anchors_pass(tmp_path):
    write(tmp_path, "docs/other.md", "# Other\n\n## Try it in minutes\n")
    page = write(tmp_path, "README.md", "[a](docs/other.md) [b](docs/other.md#try-it-in-minutes) [c](https://example.com/x) [d](#top)\n\n# Top\n")
    assert checker.check_file(page, tmp_path) == []


def test_broken_target_and_anchor_are_reported(tmp_path):
    write(tmp_path, "docs/other.md", "# Other\n")
    page = write(tmp_path, "README.md", "[a](docs/missing.md) [b](docs/other.md#nope)\n")
    assert checker.check_file(page, tmp_path) == [
        "README.md: broken link docs/missing.md",
        "README.md: missing anchor docs/other.md#nope",
    ]


def test_links_inside_code_are_ignored(tmp_path):
    page = write(tmp_path, "README.md", "```text\n[x](missing.md)\n```\n\nUse `[y](also-missing.md)` here.\n")
    assert checker.check_file(page, tmp_path) == []


def test_main_exit_code(tmp_path, capsys):
    bad = write(tmp_path, "bad.md", "[a](missing.md)\n")
    good = write(tmp_path, "good.md", "[a](bad.md)\n")
    assert checker.main([str(bad)]) == 1
    assert "broken link missing.md" in capsys.readouterr().err
    assert checker.main([str(good)]) == 0


def test_slug_matches_github_rules():
    assert checker.slug("Try it in minutes") == "try-it-in-minutes"
    assert checker.slug("`.appsec.yml` (optional)") == "appsecyml-optional"
