"""Tests for the custom Opengrep rules in rules/opengrep (gated) and rules/optin (opt-in, outside the gate).

Two layers:
* a static contract check (always runs): ids, standard metadata and a positive plus a negative annotated case per rule;
* the native `opengrep test` run through the pinned scanner image (skipped when Docker or the image is missing).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from labsec.standards import OWASP_TOP10_2025

ROOT = Path(__file__).resolve().parents[2]
GATED_DIR = ROOT / "rules" / "opengrep"
OPTIN_DIR = ROOT / "rules" / "optin"
FIXTURE_DIRS = {GATED_DIR: ROOT / "tests" / "rules", OPTIN_DIR: ROOT / "tests" / "rules-optin"}
IMAGE = "labsecurity/opengrep:2.0.0-r2"
CWE = re.compile(r"^CWE-\d+: \S")


def load_rules(rules_dir: Path = GATED_DIR) -> list[tuple[Path, dict]]:
    found = []
    for path in sorted(rules_dir.glob("*.y*ml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            found.append((path, rule))
    return found


def all_rules() -> list[tuple[Path, dict]]:
    return load_rules(GATED_DIR) + load_rules(OPTIN_DIR)


def annotation_ids(kind: str, fixtures_dir: Path) -> set[str]:
    ids: set[str] = set()
    pattern = re.compile(rf"(?://|#|<!--)\s*{kind}:\s*([^\n]*?)\s*(?:-->)?$", re.MULTILINE)
    for fixture in fixtures_dir.iterdir():
        if fixture.is_file() and fixture.suffix != ".py":
            for match in pattern.finditer(fixture.read_text(encoding="utf-8")):
                ids.update(part.strip() for part in match.group(1).split(","))
    return ids


def test_rules_exist():
    assert len(load_rules(GATED_DIR)) >= 8


@pytest.mark.parametrize("path,rule", all_rules(), ids=lambda value: value["id"] if isinstance(value, dict) else value.name)
def test_rule_contract(path, rule):
    assert re.fullmatch(r"labsec\.[a-z0-9]+\.[a-z0-9]+(-[a-z0-9]+)*", rule["id"]), "ids are labsec.<area>.<name>"
    meta = rule["metadata"]
    assert meta["category"] == "security"
    assert CWE.match(meta["cwe"]), meta["cwe"]
    assert meta["owasp"] in OWASP_TOP10_2025, meta["owasp"]
    assert meta["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    assert meta["standard"].strip(), "metadata.standard names the exact standard section"
    assert meta["references"] and all(str(r).startswith("https://") for r in meta["references"])
    assert rule["message"].strip()
    if path.parent == OPTIN_DIR:
        assert rule["severity"] == "INFO", "opt-in rules are noisy and stay outside the gate (INFO, imported as Low)"
    else:
        assert rule["severity"] in {"ERROR", "WARNING"}
        # Injection sinks import into DefectDojo as High (ERROR).
        if rule["id"].startswith("labsec.csharp.sql-"):
            assert rule["severity"] == "ERROR"
    if "asvs" in meta:
        assert all(re.fullmatch(r"V\d+\.\d+\.\d+", a) for a in meta["asvs"])


@pytest.mark.parametrize("path,rule", all_rules(), ids=lambda value: value["id"] if isinstance(value, dict) else value.name)
def test_rule_has_positive_and_negative_cases(path, rule):
    fixtures = FIXTURE_DIRS[path.parent]
    assert rule["id"] in annotation_ids("ruleid", fixtures), f"{rule['id']} has no 'ruleid:' fixture"
    assert rule["id"] in annotation_ids("ok", fixtures), f"{rule['id']} has no 'ok:' fixture"


def test_rule_ids_are_unique():
    ids = [rule["id"] for _, rule in all_rules()]
    assert len(ids) == len(set(ids))


@pytest.fixture(scope="module")
def docker_image():
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    probe = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip(f"image {IMAGE} is not built (docker compose --profile tools build opengrep)")


def opengrep(*args: str, network: bool = False) -> subprocess.CompletedProcess:
    cmd = ["docker", "run", "--rm"] + ([] if network else ["--network", "none"]) + ["-v", f"{ROOT}:/src:ro", IMAGE, *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)


@pytest.mark.parametrize("rules_dir", ["opengrep", "optin"])
def test_rules_validate(docker_image, rules_dir):
    # `--validate` downloads the public rule-lint ruleset, so it is the only call that needs the network.
    proc = opengrep("scan", "--validate", "--config", f"/src/rules/{rules_dir}", network=True)
    output = proc.stdout + proc.stderr
    if "Failed to download config" in output:
        pytest.skip("rule-lint ruleset is unreachable (offline); `opengrep test` below still loads every rule")
    assert proc.returncode == 0, output
    assert "Configuration is valid" in output


@pytest.mark.parametrize("rules_dir,fixtures", [("opengrep", "rules"), ("optin", "rules-optin")])
def test_native_rule_tests_pass(docker_image, rules_dir, fixtures):
    proc = opengrep("test", "--taint-intrafile", "--strict", "--config", f"/src/rules/{rules_dir}", f"/src/tests/{fixtures}")
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "All tests passed" in output, output
