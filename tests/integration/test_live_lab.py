"""End-to-end scan against the live lab (needs the compose stack up, bootstrap done and Docker access).

Run with: uv run pytest -m integration tests/integration
Everything it creates in the lab (DefectDojo product, SonarQube project, work copy, run folders) is removed afterwards.
"""

from __future__ import annotations

import json
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest
import requests

import fixture_repo
from labsec.config import Paths, read_vars
from labsec.profiles import inspect_profiles
from labsec.sonar import SonarClient

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.integration

EXPECTED_TOOLS = ["opengrep", "gitleaks", "trivy", "eslint", "sonarqube", "dotnet-analyzers"]


def scan(project: Path) -> tuple[int, dict, str]:
    proc = subprocess.run(
        [str(ROOT / "bin" / "scan"), str(project), "--json"], capture_output=True, text=True, timeout=3000, check=False
    )
    return proc.returncode, json.loads(proc.stdout), proc.stderr


class LabVars(dict):
    """The lab's variables: a failing assertion must never print credentials through pytest's repr of fixtures."""

    def __repr__(self) -> str:
        return "<lab variables (redacted)>"


@pytest.fixture(scope="module")
def lab():
    paths = Paths.from_env()
    cli = LabVars(read_vars(paths.cli_vars))
    if not cli.get("DD_API_TOKEN") or not cli.get("SONAR_TOKEN"):
        pytest.skip("lab not bootstrapped (run bin/scan --bootstrap)")
    return paths, cli


@pytest.fixture(scope="module")
def project(lab, tmp_path_factory):
    paths, cli = lab
    slug = f"labsec-it-{uuid.uuid4().hex[:8]}"
    repo = tmp_path_factory.mktemp("fixture") / slug
    fixture_repo.build_fixture(repo)
    yield repo
    # Teardown: remove what this test created in the lab.
    shutil.rmtree(paths.work_dir(slug), ignore_errors=True)
    shutil.rmtree(paths.data_dir / "runs" / slug, ignore_errors=True)
    requests.post(
        f"{cli['SONAR_URL']}/api/projects/delete", auth=(cli["SONAR_TOKEN"], ""), data={"project": slug}, timeout=60
    )
    headers = {"Authorization": f"Token {cli['DD_API_TOKEN']}"}
    products = requests.get(f"{cli['DD_URL']}/api/v2/products/", headers=headers, params={"name": slug}, timeout=60)
    for product in products.json().get("results", []):
        requests.delete(f"{cli['DD_URL']}/api/v2/products/{product['id']}/", headers=headers, timeout=120)


@pytest.fixture(scope="module")
def first_run(project, lab):
    before = fixture_repo.tree_digest(project)
    code, summary, stderr = scan(project)
    after = fixture_repo.tree_digest(project)
    return code, summary, stderr, before, after


def test_first_scan_runs_every_tool_and_blocks(first_run, lab):
    code, summary, stderr, _, _ = first_run
    paths, cli = lab
    assert code == 2, stderr[-2000:]
    assert summary["schema"] == "labsec.summary/v1"
    assert summary["branch"] == "main"
    assert summary["errors"] == []
    tools = {t["name"]: t for t in summary["tools"]}
    for name in EXPECTED_TOOLS:
        assert tools[name]["status"] == "ok", (name, tools[name])
        assert tools[name]["findings"] >= 1, name
    assert tools["zap"]["status"] == "skipped"
    assert summary["counts"]["new"] > 0
    assert summary["counts"]["blocking"]["high"] + summary["counts"]["blocking"]["critical"] >= 1
    assert summary["engagement_url"].startswith(cli["DD_URL"])
    found = {b["tool"] for b in summary["blocking_findings"]}
    assert {"opengrep", "gitleaks", "trivy", "dotnet-analyzers", "eslint"} <= found
    files = " ".join(str(b["file"]) for b in summary["blocking_findings"])
    assert "app.component.ts" in files and "Program.cs" in files and "settings.txt" in files
    assert "Dockerfile" in files  # Trivy misconfig: the image runs as root


def _sonar_issues(cli, project_key, **params):
    issues, page = [], 1
    while True:
        response = requests.get(
            f"{cli['SONAR_URL']}/api/issues/search",
            auth=(cli["SONAR_TOKEN"], ""),
            params={"componentKeys": project_key, "ps": 500, "p": page, **params},
            timeout=60,
        )
        data = response.json()
        issues += data["issues"]
        if page * 500 >= data["paging"]["total"]:
            return issues
        page += 1


def test_dotnet_security_rules_reach_defectdojo_and_quality_rules_stay_in_sonarqube(first_run, lab, project):
    _, summary, _, _, _ = first_run
    paths, cli = lab
    sarif = json.loads((paths.run_dir(project.name, summary["run_id"]) / "raw" / "dotnet-analyzers.sarif").read_text())
    reported = {r["ruleId"] for run in sarif["runs"] for r in run["results"]}
    assert {"SCS0005", "CA5351"} <= reported, reported  # SecurityCodeScan and an SDK security rule fire on Api/Crypto.cs
    assert not {r for r in reported if r.startswith(("RCS", "CA1", "CA2000"))}, reported  # quality: SonarQube only
    external = {i["rule"] for i in _sonar_issues(cli, project.name) if i["rule"].startswith("external_roslyn:")}
    assert any(rule.startswith("external_roslyn:MA") for rule in external), external  # Meziantou.Analyzer
    assert any(rule.startswith("external_roslyn:RCS") for rule in external), external  # Roslynator.Analyzers


def test_eslint_findings_enter_sonarqube_as_external_issues_but_only_security_ones_reach_defectdojo(first_run, lab, project):
    _, summary, _, _, _ = first_run
    paths, cli = lab
    external = {i["rule"] for i in _sonar_issues(cli, project.name) if i["rule"].startswith("external_eslint:")}
    assert "external_eslint:no-unsanitized/property" in external, external
    assert "external_eslint:@angular-eslint/template/alt-text" in external, external
    dojo_titles = [b["title"] for b in summary["blocking_findings"] if b["tool"] == "eslint"]
    # DefectDojo title-cases the rule id (`Test ID: No-Unsanitized/Property`), so compare without case.
    assert dojo_titles and all(("test id: no-unsanitized/" in t.lower() or "test id: security/" in t.lower()) for t in dojo_titles), dojo_titles


def test_sonarqube_has_every_rule_active_in_the_labsecurity_profiles(lab):
    _, cli = lab
    rows = inspect_profiles(SonarClient(cli["SONAR_URL"], token=cli["SONAR_TOKEN"]))
    assert rows and all(r["present"] and r["default"] and r["active"] == r["total"] for r in rows), rows


def test_target_repo_is_byte_identical_after_scan(first_run, project):
    _, _, _, before, after = first_run
    assert before == after
    leftovers = [p.name for p in project.rglob("*") if p.name in {".scannerwork", "bin", "obj", "node_modules"}]
    assert leftovers == []


def test_outputs_live_outside_the_repo_with_private_modes(first_run, lab, project):
    _, summary, _, _, _ = first_run
    paths, _ = lab
    run_dir = paths.run_dir(project.name, summary["run_id"])
    for directory in (run_dir, run_dir / "raw"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert (run_dir / "raw" / "gitleaks.json").is_file()
    assert not str(run_dir).startswith(str(project))


def test_no_secret_value_reaches_output_or_reports(first_run, lab, project):
    _, summary, stderr, _, _ = first_run
    paths, cli = lab
    planted = subprocess.run(
        ["git", "-C", str(project), "show", "HEAD~1:deploy/settings.txt"], capture_output=True, text=True, check=True
    ).stdout.split("=", 1)[1].strip()
    haystacks = [json.dumps(summary), stderr]
    run_dir = paths.run_dir(project.name, summary["run_id"])
    haystacks += [p.read_text(errors="ignore") for p in run_dir.rglob("*") if p.is_file() and p.stat().st_size < 5_000_000]
    for secret in (planted, cli["DD_API_TOKEN"], cli["SONAR_TOKEN"], cli["DD_ADMIN_PASSWORD"], cli["SONAR_ADMIN_PASSWORD"]):
        assert not any(secret in text for text in haystacks)


def test_second_scan_has_no_new_findings_and_still_blocks(first_run, project):
    code, summary, stderr = scan(project)
    assert summary["counts"]["new"] == 0, summary["counts"]
    assert summary["counts"]["closed"] == 0
    assert summary["counts"]["open"] == first_run[1]["counts"]["open"]
    assert code == 2, stderr[-2000:]


def test_fixing_an_issue_closes_its_finding(first_run, project):
    fixture_repo.fix_sql_injection(project)
    before = fixture_repo.tree_digest(project)
    _, summary, stderr = scan(project)
    assert fixture_repo.tree_digest(project) == before
    assert summary["errors"] == [], stderr[-1000:]
    assert summary["counts"]["closed"] >= 1, summary["counts"]
    assert "dotnet-analyzers" not in {b["tool"] for b in summary["blocking_findings"]}
