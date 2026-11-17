"""Pre-PR gate against the live lab: exit codes 2 (findings), 0 (pass), 3 (lab/tool failure), 1 (usage).

Run with: uv run pytest -m integration tests/integration/test_gate_live.py
It waits (60 s steps, up to 30 min) when another heavy analysis holds the lock. Everything it creates in the
lab (DefectDojo product, SonarQube project, work copy, run folders) is removed afterwards.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

import fixture_repo
from labsec.config import Paths, read_vars
from labsec.lock import HeavyLock, LockBusy

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.integration
BUSY = "another heavy analysis is running"


def run(*args: str, timeout: int = 3000) -> subprocess.CompletedProcess:
    return subprocess.run([str(ROOT / "bin" / "labsec"), *args], capture_output=True, text=True, timeout=timeout, check=False)


def gate(project: Path, *extra: str) -> tuple[int, dict]:
    """Run `labsec gate --json`; a busy lock is retried every 60 s for up to 30 minutes."""
    deadline = time.monotonic() + 1800
    while True:
        proc = run("gate", str(project), "--json", *extra)
        data = json.loads(proc.stdout)
        if proc.returncode == 3 and any(BUSY in p for p in data["problems"]) and time.monotonic() < deadline:
            time.sleep(60)
            continue
        return proc.returncode, data


@pytest.fixture(scope="module")
def lab():
    paths = Paths.from_env()
    cli = read_vars(paths.cli_vars)
    if not cli.get("DD_API_TOKEN") or not cli.get("SONAR_TOKEN"):
        pytest.skip("lab not bootstrapped (run bin/scan --bootstrap)")
    return paths, cli


@pytest.fixture(scope="module")
def project(lab, tmp_path_factory):
    paths, cli = lab
    slug = f"labsec-gt-{uuid.uuid4().hex[:8]}"
    repo = tmp_path_factory.mktemp("fixture") / slug
    fixture_repo.build_fixture(repo)
    yield repo
    shutil.rmtree(paths.work_dir(slug), ignore_errors=True)
    shutil.rmtree(paths.data_dir / "runs" / slug, ignore_errors=True)
    requests.post(f"{cli['SONAR_URL']}/api/projects/delete", auth=(cli["SONAR_TOKEN"], ""), data={"project": slug}, timeout=60)
    headers = {"Authorization": f"Token {cli['DD_API_TOKEN']}"}
    products = requests.get(f"{cli['DD_URL']}/api/v2/products/", headers=headers, params={"name": slug}, timeout=60)
    for product in products.json().get("results", []):
        requests.delete(f"{cli['DD_URL']}/api/v2/products/{product['id']}/", headers=headers, timeout=120)


@pytest.fixture(scope="module")
def blocked(project):
    return gate(project)


def test_vulnerable_fixture_is_blocked_by_findings_with_every_tool_ok(blocked):
    code, data = blocked
    assert code == 2 and data["exit_code"] == 2 and data["verdict"] == "BLOCKED" and data["reason"] == "findings"
    assert data["schema"] == "labsec.gate/v1" and data["problems"] == []
    tools = {t["name"]: t["status"] for t in data["summary"]["tools"]}
    for name in ("opengrep", "gitleaks", "trivy", "sonarqube", "dotnet-analyzers"):
        assert tools[name] == "ok", tools
    assert tools["zap"] == "skipped"  # no loopback URL declared, so ZAP is not required
    assert "Gate: **BLOCKED**" in data["pr_body"]
    assert "deploy/settings.txt" not in data["pr_body"]  # credential findings never expose their path in the PR body


def test_gate_passes_once_every_blocking_finding_has_a_reasoned_false_positive(blocked, project):
    slug = project.name
    listed = run("findings", slug, "--blocking", "--limit", "200", "--json")
    assert listed.returncode == 0
    for item in json.loads(listed.stdout)["findings"]:
        reason = f"{item['file']}:{item['line'] or 1} - planted by the LabSecurity test fixture, not real code"
        assert run("mark-fp", str(item["id"]), "--reason", reason).returncode == 0
    code, data = gate(project)
    assert code == 0 and data["verdict"] == "PASS" and data["reason"] is None and data["problems"] == []
    assert data["summary"]["counts"]["new"] == 0
    assert data["lab_started"] is False
    assert "Gate: **PASS**" in data["pr_body"]


def test_busy_lock_blocks_with_3_and_never_passes(project, lab):
    paths, _ = lab
    deadline = time.monotonic() + 1800
    while True:
        try:
            held = HeavyLock(paths.lock_path, owner="test_gate_live").__enter__()
            break
        except LockBusy:
            assert time.monotonic() < deadline, "heavy lock never became free"
            time.sleep(60)
    try:
        proc = run("gate", str(project), "--json")
    finally:
        held.__exit__(None, None, None)
    data = json.loads(proc.stdout)
    assert proc.returncode == 3 and data["exit_code"] == 3 and data["verdict"] == "BLOCKED"
    assert data["reason"] == "lab_or_tool_failure" and any(BUSY in p for p in data["problems"])


def test_usage_error_is_exit_1(tmp_path):
    proc = run("gate", str(tmp_path / "does-not-exist"), "--json")
    data = json.loads(proc.stdout)
    assert proc.returncode == 1 and data["verdict"] == "BLOCKED" and "not a directory" in data["problems"][0]
