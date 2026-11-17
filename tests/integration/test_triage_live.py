"""Triage cycle against the live lab: scan, mark FP / TP, generate tasks, re-scan, close the cycle.

Run with: uv run pytest -m integration tests/integration/test_triage_live.py
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

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.integration
BUSY = "another heavy analysis is running"
REASON = "{file}:{line} - planted by the LabSecurity test fixture, not real code"


def labsec(*args: str, timeout: int = 3000) -> subprocess.CompletedProcess:
    """Run bin/labsec; a busy heavy lock (exit 3) is retried every 60 s for up to 30 minutes."""
    deadline = time.monotonic() + 1800
    while True:
        proc = subprocess.run([str(ROOT / "bin" / "labsec"), *args], capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode == 3 and BUSY in proc.stdout + proc.stderr and time.monotonic() < deadline:
            time.sleep(60)
            continue
        return proc


def scan(project: Path) -> tuple[int, dict]:
    proc = subprocess.run([str(ROOT / "bin" / "scan"), str(project), "--json"], capture_output=True, text=True, timeout=3000, check=False)
    return proc.returncode, json.loads(proc.stdout)


def locked_scan(project: Path) -> tuple[int, dict]:
    deadline = time.monotonic() + 1800
    while True:
        code, summary = scan(project)
        if code == 3 and any(BUSY in e for e in summary.get("errors", [])) and time.monotonic() < deadline:
            time.sleep(60)
            continue
        return code, summary


def query(slug: str, *flags: str) -> list[dict]:
    proc = labsec("findings", slug, *flags, "--limit", "200", "--json")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["schema"] == "labsec.findings/v1"
    return data["findings"]


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
    slug = f"labsec-it-{uuid.uuid4().hex[:8]}"
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
def state(project):
    code, summary = locked_scan(project)
    assert code == 2 and summary["errors"] == [], summary
    return {"slug": project.name, "first": summary}


def test_triage_cycle_end_to_end(state, project, lab, tmp_path):
    slug = state["slug"]
    _, cli = lab
    first = state["first"]

    untriaged = query(slug, "--new", "--untriaged")
    assert len(untriaged) == first["counts"]["new"]
    fp = next(f for f in untriaged if f["tool"] == "opengrep" and f["file"].endswith("app.component.ts"))
    tp = next(f for f in untriaged if f["tool"] == "dotnet-analyzers")
    other = next(f for f in untriaged if f["tool"] == "trivy" and f["severity"] in ("High", "Critical"))

    # A reason without file:line is refused and nothing changes.
    bad = labsec("mark-fp", str(fp["id"]), "--reason", "it is fine, trust me")
    assert bad.returncode == 1 and "file:line" in bad.stderr
    assert fp["id"] in {f["id"] for f in query(slug, "--blocking")}

    # Mark one false positive (with reason), one true positive, one to-confirm.
    ok = labsec("mark-fp", str(fp["id"]), "--reason", REASON.format(file=fp["file"], line=fp["line"]), "--json")
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["schema"] == "labsec.mark/v1"
    assert labsec("mark", str(tp["id"]), "--true-positive", "--note", "reachable from the query string").returncode == 0
    assert labsec("mark", str(other["id"]), "--to-confirm").returncode == 0

    def state_of(flags, fid):
        return fid in {f["id"] for f in query(slug, *flags)}

    for flags in (("--new",), ("--blocking",), ("--open",), ("--new", "--untriaged")):
        assert not state_of(flags, fp["id"]), flags
    assert state_of(("--blocking",), tp["id"]) and not state_of(("--new", "--untriaged"), tp["id"])
    assert not state_of(("--new", "--untriaged"), other["id"]) and state_of(("--blocking",), other["id"])

    # The DD record itself says what we asked for, and risk acceptance was never touched.
    headers = {"Authorization": f"Token {cli['DD_API_TOKEN']}"}
    record = requests.get(f"{cli['DD_URL']}/api/v2/findings/{fp['id']}/", headers=headers, timeout=60).json()
    assert record["false_p"] is True and record["active"] is False and record["risk_accepted"] is False
    assert "labsec-fp" in record["tags"]
    notes = requests.get(f"{cli['DD_URL']}/api/v2/findings/{fp['id']}/notes/", headers=headers, timeout=60).json()
    assert any(fp["file"] in str(n) for n in notes.get("notes", notes if isinstance(notes, list) else []))

    # Report and tasks.
    report = labsec("report", slug)
    assert report.returncode == 0 and "Marked false positive (1)" in report.stdout and f"DD #{fp['id']}" in report.stdout
    body = labsec("report", slug, "--pr-body")
    assert body.returncode == 0 and "deploy/settings.txt" not in body.stdout

    dry = labsec("tasks", slug, "--out", str(tmp_path / "x.md"), "--dry-run")
    assert dry.returncode == 0 and not (tmp_path / "x.md").exists()
    out = tmp_path / "odd" / "tasks" / "security-findings.md"
    written = labsec("tasks", slug, "--out", str(out))
    assert written.returncode == 0, written.stderr
    text = out.read_text()
    assert f"<!-- labsec:task id={tp['id']} " in text and f"id={fp['id']} " not in text and f"id={other['id']} " not in text
    again = labsec("tasks", slug, "--out", str(out))
    assert again.returncode == 0 and "0 added" in again.stdout and out.read_text() == text

    # Re-scan: nothing new, the false positive stays closed out of the blocking set.
    code, second = locked_scan(project)
    assert code == 2 and second["counts"]["new"] == 0, second["counts"]
    assert not state_of(("--blocking",), fp["id"]) and not state_of(("--open",), fp["id"])
    assert state_of(("--blocking",), tp["id"])

    # Closing the cycle is refused while DefectDojo still shows the finding open.
    refused = labsec("tasks", slug, "--close", str(tp["id"]), "--commit", "abc1234", "--out", str(out))
    assert refused.returncode == 2 and "not mitigated" in refused.stderr and "- [ ] SEC-" in out.read_text()

    # Fix the code, re-scan, verify and close.
    fixture_repo.fix_sql_injection(project)
    code, third = locked_scan(project)
    assert third["errors"] == [] and third["counts"]["closed"] >= 1, third["counts"]
    verify = labsec("verify-closed", slug, str(tp["id"]), "--json")
    assert verify.returncode == 0, verify.stdout
    assert json.loads(verify.stdout)["results"][0]["state"] == "mitigated"
    closed = labsec("tasks", slug, "--close", str(tp["id"]), "--commit", "abc1234", "--out", str(out))
    assert closed.returncode == 0, closed.stderr
    assert f"- [x] SEC-{tp['id']} " in out.read_text()

    # Unmarking restores the false positive as a normal finding.
    assert labsec("unmark-fp", str(fp["id"])).returncode == 0
    assert state_of(("--blocking",), fp["id"])
