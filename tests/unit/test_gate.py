import json

import pytest

from labsec import gate
from labsec.config import Paths
from labsec.docker import RunResult

OK_TOOLS = [
    {"name": "opengrep", "status": "ok", "findings": 2},
    {"name": "gitleaks", "status": "ok", "findings": 1},
    {"name": "trivy", "status": "ok", "findings": 1},
    {"name": "sonarqube", "status": "ok", "findings": 3},
    {"name": "zap", "status": "skipped", "findings": 0, "reason": "no zap target declared in .appsec.yml"},
]
NO_BLOCKING = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)


def summary(tools=None, blocking=(), errors=(), engagement="http://dd.test/engagement/3"):
    counts = dict(NO_BLOCKING)
    for item in blocking:
        counts[item["severity"].lower()] += 1
    return {
        "schema": "labsec.summary/v1",
        "project": "demo",
        "branch": "feature/x",
        "run_id": "20261117T100000Z",
        "engagement_url": engagement,
        "tools": list(OK_TOOLS if tools is None else tools),
        "counts": {"new": 3, "open": 4, "closed": 0, "blocking": counts},
        "blocking_findings": list(blocking),
        "errors": list(errors),
    }


HIGH = {"id": 7, "severity": "High", "title": "SQL built by concatenation", "file": "Api/P.cs", "line": 3, "cwe": 89, "tool": "opengrep"}
LEAK = {"id": 8, "severity": "Critical", "title": "Leaked token", "file": "deploy/s.txt", "line": 1, "cwe": 798, "tool": "gitleaks"}


def replace(name, **changes):
    return [{**t, **changes} if t["name"] == name else t for t in OK_TOOLS]


# ----------------------------------------------------------------------------- evaluate
def test_pass_when_every_required_tool_is_ok_and_nothing_blocks():
    assert gate.evaluate(summary(), 0, csharp=False, zap_declared=False) == (0, [])


def test_findings_alone_block_with_2():
    assert gate.evaluate(summary(blocking=[HIGH]), 2, csharp=False, zap_declared=False) == (2, [])


@pytest.mark.parametrize("name", ["opengrep", "gitleaks", "trivy", "sonarqube"])
@pytest.mark.parametrize("status", ["failed", "skipped"])
def test_a_failed_or_skipped_required_tool_blocks_with_3_even_without_findings(name, status):
    code, problems = gate.evaluate(summary(tools=replace(name, status=status, reason="boom")), 3, csharp=False, zap_declared=False)
    assert code == 3 and problems == [f"required tool {name} is {status}: boom"]


def test_failure_takes_precedence_over_findings():
    code, _ = gate.evaluate(summary(tools=replace("trivy", status="failed"), blocking=[HIGH]), 3, csharp=False, zap_declared=False)
    assert code == 3


def test_a_missing_required_tool_blocks_with_3():
    tools = [t for t in OK_TOOLS if t["name"] != "gitleaks"]
    assert gate.evaluate(summary(tools=tools), 0, csharp=False, zap_declared=False) == (3, ["required tool gitleaks did not run"])


def test_csharp_requires_the_dotnet_analyzers():
    assert gate.evaluate(summary(), 0, csharp=True, zap_declared=False) == (3, ["required tool dotnet-analyzers did not run"])
    tools = OK_TOOLS + [{"name": "dotnet-analyzers", "status": "ok", "findings": 1}]
    assert gate.evaluate(summary(tools=tools), 0, csharp=True, zap_declared=False) == (0, [])
    failed = OK_TOOLS + [{"name": "dotnet-analyzers", "status": "failed", "findings": 0, "reason": "build"}]
    assert gate.evaluate(summary(tools=failed), 3, csharp=False, zap_declared=False)[0] == 3


def test_zap_is_required_only_when_declared():
    assert gate.evaluate(summary(), 0, csharp=False, zap_declared=False)[0] == 0
    assert gate.evaluate(summary(), 0, csharp=False, zap_declared=True) == (3, ["required tool zap is skipped: no zap target declared in .appsec.yml"])
    with_zap = replace("zap", status="ok")
    assert gate.evaluate(summary(tools=with_zap), 0, csharp=False, zap_declared=True)[0] == 0


def test_errors_or_missing_import_block_with_3():
    code, problems = gate.evaluate(summary(errors=["DefectDojo counts did not stabilize"]), 3, csharp=False, zap_declared=False)
    assert code == 3 and problems == ["DefectDojo counts did not stabilize"]
    code, problems = gate.evaluate(summary(engagement=None), 0, csharp=False, zap_declared=False)
    assert code == 3 and "not imported into DefectDojo" in problems[0]


def test_usage_error_is_not_a_pass():
    code, _ = gate.evaluate(summary(tools=[], engagement=None, errors=["invalid .appsec.yml"]), 1, csharp=False, zap_declared=False)
    assert code == 1


def test_scan_failure_without_details_still_blocks():
    assert gate.evaluate(summary(), 3, csharp=False, zap_declared=False)[0] == 3


# ----------------------------------------------------------------------------- ensure_lab
def paths(tmp_path):
    return Paths(tmp_path, tmp_path / "c", tmp_path / "d", tmp_path / "x", tmp_path / "s")


def checks(*failing):
    return [{"name": n, "status": "fail", "detail": "down"} for n in failing] or [{"name": "ok", "status": "ok", "detail": ""}]


def test_healthy_lab_is_not_touched(tmp_path):
    def boom():
        raise AssertionError("must not start anything")

    assert gate.ensure_lab(paths(tmp_path), lambda p: checks(), boom) == (True, [], False)


def test_down_lab_is_started_once_and_rechecked(tmp_path):
    states = iter([checks("service:sonarqube"), checks()])
    started = []
    ok, problems, was_started = gate.ensure_lab(paths(tmp_path), lambda p: next(states), lambda: started.append(1) or RunResult(0, ""))
    assert (ok, problems, was_started) == (True, [], True) and started == [1]


def test_lab_that_does_not_come_up_is_reported(tmp_path):
    states = iter([checks("service:sonarqube"), checks("service:sonarqube")])
    ok, problems, was_started = gate.ensure_lab(
        paths(tmp_path), lambda p: next(states), lambda: RunResult(1, "unhealthy\nsonar timed out")
    )
    assert ok is False and was_started is True
    assert "`docker compose up -d --wait` failed (exit 1)" in problems[0]
    assert "lab check service:sonarqube: down" in problems[1]


# ----------------------------------------------------------------------------- run_gate
def project(tmp_path, appsec=None, csharp=False):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    if csharp:
        (root / "Program.cs").write_text("class P {}\n")
    if appsec:
        (root / ".appsec.yml").write_text(appsec)
    return root


def fake_scan(result, code):
    calls = []

    def scan(path, *, as_json, branch_arg, paths, sink):
        calls.append((path, as_json, branch_arg))
        sink(result)
        return code

    scan.calls = calls
    return scan


def run(tmp_path, capsys, scan, root=None, as_json=True, check=lambda p: checks(), up=None, branch=None):
    root = root or project(tmp_path)
    code = gate.run_gate(str(root), as_json=as_json, branch=branch, paths=paths(tmp_path), check_fn=check, up_fn=up, scan_fn=scan)
    return code, capsys.readouterr()


def test_pass_prints_the_pr_summary_and_exits_0(tmp_path, capsys):
    scan = fake_scan(summary(), 0)
    code, out = run(tmp_path, capsys, scan, branch="feature/x")
    data = json.loads(out.out)
    assert code == 0 and data["exit_code"] == 0 and data["verdict"] == "PASS" and data["reason"] is None
    assert data["schema"] == "labsec.gate/v1" and data["summary"]["schema"] == "labsec.summary/v1"
    assert "Gate: **PASS**" in data["pr_body"] and "http://dd.test/engagement/3" in data["pr_body"]
    assert scan.calls[0][1:] == (True, "feature/x")


def test_findings_exit_2_with_pr_body_without_credential_paths(tmp_path, capsys):
    code, out = run(tmp_path, capsys, fake_scan(summary(blocking=[HIGH, LEAK]), 2))
    data = json.loads(out.out)
    assert code == 2 and data["verdict"] == "BLOCKED" and data["reason"] == "findings"
    assert "`Api/P.cs:3` SQL built by concatenation" in data["pr_body"]
    assert "deploy/s.txt" not in data["pr_body"] and "Leaked token" not in data["pr_body"]
    assert "1 credential-related" in data["pr_body"]


def test_tool_failure_exits_3(tmp_path, capsys):
    scan = fake_scan(summary(tools=replace("sonarqube", status="failed", reason="Sonar task FAILED")), 3)
    code, out = run(tmp_path, capsys, scan)
    data = json.loads(out.out)
    assert code == 3 and data["reason"] == "lab_or_tool_failure"
    assert data["problems"] == ["required tool sonarqube is failed: Sonar task FAILED"]
    assert "Problems:" in data["pr_body"]


def test_lab_that_cannot_start_exits_3_and_never_scans(tmp_path, capsys):
    scan = fake_scan(summary(), 0)
    states = iter([checks("service:sonarqube"), checks("service:sonarqube")])
    code, out = run(tmp_path, capsys, scan, check=lambda p: next(states), up=lambda: RunResult(1, "no"))
    data = json.loads(out.out)
    assert code == 3 and data["lab_started"] is True and data["summary"] is None
    assert scan.calls == [] and "the analysis did not complete" in data["pr_body"]


def test_lab_started_then_pass(tmp_path, capsys):
    states = iter([checks("service:dd-nginx"), checks()])
    code, out = run(tmp_path, capsys, fake_scan(summary(), 0), check=lambda p: next(states), up=lambda: RunResult(0, ""))
    assert code == 0 and json.loads(out.out)["lab_started"] is True


def test_busy_lock_is_a_block_not_a_pass(tmp_path, capsys):
    busy = summary(tools=[], engagement=None, errors=["another heavy analysis is running (held by: scan x); wait for it to finish"])
    code, out = run(tmp_path, capsys, fake_scan(busy, 3))
    assert code == 3 and any("another heavy analysis is running" in p for p in json.loads(out.out)["problems"])


def test_csharp_project_needs_dotnet_analyzers(tmp_path, capsys):
    code, out = run(tmp_path, capsys, fake_scan(summary(), 0), root=project(tmp_path, csharp=True))
    assert code == 3 and "dotnet-analyzers" in json.loads(out.out)["problems"][0]


def test_declared_zap_target_is_required(tmp_path, capsys):
    root = project(tmp_path, appsec="zap:\n  target_url: http://127.0.0.1:5000\n")
    code, out = run(tmp_path, capsys, fake_scan(summary(), 0), root=root)
    assert code == 3 and "required tool zap" in json.loads(out.out)["problems"][0]


def test_missing_directory_and_invalid_appsec_are_usage_errors(tmp_path, capsys):
    scan = fake_scan(summary(), 0)
    code, out = run(tmp_path, capsys, scan, root=tmp_path / "nope")
    assert code == 1 and "not a directory" in json.loads(out.out)["problems"][0]
    root = tmp_path / "bad"
    root.mkdir()
    (root / ".appsec.yml").write_text("bogus: 1\n")
    code, out = run(tmp_path, capsys, scan, root=root)
    assert code == 1 and "unknown key" in json.loads(out.out)["problems"][0] and scan.calls == []


def test_text_output_leads_with_the_verdict(tmp_path, capsys):
    code, out = run(tmp_path, capsys, fake_scan(summary(blocking=[HIGH]), 2), as_json=False)
    lines = out.out.splitlines()
    assert code == 2 and lines[0] == "GATE BLOCKED (open Critical/High findings): demo @ feature/x"
    assert "--- PR body ---" in out.out and "### Security (LabSecurity)" in out.out


def test_no_summary_is_never_a_pass(tmp_path, capsys):
    def silent(path, *, as_json, branch_arg, paths, sink):
        return 0

    code, out = run(tmp_path, capsys, silent)
    assert code == 3 and "produced no summary" in json.loads(out.out)["problems"][0]


# ----------------------------------------------------------------------------- PRESERVE: scan output is unchanged without a sink
def test_run_scan_still_prints_its_summary_when_no_sink_is_given(tmp_path, capsys):
    from labsec import pipeline

    code = pipeline.run_scan(str(tmp_path / "missing"), as_json=True, branch_arg=None, paths=paths(tmp_path))
    printed = json.loads(capsys.readouterr().out)
    assert code == 1 and printed["schema"] == "labsec.summary/v1" and "not a directory" in printed["errors"][0]


def test_run_scan_hands_the_summary_to_the_sink_instead_of_printing(tmp_path, capsys):
    from labsec import pipeline

    captured = []
    code = pipeline.run_scan(str(tmp_path / "missing"), as_json=True, branch_arg=None, paths=paths(tmp_path), sink=captured.append)
    assert code == 1 and capsys.readouterr().out == "" and captured[0]["schema"] == "labsec.summary/v1"
