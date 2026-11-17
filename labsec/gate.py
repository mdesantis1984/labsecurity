"""Pre-PR gate: make sure the lab is up, run one full lap and answer PASS or BLOCKED.

Exit codes: 0 PASS | 1 usage error (the gate could not even start; never a pass) | 2 BLOCKED by findings |
3 BLOCKED because the lab or a required tool failed. There is no silent pass: every required tool must be `ok`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from labsec import pipeline, report
from labsec.appsec import AppSecError, load_appsec
from labsec.config import Paths, read_vars, secret_values
from labsec.docker import Compose
from labsec.doctor import run_checks
from labsec.langs import detect_languages
from labsec.redact import redact
from labsec.summary import EXIT_BLOCKING, EXIT_FAILURE, EXIT_OK, blocking_total

SCHEMA = "labsec.gate/v1"
EXIT_USAGE = 1
# Always required. dotnet-analyzers joins when the project has C#; zap joins when .appsec.yml declares a target.
REQUIRED_TOOLS = ("opengrep", "gitleaks", "trivy", "sonarqube")


def ensure_lab(paths: Paths, check_fn=run_checks, up_fn=None, log=None) -> tuple[bool, list[str], bool]:
    """Return (healthy, problems, started). Starts the compose stack only when a check fails."""
    log = log or (lambda message: None)
    failing = [c for c in check_fn(paths) if c["status"] == "fail"]
    if not failing:
        return True, [], False
    log("lab is not healthy; running `docker compose up -d --wait`")
    known = secret_values(read_vars(paths.cli_vars))
    up_fn = up_fn or (lambda: Compose(paths, known).up())
    result = up_fn()
    problems = []
    if not result.ok:
        problems.append(f"`docker compose up -d --wait` failed (exit {result.returncode}): {redact(result.tail(4), known)}")
    failing = [c for c in check_fn(paths) if c["status"] == "fail"]
    problems += [f"lab check {c['name']}: {redact(c['detail'], known)}" for c in failing]
    return not failing, problems, True


def evaluate(summary: dict, scan_code: int, *, csharp: bool, zap_declared: bool) -> tuple[int, list[str]]:
    """Gate verdict from one lap: (exit code, problems). Findings alone give 2; any tool/lab problem gives 3."""
    problems: list[str] = []
    tools = {t["name"]: t for t in summary["tools"]}
    required = list(REQUIRED_TOOLS)
    if csharp or "dotnet-analyzers" in tools:
        required.append("dotnet-analyzers")
    if zap_declared:
        required.append("zap")
    for name in required:
        tool = tools.get(name)
        if tool is None:
            problems.append(f"required tool {name} did not run")
        elif tool["status"] != "ok":
            reason = f": {tool['reason']}" if tool.get("reason") else ""
            problems.append(f"required tool {name} is {tool['status']}{reason}")
    for tool in summary["tools"]:
        if tool["status"] == "failed" and tool["name"] not in required:
            problems.append(f"tool {tool['name']} failed: {tool.get('reason', 'no reason')}")
    problems += list(summary["errors"])
    if summary["engagement_url"] is None:
        problems.append("the results were not imported into DefectDojo")
    if scan_code == EXIT_USAGE:
        return EXIT_USAGE, problems or ["usage error"]
    if scan_code == EXIT_FAILURE and not problems:
        problems.append("the lap reported a lab or tool failure")
    if problems:
        return EXIT_FAILURE, problems
    if blocking_total(summary) > 0 or summary["blocking_findings"]:
        return EXIT_BLOCKING, []
    return EXIT_OK, []


def _verdict(code: int) -> str:
    return "PASS" if code == EXIT_OK else "BLOCKED"


def _reason(code: int) -> str | None:
    return {EXIT_BLOCKING: "findings", EXIT_FAILURE: "lab_or_tool_failure", EXIT_USAGE: "usage"}.get(code)


def _failure_body(slug: str, problems: list[str]) -> str:
    lines = ["### Security (LabSecurity)", "", "Gate: **BLOCKED** (lab or tool failure): the analysis did not complete."]
    lines += [f"- {problem}" for problem in problems[:6]]
    return "\n".join(lines)


def build_result(*, project: str, branch: str, code: int, problems: list[str], summary: dict | None, started: bool) -> dict:
    verdict = _verdict(code)
    if summary is not None:
        data = report.report_from_summary(summary, blocked=code == EXIT_BLOCKING)
        body = report.render_pr_body(data, verdict=verdict)
        if problems:
            body += "\n\nProblems:\n" + "\n".join(f"- {p}" for p in problems[:6])
    else:
        body = _failure_body(project, problems)
    return {
        "schema": SCHEMA,
        "project": project,
        "branch": branch,
        "verdict": verdict,
        "reason": _reason(code),
        "exit_code": code,
        "problems": problems,
        "lab_started": started,
        "summary": summary,
        "pr_body": body,
    }


def render_text(result: dict) -> str:
    reason = {"findings": "open Critical/High findings", "lab_or_tool_failure": "lab or tool failure", "usage": "cannot start"}.get(
        result["reason"]
    )
    head = f"GATE {result['verdict']}" + (f" ({reason})" if reason else "") + f": {result['project']} @ {result['branch']}"
    lines = [head]
    lines += [f"  - {problem}" for problem in result["problems"][:8]]
    lines += ["", "--- PR body ---", result["pr_body"]]
    return "\n".join(lines)


def run_gate(
    project_arg: str,
    *,
    as_json: bool,
    branch: str | None = None,
    paths: Paths | None = None,
    check_fn=run_checks,
    up_fn=None,
    scan_fn=None,
) -> int:
    paths = paths or Paths.from_env()
    scan_fn = scan_fn or pipeline.run_scan
    project = Path(project_arg).expanduser()

    def emit(result: dict) -> int:
        print(json.dumps(result, indent=2, ensure_ascii=False) if as_json else render_text(result))
        return result["exit_code"]

    if not project.is_dir():
        return emit(build_result(project=project.name, branch=branch or "", code=EXIT_USAGE,
                                 problems=[f"project path is not a directory: {project_arg}"], summary=None, started=False))
    project = project.resolve()
    try:
        appsec = load_appsec(project)
    except AppSecError as exc:
        return emit(build_result(project=project.name, branch=branch or "", code=EXIT_USAGE,
                                 problems=[redact(str(exc))], summary=None, started=False))

    healthy, problems, started = ensure_lab(paths, check_fn, up_fn, log=lambda m: print(f"[labsec] {m}", file=sys.stderr, flush=True))
    if not healthy:
        return emit(build_result(project=project.name, branch=branch or "", code=EXIT_FAILURE,
                                 problems=problems or ["the lab is not healthy"], summary=None, started=started))

    captured: list[dict] = []
    scan_code = scan_fn(str(project), as_json=True, branch_arg=branch, paths=paths, sink=captured.append)
    if not captured:
        return emit(build_result(project=project.name, branch=branch or "", code=EXIT_FAILURE,
                                 problems=["the lap produced no summary"], summary=None, started=started))
    summary = captured[0]
    csharp = bool(detect_languages(project, appsec.exclude).get("csharp"))
    code, problems = evaluate(summary, scan_code, csharp=csharp, zap_declared=appsec.zap is not None)
    return emit(build_result(project=summary["project"], branch=summary["branch"], code=code, problems=problems,
                             summary=summary, started=started))
