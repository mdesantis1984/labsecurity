"""`bin/scan <project>`: one full lap (prepare, analyze, import into DefectDojo, summarize)."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from labsec.appsec import AppSecError, load_appsec
from labsec.config import Paths, private_dir, read_vars, secret_values
from labsec.docker import Compose
from labsec.dojo import DojoClient, DojoError
from labsec.guard import UnsafeTargetError, ensure_loopback
from labsec.langs import detect_languages, slugify
from labsec.lock import HeavyLock, LockBusy
from labsec.redact import redact
from labsec.sonar import SonarClient
from labsec.summary import EXIT_FAILURE, build_summary, exit_code, render_json, render_text
from labsec import scope as scope_mod, tools

EXIT_USAGE = 1
ZERO_COUNTS = {"new": 0, "open": 0, "closed": 0, "blocking": {}}


def _log(message: str) -> None:
    print(f"[labsec] {message}", file=sys.stderr, flush=True)


def _emit(summary: dict, as_json: bool, sink=None) -> None:
    """Print the summary, or hand it to `sink` (the pre-PR gate) instead of printing."""
    if sink is not None:
        sink(summary)
        return
    print(render_json(summary) if as_json else render_text(summary))


def _failure(slug, branch, run_id, errors, as_json, code=EXIT_FAILURE, tool_list=None, sink=None) -> int:
    summary = build_summary(
        project=slug,
        branch=branch,
        run_id=run_id,
        engagement_url=None,
        tools=tool_list or [],
        counts=ZERO_COUNTS,
        blocking_findings=[],
        errors=errors,
    )
    _emit(summary, as_json, sink)
    return code


def run_scan(project_arg: str, *, as_json: bool, branch_arg: str | None, paths: Paths | None = None, sink=None) -> int:
    paths = paths or Paths.from_env()
    started = datetime.now(timezone.utc)
    run_id = started.strftime("%Y%m%dT%H%M%SZ")
    project = Path(project_arg).expanduser().resolve()
    slug = slugify(project.name)
    if not project.is_dir():
        return _failure(slug, "", run_id, [f"project path is not a directory: {project_arg}"], as_json, EXIT_USAGE, sink=sink)

    try:
        appsec = load_appsec(project)
        slug = slugify(appsec.name or project.name)
        if appsec.zap:
            ensure_loopback(appsec.zap.target_url)
            if appsec.zap.openapi_url:
                ensure_loopback(appsec.zap.openapi_url)
        branch, commit = tools.resolve_branch(project, branch_arg)
    except (AppSecError, UnsafeTargetError, ValueError) as exc:
        return _failure(slug, branch_arg or "", run_id, [redact(str(exc))], as_json, EXIT_USAGE, sink=sink)

    cli_vars = read_vars(paths.cli_vars)
    project_vars = read_vars(paths.project_vars(slug))
    known = secret_values(cli_vars, project_vars)
    dd_token, sonar_token = cli_vars.get("DD_API_TOKEN", ""), cli_vars.get("SONAR_TOKEN", "")
    if not (cli_vars.get("DD_URL") and cli_vars.get("SONAR_URL") and dd_token and sonar_token):
        return _failure(slug, branch, run_id, ["lab is not configured: run `bin/scan --bootstrap` first"], as_json, sink=sink)

    dojo = DojoClient(cli_vars["DD_URL"], dd_token)
    sonar = SonarClient(cli_vars["SONAR_URL"], token=sonar_token)
    try:
        dojo.check()
        if sonar.status() != "UP" or not sonar.token_valid():
            raise RuntimeError("SonarQube is not UP or the token is invalid (run `bin/scan --doctor`)")
    except (DojoError, RuntimeError, Exception) as exc:  # noqa: BLE001 - preflight failure is a lab failure
        return _failure(
            slug,
            branch,
            run_id,
            [f"lab not ready: {redact(str(exc), known)}", "start it with `docker compose up -d` and run `bin/scan --doctor`"],
            as_json,
            sink=sink,
        )

    try:
        with HeavyLock(paths.lock_path, owner=f"scan {slug}"):
            return _locked_scan(
                paths, project, slug, branch, commit, run_id, started, appsec, cli_vars, project_vars, known, dojo, sonar, sonar_token, as_json, sink
            )
    except LockBusy as exc:
        return _failure(slug, branch, run_id, [str(exc)], as_json, sink=sink)


def _locked_scan(paths, project, slug, branch, commit, run_id, started, appsec, cli_vars, project_vars, known, dojo, sonar, sonar_token, as_json, sink=None) -> int:
    run_dir = private_dir(paths.run_dir(slug, run_id))
    private_dir(run_dir / "raw")
    private_dir(paths.tool_cache_dir)
    for cache in ("trivy", "sonar-scanner", "dotnet"):
        private_dir(paths.tool_cache_dir / cache)
    scan_scope = scope_mod.build_scope(project, appsec.exclude)
    langs = detect_languages(project, files=scan_scope.files)
    _log(f"project {slug} @ {branch}; languages: {', '.join(f'{k}({v})' for k, v in sorted(langs.items())) or 'none'}")
    ctx = tools.Ctx(
        paths=paths,
        compose=Compose(paths, known),
        project=project,
        slug=slug,
        branch=branch,
        commit=commit,
        run_id=run_id,
        run_dir=run_dir,
        appsec=appsec,
        langs=langs,
        sonar_token=sonar_token,
        sonar=sonar,
        project_vars=project_vars,
        log=_log,
        started=started,
        scope=scan_scope,
    )
    errors: list[str] = []
    try:
        tools.prepare_work_copy(ctx)
    except Exception as exc:  # noqa: BLE001
        return _failure(slug, branch, run_id, [f"work copy: {redact(str(exc), known)}"], as_json, sink=sink)

    outcomes: list[tools.ToolOutcome] = []
    for name, runner in (
        ("opengrep", tools.run_opengrep),
        ("gitleaks", tools.run_gitleaks),
        ("trivy", tools.run_trivy),
        ("eslint", tools.run_eslint),  # before SonarQube: its report is imported there as external issues
        ("sonarqube", tools.run_sonar),
        ("zap", tools.run_zap),
    ):
        _log(f"running {name}")
        try:
            result = runner(ctx)
        except Exception as exc:  # noqa: BLE001 - one tool failing must not hide the others
            result = tools.ToolOutcome(name, "failed", reason=redact(str(exc), known)[:300])
        for outcome in result if isinstance(result, list) else [result]:
            _log(f"  {outcome.name}: {outcome.status}" + (f" ({outcome.reason})" if outcome.reason else ""))
            outcomes.append(outcome)

    engagement_name = f"{branch} {run_id}"
    engagement_id = product_id = None
    test_tools: dict[int, str] = {}
    import_started = datetime.now(timezone.utc) - timedelta(seconds=2)
    for outcome in outcomes:
        if outcome.status != "ok" or outcome.report is None:
            continue
        _log(f"importing {outcome.name} into DefectDojo ({outcome.scan_type})")
        try:
            imported = dojo.import_scan(
                scan_type=outcome.scan_type,
                file_path=outcome.report,
                product=slug,
                engagement=engagement_name,
                test_title=outcome.test_title,
                branch=branch,
                commit=commit,
                build_id=run_id,
            )
        except DojoError as exc:
            outcome.status, outcome.reason = "failed", f"import: {redact(str(exc), known)[:300]}"
            continue
        engagement_id = imported["engagement_id"]
        test_tools[imported["test_id"]] = outcome.name
        outcome.detail["test_id"] = imported["test_id"]

    counts = dict(ZERO_COUNTS)
    blocking_findings: list[dict] = []
    engagement_url = None
    per_test: dict[int, int] = {}
    if engagement_id is not None:
        try:
            product_id = dojo.product_id_of(engagement_id)
            engagement_url = dojo.engagement_url(engagement_id)
            _log("waiting for DefectDojo deduplication to settle")
            if not dojo.wait_stable(engagement_id, product_id):
                errors.append("DefectDojo counts did not stabilize within 180 s; numbers may be incomplete")
            data = dojo.summarize(engagement_id, product_id, import_started, test_tools)
            counts = {key: data[key] for key in ("new", "open", "closed", "blocking")}
            blocking_findings = data["blocking_findings"]
            per_test = data["per_test"]
        except DojoError as exc:
            errors.append(f"summary: {redact(str(exc), known)[:300]}")

    tool_rows = []
    for outcome in outcomes:
        row = {"name": outcome.name, "status": outcome.status, "findings": per_test.get(outcome.detail.get("test_id"), 0)}
        if outcome.reason:
            row["reason"] = outcome.reason
        tool_rows.append(row)
    summary = build_summary(
        project=slug,
        branch=branch,
        run_id=run_id,
        engagement_url=engagement_url,
        tools=tool_rows,
        counts=counts,
        blocking_findings=blocking_findings,
        errors=errors,
        scope=scan_scope.to_summary(),
    )
    summary_path = run_dir / "summary.json"
    summary_path.write_text(render_json(summary), encoding="utf-8")
    os.chmod(summary_path, 0o600)
    _emit(summary, as_json, sink)
    return exit_code(summary)
