"""Subcommands of `labsec`: findings, report, mark-fp, unmark-fp, mark, tasks, verify-closed, gate.

All of them read and write DefectDojo through its API only (never raw reports), print compact text by default and a
versioned JSON document with `--json`. Exit codes: 0 ok | 1 usage or unknown object | 2 the answer is "no"
(blocked, not mitigated) | 3 lab failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from labsec import __version__, report, tasks, triage
from labsec.config import Paths
from labsec.dojo import DojoError
from labsec.project import LabNotReady, UsageError, connect, resolve_project
from labsec.redact import redact

SUBCOMMANDS = ("findings", "report", "mark-fp", "unmark-fp", "mark", "tasks", "verify-closed", "gate")
ERROR_SCHEMA = "labsec.error/v1"

EXAMPLES = """\
examples:
  labsec findings my-app --blocking --json          what blocks the PR right now
  labsec findings my-app --new --untriaged          new findings that still need a verdict
  labsec report my-app                              markdown report for the conversation; also saved under the data root
  labsec report my-app --pr-body                    counts and links for a PR description
  labsec mark-fp 123 --reason "Api/Repo.cs:42 - the value is a compile-time constant"
  labsec mark 124 --true-positive                   confirmed against the real code
  labsec tasks my-app --out my-app/odd/tasks/security-findings.md
  labsec verify-closed my-app 124 125               after a re-run: which ones are mitigated?
  labsec gate my-app                                pre-PR gate: exit 0 PASS, 2 findings, 3 lab or tool failure
"""


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="labsec",
        description="LabSecurity triage, report, tasks and gate (DefectDojo API only; never raw reports).",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"labsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    def add(name, help_text, project=True):
        p = sub.add_parser(name, help=help_text, description=help_text)
        if project:
            p.add_argument("project", help="project directory or DefectDojo product slug")
        p.add_argument("--json", action="store_true", help="versioned JSON output")
        return p

    p = add("findings", "compact list of findings (labsec.findings/v1)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--open", dest="view", action="store_const", const="open", help="active findings of the product (default)")
    group.add_argument("--new", dest="view", action="store_const", const="new", help="active findings first seen in the run")
    group.add_argument("--blocking", dest="view", action="store_const", const="blocking",
                       help="open Critical/High that are neither false positive nor risk accepted")
    p.add_argument("--severity", help="comma list: critical,high,medium,low,info")
    p.add_argument("--untriaged", action="store_true", help="only findings nobody classified yet")
    p.add_argument("--limit", type=int, default=50, help="maximum findings returned (default 50)")
    p.add_argument("--run", default="latest", help="run for --new: latest, an engagement id or a run id")

    p = add("report", "human report of a run: counts, new Critical/High, what blocks, false positives (labsec.report/v1)")
    p.add_argument("--run", default="latest", help="latest, an engagement id or a run id")
    p.add_argument("--pr-body", action="store_true", help="PR description variant: counts and links, no credential paths")
    p.add_argument("--out", metavar="DIR",
                   help="save the report files here instead of <data root>/reports/<repo>-<hash>/<UTC timestamp>/ "
                        "(never inside the scanned repository or LabSecurity's repository)")
    p.add_argument("--no-save", action="store_true", help="print only; write no report files")

    p = add("mark-fp", "mark a finding as false positive; needs a file:line reason", project=False)
    p.add_argument("id", type=int, help="DefectDojo finding id")
    p.add_argument("--reason", required=True, help='"<file:line> - why it is not exploitable"')

    p = add("unmark-fp", "revert a false-positive mark made by LabSecurity", project=False)
    p.add_argument("id", type=int, help="DefectDojo finding id")

    p = add("mark", "record the verdict of a triaged finding (tag + note; never closes or accepts anything)", project=False)
    p.add_argument("id", type=int, help="DefectDojo finding id")
    kind = p.add_mutually_exclusive_group(required=True)
    kind.add_argument("--true-positive", action="store_true", help="confirmed against the real code (tag + note)")
    kind.add_argument("--to-confirm", action="store_true", help="doubt: tag only, no status change")
    p.add_argument("--note", help="optional short note stored in DefectDojo")

    p = add("tasks", "generate or close ODD tasks for confirmed true positives (labsec.tasks/v1)")
    p.add_argument("--out", help="ODD task file to write (explicit opt-in; without it nothing is written)")
    p.add_argument("--feature-doc", help="ODD feature document to put the tasks in instead (also explicit opt-in)")
    p.add_argument("--dry-run", action="store_true", help="print the resulting file, write nothing (default without --out)")
    p.add_argument("--close", type=int, metavar="DD_ID", help="mark the task of this finding done (only if mitigated)")
    p.add_argument("--commit", help="fix commit recorded as evidence by --close")

    p = add("verify-closed", "after a re-run: which findings are mitigated now (labsec.verify/v1)")
    p.add_argument("ids", type=int, nargs="+", metavar="dd-id", help="DefectDojo finding ids")

    p = add("gate", "pre-PR gate: lab up, one full lap, PASS or BLOCKED (labsec.gate/v1)")
    p.add_argument("--branch", help="branch label and Gitleaks history (default: current branch)")
    return parser


def _error(message: str, as_json: bool, code: int) -> int:
    clean = redact(message)
    if as_json:
        _print_json({"schema": ERROR_SCHEMA, "error": clean, "exit_code": code})
    else:
        print(f"labsec: {clean}", file=sys.stderr)
    return code


def dispatch(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    as_json = args.json
    if args.command == "gate":
        from labsec.gate import run_gate

        return run_gate(args.project, as_json=as_json, branch=args.branch)
    try:
        return _run(args, as_json)
    except UsageError as exc:
        return _error(str(exc), as_json, 1)
    except tasks.TaskNotClosable as exc:
        if as_json:
            _print_json({"schema": ERROR_SCHEMA, "error": redact(str(exc)), "exit_code": 2, "state": exc.state})
        else:
            print(f"labsec: {redact(str(exc))}", file=sys.stderr)
        return 2
    except (LabNotReady, DojoError) as exc:
        return _error(f"lab failure: {exc}", as_json, 3)


def _run(args, as_json: bool) -> int:
    dojo = connect()
    command = args.command
    if command == "findings":
        project = resolve_project(args.project)
        data = triage.list_findings(
            dojo,
            project.slug,
            view=args.view or "open",
            severities=triage.parse_severities(args.severity),
            untriaged=args.untriaged,
            limit=args.limit,
            run=args.run,
        )
        print(json.dumps(data, indent=2, ensure_ascii=False) if as_json else triage.render_findings_text(data))
        return 0
    if command == "report":
        project = resolve_project(args.project)
        data = report.build_report(dojo, project.slug, args.run)
        if not args.no_save:
            paths = Paths.from_env()
            try:
                directory = report.target_dir(paths, project.slug, project.path, args.out)
            except ValueError as exc:
                raise UsageError(str(exc)) from exc
            report.save(directory, data)
            data["saved_to"] = str(directory)
            print(f"labsec: report saved to {directory}", file=sys.stderr)
        elif args.out:
            raise UsageError("--out and --no-save contradict each other")
        if as_json:
            data["markdown"] = report.render_pr_body(data) if args.pr_body else report.render_markdown(data)
            _print_json(data)
        else:
            print(report.render_pr_body(data) if args.pr_body else report.render_markdown(data))
        return 0
    if command in ("mark-fp", "unmark-fp", "mark"):
        if command == "mark-fp":
            result = triage.mark_false_positive(dojo, args.id, args.reason)
        elif command == "unmark-fp":
            result = triage.unmark_false_positive(dojo, args.id)
        elif args.true_positive:
            result = triage.mark_true_positive(dojo, args.id, args.note)
        else:
            result = triage.mark_to_confirm(dojo, args.id, args.note)
        print(json.dumps(result, indent=2, ensure_ascii=False) if as_json else triage.render_mark_text(result))
        return 0
    if command == "verify-closed":
        project = resolve_project(args.project)
        data = tasks.verify_closed(dojo, project.slug, args.ids)
        print(json.dumps(data, indent=2, ensure_ascii=False) if as_json else tasks.render_verify_text(data))
        return 0 if data["all_mitigated"] else 2
    if command == "tasks":
        return _tasks(args, dojo, as_json)
    raise UsageError(f"unknown command {command!r}")


def _tasks(args, dojo, as_json: bool) -> int:
    project = resolve_project(args.project)
    if args.close is not None:
        if not args.commit:
            raise UsageError("--close needs --commit <sha> (the fix commit is the evidence)")
        path, explicit = tasks.target_path(project.path, args.out, args.feature_doc)
        result = tasks.close_task(dojo, project.slug, args.close, args.commit, path, dry_run=args.dry_run, explicit=explicit)
        if as_json:
            _print_json(result)
        else:
            if result["already_closed"]:
                print(f"task SEC-{args.close} is already done in {result['target']}")
            else:
                verb = "task marked done" if result["mode"] == "written" else "dry run: task would be marked done"
                print(f"{verb}: SEC-{args.close} fix commit {result['commit']} ({result['target']})")
        return 0
    if args.commit:
        raise UsageError("--commit only makes sense together with --close")
    if project.path is None and not (args.out or args.feature_doc):
        raise UsageError("a product slug has no project directory: pass --out <task file> or give the project path")
    result = tasks.generate(
        dojo, project.slug, project.path, out=args.out, feature_doc=args.feature_doc, dry_run=args.dry_run
    )
    if as_json:
        _print_json(result)
    else:
        print(tasks.render_generate_text(result, with_content=result["mode"] == "dry-run"))
    return 0
