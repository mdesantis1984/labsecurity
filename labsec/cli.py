"""Command line entry point for `bin/scan`."""

from __future__ import annotations

import argparse
import sys

from labsec import __version__

EPILOG = """\
exit codes (scan): 0 ok | 1 usage or invalid .appsec.yml | 2 blocking findings (open Critical/High) |
3 lab or tool failure (the lap is incomplete: treat it as BLOCKED). --doctor: 0 healthy, 3 failing checks.

subcommands (triage, report, tasks, gate; `bin/labsec <command> --help`, same program as `bin/scan`):
  findings | report | mark-fp | unmark-fp | mark | tasks | verify-closed | gate
A project directory named like a subcommand must be written with a path (./findings).
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan",
        description="LabSecurity: run one full AppSec lap over a project and summarize the results.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?", help="project directory to analyze (read-only)")
    parser.add_argument("--bootstrap", action="store_true", help="obtain the DefectDojo/SonarQube tokens (idempotent)")
    parser.add_argument("--doctor", action="store_true", help="check that every part of the lab responds")
    parser.add_argument("--json", action="store_true", help="stable JSON output (labsec.summary/v1, labsec.doctor/v1)")
    parser.add_argument("--branch", help="branch label and Gitleaks history to scan (default: current branch)")
    parser.add_argument("--version", action="version", version=f"labsec {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    from labsec.commands import SUBCOMMANDS, dispatch

    if argv and argv[0] in SUBCOMMANDS:
        return dispatch(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.bootstrap and args.doctor:
        parser.error("--bootstrap and --doctor are separate commands")
    if args.bootstrap:
        from labsec.bootstrap import bootstrap

        return bootstrap()
    if args.doctor:
        from labsec.doctor import doctor

        return doctor(as_json=args.json)
    if not args.path:
        parser.error("a project path is required (or use --bootstrap / --doctor)")
    from labsec.pipeline import run_scan

    return run_scan(args.path, as_json=args.json, branch_arg=args.branch)


if __name__ == "__main__":
    sys.exit(main())
