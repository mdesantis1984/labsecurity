"""Run summary: stable JSON (labsec.summary/v1), short human text and exit codes.

Exit codes: 0 ok, 2 blocking findings, 3 lab or tool failure (takes precedence: the lap is incomplete).
"""

from __future__ import annotations

import json

from labsec.redact import redact

SCHEMA = "labsec.summary/v1"
SEVERITIES = ("critical", "high", "medium", "low", "info")
TOOL_STATUSES = ("ok", "failed", "skipped")
_FINDING_KEYS = ("id", "severity", "title", "file", "line", "cwe", "tool")
EXIT_OK, EXIT_BLOCKING, EXIT_FAILURE = 0, 2, 3


def _clean(value):
    return redact(value) if isinstance(value, str) else value


def build_summary(*, project, branch, run_id, engagement_url, tools, counts, blocking_findings, errors) -> dict:
    clean_tools = []
    for tool in tools:
        if tool["status"] not in TOOL_STATUSES:
            raise ValueError(f"invalid tool status {tool['status']!r}")
        entry = {"name": tool["name"], "status": tool["status"], "findings": int(tool.get("findings", 0))}
        if tool.get("reason"):
            entry["reason"] = _clean(tool["reason"])
        clean_tools.append(entry)
    blocking = counts.get("blocking", {})
    return {
        "schema": SCHEMA,
        "project": project,
        "branch": branch,
        "run_id": run_id,
        "engagement_url": engagement_url,
        "tools": clean_tools,
        "counts": {
            "new": int(counts.get("new", 0)),
            "open": int(counts.get("open", 0)),
            "closed": int(counts.get("closed", 0)),
            "blocking": {sev: int(blocking.get(sev, 0)) for sev in SEVERITIES},
        },
        "blocking_findings": [
            {key: _clean(finding.get(key)) for key in _FINDING_KEYS} for finding in blocking_findings
        ],
        "errors": [_clean(error) for error in errors],
    }


def blocking_total(summary: dict) -> int:
    return sum(summary["counts"]["blocking"].values())


def exit_code(summary: dict) -> int:
    if summary["errors"] or any(t["status"] == "failed" for t in summary["tools"]):
        return EXIT_FAILURE
    if blocking_total(summary) > 0 or summary["blocking_findings"]:
        return EXIT_BLOCKING
    return EXIT_OK


def render_json(summary: dict) -> str:
    return json.dumps(summary, indent=2, ensure_ascii=False)


def render_text(summary: dict, max_findings: int = 8) -> str:
    counts = summary["counts"]
    blocking = counts["blocking"]
    tools = ", ".join(
        f"{t['name']} {t['status']}" + (f" ({t['findings']})" if t["status"] == "ok" else "") for t in summary["tools"]
    )
    lines = [
        f"LabSecurity | {summary['project']} @ {summary['branch']} | run {summary['run_id']}",
        f"tools: {tools or 'none'}",
        f"new {counts['new']} | open {counts['open']} | closed {counts['closed']} | "
        f"blocking {blocking_total(summary)} ("
        + ", ".join(f"{sev} {blocking[sev]}" for sev in SEVERITIES)
        + ")",
    ]
    findings = summary["blocking_findings"]
    if findings:
        lines.append(f"BLOCKED: {len(findings)} open Critical/High finding(s) not marked false positive or accepted")
        for f in findings[:max_findings]:
            where = f["file"] or "?"
            if f["line"]:
                where += f":{f['line']}"
            cwe = f", CWE-{f['cwe']}" if f["cwe"] else ""
            lines.append(f"  {f['severity']} {where} {f['title']} [{f['tool']}{cwe}] (id {f['id']})")
        if len(findings) > max_findings:
            lines.append(f"  ... and {len(findings) - max_findings} more (use --json)")
    if summary["errors"]:
        lines.append(f"ERRORS ({len(summary['errors'])}):")
        lines.extend(f"  {error}" for error in summary["errors"][:4])
    if summary["engagement_url"]:
        lines.append(f"engagement: {summary['engagement_url']}")
    return "\n".join(lines)
