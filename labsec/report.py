"""The human report of a lap: counts by severity, new Critical/High, what blocks, false positives, the link.

Built from the DefectDojo API only. No descriptions, payloads or credential values; the PR-body variant also drops
the file paths of credential-related findings.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from labsec import triage
from labsec.config import Paths, private_dir
from labsec.dojo import SEVERITY_BLOCKING, DojoClient
from labsec.knowledge import explanation, is_secret
from labsec.triage import SEVERITIES, where

SCHEMA = "labsec.report/v1"
MAX_LISTED = 25
SEV_KEYS = tuple(s.lower() for s in SEVERITIES)


def _by_severity(raw: list[dict]) -> dict:
    counts = dict.fromkeys(SEV_KEYS, 0)
    for finding in raw:
        key = str(finding.get("severity", "")).lower()
        if key in counts:
            counts[key] += 1
    return counts


def build_report(dojo: DojoClient, slug: str, run: str = "latest") -> dict:
    product = triage.product_of(dojo, slug)
    engagement = triage.select_engagement(dojo, product["id"], run)
    open_raw = triage.fetch(dojo, product["id"], "open")
    new_raw = triage.fetch(dojo, product["id"], "new", engagement["id"])
    blocking_raw = [f for f in open_raw if triage.is_blocking(f)]
    fp_raw = dojo.findings(test__engagement__product=product["id"], false_p="true")

    blocking = [triage.view_of(dojo, f) for f in sorted(blocking_raw, key=triage.sort_key)]
    new_high = [
        triage.view_of(dojo, f) for f in sorted(new_raw, key=triage.sort_key) if f.get("severity") in SEVERITY_BLOCKING
    ]
    to_confirm = [
        triage.view_of(dojo, f) for f in sorted(open_raw, key=triage.sort_key) if triage.triage_state(f) == "to-confirm"
    ]
    false_positives = []
    for finding in sorted(fp_raw, key=triage.sort_key):
        item = triage.view_of(dojo, finding)
        item["reason"] = triage.reason_of(dojo, finding["id"]) if triage.TAG_FP in (finding.get("tags") or []) else None
        false_positives.append(item)
    tools = sorted({t.get("title") or "unknown" for t in dojo.tests_of(engagement["id"])})
    return {
        "schema": SCHEMA,
        "project": slug,
        "branch": engagement.get("branch_tag") or str(engagement.get("name", "")).rsplit(" ", 1)[0],
        "run": {
            "engagement_id": engagement["id"],
            "run_id": triage.engagement_run_id(engagement),
            "url": f"{dojo.url}/engagement/{engagement['id']}",
        },
        "tools": tools,
        "blocked": bool(blocking),
        "counts": {
            "new": len(new_raw),
            "open": len(open_raw),
            "closed": None,
            "new_by_severity": _by_severity(new_raw),
            "open_by_severity": _by_severity(open_raw),
            "blocking": _by_severity(blocking_raw),
            "untriaged_new": sum(1 for f in new_raw if not triage.is_classified(f)),
            "true_positives": sum(1 for f in open_raw if triage.triage_state(f) == "true-positive"),
            "to_confirm": len(to_confirm),
            "false_positives": len(false_positives),
        },
        "blocking": blocking,
        "new_critical_high": new_high,
        "to_confirm": to_confirm,
        "false_positives": false_positives,
    }


def report_from_summary(summary: dict, blocked: bool | None = None) -> dict:
    """Adapt a `labsec.summary/v1` document (one lap) to the report shape; used by the pre-PR gate."""
    counts = summary["counts"]
    blocking_items = [
        {**f, "rule": None, "status": {}, "triage": "untriaged", "url": None} for f in summary["blocking_findings"]
    ]
    return {
        "schema": SCHEMA,
        "project": summary["project"],
        "branch": summary["branch"],
        "run": {"engagement_id": None, "run_id": summary["run_id"], "url": summary["engagement_url"]},
        "tools": [f"{t['name']} {t['status']}" for t in summary["tools"]],
        "blocked": bool(blocking_items) if blocked is None else blocked,
        "counts": {
            "new": counts["new"],
            "open": counts["open"],
            "closed": counts["closed"],
            "new_by_severity": None,
            "open_by_severity": None,
            "blocking": dict(counts["blocking"]),
            "untriaged_new": None,
            "true_positives": None,
            "to_confirm": None,
            "false_positives": None,
        },
        "blocking": blocking_items,
        "new_critical_high": [],
        "to_confirm": [],
        "false_positives": [],
    }


# ----------------------------------------------------------------------------- saving
FILES = ("report.json", "report.md", "pr-body.md")


def target_dir(paths: Paths, slug: str, project_path: Path | None, out: str | None) -> Path:
    """Where a report goes: `--out DIR`, or `<data root>/reports/<repo>-<hash>/<UTC timestamp>/`.

    A report holds findings, so it never goes inside the scanned repository nor inside LabSecurity's own repository.
    """
    if out is None:
        return paths.new_report_dir(slug, project_path)
    target = Path(out).expanduser().resolve()
    for forbidden, label in ((project_path, "the scanned repository"), (paths.root.resolve(), "the LabSecurity repository")):
        if forbidden is not None and target.is_relative_to(forbidden):
            raise ValueError(f"--out must not be inside {label} ({forbidden}); reports hold findings and must not be committed")
    return private_dir(target)


def save(directory: Path, data: dict) -> list[Path]:
    """Write report.json, report.md and pr-body.md (mode 600) into `directory`."""
    contents = {
        "report.json": json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        "report.md": render_markdown(data) + "\n",
        "pr-body.md": render_pr_body(data) + "\n",
    }
    written = []
    for name in FILES:
        path = directory / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(contents[name])
        os.chmod(path, 0o600)
        written.append(path)
    return written


# ----------------------------------------------------------------------------- rendering
def _sev_table(counts: dict) -> list[str]:
    new, open_, blocking = counts["new_by_severity"], counts["open_by_severity"], counts["blocking"]
    if new is None or open_ is None:
        closed = counts["closed"] if counts["closed"] is not None else "?"
        return [
            f"new {counts['new']} | open {counts['open']} | closed {closed} | blocking {sum(blocking.values())} ("
            + ", ".join(f"{k} {blocking.get(k, 0)}" for k in SEV_KEYS[:4])
            + ")"
        ]
    lines = ["| Severity | New | Open | Blocking |", "| --- | ---: | ---: | ---: |"]
    for sev, key in zip(SEVERITIES, SEV_KEYS):
        if key == "info" and not (new[key] or open_[key]):
            continue
        lines.append(f"| {sev} | {new[key]} | {open_[key]} | {blocking.get(key, 0)} |")
    lines.append(f"| **Total** | {counts['new']} | {counts['open']} | {sum(blocking.values())} |")
    return lines


def _finding_line(item: dict) -> str:
    bits = [f"DD #{item['id']}"]
    if item.get("cwe"):
        bits.append(f"CWE-{item['cwe']}")
    if item.get("tool"):
        bits.append(item["tool"])
    if item.get("triage") and item["triage"] != "untriaged":
        bits.append(item["triage"])
    link = f" <{item['url']}>" if item.get("url") else ""
    return f"- **{item['severity']}** `{where(item)}` - {explanation(item)} ({', '.join(bits)}){link}"


def _listed(items: list[dict], hint: str) -> list[str]:
    if not items:
        return ["- none"]
    out = [_finding_line(item) for item in items[:MAX_LISTED]]
    if len(items) > MAX_LISTED:
        out.append(f"- ... and {len(items) - MAX_LISTED} more ({hint})")
    return out


def render_markdown(report: dict) -> str:
    counts, run = report["counts"], report["run"]
    blocking = report["blocking"]
    status = (
        f"**BLOCKED**: {len(blocking)} open Critical/High finding(s) that are neither false positives nor risk-accepted"
        if report["blocked"]
        else "**Not blocked**: no open Critical/High finding outside false positives and accepted risks"
    )
    lines = [
        f"## LabSecurity report: {report['project']} @ {report['branch']} (run {run['run_id']})",
        "",
        status,
        f"DefectDojo: {run['url']}" if run.get("url") else "DefectDojo: no engagement",
        "",
        *_sev_table(counts),
    ]
    if report["tools"]:
        lines += ["", "Tools: " + ", ".join(report["tools"])]
    lines += ["", f"### New Critical/High ({len(report['new_critical_high'])})"]
    lines += _listed(report["new_critical_high"], "labsec findings <project> --new --severity critical,high")
    lines += ["", f"### What blocks ({len(blocking)})"]
    listed = {item["id"] for item in report["new_critical_high"][:MAX_LISTED]}
    extra = [item for item in blocking if item["id"] not in listed]
    if blocking and not extra:
        lines.append(f"- the {len(blocking)} finding(s) listed above")
    else:
        lines += _listed(extra, "labsec findings <project> --blocking")
        if listed & {item["id"] for item in blocking}:
            lines.append(f"- plus the {len(blocking) - len(extra)} listed above")
    if report["to_confirm"]:
        lines += ["", f"### To confirm ({len(report['to_confirm'])})"]
        lines += _listed(report["to_confirm"], "labsec findings <project> --open")
    fps = report["false_positives"]
    if fps:
        lines += ["", f"### Marked false positive ({len(fps)}): review them; revert with `labsec unmark-fp <id>`"]
        for item in fps[:MAX_LISTED]:
            reason = item.get("reason") or "no reason recorded (marked outside LabSecurity)"
            lines.append(f"- DD #{item['id']} **{item['severity']}** `{where(item)}` - {reason}")
        if len(fps) > MAX_LISTED:
            lines.append(f"- ... and {len(fps) - MAX_LISTED} more")
    untriaged = counts.get("untriaged_new")
    if untriaged:
        lines += ["", f"{untriaged} new finding(s) still need triage (`labsec findings <project> --new --untriaged`)."]
    return "\n".join(lines)


def render_pr_body(report: dict, *, verdict: str | None = None) -> str:
    """Counts and links for a PR description: no explanations, no reasons, no paths of credential findings."""
    counts, run = report["counts"], report["run"]
    blocking = report["blocking"]
    credential_items = [f for f in blocking if is_secret(f)]
    other_items = [f for f in blocking if not is_secret(f)]
    lines = ["### Security (LabSecurity)", ""]
    if verdict:
        lines += [f"Gate: **{verdict}**", ""]
    lines += _sev_table(counts)
    suffix = f" ({len(credential_items)} credential-related, details only in DefectDojo)" if credential_items else ""
    lines += ["", f"Blocking findings: {len(blocking)}{suffix}"]
    for item in other_items[:MAX_LISTED]:
        link = f" <{item['url']}>" if item.get("url") else ""
        lines.append(f"- **{item['severity']}** `{where(item)}` {item['title']}{link}")
    if len(other_items) > MAX_LISTED:
        lines.append(f"- ... and {len(other_items) - MAX_LISTED} more in DefectDojo")
    fp_count = counts.get("false_positives")
    if fp_count:
        lines.append(f"False positives marked (with verifiable reasons): {fp_count}")
    lines.append("")
    lines.append(f"DefectDojo: {run['url']}" if run.get("url") else "DefectDojo: no engagement")
    return "\n".join(lines)
